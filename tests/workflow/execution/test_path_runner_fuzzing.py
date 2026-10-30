from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from types import SimpleNamespace

import pytest

import cloud_dast.verification.oracles.grounded
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.finding_examples import load_finding_examples
from cloud_dast.contracts.metrics import measure_component_activity
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
    VerificationPlan,
)
from cloud_dast.infrastructure.events import JsonlExampleDatabase
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    ExecutionTrace,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
    ScenarioPosition,
    TraceStep,
    TransportStatus,
    VerdictStatus,
)
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    DomainEvent,
    DownstreamDecision,
    EventScope,
    FactVerified,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    changed,
    duration,
    field,
    has,
    input_field,
    output_field,
)
from cloud_dast.qdl.reasoning import QdlPlan
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.candidates.session import StepCandidateRunner
from cloud_dast.runtime.differential.evidence import Store
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.contracts import PrefilterResult
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.execution.terminal import PathAttempt
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState
from cloud_dast.runtime.observation_recording import Coordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
)
from cloud_dast.verification.evaluation import ObservationEvaluation
from cloud_dast.verification.evidence_facts import verified_fact_id
from cloud_dast.verification.oracles import latency, primitive_router, witness
from cloud_dast_fuzzing import (
    FindingShrinker,
    FuzzSession,
    GeneratorBandit,
    GoalPayloadGenerator,
    TemplateGenerator,
)
from cloud_dast_fuzzing.corpus import PayloadCorpusCompiler
from cloud_dast_fuzzing.strategies.grammar import GrammarGenerator
from cloud_dast_llm.generator import LlmGenerator
from cloud_dast_symbolic import SymbolicPrefilter
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.append(event)

    def read(self) -> Iterable[DomainEvent]:
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class SequentialModelClient:
    def __init__(self, values: tuple[str, ...]) -> None:
        self.values = values
        self.requests: list[ModelRequest] = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        value = self.values[min(len(self.requests) - 1, len(self.values) - 1)]
        return ModelResponse(
            structured={"checks": [{"request": {"secret_id": value}}]},
            content="{}",
            model_id="fake-model",
            request_id=request.request_id,
        )


class RecordingTarget:
    def __init__(
        self,
        outcomes: tuple[AccessOutcome, ...] = (AccessOutcome.DENIED,),
        *,
        output: ResponseData | None = None,
        response_summary: str | None = None,
        transport_status: TransportStatus | None = None,
    ) -> None:
        self.outcomes = outcomes
        self.output = output
        self.response_summary = response_summary
        self.transport_status = transport_status
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        index = min(len(self.executed) - 1, len(self.outcomes) - 1)
        outcome = self.outcomes[index]
        status = (
            self.transport_status
            if self.transport_status is not None
            else HttpStatus(code=403 if outcome is AccessOutcome.DENIED else 200)
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=outcome,
            response_summary=self.response_summary or outcome.value,
            transport_status=status,
            output=self.output,
        )


class FakeFuzzSession:
    def __init__(
        self,
        checks: tuple[Check, ...],
        *,
        stop_after: int | None = None,
        stop_on_fail: bool = False,
    ) -> None:
        self.checks = checks
        self.stop_after = stop_after
        self.stop_on_fail = stop_on_fail
        self.returned = 0
        self.stopped = False
        self.previewed = 0
        self._preview: list[Check] = []
        self.records: list[tuple[Check, VerdictStatus]] = []
        self.observations: list[Observation] = []
        self.passes = 0
        self.failures = 0
        self.unscoreable = 0

    def preview(self) -> Check | None:
        if self.stopped:
            return None
        index = self.returned + len(self._preview)
        if index >= len(self.checks):
            return None
        check = self.checks[index]
        self._preview.append(check)
        self.previewed += 1
        return check

    def next(self) -> Check | None:
        if self.stopped:
            return None
        if self._preview:
            check = self._preview.pop(0)
        else:
            if self.returned >= len(self.checks):
                return None
            check = self.checks[self.returned]
        self.returned += 1
        return check

    def record(
        self,
        check: Check,
        verdict: VerdictStatus,
        *,
        grounded: bool = True,
        proximity: float | None = None,
        observation: Observation | None = None,
        solver_prefiltered: bool = False,
    ) -> None:
        self.records.append((check, verdict))
        if observation is not None:
            self.observations.append(observation)
        if not grounded or verdict not in {VerdictStatus.PASS, VerdictStatus.FAIL}:
            self.unscoreable += 1
        elif verdict is VerdictStatus.FAIL:
            self.failures += 1
        else:
            self.passes += 1
        if self.stop_after is not None and len(self.records) >= self.stop_after:
            self.stopped = True
        if self.stop_on_fail and verdict is VerdictStatus.FAIL:
            self.stopped = True


class StaticFuzzGenerator:
    """Return one fixed check so the adaptive session has a concrete seed."""

    def __init__(self, check: Check) -> None:
        self._check = check

    def generate(
        self, plan, method, invariant, scenario, *, feedback=None
    ) -> tuple[Check, ...]:
        del feedback
        return (self._check,)


class RecordingGuardrail:
    """Campaign guardrail double that records every candidate decision."""

    def __init__(self) -> None:
        self.calls: list[Check] = []

    def allows(self, check: Check) -> bool:
        self.calls.append(check)
        return True


def _check(
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
    *,
    check_id: str,
    secret_id: str = "secret-victim",
    folder_id: object | None = None,
) -> Check:
    return Check(
        check_id=check_id,
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=(("secret_id", secret_id), ("folder_id", folder_id)),
        identities=("attacker",),
    )


def _step(
    plan: VerificationPlan,
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
    *,
    step_id: str = "step:1",
    effect_ids: tuple[str, ...] = (),
) -> QdlExecutionStep:
    return QdlExecutionStep(
        step_id=step_id,
        goal_id="goal:test",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
        effect_ids=effect_ids,
    )


def _view(step: QdlExecutionStep) -> tuple[QdlPlan, QdlExecutionView]:
    path = QdlExecutionPath(
        path_id="path:test",
        goal_id="goal:test",
        kind="invariant",
        description="test path",
        steps=(step,),
    )
    return QdlPlan(graph_hash="graph:test"), QdlExecutionView(
        graph_hash="graph:test",
        paths=(path,),
        invariants={step.invariant.invariant_id: step.invariant},
    )


def _two_step_view(
    method: MethodSpec,
    plan: VerificationPlan,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
) -> tuple[QdlPlan, QdlExecutionView, str, str, InvariantProjection]:
    ship_method = method.model_copy(update={"method_id": "grpc:ship", "name": "Ship"})
    ship_invariant = _invariant_for_method(invariant, ship_method)
    ship_plan = plan.model_copy(
        update={
            "plan_id": "plan:ship",
            "method_id": ship_method.method_id,
            "invariant_id": ship_invariant.invariant_id,
        }
    )
    first = _step(
        plan,
        method,
        invariant,
        scenario,
        effect_ids=("fact:effect:first",),
    )
    second = _step(
        ship_plan,
        ship_method,
        ship_invariant,
        scenario,
        step_id="step:2",
        effect_ids=("fact:effect:second",),
    )
    path = QdlExecutionPath(
        path_id="path:two-steps",
        goal_id="goal:test",
        kind="attack",
        description="two-step path",
        steps=(first, second),
    )
    return (
        QdlPlan(graph_hash="graph:test"),
        QdlExecutionView(
            graph_hash="graph:test",
            paths=(path,),
            invariants={
                invariant.invariant_id: invariant,
                ship_invariant.invariant_id: ship_invariant,
            },
        ),
        method.method_id,
        ship_method.method_id,
        ship_invariant,
    )


def _invariant_for_method(
    base: InvariantProjection,
    method: MethodSpec,
) -> InvariantProjection:
    return base.model_copy(
        update={
            "invariant_id": f"{base.invariant_id}:{method.method_id}",
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value=base.norm_id),
                    allowed(Atom(value=f"action:{method.method_id}")),
                ),
            ),
        }
    )


def _field_invariant(
    base: InvariantProjection, method: MethodSpec
) -> InvariantProjection:
    return base.model_copy(
        update={
            "invariant_id": f"{base.invariant_id}:field:{method.method_id}",
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:forbidden-field"),
                    has(
                        Atom(value=f"action:{method.method_id}"),
                        field(Atom(value="secret"), Atom(value="token")),
                    ),
                ),
            ),
        }
    )


def _changed_invariant(base: InvariantProjection) -> InvariantProjection:
    return base.model_copy(
        update={
            "invariant_id": f"{base.invariant_id}:changed",
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:immutable-total"),
                    changed(Atom(value="resource:order"), Atom(value="total")),
                ),
            ),
        }
    )


def _concurrency_check(
    index: int,
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> Check:
    return Check(
        check_id=f"check:concurrency:{index}",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=(("total", 10),),
        identities=("attacker",),
    )


def _concurrency_observation(
    index: int,
    method: MethodSpec,
    scenario: ScenarioPosition,
    *,
    value: int,
) -> Observation:
    return Observation(
        observation_id=f"observation:concurrency:{index}",
        check_id=f"check:concurrency:{index}",
        scenario_id=scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
        output=ResponseData(fields=(("total", value),)),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=f"observation:concurrency:{index}",
                    step_id=f"step:concurrency:{index}",
                    method_id=method.method_id,
                    scenario_id=scenario.scenario_id,
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
    )


def _concurrency_result(
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> ConcurrencyResult:
    checks = tuple(
        _concurrency_check(index, method, scenario, invariant) for index in range(6)
    )
    return ConcurrencyResult(
        read_before=(
            checks[0],
            _concurrency_observation(0, method, scenario, value=10),
        ),
        probes=tuple(
            (
                checks[index],
                _concurrency_observation(index, method, scenario, value=10),
            )
            for index in range(1, 5)
        ),
        read_after=(
            checks[5],
            _concurrency_observation(5, method, scenario, value=20),
        ),
    )


def _runner(
    target: RecordingTarget,
    *,
    fuzz_session_factory=None,
    symbolic_prefilter=None,
    grounded_oracle=None,
    primitive_oracle=None,
    events: EventLog | None = None,
    metrics: CampaignMetrics | None = None,
    example_database=None,
) -> tuple[BoundPathRunner, EventLog]:
    events = events or EventLog()
    checker = Checker(
        target,
        TemplateGenerator(),
        AllowAllGuardrail(),
        events,
    )
    service = checker
    return (
        assemble_runner(
            service,
            EventProjection(events, events),
            grounded_oracle=grounded_oracle,
            primitive_oracle=primitive_oracle,
            fuzz_session_factory=fuzz_session_factory,
            finding_shrinker_factory=lambda **kwargs: FindingShrinker(**kwargs),
            example_database=example_database,
            symbolic_prefilter=symbolic_prefilter,
            metrics=metrics,
        ),
        events,
    )


def test_fuzz_session_continues_after_pass_verdicts(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = tuple(
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id=f"check:{index}",
            secret_id=f"secret-{index}",
        )
        for index in range(3)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=3)
    runner, _ = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 3
    assert [record[1] for record in fuzz_session.records] == [
        VerdictStatus.PASS,
        VerdictStatus.PASS,
        VerdictStatus.PASS,
    ]
    assert fuzz_session.stopped


def test_fuzz_session_receives_full_observation_feedback(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    check = _check(
        method_spec,
        invariant,
        scenario_position,
        check_id="check:feedback",
        secret_id="candidate",
    )
    fuzz_session = FakeFuzzSession((check,), stop_after=1)
    target = RecordingTarget(
        output=ResponseData(fields=(("error.message", "resource not found"),)),
        response_summary="resource not found",
        transport_status=HttpStatus(code=404),
    )
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    assert tuple(fuzz_session.observations) == result.observations
    assert dict(fuzz_session.observations[0].output.fields)["error.message"] == (
        "resource not found"
    )


def test_path_runner_feeds_observation_back_to_grammar_generator(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    model = SequentialModelClient(("candidate-one", "candidate-two"))
    fuzz_session = FuzzSession(
        plan=verification_plan,
        method=method_spec,
        invariant=invariant,
        scenario=scenario_position,
        generators={
            "grammar": GoalPayloadGenerator(
                GrammarGenerator(
                    LlmGenerator(
                        model,
                        seed_generator=TemplateGenerator(),
                        task="generate_test_case",
                    ),
                    payload_compiler=PayloadCorpusCompiler(),
                ),
            )
        },
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAllGuardrail(),
        max_checks=2,
    )
    target = RecordingTarget(
        output=ResponseData(
            fields=(("error.message", "resource not found"),),
        ),
        outcomes=(AccessOutcome.ERROR,),
        response_summary="resource not found",
        transport_status=HttpStatus(code=404),
    )
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.checks) == 2
    assert len(model.requests) == 2
    feedback = model.requests[1].context["execution_feedback"]
    attempt = feedback["attempts"][0]
    # The next candidate receives the bounded values from the executed request.
    assert attempt["evidence"]["request"]["values"][0]["name"] == "secret_id"
    assert (
        attempt["evidence"]["request"]["values"][0]["value"]
        == dict(result.checks[0].request)["secret_id"]
    )
    response_leaf = attempt["evidence"]["response"]["leaves"][0]
    assert response_leaf["path"] == "error.message"
    assert response_leaf["value"] == "resource not found"


def test_fuzz_session_respects_campaign_check_budget(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = tuple(
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id=f"check:{index}",
            secret_id=f"secret-{index}",
        )
        for index in range(3)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=3)
    runner, _ = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        plan,
        view,
    )

    assert len(result.observations) == 2
    assert len(fuzz_session.records) == 2
    assert not fuzz_session.stopped


def test_budget_exhaustion_closes_executed_step_with_terminal_path_event(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = tuple(
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id=f"check:{index}",
            secret_id=f"secret-{index}",
        )
        for index in range(2)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=2)
    runner, events = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=1,
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    step_events = [
        event for event in events.events if isinstance(event, QdlStepEvaluated)
    ]
    assert len(step_events) == 1
    path_events = [
        event for event in events.events if isinstance(event, QdlPathEvaluated)
    ]
    assert len(path_events) == 1
    assert path_events[0].path_id == "path:test"
    assert path_events[0].outcome == "blocked"
    assert path_events[0].attempted_steps == 1
    assert path_events[0].step_count == 1
    assert path_events[0].probe_count == 1
    assert path_events[0].reason == step_events[0].reason


def test_component_lifecycle_events_prove_generator_activation(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = (
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id="check:component",
        ),
    )
    fuzz_session = FakeFuzzSession(checks)
    runner, events = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    plan = verification_plan.model_copy(
        update={
            "sink_types": (("secret_id", "sql"),),
            "probe_fields": ("secret_id",),
            "grammar_dialects": (("secret_id", "mysql"),),
        }
    )
    step = _step(plan, method_spec, invariant, scenario_position)
    path_plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        path_plan,
        view,
    )

    assert len(result.observations) == 1
    invoked = [event for event in events.events if isinstance(event, ComponentInvoked)]
    outputs = [event for event in events.events if isinstance(event, ComponentOutput)]
    decisions = [
        event for event in events.events if isinstance(event, DownstreamDecision)
    ]
    assert [event.component for event in invoked] == ["generator:template"]
    assert invoked[0].input_completeness == {
        "sink_facts": 1,
        "probe_fields": 1,
        "dialects": 1,
    }
    assert outputs[0].summary["scored"] == 1
    assert any(
        event.by == "oracle"
        and event.check_id == "check:component"
        and event.observation_id == result.observations[0].observation_id
        and event.path_id == "path:test"
        for event in decisions
    )

    activity = measure_component_activity(events.events)["generator:template"]
    assert activity.activation_proven is True
    assert any(correlation.is_complete for correlation in activity.correlations)


def test_zero_budget_marks_remaining_paths_without_selection(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    target = RecordingTarget()
    runner, events = _runner(target)
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    _plan, view = _view(step)
    scheduler = CoverageDrivenScheduler(view.paths)

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=0,
        ),
        scheduler,
    )

    assert result.observations == ()
    assert not target.executed
    assert scheduler.state.selections == []
    assert scheduler.remaining == 0
    assert "path:test" in scheduler.state.blocked
    terminal = [event for event in events.events if isinstance(event, QdlPathEvaluated)]
    assert [(event.path_id, event.outcome) for event in terminal] == [
        ("path:test", "blocked")
    ]
    assert terminal[0].reason == "campaign check budget exhausted before path execution"


def test_canonical_neighbor_terminal_events_survive_replay(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    paths = tuple(
        QdlExecutionPath(
            path_id=path_id,
            goal_id="goal:test",
            kind="invariant",
            description=path_id,
            steps=(step,),
        )
        for path_id in ("path:first", "path:neighbor")
    )
    events = EventLog()
    runner, _ = _runner(RecordingTarget(), events=events)
    scheduler = CoverageDrivenScheduler(paths)
    scope = EventScope(campaign_id="campaign:canonical", run_id="run:first")

    first = scheduler.next_path()
    assert first is not None
    scheduler.record_outcome(
        first.path_id,
        "blocked",
        attempted_steps=tuple(step.step_id for step in first.steps),
        reward=0.9,
    )
    second = scheduler.next_path()
    assert second is not None
    scheduler.record_outcome(
        second.path_id,
        "blocked",
        attempted_steps=tuple(step.step_id for step in second.steps),
        reward=0.9,
    )
    third = scheduler.next_path()
    assert third is not None
    scheduler.record_outcome(
        third.path_id,
        "blocked",
        attempted_steps=tuple(step.step_id for step in third.steps),
        reward=0.9,
    )

    runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=0,
        ),
        scheduler,
        scope=scope,
    )

    terminal = [event for event in events.events if isinstance(event, QdlPathEvaluated)]
    assert {event.path_id for event in terminal} == {"path:first", "path:neighbor"}
    assert all("canonical" in event.reason for event in terminal)

    replay_scope = EventScope(
        campaign_id="campaign:canonical",
        run_id="run:replay",
        baseline_event_ids=frozenset(event.event_id for event in events.events),
    )
    replay = _runner(RecordingTarget(), events=events)[0].execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=0,
        ),
        CoverageDrivenScheduler(paths),
        scope=replay_scope,
    )

    assert replay.observations == ()


def test_path_without_probe_publishes_blocked_path_event(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    fuzz_session = FakeFuzzSession(())
    runner, events = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert result.observations == ()
    path_events = [
        event for event in events.events if isinstance(event, QdlPathEvaluated)
    ]
    assert len(path_events) == 1
    assert path_events[0].path_id == "path:test"
    assert path_events[0].outcome == "blocked"
    assert path_events[0].attempted_steps == 0
    assert path_events[0].probe_count == 0


def test_ungrounded_failure_does_not_convert_proximity_into_path_reward(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    privileged = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={"effective_permissions": frozenset({"lockbox.payload.get"})}
            )
        }
    )
    checks = tuple(
        _check(
            method_spec,
            invariant,
            privileged,
            check_id=f"check:{index}",
            secret_id=f"secret-{index}",
        )
        for index in range(2)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=2)
    runner, events = _runner(
        RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.ALLOWED)),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, privileged)
    _plan, view = _view(step)
    scheduler = CoverageDrivenScheduler(view.paths)

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        scheduler,
    )

    # The norm expects DENIED while the IAM-grounded expectation is ALLOWED,
    # so both ALLOWED observations are FAIL verdicts without grounding.
    assert len(result.observations) == 2
    assert fuzz_session.failures == 0
    assert fuzz_session.unscoreable == 2
    assert scheduler.state.progress["path:test"] == 0.0
    assert "path:test" in scheduler.state.blocked
    path_events = [
        event for event in events.events if isinstance(event, QdlPathEvaluated)
    ]
    assert path_events[-1].path_id == "path:test"
    assert path_events[-1].outcome == "blocked"


def test_replay_restores_original_path_outcomes(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    shared_events = EventLog()
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.DENIED))
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    completed_path = QdlExecutionPath(
        path_id="path:first",
        goal_id="goal:test",
        kind="invariant",
        description="path that completes",
        steps=(step,),
    )
    blocked_path = QdlExecutionPath(
        path_id="path:second",
        goal_id="goal:test",
        kind="invariant",
        description="path that blocks",
        steps=(step,),
    )
    view = QdlExecutionView(
        graph_hash="graph:test",
        paths=(completed_path, blocked_path),
        invariants={step.invariant.invariant_id: step.invariant},
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    first_metrics = CampaignMetrics()
    runner, _ = _runner(target, events=shared_events, metrics=first_metrics)
    scheduler = CoverageDrivenScheduler(view.paths)

    first = runner.execute_round(request, scheduler)

    assert len(first.observations) == 2
    assert scheduler.state.completed == {"path:first"}
    assert scheduler.state.blocked == {"path:second"}
    assert first_metrics.snapshot().intent_states == {
        "path:first": IntentState.VERIFIED,
        "path:second": IntentState.BLOCKED,
    }

    replay_metrics = CampaignMetrics()
    replay_runner, _ = _runner(target, events=shared_events, metrics=replay_metrics)
    replay_scheduler = CoverageDrivenScheduler(view.paths)

    second = replay_runner.execute_round(request, replay_scheduler)

    # Replay is idempotent for live work and restores the same terminal
    # path set: the blocked path must not turn into completed/VERIFIED.
    assert second.observations == ()
    assert not target.executed[2:]
    assert replay_scheduler.state.completed == {"path:first"}
    assert replay_scheduler.state.blocked == {"path:second"}
    assert replay_metrics.snapshot().intent_states == {
        "path:first": IntentState.VERIFIED,
        "path:second": IntentState.BLOCKED,
    }
    replay_events = [
        event
        for event in shared_events.events
        if isinstance(event, QdlPathEvaluated)
        and "cross-campaign replay" in event.reason
    ]
    assert {(event.path_id, event.outcome) for event in replay_events} == {
        ("path:first", "completed"),
        ("path:second", "blocked"),
    }

    # Repeated replay into the same log keeps the restored states stable.
    third_scheduler = CoverageDrivenScheduler(view.paths)
    replay_runner.execute_round(request, third_scheduler)

    assert third_scheduler.state.completed == {"path:first"}
    assert third_scheduler.state.blocked == {"path:second"}
    assert replay_metrics.snapshot().intent_states == {
        "path:first": IntentState.VERIFIED,
        "path:second": IntentState.BLOCKED,
    }


def test_fuzz_session_that_never_fails_blocks_later_qdl_steps(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = tuple(
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id=f"check:{index}",
            secret_id=f"secret-{index}",
        )
        for index in range(2)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=2)
    runner, _ = _runner(
        RecordingTarget(),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    plan, view, first_method_id, second_method_id, _ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        scenario_position,
    )

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 2
    assert {check.method_id for check in result.checks} == {first_method_id}
    assert second_method_id not in {check.method_id for check in result.checks}


def test_fuzz_session_stops_after_fail_reward(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    checks = (
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id="check:1",
        ),
        _check(
            method_spec,
            invariant,
            scenario_position,
            check_id="check:2",
            secret_id="secret-2",
        ),
    )

    fuzz_session = FakeFuzzSession(checks, stop_on_fail=True)
    runner, _ = _runner(
        RecordingTarget((AccessOutcome.ALLOWED,)),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    assert fuzz_session.records[0][1] is VerdictStatus.FAIL
    assert fuzz_session.stopped


def test_finding_is_shrunk_and_replayed_from_example_database(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
    tmp_path,
) -> None:
    grounded_scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "effective_permissions": frozenset(),
                    "permissions_known": True,
                }
            )
        }
    )
    database = JsonlExampleDatabase(tmp_path / "events.jsonl.examples.jsonl")
    initial_check = _check(
        method_spec,
        invariant,
        grounded_scenario,
        check_id="check:initial",
        secret_id="secret-victim-with-long-payload",
    )
    initial_session = FuzzSession(
        plan=verification_plan,
        method=method_spec,
        invariant=invariant,
        scenario=grounded_scenario,
        generators={"fuzzing": StaticFuzzGenerator(initial_check)},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAllGuardrail(),
        max_checks=2,
    )
    target = RecordingTarget((AccessOutcome.ALLOWED,))
    runner, events = _runner(
        target,
        fuzz_session_factory=lambda step: initial_session,
        example_database=database,
    )
    step = _step(verification_plan, method_spec, invariant, grounded_scenario)
    plan, view = _view(step)

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    assert len(target.executed) == 2
    minimal = result.minimal_checks[
        (result.observations[0].observation_id, invariant.invariant_id)
    ]
    assert minimal.request == (("secret_id", ""),)
    assert load_finding_examples(
        database,
        method_id=method_spec.method_id,
        invariant_id=invariant.invariant_id,
        scenario_id=grounded_scenario.scenario_id,
    )[0].request == (("secret_id", ""),)

    replay_check = _check(
        method_spec,
        invariant,
        grounded_scenario,
        check_id="check:not-replayed",
        secret_id="not-replayed",
    )
    replay_session = FuzzSession(
        plan=verification_plan,
        method=method_spec,
        invariant=invariant,
        scenario=grounded_scenario,
        generators={"fuzzing": StaticFuzzGenerator(replay_check)},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAllGuardrail(),
        max_checks=1,
        example_database=database,
    )
    replay_target = RecordingTarget((AccessOutcome.ALLOWED,))
    replay_runner, _ = _runner(
        replay_target,
        events=events,
        fuzz_session_factory=lambda step: replay_session,
        example_database=database,
    )

    replay = replay_runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=1,
        ),
        plan,
        view,
    )

    assert len(replay.observations) == 1
    assert len(replay_target.executed) == 1
    assert replay.checks[0].request == (("secret_id", ""),)
    assert replay_session.state.failures == 1
    assert replay_session.stopped


class LatencyTarget:
    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
            duration_ms=120.0,
        )


def _latency_path(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> QdlExecutionPath:
    latency_invariant = invariant.model_copy(
        update={
            "invariant_id": "invariant:latency",
            "norm_id": "norm:latency",
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:latency"),
                    duration(
                        Atom(value=f"action:{method_spec.method_id}"),
                        Atom(value=100),
                    ),
                ),
            ),
        }
    )
    latency_plan = verification_plan.model_copy(
        update={
            "plan_id": "plan:latency",
            "invariant_id": latency_invariant.invariant_id,
        }
    )
    latency_step = _step(
        latency_plan, method_spec, latency_invariant, scenario_position
    )
    path = QdlExecutionPath(
        path_id="path:latency",
        goal_id="goal:latency",
        kind="invariant",
        description="latency path",
        steps=(latency_step,),
    )
    return path


def test_execute_round_keeps_prewarmed_duration_path_without_baseline(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    latency_oracle = latency.Oracle()
    latency_target = LatencyTarget()
    runner, _ = _runner(
        latency_target,
        primitive_oracle=primitive_router.Oracle(
            witness_oracle=witness.Oracle(latency_oracle=latency_oracle)
        ),
    )
    path = _latency_path(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    scheduler = CoverageDrivenScheduler(
        (path,),
        has_latency_baseline=latency_oracle.has_baseline,
    )

    assert scheduler.is_prewarmed(path.path_id)
    assert scheduler.remaining == 0

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=3,
        ),
        scheduler,
    )

    assert result.observations == ()
    assert latency_target.executed == []
    assert scheduler.is_prewarmed(path.path_id)
    assert path.path_id not in scheduler.state.selections


def test_execute_round_runs_one_bootstrapped_duration_path(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    latency_oracle = latency.Oracle()
    latency_target = LatencyTarget()
    runner, _ = _runner(
        latency_target,
        primitive_oracle=primitive_router.Oracle(
            witness_oracle=witness.Oracle(latency_oracle=latency_oracle)
        ),
    )
    path = _latency_path(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    scheduler = CoverageDrivenScheduler(
        (path,),
        has_latency_baseline=latency_oracle.has_baseline,
    )

    assert scheduler.bootstrap_prewarmed((method_spec.method_id,)) == 1
    assert scheduler.remaining == 1

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        scheduler,
    )

    assert len(latency_target.executed) == 1
    assert result.observations
    assert scheduler.state.outcomes["path:latency"] == "retryable"

    latency_oracle.update_baseline(
        method_spec.method_id,
        (100.0,),
        min_samples=1,
    )
    scheduler.release_prewarmed((method_spec.method_id,))
    assert scheduler.remaining == 1

    scored = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=1,
        ),
        scheduler,
    )

    assert len(latency_target.executed) == 2
    assert scored.observations
    assert "path:latency" in scheduler.state.completed


def test_execute_round_executes_duration_path_after_baseline_release(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    latency_oracle = latency.Oracle()
    latency_target = LatencyTarget()
    runner, _ = _runner(
        latency_target,
        primitive_oracle=primitive_router.Oracle(
            witness_oracle=witness.Oracle(latency_oracle=latency_oracle)
        ),
    )
    path = _latency_path(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    scheduler = CoverageDrivenScheduler(
        (path,),
        has_latency_baseline=latency_oracle.has_baseline,
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
        max_checks=1,
    )

    before = runner.execute_round(request, scheduler)
    assert before.observations == ()
    assert latency_target.executed == []
    assert scheduler.is_prewarmed(path.path_id)

    latency_oracle.update_baseline(
        method_spec.method_id,
        (90.0, 100.0, 100.0),
    )
    assert scheduler.release_prewarmed((method_spec.method_id,)) == 1
    assert not scheduler.is_prewarmed(path.path_id)

    result = runner.execute_round(
        request,
        scheduler,
    )

    assert scheduler.state.prewarmed == set()
    assert "path:latency" in scheduler.state.completed
    assert result.observations
    assert latency_target.executed


def test_fuzz_failure_verifies_effect_and_unblocks_next_step(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    plan, view, first_method_id, second_method_id, ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        scenario_position,
    )
    first_session = FakeFuzzSession(
        (
            _check(
                method_spec,
                invariant,
                scenario_position,
                check_id="check:first",
            ),
        ),
        stop_on_fail=True,
    )
    second_session = FakeFuzzSession(
        (
            _check(
                method_spec.model_copy(
                    update={"method_id": "grpc:ship", "name": "Ship"}
                ),
                ship_invariant,
                scenario_position,
                check_id="check:second",
            ),
        ),
        stop_after=1,
    )
    sessions = [first_session, second_session]
    runner, _ = _runner(
        RecordingTarget((AccessOutcome.ALLOWED,)),
        fuzz_session_factory=lambda step: sessions.pop(0),
    )
    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert [check.method_id for check in result.checks] == [
        first_method_id,
        second_method_id,
    ]
    assert [record[1] for record in first_session.records] == [VerdictStatus.FAIL]
    assert [record[1] for record in second_session.records] == [VerdictStatus.FAIL]


def test_two_step_fail_pass_blocks_the_whole_path(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    plan, view, first_method_id, second_method_id, _ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        scenario_position,
    )
    runner, events = _runner(
        RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.DENIED))
    )
    scheduler = CoverageDrivenScheduler(view.paths)

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        scheduler,
    )

    assert len(result.observations) == 2
    assert [check.method_id for check in result.checks] == [
        first_method_id,
        second_method_id,
    ]
    assert scheduler.state.completed == set()
    assert scheduler.state.blocked == {"path:two-steps"}
    step_events = [
        event
        for event in events.events
        if isinstance(event, QdlStepEvaluated) and event.path_id == "path:two-steps"
    ]
    assert [(event.verdict, event.phase) for event in step_events] == [
        (VerdictStatus.FAIL, "active"),
        (VerdictStatus.PASS, "blocked"),
    ]
    path_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated) and event.path_id == "path:two-steps"
    ]
    assert len(path_events) == 1
    assert path_events[0].outcome == "blocked"
    assert path_events[0].attempted_steps == 2
    assert path_events[0].step_count == 2
    assert path_events[0].probe_count == 2
    verified = {
        fact_id
        for event in events.events
        if isinstance(event, FactVerified)
        and (fact_id := verified_fact_id(event.fact)) is not None
    }
    assert "fact:effect:first" in verified
    assert "fact:effect:second" not in verified


def test_changed_norm_does_not_attribute_saved_batch_to_a_fresh_check(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    changed_invariant = _changed_invariant(invariant)
    changed_plan = verification_plan.model_copy(
        update={"invariant_id": changed_invariant.invariant_id}
    )
    step = _step(
        changed_plan,
        method_spec,
        changed_invariant,
        scenario_position,
        effect_ids=("fact:effect:changed",),
    )
    plan, view = _view(step)
    runner, _ = _runner(RecordingTarget((AccessOutcome.ALLOWED,)))
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    evidence_store = Store()
    runner.differential.record_concurrency_evidence(
        runner.differential.build_evidence_key(step, request),
        _concurrency_result(method_spec, scenario_position, changed_invariant),
        evidence_store=evidence_store,
    )
    scheduler = CoverageDrivenScheduler(view.paths)

    result = runner.execute_round(request, scheduler, evidence_store=evidence_store)

    assert len(result.observations) == 1
    verdict = result.policy_verdicts[
        (result.observations[0].observation_id, changed_invariant.invariant_id)
    ]
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert verdict.evidence_refs == (result.observations[0].observation_id,)
    assert scheduler.state.blocked == {"path:test"}


def test_changed_norm_does_not_score_sequential_retries_as_a_pair(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    changed_invariant = _changed_invariant(invariant)
    changed_plan = verification_plan.model_copy(
        update={"invariant_id": changed_invariant.invariant_id}
    )
    step = _step(
        changed_plan,
        method_spec,
        changed_invariant,
        scenario_position,
    )
    plan, view = _view(step)
    values = iter((10, 20))

    def target(check: Check) -> Observation:
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("total", next(values)),)),
        )

    checks = tuple(
        _concurrency_check(index, method_spec, scenario_position, changed_invariant)
        for index in range(2)
    )
    fuzz_session = FakeFuzzSession(checks, stop_after=2)
    runner, _ = _runner(
        target,  # type: ignore[arg-type]
        fuzz_session_factory=lambda _: fuzz_session,
    )
    scheduler = CoverageDrivenScheduler(view.paths)

    result = runner.execute_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        scheduler,
    )

    assert len(result.observations) == 2
    assert all(
        verdict.status is VerdictStatus.UNSCOREABLE
        and verdict.grounded is False
        and verdict.rationale == "changed QDL norm requires a paired or read-back trace"
        for verdict in result.policy_verdicts.values()
    )
    assert scheduler.state.blocked == {"path:test"}


def test_ungrounded_fuzz_failure_does_not_unblock_next_step(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    privileged_scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={"effective_permissions": frozenset(method_spec.permissions)}
            )
        }
    )
    fuzz_session = FakeFuzzSession(
        (
            _check(
                method_spec,
                invariant,
                privileged_scenario,
                check_id="check:ungrounded",
            ),
        ),
        stop_after=1,
    )
    runner, events = _runner(
        RecordingTarget((AccessOutcome.ALLOWED,)),
        fuzz_session_factory=lambda step: fuzz_session,
    )
    plan, view, first_method_id, second_method_id, _ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        privileged_scenario,
    )

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    assert fuzz_session.records[0][1] is VerdictStatus.FAIL
    assert fuzz_session.unscoreable == 1
    assert fuzz_session.failures == 0
    assert {check.method_id for check in result.checks} == {first_method_id}
    assert second_method_id not in {check.method_id for check in result.checks}
    step_events = [
        event
        for event in events.events
        if isinstance(event, QdlStepEvaluated) and event.path_id == "path:two-steps"
    ]
    assert len(step_events) == 1
    assert step_events[0].verdict is VerdictStatus.UNSCOREABLE
    assert step_events[0].completed_steps == ()
    path_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated) and event.path_id == "path:two-steps"
    ]
    assert len(path_events) == 1
    assert path_events[0].outcome == "blocked"
    assert path_events[0].attempted_steps == 1
    assert path_events[0].step_count == 2
    assert path_events[0].probe_count == 1
    assert not any(isinstance(event, FactVerified) for event in events.events)


def test_without_factory_each_qdl_step_is_one_shot(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    plan, view, first_method_id, second_method_id, ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        scenario_position,
    )
    runner, _ = _runner(RecordingTarget((AccessOutcome.ALLOWED,)))

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        plan,
        view,
    )

    assert [observation.check_id for observation in result.observations] == [
        result.checks[0].check_id,
        result.checks[1].check_id,
    ]
    assert [check.method_id for check in result.checks] == [
        first_method_id,
        second_method_id,
    ]


def test_unverified_step_blocks_later_qdl_steps_without_factory(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    plan, view, first_method_id, second_method_id, _ship_invariant = _two_step_view(
        method_spec,
        verification_plan,
        invariant,
        scenario_position,
    )
    runner, _ = _runner(RecordingTarget((AccessOutcome.DENIED,)))

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    assert [check.method_id for check in result.checks] == [first_method_id]
    assert second_method_id not in {check.method_id for check in result.checks}


def test_fuzz_reward_uses_forwarded_executed_check(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    method_with_folder = method_spec.model_copy(
        update={
            "fields": (
                *method_spec.fields,
                FieldSpec(name="folder_id", type="string", required=False),
            )
        }
    )
    checks = (
        _check(
            method_with_folder,
            invariant,
            scenario_position,
            check_id="check:1",
        ),
        _check(
            method_with_folder,
            invariant,
            scenario_position,
            check_id="check:2",
            secret_id="secret-2",
        ),
    )
    producer = method_with_folder.model_copy(
        update={"method_id": "producer:folder", "fields": ()}
    )
    producer_invariant = _invariant_for_method(invariant, producer)
    coupling = (
        output_field(Atom(value=producer.method_id), Atom(value="folder_id")),
        input_field(Atom(value=method_with_folder.method_id), Atom(value="folder_id")),
        "eq",
    )
    consumer_plan = verification_plan.model_copy(update={"couplings": (coupling,)})
    producer_plan = consumer_plan.model_copy(
        update={
            "plan_id": "plan:producer",
            "method_id": producer.method_id,
            "invariant_id": producer_invariant.invariant_id,
        }
    )
    producer_check = _check(
        producer, producer_invariant, scenario_position, check_id="check:producer"
    ).model_copy(update={"request": ()})
    producer_session = FakeFuzzSession((producer_check,), stop_after=1)
    fuzz_session = FakeFuzzSession(checks, stop_after=2)
    target = RecordingTarget(
        (AccessOutcome.ALLOWED, AccessOutcome.DENIED),
        output=ResponseData(fields=(("folder_id", "folder-forwarded"),)),
    )
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: (
            producer_session
            if step.method.method_id == producer.method_id
            else fuzz_session
        ),
    )
    step = _step(consumer_plan, method_with_folder, invariant, scenario_position)
    producer_step = _step(
        producer_plan,
        producer,
        producer_invariant,
        scenario_position,
        step_id="step:producer",
        effect_ids=("fact:producer",),
    )
    plan, view = _view(step)
    view = replace(
        view,
        paths=(replace(view.paths[0], kind="attack", steps=(producer_step, step)),),
        invariants={
            invariant.invariant_id: invariant,
            producer_invariant.invariant_id: producer_invariant,
        },
    )
    result = runner.execute_plan(
        LiveRequest(
            service=method_with_folder.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )
    assert len(result.observations) == 3
    assert len(fuzz_session.records) == 2
    assert dict(fuzz_session.records[-1][0].request)["folder_id"] == "folder-forwarded"
    assert dict(checks[-1].request)["folder_id"] is None


def _numeric_method() -> MethodSpec:
    return MethodSpec(
        method_id="grpc:numeric.Set",
        service="numeric-service",
        name="Set",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(name="from", type="int32", required=True, minimum=0, maximum=10),
            FieldSpec(name="to", type="int32", required=True, minimum=0, maximum=10),
        ),
    )


def _numeric_coupling(left: str, right: str, operator: str):
    method_id = _numeric_method().method_id
    return (
        input_field(Atom(value=method_id), Atom(value=left)),
        input_field(Atom(value=method_id), Atom(value=right)),
        operator,
    )


def _numeric_binding(
    verification_plan: VerificationPlan,
    invariant: InvariantProjection,
    scenario_position: ScenarioPosition,
    *,
    couplings: tuple[tuple[tuple[str, str], tuple[str, str], str], ...],
) -> tuple[MethodSpec, VerificationPlan, InvariantProjection, Check]:
    method = _numeric_method()
    bound_invariant = _invariant_for_method(invariant, method)
    bound_plan = verification_plan.model_copy(
        update={
            "method_id": method.method_id,
            "invariant_id": bound_invariant.invariant_id,
            "couplings": couplings,
        }
    )
    check = Check(
        invariant_id=bound_invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(("from", 1), ("to", 2)),
        identities=("attacker",),
    )
    return method, bound_plan, bound_invariant, check


def test_symbolic_prefilter_skips_unsat_candidate(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    method, plan, bound_invariant, check = _numeric_binding(
        verification_plan,
        invariant,
        scenario_position,
        couplings=(
            _numeric_coupling("from", "to", "gt"),
            _numeric_coupling("from", "to", "lt"),
        ),
    )
    fuzz_session = FakeFuzzSession((check,), stop_after=1)
    target = RecordingTarget((AccessOutcome.ALLOWED,))
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: fuzz_session,
        symbolic_prefilter=SymbolicPrefilter(),
    )
    step = _step(plan, method, bound_invariant, scenario_position)

    result = runner.execute_plan(
        LiveRequest(
            service=method.service,
            principal_id="principal-attacker",
            resource_id="resource-victim",
        ),
        *_view(step),
    )

    assert result.observations == ()
    assert target.executed == []
    assert fuzz_session.records == []


def test_symbolic_prefilter_executes_solver_values(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    method, plan, bound_invariant, check = _numeric_binding(
        verification_plan,
        invariant,
        scenario_position,
        couplings=(_numeric_coupling("from", "to", "eq"),),
    )
    fuzz_session = FakeFuzzSession((check,), stop_after=1)
    target = RecordingTarget((AccessOutcome.ALLOWED,))
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: fuzz_session,
        symbolic_prefilter=SymbolicPrefilter(),
    )
    step = _step(plan, method, bound_invariant, scenario_position)

    result = runner.execute_plan(
        LiveRequest(
            service=method.service,
            principal_id="principal-attacker",
            resource_id="resource-victim",
        ),
        *_view(step),
    )

    assert len(result.observations) == 1
    executed = dict(target.executed[0].request)
    assert executed["from"] == executed["to"]
    assert fuzz_session.records[0][0] == target.executed[0]


def _cross_action_path(
    verification_plan: VerificationPlan,
    invariant: InvariantProjection,
    scenario_position: ScenarioPosition,
    *,
    field_name: str = "cName",
    field_type: str = "string",
    couplings: tuple[tuple[tuple[str, str], tuple[str, str], str], ...] | None = None,
):
    add = MethodSpec(
        method_id="grpc:add",
        service="service",
        name="Add",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"test.add"}),
        fields=(FieldSpec(name=field_name, type=field_type, required=True),),
    )
    remove = MethodSpec(
        method_id="grpc:remove",
        service="service",
        name="Remove",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"test.remove"}),
        fields=(FieldSpec(name=field_name, type=field_type, required=True),),
    )
    add_invariant = _invariant_for_method(invariant, add)
    remove_invariant = _invariant_for_method(invariant, remove)
    plan_couplings = couplings or (
        (
            input_field(Atom(value="action:grpc:add"), Atom(value=field_name)),
            input_field(Atom(value="action:grpc:remove"), Atom(value=field_name)),
            "eq",
        ),
    )
    add_plan = verification_plan.model_copy(
        update={
            "plan_id": "plan:add",
            "method_id": add.method_id,
            "invariant_id": add_invariant.invariant_id,
            "couplings": plan_couplings,
        }
    )
    remove_plan = verification_plan.model_copy(
        update={
            "plan_id": "plan:remove",
            "method_id": remove.method_id,
            "invariant_id": remove_invariant.invariant_id,
            "couplings": plan_couplings,
        }
    )
    steps = (
        _step(add_plan, add, add_invariant, scenario_position),
        _step(
            remove_plan,
            remove,
            remove_invariant,
            scenario_position,
            step_id="step:remove",
        ),
    )
    path = QdlExecutionPath(
        path_id="path:cross-action",
        goal_id="goal:test",
        kind="attack",
        description="cross-action coupling",
        steps=steps,
    )
    view = QdlExecutionView(
        graph_hash="graph:test",
        paths=(path,),
        invariants={
            add_invariant.invariant_id: add_invariant,
            remove_invariant.invariant_id: remove_invariant,
        },
    )
    return QdlPlan(graph_hash="graph:test"), view, add, remove


def _cross_action_check(
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario_position: ScenarioPosition,
    *,
    check_id: str,
    value: object,
    field_name: str = "cName",
) -> Check:
    return Check(
        check_id=check_id,
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario_position.scenario_id,
        request=((field_name, value),),
        identities=("attacker",),
    )


def test_sequence_prefilter_enforces_cross_action_coupling_in_live_path(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    plan, view, add, remove = _cross_action_path(
        verification_plan,
        invariant,
        scenario_position,
    )
    add_invariant = next(step.invariant for step in view.paths[0].steps[:1])
    remove_invariant = view.paths[0].steps[1].invariant
    add_check = _cross_action_check(
        add,
        add_invariant,
        scenario_position,
        check_id="check:add",
        value="seed-add",
    )
    remove_check = _cross_action_check(
        remove,
        remove_invariant,
        scenario_position,
        check_id="check:remove",
        value="seed-remove",
    )
    sessions = [
        FakeFuzzSession((add_check,), stop_after=1),
        FakeFuzzSession((remove_check,), stop_after=1),
    ]
    add_session, remove_session = sessions
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.ALLOWED))
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: sessions.pop(0),
        symbolic_prefilter=SymbolicPrefilter(),
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
    )

    result = runner.execute_plan(
        LiveRequest(
            service=add.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 2
    add_name = dict(target.executed[0].request)["cName"]
    remove_name = dict(target.executed[1].request)["cName"]
    assert add_name == remove_name
    assert add_name not in {"seed-add", "seed-remove"}
    assert add_session.records[0][0] == target.executed[0]
    assert remove_session.records[0][0] == target.executed[1]


def test_sequence_prefilter_blocks_cross_action_unsat_before_live_calls(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    contradictory = (
        (
            input_field(Atom(value="action:grpc:add"), Atom(value="value")),
            input_field(Atom(value="action:grpc:remove"), Atom(value="value")),
            "gt",
        ),
        (
            input_field(Atom(value="action:grpc:add"), Atom(value="value")),
            input_field(Atom(value="action:grpc:remove"), Atom(value="value")),
            "lt",
        ),
    )
    plan, view, add, remove = _cross_action_path(
        verification_plan,
        invariant,
        scenario_position,
        field_name="value",
        field_type="int32",
        couplings=contradictory,
    )
    add_step = view.paths[0].steps[0]
    remove_step = view.paths[0].steps[1]
    add_check = _cross_action_check(
        add,
        add_step.invariant,
        scenario_position,
        check_id="check:add",
        value=1,
        field_name="value",
    )
    remove_check = _cross_action_check(
        remove,
        remove_step.invariant,
        scenario_position,
        check_id="check:remove",
        value=2,
        field_name="value",
    )
    sessions = [
        FakeFuzzSession((add_check,), stop_after=1),
        FakeFuzzSession((remove_check,), stop_after=1),
    ]
    add_session, remove_session = sessions
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.ALLOWED))
    runner, events = _runner(
        target,
        fuzz_session_factory=lambda step: sessions.pop(0),
        symbolic_prefilter=SymbolicPrefilter(),
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
    )

    result = runner.execute_plan(
        LiveRequest(
            service=add.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert result.observations == ()
    assert result.checks == ()
    assert target.executed == []
    assert add_session.records == []
    assert remove_session.records == []
    path_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated) and event.path_id == "path:cross-action"
    ]
    assert path_events[-1].outcome == "blocked"
    assert path_events[-1].reason == "symbolically unsatisfiable path"


def test_prefiltered_path_uses_next_for_each_executed_check(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    plan, view, add, remove = _cross_action_path(
        verification_plan,
        invariant,
        scenario_position,
    )
    add_invariant = view.paths[0].steps[0].invariant
    remove_invariant = view.paths[0].steps[1].invariant
    add_check = _cross_action_check(
        add,
        add_invariant,
        scenario_position,
        check_id="check:add",
        value="seed-add",
    )
    remove_check = _cross_action_check(
        remove,
        remove_invariant,
        scenario_position,
        check_id="check:remove",
        value="seed-remove",
    )
    fuzz_session = FakeFuzzSession((add_check, remove_check), stop_after=2)
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.ALLOWED))
    runner, _ = _runner(
        target,
        fuzz_session_factory=lambda step: fuzz_session,
        symbolic_prefilter=SymbolicPrefilter(),
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
    )

    result = runner.execute_plan(
        LiveRequest(
            service=add.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 2
    assert fuzz_session.previewed == 2
    assert fuzz_session.returned == 2
    assert fuzz_session.records[0][0] == target.executed[0]
    assert fuzz_session.records[1][0] == target.executed[1]


def test_prefiltered_path_without_fuzz_session_executes_one_shot(
    verification_plan,
    invariant,
    scenario_position,
) -> None:
    plan, view, add, remove = _cross_action_path(
        verification_plan,
        invariant,
        scenario_position,
        field_name="value",
        field_type="int32",
    )
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.ALLOWED))
    runner, _ = _runner(
        target,
        symbolic_prefilter=SymbolicPrefilter(),
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
    )

    result = runner.execute_plan(
        LiveRequest(
            service=add.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 2
    assert [check.method_id for check in result.checks] == [
        add.method_id,
        remove.method_id,
    ]
    assert (
        dict(target.executed[0].request)["value"]
        == dict(target.executed[1].request)["value"]
    )


@pytest.fixture
def recorder_inputs(method_spec, scenario_position, verification_plan, invariant):
    """Build domain inputs independently of live-runner assembly."""
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    _, view = _view(step)
    attempt = PathAttempt(view.paths[0])
    state = CampaignRoundState([], {}, {}, {}, {}, {}, Store())
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    check = _check(method_spec, invariant, scenario_position, check_id="check:original")
    check = check.model_copy(update={"generator": "grammar"})
    forwarded = check.model_copy(update={"check_id": "check:forwarded"})
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    classification = ObservationEvaluation(
        VerdictStatus.FAIL, None, VerdictStatus.FAIL, "classified", True, True
    )
    case = SimpleNamespace(
        attempt=attempt,
        state=state,
        step=step,
        request=request,
        observation=observation,
        classification=classification,
        checks=[check],
        forwarded=forwarded,
        events=[],
        fail_at=None,
        failure=None,
        strategy_after="grammar",
        feedback=[],
        executed=[],
        published=[],
        scope=None,
        use_session=True,
        normless=False,
        trace_tail=(),
        proximity_traces=[],
        max_checks=1,
        run_result=None,
    )
    key = (observation.observation_id, invariant.invariant_id)
    case.key = key
    return case


@pytest.fixture
def recorder_case(recorder_inputs, monkeypatch):
    """Run actual candidate feedback inside the bound recorder lifecycle."""
    case = recorder_inputs
    attempt, state, step = case.attempt, case.state, case.step
    request, observation, key = case.request, case.observation, case.key
    check, forwarded = case.checks[0], case.forwarded

    def mark(stage):
        case.events.append(stage)
        if case.fail_at == stage:
            if case.failure is not None:
                raise case.failure
            raise RuntimeError(stage)

    def classify(actual_step, actual_observation, actual_request, trace, **kwargs):
        assert actual_step is step and actual_request is request
        assert actual_observation is observation
        assert trace == (observation,)
        assert state.observations == attempt.observations == [observation]
        assert state.provenance[key].identities == ("attacker",)
        assert kwargs["evidence_store"] is state.differential_evidence
        mark("classify")
        return case.classification

    def publish(actual_observation, actual_classification, invocation_id, generator):
        assert bindings[-1:] == [attempt.path.path_id]
        assert invocation_id == (
            f"{attempt.path.path_id}:{step.step_id}:{check.generator}:{check.check_id}"
        )
        assert generator == "grammar"
        assert actual_observation is observation
        assert actual_classification is case.classification
        assert state.path_reasons[attempt.path.path_id] == "classified"
        mark("publish")

    bindings = []

    def bind_publisher(service, path, verified_fact_ids, *, step_index, scope):
        assert service == request.service and path is attempt.path
        assert verified_fact_ids is state.replay.verified_fact_ids
        assert step_index == 0 and scope is case.scope
        bindings.append(path.path_id)
        return publish

    def latest_check():
        mark("checks")
        return case.checks[-1]

    def generator_outcome(method_id, strategy, progress):
        assert method_id == step.method.method_id
        assert strategy == (
            case.session.current_strategy if case.use_session else "oneshot"
        )
        assert progress == case.classification.progress
        mark("generator")
        attempt.observations.extend(case.trace_tail)

    def proximity(effect, trace, verdict, *, step_count):
        assert trace == (observation, *case.trace_tail) and step_count == 1
        case.proximity_traces.append(trace)
        assert verdict == case.classification.verdict
        mark("proximity")
        return 0.75

    def feedback(actual_check, verdict, **kwargs):
        assert actual_check is check
        assert verdict == case.classification.verdict
        assert attempt.best_proximity == 0.75
        assert not attempt.effect_verified
        assert kwargs == dict(
            grounded=True,
            proximity=0.75,
            observation=observation,
            solver_prefiltered=True,
        )
        case.feedback.append(actual_check)
        case.checks.append(forwarded)
        case.session.current_strategy = case.strategy_after
        mark("feedback")

    def finding():
        assert attempt.effect_verified
        assert state.minimal_checks == (
            {} if case.strategy_after == "replay" else {key: case.checks[-1]}
        )
        mark("finding")

    case.session = SimpleNamespace(
        current_strategy="grammar",
        record=feedback,
        next=lambda: check,
        stopped=False,
    )
    metrics = SimpleNamespace(
        record_generator_outcome=generator_outcome, record_finding=finding
    )
    monkeypatch.setattr(
        "cloud_dast.runtime.candidates.session.trace_proximity", proximity
    )
    coordinator = Coordinator(
        classify_observation=classify,
        executed_check_identities=lambda obs: ("attacker",),
        publish_effects=bind_publisher,
        latest_check=latest_check,
        metrics=metrics,
    )

    def execute(actual, budget, **kwargs):
        assert actual is check
        assert kwargs == dict(
            scope=case.scope,
            action_id=step.method.method_id,
            path_id=attempt.path.path_id,
            step_id=step.step_id,
        )
        budget.spend()
        case.executed.append(actual)
        return observation

    def publish_component(event, scope):
        assert scope is case.scope
        case.published.append(event)

    candidate_runner = StepCandidateRunner(
        fuzz_session_factory=None,
        symbolic_prefilter=None,
        publish=publish_component,
        execute_step_with_budget=execute,
        execute_check_with_budget=execute,
        path_scoped_step=lambda actual_step, path: actual_step,
        latest_check=latest_check,
        metrics=metrics,
    )
    case.record_proximity = attempt.record_proximity

    def record():
        nonlocal step
        if case.normless:
            step = replace(
                step, invariant=step.invariant.model_copy(update={"norm_fact": None})
            )
            case.step = step
            attempt.path = replace(attempt.path, steps=(step,))
        session = case.session if case.use_session else None
        record_observation = coordinator.bind(
            request,
            attempt,
            state,
            step_index=0,
            fuzz_session=session,
            scope=case.scope,
        )
        case.budget = CallLimits(max_checks=case.max_checks)
        case.run_result, _prefiltered = candidate_runner.run(
            attempt.path,
            0,
            case.budget,
            prefiltered=PrefilterResult((check,), (check,), (session,), "sat"),
            fuzz_session=session,
            scope=case.scope,
            record_observation=record_observation,
            record_proximity=case.record_proximity,
        )
        # Preserve the old identity assertion as fixture plumbing only.
        return case.classification

    case.record = record
    return case


@pytest.mark.parametrize(
    ("fail_at", "error_type"),
    [
        pytest.param(stage, RuntimeError, id=stage)
        for stage in ("classify", "publish", "feedback", "finding")
    ]
    + [
        pytest.param(stage, StopIteration, id=f"stop_iteration-{stage}")
        for stage in ("classify", "publish", "finding")
    ],
)
def test_recorder_partial_failure(recorder_case, fail_at, error_type):
    case = recorder_case
    case.fail_at = fail_at
    case.failure = error_type(fail_at)
    with pytest.raises(error_type, match=f"^{fail_at}$") as raised:
        case.record()
    assert raised.value is case.failure
    assert case.run_result is None
    assert case.budget.exhausted and case.budget.live_calls == 1
    stages = [
        "classify",
        "publish",
        "checks",
        "generator",
        "proximity",
        "feedback",
        "checks",
        "finding",
    ]
    assert case.events == stages[: stages.index(fail_at) + 1]
    assert case.state.observations == case.attempt.observations == [case.observation]
    assert case.key in case.state.provenance
    assert case.state.path_reasons == (
        {} if fail_at == "classify" else {case.attempt.path.path_id: "classified"}
    )
    assert case.attempt.best_proximity == (
        0.75 if fail_at in {"feedback", "finding"} else 0.0
    )
    assert case.attempt.effect_verified == (fail_at == "finding")
    assert case.state.minimal_checks == (
        {case.key: case.forwarded} if fail_at == "finding" else {}
    )
    assert len(case.feedback) == (1 if fail_at in {"feedback", "finding"} else 0)


@pytest.mark.parametrize("strategy_after", ["grammar", "replay"])
def test_recorder_feedback_finalization(recorder_case, strategy_after):
    case = recorder_case
    case.strategy_after = strategy_after
    assert case.record() is case.classification
    assert case.run_result is True
    assert case.budget.exhausted and case.budget.live_calls == 1
    assert not case.session.stopped
    assert case.executed == [case.checks[0]]
    assert case.events == [
        "classify",
        "publish",
        "checks",
        "generator",
        "proximity",
        "feedback",
        "checks",
        "finding",
    ]
    assert case.attempt.effect_verified
    assert case.attempt.best_proximity == 0.75
    assert case.state.minimal_checks == (
        {} if strategy_after == "replay" else {case.key: case.forwarded}
    )
    # A later unscoreable result cannot erase a previously established proof.
    case.classification = replace(
        case.classification, progress=VerdictStatus.UNSCOREABLE, effect_verified=False
    )
    case.attempt.observations.clear()
    case.state.observations.clear()
    case.session.record = lambda *args, **kwargs: None
    case.events.clear()
    assert case.record() is case.classification
    assert case.run_result is False
    assert case.budget.exhausted and case.budget.live_calls == 1
    assert len(case.executed) == 2 and not case.session.stopped
    assert case.attempt.effect_verified
    assert case.events == ["classify", "publish", "checks", "generator", "proximity"]


def test_recorder_one_shot_preserves_scope_and_finalizes(recorder_case):
    case = recorder_case
    case.use_session = False
    case.scope = EventScope(campaign_id="campaign:test", run_id="run:test")
    case.record()

    assert case.run_result is True
    assert case.budget.exhausted and case.budget.live_calls == 1
    assert case.executed == [case.checks[0]]
    assert case.published
    assert case.feedback == []
    assert case.proximity_traces == []
    assert case.attempt.best_proximity == 0.0
    assert case.attempt.effect_verified
    assert case.state.minimal_checks == {case.key: case.checks[0]}
    assert case.events == [
        "classify",
        "publish",
        "checks",
        "generator",
        "checks",
        "finding",
    ]


@pytest.mark.parametrize("normless", [False, True])
def test_recorder_unverified_feedback_cannot_grow_reward(recorder_case, normless):
    case = recorder_case
    case.normless = normless
    case.classification = replace(
        case.classification,
        verdict=VerdictStatus.UNSCOREABLE if normless else VerdictStatus.FAIL,
        progress=VerdictStatus.UNSCOREABLE,
        grounded=False,
        effect_verified=False,
    )
    case.attempt.best_proximity = 0.4
    feedback = []
    rewards = []

    def record_proximity(value):
        rewards.append(value)
        case.attempt.record_proximity(value)

    case.record_proximity = record_proximity
    case.session.record = lambda check, verdict, **kwargs: feedback.append(
        (check, verdict, kwargs)
    )
    case.record()

    assert case.run_result is False
    assert case.budget.exhausted and not case.session.stopped
    assert case.executed == [case.checks[0]]
    assert feedback == [
        (
            case.checks[0],
            case.classification.verdict,
            dict(
                grounded=False,
                proximity=None if normless else 0.0,
                observation=case.observation,
                solver_prefiltered=True,
            ),
        )
    ]
    assert rewards == ([] if normless else [0.0])
    assert case.attempt.best_proximity == 0.4
    assert not case.attempt.effect_verified
    assert case.state.minimal_checks == {}
    assert case.events == ["classify", "publish", "checks", "generator"] + (
        [] if normless else ["proximity"]
    )


@pytest.mark.parametrize("update_before_raise", [False, True])
def test_recorder_proximity_callback_failure_skips_finalization(
    recorder_case, update_before_raise
):
    case = recorder_case
    case.attempt.best_proximity = 0.4

    def fail_proximity(value):
        assert value == 0.75
        if update_before_raise:
            case.attempt.record_proximity(value)
        raise RuntimeError("reward callback")

    case.record_proximity = fail_proximity
    with pytest.raises(RuntimeError, match="^reward callback$"):
        case.record()

    assert case.events == ["classify", "publish", "checks", "generator", "proximity"]
    assert case.budget.exhausted
    assert case.state.observations == case.attempt.observations == [case.observation]
    assert case.key in case.state.provenance
    assert case.state.path_reasons == {case.attempt.path.path_id: "classified"}
    assert case.attempt.best_proximity == (0.75 if update_before_raise else 0.4)
    assert case.feedback == []
    assert not case.attempt.effect_verified
    assert case.state.minimal_checks == {}


def test_recorder_feedback_uses_trace_after_generator_metric(recorder_case):
    case = recorder_case
    tail = case.observation.model_copy(
        update={"observation_id": "observation:reentrant"}
    )
    case.trace_tail = (tail,)
    case.classification = replace(
        case.classification, progress=VerdictStatus.UNSCOREABLE, effect_verified=False
    )
    case.session.record = lambda *args, **kwargs: None
    case.record()

    assert case.run_result is False
    assert case.proximity_traces == [(case.observation, tail)]
    assert isinstance(case.proximity_traces[0], tuple)
    assert case.state.observations == [case.observation]
    assert case.attempt.observations == [case.observation, tail]
    assert case.attempt.best_proximity == 0.75
    assert not case.attempt.effect_verified
    assert case.state.minimal_checks == {}


def test_recorder_exhausted_budget_does_not_start_lifecycle(recorder_case):
    case = recorder_case
    case.max_checks = 0
    case.record()

    assert case.run_result is False
    assert case.budget.exhausted and case.budget.live_calls == 0
    assert case.executed == case.published == case.events == []
    assert case.state.observations == case.attempt.observations == []
    assert case.state.provenance == case.state.minimal_checks == {}
    assert case.attempt.best_proximity == 0.0
    assert not case.attempt.effect_verified


@pytest.mark.parametrize(
    ("limit", "failure", "deferred", "advance"),
    [
        (1, None, False, False),
        (2, None, False, False),
        (6, None, False, False),
        (6, "error", False, False),
        (6, "cancel", False, False),
        (2, None, True, False),
        (3, None, False, True),
    ],
)
def test_path_preview_applies_only_to_its_emitted_candidate(
    verification_plan, invariant, scenario_position, limit, failure, deferred, advance
):
    from asyncio import CancelledError
    from itertools import count

    plan, view, add, _remove = _cross_action_path(
        verification_plan, invariant, scenario_position
    )
    path = view.paths[0]
    steps = tuple(
        replace(
            step,
            plan=step.plan.model_copy(
                update={
                    "couplings": (
                        *step.plan.couplings,
                        (
                            output_field(
                                Atom(value="action:grpc:add"), Atom(value="id")
                            ),
                            input_field(
                                Atom(value="action:grpc:remove"), Atom(value="cName")
                            ),
                            "eq",
                        ),
                    ),
                }
            )
            if deferred
            else step.plan,
            method=step.method.model_copy(
                update={
                    "fields": (
                        *step.method.fields,
                        FieldSpec(name="payload", type="string"),
                        FieldSpec(name="sample", type="int32"),
                    )
                }
            ),
        )
        for step in path.steps
    )
    view = replace(view, paths=(replace(path, steps=steps),))
    selected, recorded = [], []
    generations = count()

    class Generator:
        def generate(self, plan, method, invariant, scenario, **kwargs):
            generation = next(generations)
            checks = []
            for index in range(
                1 if advance and method.method_id != add.method_id else 2
            ):
                value = (
                    ("actual-second" if method.method_id == add.method_id else None)
                    if advance
                    else f"value:{index}"
                )
                marker = f"marker:{method.method_id}:{generation}:{index}"
                request = (("cName", value), ("payload", marker))
                if deferred:
                    request += (("sample", 5),)
                checks.append(
                    _cross_action_check(
                        method,
                        invariant,
                        scenario,
                        check_id=f"{method.method_id}:{generation}:{index}",
                        value=value,
                    ).model_copy(update={"probe_marker": marker, "request": request})
                )
            return tuple(checks)

    class Session(FuzzSession):
        def next(self):
            check = super().next()
            if check is not None:
                selected.append(check)
            return check

        def record(self, check, verdict, **kwargs):
            super().record(check, verdict, **kwargs)
            recorded.append(check)

    def factory(request):
        return Session(
            plan=request.plan,
            method=request.method,
            invariant=request.invariant,
            scenario=request.scenario,
            generators={"template": Generator()},
            policy=GeneratorBandit(seed=0),
            guardrail=AllowAllGuardrail(),
            max_checks=1
            if advance and request.method.method_id != add.method_id
            else 2,
        )

    error = (
        CancelledError("target cancelled")
        if failure == "cancel"
        else RuntimeError("target failed")
    )

    class Target(RecordingTarget):
        def __call__(self, check):
            observation = super().__call__(check)
            if failure is not None and len(self.executed) == 2:
                raise error
            return observation

    target = Target(
        outcomes=(AccessOutcome.DENIED, AccessOutcome.ALLOWED, AccessOutcome.ALLOWED)
        if advance
        else (AccessOutcome.DENIED,)
    )
    runner, events = _runner(
        target,
        fuzz_session_factory=factory,
        symbolic_prefilter=SymbolicPrefilter(),
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
    )
    request = LiveRequest(
        service=add.service,
        principal_id="principal-attacker",
        resource_id="victim",
        max_checks=limit,
    )
    budget = CallLimits(limit)
    if failure is None:
        result = runner.execute_round(
            request, CoverageDrivenScheduler(view.paths), budget=budget
        )
        assert len(result.observations) == len(target.executed)
    else:
        with pytest.raises(type(error)) as caught:
            runner.execute_round(
                request, CoverageDrivenScheduler(view.paths), budget=budget
            )
        assert caught.value is error
    assert [c.check_id for c in target.executed] == [c.check_id for c in selected]
    assert min(limit, 2) <= len(target.executed) == budget.live_calls <= limit
    assert len(recorded) == len(target.executed) - int(failure is not None)
    assert len({c.probe_marker for c in selected}) == len(selected)
    for executed, candidate in zip(target.executed, selected, strict=True):
        assert executed.probe_marker == candidate.probe_marker
        assert dict(executed.request)["payload"] == candidate.probe_marker
    invoked = [
        event
        for event in events.events
        if isinstance(event, ComponentInvoked)
        and event.component.startswith("generator:")
    ]
    assert [e.check_id for e in invoked] == [c.check_id for c in selected]
    if advance:
        assert [check.method_id for check in target.executed] == [
            add.method_id,
            add.method_id,
            _remove.method_id,
        ]
        assert dict(target.executed[-1].request)["cName"] == "actual-second"


@pytest.mark.parametrize("outcome", [AccessOutcome.DENIED, AccessOutcome.ALLOWED])
def test_candidate_feedback_reads_only_its_receipt(
    method_spec, scenario_position, verification_plan, invariant, outcome
):
    from cloud_dast.qdl.graph import QdlGraph

    snapshots, recorded = [], []

    class Ledger(Checker):
        @property
        def checks(self):
            snapshot = super().checks
            snapshots.append(len(snapshot))
            return snapshot

    class Generator:
        def generate(self, plan, method, invariant, scenario, **kwargs):
            return tuple(
                _check(method, invariant, scenario, check_id=f"check:{index}")
                for index in range(3)
            )

    class Session(FuzzSession):
        def record(self, check, verdict, **kwargs):
            super().record(check, verdict, **kwargs)
            recorded.append(check)

    def factory(request):
        return Session(
            plan=request.plan,
            method=request.method,
            invariant=request.invariant,
            scenario=request.scenario,
            generators={"template": Generator()},
            policy=GeneratorBandit(seed=0),
            guardrail=AllowAllGuardrail(),
            max_checks=3,
        )

    events = EventLog()
    target = RecordingTarget((outcome,))
    checker = Ledger(target, TemplateGenerator(), AllowAllGuardrail(), events)
    runner = assemble_runner(
        checker,
        EventProjection(events, events),
        fuzz_session_factory=factory,
        grounded_oracle=cloud_dast.verification.oracles.grounded.Oracle(),
        formal_repository=SimpleNamespace(
            load_merged=lambda prefix: QdlGraph(),
            save=lambda *args, **kwargs: None,
        ),
    )
    plan, view = _view(
        _step(verification_plan, method_spec, invariant, scenario_position)
    )
    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=3,
        ),
        plan,
        view,
    )
    assert len(target.executed) == len(recorded) == len(result.checks)
    assert 1 <= len(result.checks) <= 3
    assert recorded == target.executed
    assert tuple(recorded) == result.checks
    assert snapshots == [len(result.checks)]  # One immutable round result snapshot.
