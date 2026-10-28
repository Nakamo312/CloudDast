from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import cloud_dast
from cloud_dast.api import LiveRequest
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
    ScenarioPosition,
    TransportStatus,
    VerdictStatus,
)
from cloud_dast.model.events import DomainEvent, QdlStepEvaluated
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, allowed
from cloud_dast.runtime.campaign.round import Runner
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
)
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.planning import QdlPlan
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing import (
    FindingShrinker,
    FuzzSession,
    GeneratorBandit,
    TemplateGenerator,
)
from tests.support.guardrails import AllowAllGuardrail


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
        BoundPathRunner(
            service,
            events,
            events,
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


def test_blocked_prefix_does_not_spend_unexecuted_tail_budget(
    method_spec, verification_plan, invariant, scenario_position
):
    assert Path(cloud_dast.__file__).is_relative_to(Path.cwd())
    _, view, prefix_id, tail_id, _ = _two_step_view(
        method_spec, verification_plan, invariant, scenario_position
    )
    path = view.paths[0]
    target = RecordingTarget(outcomes=(AccessOutcome.DENIED,))

    def session(step):
        return FuzzSession(
            plan=step.plan,
            method=step.method,
            invariant=step.invariant,
            scenario=step.scenario,
            generators={"template": TemplateGenerator()},
            policy=GeneratorBandit(seed=0),
            guardrail=AllowAllGuardrail(),
            max_checks=1,
        )

    runner, events = _runner(target, fuzz_session_factory=session)
    scheduler = CoverageDrivenScheduler((path,))
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
        max_checks=20,
    )
    first_result = runner.execute_round(request, scheduler)
    assert all(
        verdict.deterministic
        and verdict.grounded
        and verdict.status is VerdictStatus.PASS
        for verdict in first_result.policy_verdicts.values()
    )
    assert [check.method_id for check in target.executed] == [prefix_id] * 3
    assert {
        event.verdict for event in events.events if isinstance(event, QdlStepEvaluated)
    } == {VerdictStatus.PASS}
    assert scheduler.next_path() is None
    assert {
        (key.action_id, count)
        for key, count in scheduler.state.canonical_attempts.items()
    } == {(prefix_id, 3)}

    # Content-versioned copies of the tested prefix retain the spent budget.
    version = replace(
        path,
        path_id="path:rebound",
        steps=(replace(path.steps[0], step_id="step:rebound"), path.steps[1]),
    )
    scheduler.add_paths((version,))
    assert scheduler.next_path() is None

    # A genuinely different predecessor can reach the previously untouched tail.
    old_prefix, tail = path.steps
    method = method_spec.model_copy(
        update={"method_id": "grpc:other-prefix", "name": "Other"}
    )
    norm = _invariant_for_method(invariant, method)
    prefix = replace(
        old_prefix,
        step_id="step:other-prefix",
        method=method,
        invariant=norm,
        plan=old_prefix.plan.model_copy(
            update={"method_id": method.method_id, "invariant_id": norm.invariant_id}
        ),
    )
    alternative = replace(path, path_id="path:alternative", steps=(prefix, tail))
    scheduler.add_paths((alternative,))
    assert scheduler.remaining == 1
    target.outcomes = (AccessOutcome.ALLOWED,)
    result = runner.execute_round(request, scheduler)
    assert [check.method_id for check in target.executed] == [prefix_id] * 3 + [
        method.method_id,
        tail_id,
    ]
    assert alternative.path_id in scheduler.state.completed
    assert {
        (key.action_id, count)
        for key, count in scheduler.state.canonical_attempts.items()
    } == {(prefix_id, 3), (method.method_id, 1), (tail_id, 1)}
    assert {provenance.step_id for provenance in result.provenance.values()} == {
        prefix.step_id,
        tail.step_id,
    }


def test_empty_execution_and_replay_do_not_charge_canonical_attempts(
    method_spec, verification_plan, invariant, scenario_position
):
    assert Path(cloud_dast.__file__).is_relative_to(Path.cwd())
    _, view, _, _, _ = _two_step_view(
        method_spec, verification_plan, invariant, scenario_position
    )
    path = view.paths[0]
    target = RecordingTarget()
    runner, _ = _runner(target, fuzz_session_factory=lambda step: FakeFuzzSession(()))
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    scheduler = CoverageDrivenScheduler((path,))
    result = runner.execute_round(request, scheduler)
    assert not target.executed
    assert not result.observations
    assert path.path_id in scheduler.state.blocked
    assert not scheduler.state.canonical_attempts

    replay_scheduler = CoverageDrivenScheduler((path,))
    replay = runner.execute_round(request, replay_scheduler)
    assert not replay.observations
    assert not target.executed
    assert path.path_id in replay_scheduler.state.blocked
    assert not replay_scheduler.state.canonical_attempts

    rebound = replace(path, path_id="path:new-inputs")
    replay_scheduler.add_paths((rebound,))
    assert replay_scheduler.next_path() == rebound


def test_retry_that_stops_earlier_charges_only_current_observations(
    method_spec, verification_plan, invariant, scenario_position
):
    from cloud_dast.api import ObservationProvenance
    from cloud_dast.model import Observation
    from cloud_dast.runtime.execution.terminal import PathAttempt

    _, view, prefix_id, tail_id, _ = _two_step_view(
        method_spec, verification_plan, invariant, scenario_position
    )
    path = view.paths[0]
    runner, _ = _runner(RecordingTarget())
    state = Runner.replay_state(
        (), scope=None, blocked_reasons=None, evidence_store=None
    )
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() == path
    previous = []
    for index, step in enumerate(path.steps):
        observation = Observation(
            observation_id=f"old:{index}",
            check_id=f"check:old:{index}",
            scenario_id=step.scenario.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="synthetic",
        )
        previous.append(observation)
        state.provenance[(observation.observation_id, step.invariant.invariant_id)] = (
            ObservationProvenance(
                step.goal_id, path.path_id, step.step_id, step.invariant.invariant_id
            )
        )
    runner._path_terminal.finish(
        PathAttempt(path=path, observations=previous, best_proximity=1.0),
        scheduler,
        state,
        scope=None,
    )
    assert scheduler.next_path() == path
    first = path.steps[0]
    current = previous[0].model_copy(
        update={"observation_id": "current", "check_id": "check:current"}
    )
    state.provenance[(current.observation_id, first.invariant.invariant_id)] = (
        ObservationProvenance(
            first.goal_id, path.path_id, first.step_id, first.invariant.invariant_id
        )
    )
    runner._path_terminal.finish(
        PathAttempt(path=path, observations=[current], best_proximity=1.0),
        scheduler,
        state,
        scope=None,
    )
    assert {
        (key.action_id, count)
        for key, count in scheduler.state.canonical_attempts.items()
    } == {(prefix_id, 2), (tail_id, 1)}
    assert state.path_history[path.path_id] == [*previous, current]


def test_causal_block_does_not_recharge_an_earlier_attempts_tail(
    method_spec, verification_plan, invariant, scenario_position
):
    from cloud_dast.api import ObservationProvenance
    from cloud_dast.model import Observation
    from cloud_dast.model.events import QdlPathEvaluated

    _, view, prefix_id, tail_id, _ = _two_step_view(
        method_spec, verification_plan, invariant, scenario_position
    )
    path = view.paths[0]
    runner, events = _runner(RecordingTarget())
    state = Runner.replay_state(
        (), scope=None, blocked_reasons=None, evidence_store=None
    )
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() == path
    scheduler.record_outcome(
        path.path_id,
        "blocked",
        attempted_steps=(s.step_id for s in path.steps),
        reward=1.0,
    )
    assert scheduler.next_path() == path
    for index, step in enumerate(path.steps):
        state.provenance[(f"old:{index}", step.invariant.invariant_id)] = (
            ObservationProvenance(
                step.goal_id, path.path_id, step.step_id, step.invariant.invariant_id
            )
        )
    first, tail = path.steps
    current = Observation(
        observation_id="current",
        check_id="check:current",
        scenario_id=first.scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="synthetic",
    )
    state.provenance[(current.observation_id, first.invariant.invariant_id)] = (
        ObservationProvenance(
            first.goal_id, path.path_id, first.step_id, first.invariant.invariant_id
        )
    )
    from cloud_dast.runtime.execution.terminal import PathAttempt

    runner._path_terminal.finish(
        PathAttempt(path=path, observations=[current]), scheduler, state, scope=None
    )
    assert {
        (key.action_id, count)
        for key, count in scheduler.state.canonical_attempts.items()
    } == {(prefix_id, 2), (tail_id, 1)}
    (event,) = (event for event in events.events if isinstance(event, QdlPathEvaluated))
    # Ordinary terminal events expose cumulative path steps and current probes.
    # The canonical accounting above must charge only the current prefix again.
    assert event.attempted_steps == len(path.steps) == 2
    assert event.probe_count == 1


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
