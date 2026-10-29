from __future__ import annotations

from collections.abc import Iterable

from cloud_dast.candidates import TemplateGenerator
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    MethodSpec,
    Observation,
    ScenarioPosition,
    Severity,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DomainEvent,
    EventScope,
    FactVerified,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    input_field,
)
from cloud_dast.runtime.campaign.replay import EventGraph
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.coverage import build_coverage_matrix
from cloud_dast.verification.evidence_facts import verified_fact
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}
        self.read_calls = 0

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.append(event)

    def read(self) -> Iterable[DomainEvent]:
        self.read_calls += 1
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class RecordingTarget:
    def __init__(self, outcomes: tuple[AccessOutcome, ...]) -> None:
        self.outcomes = outcomes
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        index = min(len(self.executed) - 1, len(self.outcomes) - 1)
        outcome = self.outcomes[index]
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=outcome,
            response_summary=outcome.value,
            transport_status=HttpStatus(
                code=403 if outcome is AccessOutcome.DENIED else 200
            ),
        )


def _step(
    plan: VerificationPlan,
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
) -> QdlExecutionStep:
    return QdlExecutionStep(
        step_id="step:1",
        goal_id="goal:test",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
        effect_ids=(),
    )


def _runner(
    target: RecordingTarget,
    events: EventLog,
    metrics: CampaignMetrics | None = None,
) -> BoundPathRunner:
    checker = Checker(
        target,
        TemplateGenerator(),
        AllowAllGuardrail(),
        events,
    )
    return assemble_runner(
        checker,
        events,
        events,
        grounded_oracle=GroundedOutcomeOracle(),
        primitive_oracle=PrimitiveOracleRouter(),
        metrics=metrics,
    )


def _refers_to_fixture_facts(action: Atom, resource: Atom) -> tuple[Fact, Fact]:
    target = input_field(action, Atom(value="order_id"))
    declaration = Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("is"),
        args=(target, Atom(value="InputField")),
    )
    reference = Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_schema(
            next(
                schema
                for schema in EXTENSION_PREDICATE_SCHEMAS
                if schema.name == "refers_to"
            )
        ),
        args=(target, resource),
    )
    return declaration, reference


def _coverage_graph() -> tuple[QdlGraph, InvariantProjection]:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    status = Atom(value="status")
    norm = Atom(value="norm:immutable-status")
    effect = changed(resource, status)

    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(service, Atom(value="Service")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="ResourceType")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(norm, Atom(value="Norm")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("causes"),
                args=(action, effect),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(norm, effect),
            ),
            *_refers_to_fixture_facts(action, resource),
        )
    )
    invariant = InvariantProjection(
        invariant_id="invariant:immutable-status",
        norm_id="norm:immutable-status",
        statement="Order status must be immutable",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(norm, effect),
        ),
    )
    return graph, invariant


def test_replay_restores_blocked_outcome_and_retry_policy(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    verification_plan: VerificationPlan,
    invariant: InvariantProjection,
) -> None:
    events = EventLog()
    target = RecordingTarget((AccessOutcome.ALLOWED, AccessOutcome.DENIED))
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    paths = (
        QdlExecutionPath(
            path_id="path:first",
            goal_id="goal:test",
            kind="invariant",
            description="completed path",
            steps=(step,),
        ),
        QdlExecutionPath(
            path_id="path:second",
            goal_id="goal:test",
            kind="invariant",
            description="blocked path",
            steps=(step,),
        ),
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    metrics = CampaignMetrics()
    runner = _runner(target, events, metrics)
    scheduler = CoverageDrivenScheduler(paths)
    first_scope = EventScope(campaign_id="campaign:test", run_id="run:first")

    first = runner.execute_round(request, scheduler, scope=first_scope)

    assert len(first.observations) == 2
    assert scheduler.state.completed == {"path:first"}
    assert scheduler.state.blocked == {"path:second"}
    assert metrics.snapshot().intent_states == {
        "path:first": IntentState.VERIFIED,
        "path:second": IntentState.BLOCKED,
    }
    original_blocked = next(
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated)
        and event.path_id == "path:second"
        and event.run_id == "run:first"
    )
    assert original_blocked.previous_outcome is None
    assert original_blocked.retry_policy == "bounded"
    assert original_blocked.campaign_id == "campaign:test"

    replay_metrics = CampaignMetrics()
    replay_runner = _runner(target, events, replay_metrics)
    replay_scheduler = CoverageDrivenScheduler(paths)
    replay_scope = EventScope(
        campaign_id="campaign:test",
        run_id="run:replay",
        baseline_event_ids=frozenset(event.event_id for event in events.events),
    )

    replay = replay_runner.execute_round(
        request,
        replay_scheduler,
        scope=replay_scope,
    )

    assert replay.observations == ()
    assert not target.executed[2:]
    assert replay_scheduler.state.completed == {"path:first"}
    assert replay_scheduler.state.blocked == {"path:second"}
    assert replay_metrics.snapshot().intent_states == {
        "path:first": IntentState.VERIFIED,
        "path:second": IntentState.BLOCKED,
    }
    replay_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated) and event.run_id == "run:replay"
    ]
    assert {(event.path_id, event.outcome) for event in replay_events} == {
        ("path:first", "completed"),
        ("path:second", "blocked"),
    }
    assert all(event.previous_outcome == event.outcome for event in replay_events)
    assert all(event.retry_policy == "none" for event in replay_events)


def test_repeated_rounds_use_incremental_projection_without_full_reads(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    verification_plan: VerificationPlan,
    invariant: InvariantProjection,
) -> None:
    events = EventLog()
    target = RecordingTarget((AccessOutcome.ALLOWED,))
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    path = QdlExecutionPath(
        path_id="path:first",
        goal_id="goal:test",
        kind="invariant",
        description="completed path",
        steps=(step,),
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    runner = _runner(target, events)
    scope = EventScope(campaign_id="campaign:test", run_id="run:first")

    first = runner.execute_round(
        request,
        CoverageDrivenScheduler((path,)),
        scope=scope,
    )
    second = runner.execute_round(
        request,
        CoverageDrivenScheduler((path,)),
        scope=scope,
    )

    assert first.observations
    assert second.observations == ()
    assert len(target.executed) == 1
    assert events.read_calls == 0


def test_historical_terminal_event_does_not_close_current_campaign(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    verification_plan: VerificationPlan,
    invariant: InvariantProjection,
) -> None:
    events = EventLog()
    historical = QdlPathEvaluated(
        path_id="path:current",
        outcome="completed",
        attempted_steps=1,
        step_count=1,
        probe_count=1,
        reason="old campaign",
        campaign_id="campaign:old",
        run_id="run:old",
    )
    events.append(historical)
    target = RecordingTarget((AccessOutcome.DENIED,))
    step = _step(verification_plan, method_spec, invariant, scenario_position)
    path = QdlExecutionPath(
        path_id="path:current",
        goal_id="goal:test",
        kind="invariant",
        description="current path",
        steps=(step,),
    )
    runner = _runner(target, events)
    scheduler = CoverageDrivenScheduler((path,))
    scope = EventScope(
        campaign_id="campaign:current",
        run_id="run:current",
        baseline_event_ids=frozenset(event.event_id for event in events.events),
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )

    result = runner.execute_round(request, scheduler, scope=scope)

    assert result.observations
    assert "path:current" in scheduler.state.blocked
    current_events = [event for event in events.events if event.run_id == "run:current"]
    assert current_events
    assert not any(
        isinstance(event, QdlPathEvaluated) and "cross-campaign replay" in event.reason
        for event in current_events
    )


def test_historical_coverage_events_do_not_close_current_run() -> None:
    graph, invariant = _coverage_graph()
    historical_observation = Observation(
        check_id="check:historical",
        scenario_id="scenario:historical",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )

    def witnessed_events(observation, **scope):
        return (
            CheckCompleted(
                observation=observation,
                correlation_id=observation.check_id,
                **scope,
            ),
            CoverageUpdated(
                check_id=observation.check_id,
                method_id="grpc:orders.Update",
                invariant_id=invariant.invariant_id,
                scenario_id=observation.scenario_id,
                correlation_id=observation.check_id,
                **scope,
            ),
            QdlStepEvaluated(
                path_id="path:coverage",
                step_id="step:coverage",
                action_id="action:grpc:orders.Update",
                check_id=observation.check_id,
                observation_id=observation.observation_id,
                verdict="fail",
                phase="goal_reached",
                reason="grounded effect witness",
                step_index=0,
                norm_fact=invariant.norm_fact,
                **scope,
            ),
        )

    historical_events = witnessed_events(historical_observation)
    scope = EventScope(
        campaign_id="campaign:current",
        run_id="run:current",
        baseline_event_ids=frozenset(event.event_id for event in historical_events),
    )

    historical_matrix = build_coverage_matrix(
        graph,
        invariants={invariant.invariant_id: invariant},
        events=historical_events,
        scope=scope,
    )

    assert historical_matrix.campaign_id == "campaign:current"
    assert historical_matrix.run_id == "run:current"
    assert historical_matrix.coverage_cells()
    assert not any(
        cell.status == "covered" for cell in historical_matrix.coverage_cells()
    )
    assert all(not cell.observation_ids for cell in historical_matrix.coverage_cells())

    current_observation = Observation(
        check_id="check:current",
        scenario_id="scenario:current",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    current_events = witnessed_events(
        current_observation, campaign_id="campaign:current", run_id="run:current"
    )

    current_matrix = build_coverage_matrix(
        graph,
        invariants={invariant.invariant_id: invariant},
        events=current_events,
        scope=scope,
    )

    assert current_matrix.coverage_cells()
    eligible_cells = [
        cell
        for cell in current_matrix.coverage_cells()
        if getattr(cell, "field_kind", None) != "input"
    ]
    input_cells = [
        cell
        for cell in current_matrix.coverage_cells()
        if getattr(cell, "field_kind", None) == "input"
    ]
    assert all(cell.status == "covered" for cell in eligible_cells)
    assert all(
        cell.observation_ids == (current_observation.observation_id,)
        for cell in eligible_cells
    )
    assert input_cells
    assert all(cell.status == "blind" for cell in input_cells)


def test_campaign_state_replay_uses_campaign_scope() -> None:
    historical = FactVerified(
        fact=verified_fact("fact:historical"),
        campaign_id="campaign:old",
        run_id="run:old",
    )
    current = FactVerified(
        fact=verified_fact("fact:current"),
        campaign_id="campaign:current",
        run_id="run:current",
    )
    scope = EventScope(
        campaign_id="campaign:current",
        run_id="run:current",
        baseline_event_ids=frozenset(event.event_id for event in (historical, current)),
    )

    state = EventGraph.replay((historical, current), scope=scope)

    assert state.verified_fact_ids == frozenset({"fact:current"})
