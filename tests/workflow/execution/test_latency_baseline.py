from __future__ import annotations

from unittest.mock import Mock

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    HttpStatus,
    JsonValue,
    MethodSpec,
    Observation,
    ScenarioPosition,
    Severity,
    TraceStep,
    TransportStatus,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, Variable, duration
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.campaign import (
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.deficits import Deficit
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.oracles.latency import (
    LatencyOracle,
    collect_delivered_durations,
)


class ExplodingGrounding:
    @property
    def reactive_capable(self) -> bool:
        return True

    def prepare_reactive(self, *args, **kwargs):
        raise AssertionError("missing_baseline must not call reactive LLM grounding")


def _baseline_deficit() -> Deficit:
    action = Atom(value="action:orders.Get")
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (action, duration(action, Variable(name="AnyMilliseconds"))),
        ),
        predicate_class="causes",
        axis="availability",
        action="action:orders.Get",
    )


def _observation(
    index: int,
    duration_ms: float,
    *,
    method_id: str = "orders.Get",
    observed_outcome: AccessOutcome = AccessOutcome.ALLOWED,
    transport_status: TransportStatus | None = HttpStatus(code=200),
    error_reason: str | None = None,
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    observation_id = f"observation-{index}"
    return Observation(
        check_id=f"check-{index}",
        scenario_id="scenario",
        observed_outcome=observed_outcome,
        response_summary="allowed",
        transport_status=transport_status,
        duration_ms=duration_ms,
        error_reason=error_reason,
        response_tree=response_tree,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id=f"check-{index}",
                    method_id=method_id,
                    scenario_id="scenario",
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
    )


def _latency_invariant(method_id: str = "orders.Get") -> InvariantProjection:
    effect = duration(Atom(value=f"action:{method_id}"), Atom(value=110))
    return InvariantProjection(
        invariant_id="invariant:latency",
        norm_id="norm:latency",
        statement="latency must stay bounded",
        severity=Severity.LOW,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:latency"), effect),
        ),
    )


def _workflow(oracle: LatencyOracle) -> LiveWorkflow:
    return assemble_workflow(
        grounding=ExplodingGrounding(),
        scenario_binder=None,
        path_runner=Mock(
            spec_set=assemble_runner(Mock(), EventProjection(Mock(), Mock()))
        ),
        finding_evaluator=None,
        options=LiveWorkflowOptions(
            latency_oracle=oracle, grounding_runner=ThreadedGroundingRunner()
        ),
    )


def _latency_execution_path(
    method_spec: MethodSpec,
    verification_plan: VerificationPlan,
    scenario_position: ScenarioPosition,
    *,
    path_id: str = "path:latency",
) -> QdlExecutionPath:
    latency_invariant = _latency_invariant(method_spec.method_id)
    latency_plan = verification_plan.model_copy(
        update={"invariant_id": latency_invariant.invariant_id}
    )
    step = QdlExecutionStep(
        step_id="step:latency",
        goal_id="goal:latency",
        plan=latency_plan,
        method=method_spec,
        scenario=scenario_position,
        invariant=latency_invariant,
    )
    return QdlExecutionPath(
        path_id=path_id,
        goal_id="goal:latency",
        kind="invariant",
        description="latency path",
        steps=(step,),
    )


def test_latency_oracle_updates_runtime_baseline_from_durations() -> None:
    oracle = LatencyOracle()

    oracle.update_baseline("action:orders.Get", (100.0, 102.0))
    assert "action:orders.Get" not in oracle.baselines

    oracle.update_baseline("action:orders.Get", (100.0, 102.0, 104.0))
    verdict = oracle.evaluate_policy(
        _latency_invariant(),
        (_observation(0, 113.0),),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True


def test_missing_baseline_creates_runtime_baseline_without_llm_call() -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        _observation(index, duration_ms)
        for index, duration_ms in enumerate((100.0, 102.0, 104.0), start=1)
    )
    deficit = _baseline_deficit()
    deficits = DeficitQueue()
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        LiveRequest(service="orders", principal_id="principal", resource_id="resource"),
        deficits,
        accumulator,
    )

    assert promoted == 1
    assert deficits.closed_count == 1
    assert oracle.baselines["orders.Get"].samples == 3


def test_missing_baseline_waits_for_three_duration_samples() -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        _observation(index, duration_ms)
        for index, duration_ms in enumerate((100.0, 102.0), start=1)
    )
    deficit = _baseline_deficit()
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        LiveRequest(service="orders", principal_id="principal", resource_id="resource"),
        deficits,
        accumulator,
    )

    assert promoted == 0
    assert deficits.pending_count == 1
    assert deficits.closed_count == 0
    assert "action:orders.Get" not in oracle.baselines


def test_runtime_baseline_updates_and_releases_prewarmed_duration_path(
    method_spec,
    verification_plan,
    scenario_position,
) -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    path = _latency_execution_path(
        method_spec,
        verification_plan,
        scenario_position,
    )
    scheduler = CoverageDrivenScheduler(
        (path,),
        has_latency_baseline=oracle.has_baseline,
    )
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        _observation(
            index,
            duration_ms,
            method_id=method_spec.method_id,
        )
        for index, duration_ms in enumerate((100.0, 102.0, 104.0), start=1)
    )

    assert scheduler.remaining == 0
    assert workflow._differential.update_latency_baselines(scheduler, accumulator) == 1
    assert workflow._differential.release_latency_ready_paths(scheduler) == 1

    assert oracle.baselines[method_spec.method_id].samples == 3
    assert scheduler.remaining == 1
    assert scheduler.next_path().path_id == path.path_id


def test_latency_bootstrap_builds_initial_baseline_from_one_observation(
    method_spec,
    verification_plan,
    scenario_position,
) -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    first = _latency_execution_path(
        method_spec,
        verification_plan,
        scenario_position,
        path_id="path:latency-first",
    )
    second = _latency_execution_path(
        method_spec,
        verification_plan,
        scenario_position,
        path_id="path:latency-second",
    )
    scheduler = CoverageDrivenScheduler(
        (first, second),
        has_latency_baseline=oracle.has_baseline,
    )

    assert scheduler.remaining == 0
    assert workflow._differential.release_latency_ready_paths(scheduler) == 1
    assert scheduler.remaining == 1
    assert scheduler.next_path().path_id == first.path_id
    scheduler.record_outcome(
        first.path_id, "blocked", attempted_steps=("step:latency",)
    )

    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(
        _observation(1, 100.0, method_id=method_spec.method_id),
    )
    assert workflow._differential.update_latency_baselines(scheduler, accumulator) == 1
    assert oracle.baselines[method_spec.method_id].samples == 1
    assert workflow._differential.release_latency_ready_paths(scheduler) == 2

    assert scheduler.remaining == 2
    assert first.path_id not in scheduler.state.blocked
    assert scheduler.next_path().path_id == second.path_id


def test_collect_delivered_durations_ignores_transport_errors() -> None:
    observations = (
        _observation(
            1,
            100.0,
            observed_outcome=AccessOutcome.ERROR,
            transport_status=None,
        ),
        _observation(2, 101.0, observed_outcome=AccessOutcome.UNKNOWN),
        _observation(
            3,
            102.0,
            transport_status=HttpStatus(code=401),
            response_tree=(("identity", "unauthenticated"),),
        ).model_copy(update={"auth_failed": True}),
        _observation(
            4,
            103.0,
            observed_outcome=AccessOutcome.ERROR,
            transport_status=HttpStatus(code=500),
            response_tree=(("error", "unavailable"),),
        ),
        _observation(5, 104.0),
    )

    assert collect_delivered_durations(observations) == (103.0, 104.0)


def test_latency_oracle_marks_transport_error_unscoreable() -> None:
    oracle = LatencyOracle()
    oracle.update_baseline("action:orders.Get", (100.0, 102.0, 104.0))
    observation = _observation(
        5,
        999.0,
        observed_outcome=AccessOutcome.ERROR,
        transport_status=None,
    )

    verdict = oracle.evaluate_policy(_latency_invariant(), (observation,))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "no delivered response" in verdict.rationale


def test_latency_baseline_uses_only_delivered_observations() -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        (
            _observation(1, 100.0),
            _observation(
                2,
                101.0,
                observed_outcome=AccessOutcome.ERROR,
                transport_status=None,
            ),
            _observation(3, 102.0),
        )
    )
    deficit = _baseline_deficit()
    deficits = DeficitQueue()
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        LiveRequest(service="orders", principal_id="principal", resource_id="resource"),
        deficits,
        accumulator,
    )

    assert promoted == 0
    assert "action:orders.Get" not in oracle.baselines


def test_runtime_baseline_includes_delivered_error_response() -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        (
            _observation(1, 100.0),
            _observation(
                2,
                102.0,
                observed_outcome=AccessOutcome.ERROR,
                transport_status=HttpStatus(code=500),
                response_tree=(("error", "unavailable"),),
            ),
            _observation(
                3,
                999.0,
                observed_outcome=AccessOutcome.ERROR,
                transport_status=None,
            ),
            _observation(4, 104.0),
        )
    )
    deficit = _baseline_deficit()
    deficits = DeficitQueue()
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        LiveRequest(service="orders", principal_id="principal", resource_id="resource"),
        deficits,
        accumulator,
    )

    assert promoted == 1
    assert oracle.baselines["orders.Get"].samples == 3


def test_runtime_baseline_excludes_explicit_timeout() -> None:
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend(
        (
            _observation(1, 100.0),
            _observation(2, 102.0),
            _observation(
                3,
                999.0,
                observed_outcome=AccessOutcome.UNKNOWN,
                transport_status=HttpStatus(code=504),
                error_reason="context deadline exceeded",
            ),
        )
    )
    deficit = _baseline_deficit()
    deficits = DeficitQueue()
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        LiveRequest(service="orders", principal_id="principal", resource_id="resource"),
        deficits,
        accumulator,
    )

    assert promoted == 0
    assert "action:orders.Get" not in oracle.baselines
