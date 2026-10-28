from __future__ import annotations

from cloud_dast.api import (
    ExecutionResult,
    ObservationProvenance,
    ScenarioBinding,
)
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    MethodSpec,
    Observation,
    ScenarioPosition,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    create,
    duration,
)
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
)
from cloud_dast.runtime.planning import QdlPlan
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_coverage import build_norm_coverage
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="example.Get",
        service="example",
        name="Get",
        layer=EndpointLayer.PUBLIC,
    )


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="target norm",
        severity=Severity.MEDIUM,
    )


def _scenario() -> ScenarioPosition:
    from cloud_dast.model import ScenarioProfile, ScopeRelation, StandState

    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _binding(
    path: QdlExecutionPath,
    invariant: InvariantProjection | None = None,
) -> ScenarioBinding:
    invariant = invariant or _invariant()
    return ScenarioBinding(
        scenario=_scenario(),
        graph=QdlGraph(),
        plan=QdlPlan(graph_hash="graph", invariants=()),
        invariants={invariant.invariant_id: invariant},
        execution=QdlExecutionView(
            graph_hash="graph",
            paths=(path,),
            invariants={invariant.invariant_id: invariant},
        ),
        methods=(),
    )


def _latency_invariant() -> InvariantProjection:
    effect = duration(Atom(value="action:example.Get"), Atom(value=5000))
    return InvariantProjection(
        invariant_id="invariant:latency",
        norm_id="norm:latency",
        statement="latency must stay within the runtime baseline",
        severity=Severity.LOW,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:latency"), effect),
        ),
    )


def _changed_invariant() -> InvariantProjection:
    effect = changed(Atom(value="resource:order"), Atom(value="total"))
    return InvariantProjection(
        invariant_id="invariant:immutable-total",
        norm_id="norm:immutable-total",
        statement="order total must stay immutable",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:immutable-total"), effect),
        ),
    )


def _create_invariant() -> InvariantProjection:
    effect = create(Atom(value="resource:order"))
    return InvariantProjection(
        invariant_id="invariant:no-order-creation",
        norm_id="norm:no-order-creation",
        statement="attacker must not create orders",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:no-order-creation"), effect),
        ),
    )


def test_norm_coverage_reports_scheduler_oracle_and_verdict() -> None:
    invariant = _invariant()
    method = _method()
    scenario = _scenario()
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=VerificationPlan(
            plan_id="plan",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    path = QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="test path",
        steps=(step,),
    )
    binding = _binding(path)
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() is not None
    scheduler.record_outcome("path", "blocked", attempted_steps=("step",))

    observation = Observation(
        check_id="check",
        scenario_id=scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    execution = ExecutionResult(
        observations=(observation,),
        checks=(),
        traces={},
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                "goal", "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.UNSCOREABLE,
                confidence=0.0,
                rationale="no deterministic evidence",
                model_id="test",
                deterministic=True,
                grounded=False,
            )
        },
    )
    events = (
        QdlPathEvaluated(
            path_id="path",
            outcome="blocked",
            attempted_steps=1,
            step_count=1,
            probe_count=1,
            reason="QDL effect chain was not verified",
        ),
    )

    rows = build_norm_coverage(binding, execution, scheduler, events=events)

    assert len(rows) == 1
    row = rows[0]
    assert row.norm_id == "norm"
    assert row.path_count == 1
    assert row.scheduled is True
    assert row.selected is True
    assert row.executed is True
    assert row.oracle_called is True
    assert row.verdict == "unscoreable"
    assert row.blocked_reason == "no deterministic evidence"
    # The invariant carries no QDL norm fact, so its semantic deficit stays
    # visible even though the pipeline reached an unscoreable verdict.
    assert row.deficit == "semantic_blind"


def test_norm_coverage_explains_unbound_norm() -> None:
    binding = _binding(
        QdlExecutionPath(
            path_id="other",
            goal_id="goal",
            kind="invariant",
            description="test path",
            steps=(),
        )
    )
    scheduler = CoverageDrivenScheduler(())

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.path_count == 0
    assert row.scheduled is False
    assert row.selected is False
    assert row.executed is False
    assert row.oracle_called is False
    assert row.verdict == "not_executed"
    assert row.blocked_reason == "no executable path bound to norm"
    # The plain fixture invariant has no norm fact: the semantic deficit
    # dominates the missing executable derivation.
    assert row.deficit == "semantic_blind"


def test_norm_coverage_classifies_typed_blind_deficits() -> None:
    """Every unexecuted norm row carries one of the five S24 blind types."""

    invariant = _latency_invariant()
    binding = _binding(
        QdlExecutionPath(
            path_id="path",
            goal_id="goal",
            kind="invariant",
            description="test path",
            steps=(),
        ),
        invariant=invariant,
    )
    scheduler = CoverageDrivenScheduler(())

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.effect == "duration"
    assert '"name":"duration"' in row.effect_id
    assert row.deficit == "capability_blind"

    no_semantics = _invariant()
    assert no_semantics.norm_fact is None
    semantic_binding = _binding(
        QdlExecutionPath(
            path_id="path",
            goal_id="goal",
            kind="invariant",
            description="test path",
            steps=(),
        ),
        invariant=no_semantics,
    )
    semantic_rows = build_norm_coverage(
        semantic_binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )
    assert semantic_rows[0].deficit == "semantic_blind"


def test_norm_coverage_explains_budget_exhaustion_before_selection() -> None:
    invariant = _invariant()
    method = _method()
    scenario = _scenario()
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=VerificationPlan(
            plan_id="plan",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    path = QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="test path",
        steps=(step,),
    )
    binding = _binding(path)
    scheduler = CoverageDrivenScheduler((path,))

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
        budget_exhausted=True,
    )

    assert rows[0].scheduled is True
    assert rows[0].selected is False
    assert rows[0].blocked_reason == (
        "campaign check budget exhausted before path selection"
    )


def test_norm_coverage_reports_prewarmed_duration_path() -> None:
    invariant = _latency_invariant()
    method = _method()
    scenario = _scenario()
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=VerificationPlan(
            plan_id="plan",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    path = QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="duration path",
        steps=(step,),
    )
    binding = _binding(path, invariant)
    scheduler = CoverageDrivenScheduler(
        (path,),
        has_latency_baseline=lambda _action: False,
    )

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )

    assert rows[0].path_count == 1
    assert rows[0].scheduled is True
    assert rows[0].selected is False
    assert rows[0].executed is False
    assert rows[0].blocked_reason == "path is waiting for a runtime latency baseline"


def test_norm_coverage_distinguishes_missing_oracle_from_unscoreable() -> None:
    invariant = _invariant()
    method = _method()
    scenario = _scenario()
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=VerificationPlan(
            plan_id="plan",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    path = QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="test path",
        steps=(step,),
    )
    binding = _binding(path)
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() is not None
    scheduler.record_outcome("path", "blocked", attempted_steps=("step",))
    observation = Observation(
        check_id="check",
        scenario_id=scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    execution = ExecutionResult(
        observations=(observation,),
        checks=(),
        traces={},
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                "goal", "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.UNSCOREABLE,
                confidence=1.0,
                rationale="QDL invariant has no executable norm fact",
                model_id="deterministic",
                deterministic=True,
                grounded=False,
                oracle_called=False,
            )
        },
    )

    rows = build_norm_coverage(binding, execution, scheduler)

    assert rows[0].executed is True
    assert rows[0].oracle_called is False
    assert rows[0].verdict == "no_oracle"
    assert rows[0].blocked_reason == "no deterministic oracle produced a verdict"


def test_norm_coverage_aggregates_superseded_path_versions() -> None:
    invariant = _invariant()
    method = _method()
    scenario = _scenario()
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=VerificationPlan(
            plan_id="plan",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    current_path = QdlExecutionPath(
        path_id="path:v2",
        goal_id="goal",
        kind="invariant",
        description="current path version",
        steps=(step,),
    )
    binding = _binding(current_path)
    scheduler = CoverageDrivenScheduler((current_path,))
    assert scheduler.next_path() is not None
    scheduler.record_outcome("path:v2", "blocked", attempted_steps=("step",))

    observations = tuple(
        Observation(
            check_id=f"check:{index}",
            scenario_id=scenario.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary="denied",
        )
        for index in range(2)
    )
    checks = tuple(
        Check(
            check_id=observation.check_id,
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
            request=(("resource_id", "resource"),),
            identities=("attacker",),
        )
        for observation in observations
    )
    execution = ExecutionResult(
        observations=observations,
        checks=checks,
        traces={},
        provenance={
            (
                observations[0].observation_id,
                invariant.invariant_id,
            ): ObservationProvenance("goal", "path:v1", "step", invariant.invariant_id),
            (
                observations[1].observation_id,
                invariant.invariant_id,
            ): ObservationProvenance("goal", "path:v2", "step", invariant.invariant_id),
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.UNSCOREABLE,
                confidence=1.0,
                rationale="oracle-specific blocked reason",
                model_id="deterministic",
                deterministic=True,
                grounded=False,
                oracle_called=True,
            )
            for observation in observations
        },
    )
    events = (
        QdlStepEvaluated(
            path_id="path:v1",
            step_id="step",
            verdict=VerdictStatus.UNSCOREABLE,
            phase="unscoreable",
            reason="oracle-specific blocked reason",
            step_index=0,
        ),
    )

    rows = build_norm_coverage(binding, execution, scheduler, events=events)

    assert len(rows) == 1
    row = rows[0]
    assert row.path_ids == ("path:v1", "path:v2")
    assert row.path_count == 2
    assert row.scheduled is True
    assert row.selected is True
    assert row.executed is True
    assert row.oracle_called is True
    assert row.check_count == 2
    assert row.blocked_reason == "oracle-specific blocked reason"


# --- S24R: typed norm deficits through the term coverage algebra -----------


def _bound_path(invariant: InvariantProjection) -> QdlExecutionPath:
    method = _method()
    scenario = _scenario()
    return QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="test path",
        steps=(
            QdlExecutionStep(
                step_id="step",
                goal_id="goal",
                plan=VerificationPlan(
                    plan_id="plan",
                    invariant_id=invariant.invariant_id,
                    method_id=method.method_id,
                    scenario_id=scenario.scenario_id,
                ),
                method=method,
                scenario=scenario,
                invariant=invariant,
            ),
        ),
    )


def test_norm_deficit_is_typed_by_missing_factor() -> None:
    invariant = _latency_invariant()
    binding = _binding(_bound_path(invariant), invariant=invariant)
    scheduler = CoverageDrivenScheduler(())

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )

    assert rows[0].deficit == "capability_blind"
    assert rows[0].missing_factor == "oracle"


def test_norm_without_deterministic_primitive_is_oracle_blind() -> None:
    invariant = _create_invariant()
    path = _bound_path(invariant)
    binding = _binding(path, invariant=invariant)
    scheduler = CoverageDrivenScheduler((path,))

    rows = build_norm_coverage(
        binding,
        ExecutionResult((), (), {}, {}, {}),
        scheduler,
    )

    row = rows[0]
    assert row.effect == "create"
    assert row.scheduled is True
    assert row.deficit == "oracle_blind"
    assert row.missing_factor == "oracle"


def test_executed_norm_without_verdict_is_runtime_evidence_deficit() -> None:
    invariant = _changed_invariant()
    path = _bound_path(invariant)
    binding = _binding(path, invariant=invariant)
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() is not None
    scheduler.record_outcome("path", "blocked", attempted_steps=("step",))
    observation = Observation(
        check_id="check",
        scenario_id=_scenario().scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    execution = ExecutionResult(
        observations=(observation,),
        checks=(),
        traces={},
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                "goal", "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.UNSCOREABLE,
                confidence=1.0,
                rationale="oracle produced no verdict",
                model_id="deterministic",
                deterministic=True,
                grounded=False,
                oracle_called=False,
            )
        },
    )

    rows = build_norm_coverage(binding, execution, scheduler)

    row = rows[0]
    assert row.executed is True
    assert row.oracle_called is False
    assert row.deficit == "evidence_blind"
    assert row.missing_factor == "runtime"
    assert row.blocked_reason == "no deterministic oracle produced a verdict"
