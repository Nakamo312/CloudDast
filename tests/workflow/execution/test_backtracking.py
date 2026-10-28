from __future__ import annotations

from cloud_dast.api import (
    ObservationProvenance,
)
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    changed,
)
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
)
from cloud_dast.runtime.recovery import (
    _CLUE_CACHE_CAPACITY,
    BranchSelector,
    ClueCache,
    Coordinator,
    Reviewer,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict


def _method(method_id: str) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service="svc",
        name=method_id.rsplit(".", 1)[-1],
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="resource_id", type="string", required=True),),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _step(path_id: str, method_id: str, effect=None) -> QdlExecutionStep:
    action = Atom(value=f"action:{method_id}")
    if effect is None:
        effect = allowed(action)
    norm_fact = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value=f"norm:{method_id}"), effect),
    )
    return QdlExecutionStep(
        step_id=f"step:{path_id}",
        goal_id=f"goal:{path_id}",
        plan=VerificationPlan(
            plan_id=f"plan:{path_id}",
            invariant_id=f"invariant:{method_id}",
            method_id=method_id,
            scenario_id="scenario",
        ),
        method=_method(method_id),
        scenario=_scenario(),
        invariant=InvariantProjection(
            invariant_id=f"invariant:{method_id}",
            norm_id=f"norm:{method_id}",
            statement="action must not be allowed",
            severity=Severity.HIGH,
            norm_fact=norm_fact,
        ),
    )


def _path(path_id: str, method_id: str, effect=None) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{path_id}",
        kind="invariant",
        description="test branch",
        steps=(_step(path_id, method_id, effect),),
    )


def _observation(
    observation_id: str,
    *,
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
) -> Observation:
    return Observation(
        check_id=f"check:{observation_id}",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary="observed",
        observation_id=observation_id,
    )


def _verdict(
    status: VerdictStatus = VerdictStatus.UNSCOREABLE,
    rationale: str = "transport could not be scored",
) -> PolicyVerdict:
    return PolicyVerdict(
        status=status,
        confidence=0.5,
        rationale=rationale,
        model_id="test-oracle",
    )


def test_clue_cache_reuses_a_runtime_witness_across_actions() -> None:
    cache = ClueCache()
    source_step = _step("source", "svc.Get")
    target_step = _step("target", "svc.List")

    clue = cache.record_step(
        source_step,
        _observation("observation:source"),
        VerdictStatus.UNSCOREABLE,
    )
    assert clue is not None
    attached = cache.attach_path(clue, "source")

    assert cache.find_clue(target_step) == attached
    assert cache.find_clue(target_step, excluded_path_id="source") is None


def test_clue_cache_ignores_transport_without_a_witness() -> None:
    cache = ClueCache()
    step = _step("transport", "svc.Get")

    assert (
        cache.record_step(
            step,
            _observation("observation:transport", outcome=AccessOutcome.UNKNOWN),
            VerdictStatus.UNSCOREABLE,
        )
        is None
    )


def test_clue_cache_ignores_duplicate_observation_identity() -> None:
    cache = ClueCache()
    step = _step("source", "svc.Get")
    observation = _observation("observation:source")

    assert cache.record_step(step, observation, VerdictStatus.UNSCOREABLE) is not None
    assert cache.record_step(step, observation, VerdictStatus.UNSCOREABLE) is None


def test_clue_cache_evicts_the_oldest_witness_when_bounded() -> None:
    cache = ClueCache()
    target_step = _step("target", "svc.List")
    width = len(str(_CLUE_CACHE_CAPACITY + 1))

    for index in range(_CLUE_CACHE_CAPACITY + 1):
        clue = cache.record_step(
            _step(f"source-{index}", "svc.Get"),
            _observation(f"observation:{index:0{width}d}"),
            VerdictStatus.FAIL,
        )
        assert clue is not None
        cache.attach_path(clue, f"source-{index}")

    clue = cache.find_clue(target_step)

    assert clue is not None
    assert clue.observation_id == f"observation:{1:0{width}d}"


def test_strategist_switches_to_a_sibling_goal_without_state_rollback() -> None:
    strategist = BranchSelector(ClueCache())
    blocked = _path("blocked", "svc.Get")
    scenario_before = blocked.steps[0].scenario.model_copy(deep=True)
    unrelated = _path(
        "unrelated",
        "svc.Delete",
        changed(
            Atom(value="resource:secret"),
            Atom(value="resourceType"),
        ),
    )
    sibling = _path("sibling", "svc.List")

    decision = strategist.select_branch(
        (unrelated, sibling),
        blocked,
        blocked.steps[0],
    )

    assert decision is not None
    assert decision.path_id == "sibling"
    assert decision.reason == "sibling_goal"
    assert decision.blocked_path_id == "blocked"
    assert blocked.steps[0].scenario == scenario_before


def test_strategist_prefers_long_range_clue_reuse_over_discovery_order() -> None:
    cache = ClueCache()
    blocked = _path("blocked", "svc.Get")
    source_step = _step("source", "svc.Create")
    clue = cache.record_step(
        source_step,
        _observation("observation:source"),
        VerdictStatus.UNSCOREABLE,
    )
    assert clue is not None
    cache.attach_path(clue, "source")
    strategist = BranchSelector(cache)
    fallback = _path("fallback", "svc.Delete")
    clue_path = _path("clue-path", "svc.List")

    decision = strategist.select_branch(
        (fallback, clue_path),
        blocked,
        blocked.steps[0],
    )

    assert decision is not None
    assert decision.path_id == "clue-path"
    assert decision.reason == "clue_reuse"
    assert decision.clue is not None
    assert decision.clue.observation_id == "observation:source"


def test_recovery_reviewer_routes_unscoreable_and_blocked_steps() -> None:
    path = _path("path", "svc.Get")
    step = path.steps[0]
    clue = ClueCache().record_step(
        _step("source", "svc.Create"),
        _observation("observation:source"),
        VerdictStatus.UNSCOREABLE,
    )
    assert clue is not None

    blocked = Reviewer.review_blocked(path, step, clue)
    unscoreable = Reviewer.review_unscoreable(
        path,
        step,
        _verdict(),
        clue,
    )
    baseline = Reviewer.review_unscoreable(
        path,
        step,
        _verdict(rationale="no runtime latency baseline for method action:svc.Get"),
        clue,
    )

    assert (blocked.recovery, blocked.target) == (
        "reuse_clue",
        "observation:source",
    )
    assert (unscoreable.recovery, unscoreable.target) == (
        "reuse_clue",
        "observation:source",
    )
    assert (baseline.recovery, baseline.target) == (
        "update_runtime_baseline",
        "svc.Get",
    )


def test_coordinator_defers_remaining_branches_after_one_switch() -> None:
    coordinator = Coordinator()
    blocked = _path("blocked", "svc.Get")
    source_step = _step("source", "svc.Create")
    observation = _observation("observation:source")
    verdict = _verdict(VerdictStatus.FAIL)
    clue = coordinator.clue_cache.record_step(
        source_step,
        observation,
        verdict.status,
    )
    assert clue is not None
    coordinator.clue_cache.attach_path(clue, "source")
    coordinator.record_round(
        (blocked,),
        (observation,),
        {
            (
                "observation:source",
                source_step.invariant.invariant_id,
            ): ObservationProvenance(
                None, "source", "step:source", source_step.invariant.invariant_id
            )
        },
        {("observation:source", source_step.invariant.invariant_id): verdict},
        {"blocked": blocked.steps[0]},
        ("blocked",),
    )
    first = _path("first", "svc.List")
    second = _path("second", "svc.Delete")

    selection = coordinator.select_next_paths((first, second))

    assert selection.paths == (first,)
    assert selection.remaining == (second,)
    assert selection.decision is not None
    assert selection.decision.reason == "clue_reuse"
    assert selection.recovery is not None
    assert selection.recovery.recovery == "switch_branch"
    assert selection.recovery.target == "first"


def test_recovery_intents_are_drained_once() -> None:
    coordinator = Coordinator()
    blocked = _path("blocked", "svc.Get")
    coordinator.record_round(
        (blocked,),
        (),
        {},
        {},
        {"blocked": blocked.steps[0]},
        ("blocked",),
    )

    drained = coordinator.drain_recovery_intents()

    assert len(drained) == 1
    assert drained[0].recovery == "ground_alternatives"
    assert coordinator.recovery_intents() == ()
    assert coordinator.drain_recovery_intents() == ()
