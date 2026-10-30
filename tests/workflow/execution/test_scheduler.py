from __future__ import annotations

import logging

import pytest

import cloud_dast.verification.oracles.latency
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    changed,
    duration,
    external_call,
    identity,
    reached,
)
from cloud_dast.runtime.prioritization import InterestPrioritizer
from cloud_dast.runtime.scheduler import (
    CoverageDrivenScheduler,
)


def make_step(step_id: str, effect=None, action_id: str = "get") -> QdlExecutionStep:
    from cloud_dast.model import (
        EndpointLayer,
        FieldSpec,
        MethodSpec,
        ScenarioPosition,
        ScenarioProfile,
        ScopeRelation,
        Severity,
        StandState,
    )

    method = MethodSpec(
        method_id=action_id,
        service="svc",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="id", type="string", required=True),),
    )
    scenario = ScenarioPosition(
        scenario_id="s",
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
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="test",
        severity=Severity.HIGH,
        norm_fact=(
            None
            if effect is None
            else Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(Atom(value="norm"), effect),
            )
        ),
    )
    plan = VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id=action_id,
        scenario_id="s",
    )
    return QdlExecutionStep(
        step_id=step_id,
        goal_id="goal",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
    )


def make_path(
    path_id: str,
    kind: str = "invariant",
    steps: int = 1,
    effect=None,
    action_id: str = "get",
) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{path_id}",
        kind=kind,
        description="test",
        steps=tuple(
            make_step(f"step:{path_id}:{i}", effect=effect, action_id=action_id)
            for i in range(steps)
        ),
    )


def test_scheduler_prefers_fewer_steps() -> None:
    """Quick wins first: single-step paths before multi-step."""
    one_step = make_path("single", steps=1)
    three_step = make_path("triple", steps=3)
    scheduler = CoverageDrivenScheduler((three_step, one_step))

    assert scheduler.next_path().path_id == "single"
    assert scheduler.next_path().path_id == "triple"


def test_scheduler_prefers_invariant_over_forbidden() -> None:
    """Invariant paths (simpler) before forbidden-state paths."""
    forbidden = make_path("forbidden", kind="forbidden")
    invariant = make_path("invariant", kind="invariant")
    scheduler = CoverageDrivenScheduler((forbidden, invariant))

    assert scheduler.next_path().path_id == "invariant"


def test_scheduler_skips_completed_and_blocked() -> None:
    paths = (
        make_path("a"),
        make_path("b"),
        make_path("c"),
    )
    scheduler = CoverageDrivenScheduler(paths)
    scheduler.record_outcome("a", "completed", attempted_steps=("step:a:0",))
    scheduler.record_outcome("b", "blocked", attempted_steps=("step:b:0",))

    assert scheduler.next_path().path_id == "c"
    assert scheduler.next_path() is None


def test_scheduler_remaining_counts_eligible() -> None:
    paths = (make_path("a"), make_path("b"), make_path("c"))
    scheduler = CoverageDrivenScheduler(paths)

    assert scheduler.remaining == 3
    scheduler.record_outcome("a", "completed", attempted_steps=("step:a:0",))
    assert scheduler.remaining == 2
    scheduler.record_outcome("b", "blocked", attempted_steps=("step:b:0",))
    assert scheduler.remaining == 1


def test_scheduler_does_not_reselect_completed() -> None:
    paths = (make_path("a"),)
    scheduler = CoverageDrivenScheduler(paths)
    scheduler.record_outcome("a", "completed", attempted_steps=("step:a:0",))

    assert scheduler.next_path() is None


def test_scheduler_tracks_selections() -> None:
    paths = (make_path("a"), make_path("b"))
    scheduler = CoverageDrivenScheduler(paths)
    scheduler.next_path()
    scheduler.next_path()

    assert len(scheduler.state.selections) == 2


def test_add_paths_extends_scheduler_and_ignores_known_ids() -> None:
    initial = make_path("initial")
    scheduler = CoverageDrivenScheduler((initial,))

    assert scheduler.add_paths((make_path("initial"), make_path("new"))) == 1
    assert scheduler.add_paths((make_path("initial"),)) == 0
    assert [path.path_id for path in scheduler.paths] == ["initial", "new"]

    scheduler.next_path()  # initial
    scheduler.next_path()  # new
    scheduler.record_outcome(
        "initial", "completed", attempted_steps=("step:initial:0",)
    )
    scheduler.record_outcome("new", "blocked", attempted_steps=("step:new:0",))

    assert scheduler.remaining == 0
    # A probe-field version of a completed path is new work.
    assert scheduler.add_paths((make_path("initial:pv2"),)) == 1
    assert scheduler.remaining == 1


def test_replaced_path_version_is_retired_without_becoming_blocked() -> None:
    old = make_path("logical:pvold")
    replacement = make_path("logical:pvnew")
    scheduler = CoverageDrivenScheduler((old,))

    assert scheduler.add_paths((replacement,)) == 1
    assert scheduler.supersede_replaced_paths(replacement_paths=(replacement,)) == 1
    assert old.path_id in scheduler.state.superseded
    assert old.path_id not in scheduler.state.blocked
    assert scheduler.next_path().path_id == replacement.path_id
    assert scheduler.terminal_reason(old.path_id) == (
        "superseded by QDL path logical:pvnew"
    )


def test_superseded_path_stays_in_history_but_is_not_counted_as_remaining() -> None:
    old = make_path("logical:pvold")
    replacement = make_path("logical:pvnew")
    scheduler = CoverageDrivenScheduler((old, replacement))

    assert scheduler.supersede_replaced_paths((replacement,)) == 1
    assert [path.path_id for path in scheduler.paths] == [
        old.path_id,
        replacement.path_id,
    ]
    assert scheduler.remaining == 1


def test_untried_paths_run_first_in_cost_order() -> None:
    cheap = make_path("cheap", steps=1)
    pricey = make_path("pricey", steps=3)
    scheduler = CoverageDrivenScheduler((pricey, cheap))

    assert scheduler.next_path().path_id == "cheap"
    assert scheduler.next_path().path_id == "pricey"


def test_scheduler_retries_partial_progress_after_exploration() -> None:
    good = make_path("good", steps=1)
    dead = make_path("dead", steps=1)
    scheduler = CoverageDrivenScheduler((good, dead))

    # Exploration phase: each arm is pulled once.
    first = scheduler.next_path()
    scheduler.record_outcome(
        first.path_id,
        "blocked",
        attempted_steps=tuple(step.step_id for step in first.steps),
        reward=0.0 if first.path_id == "dead" else 0.9,
    )
    second = scheduler.next_path()
    scheduler.record_outcome(
        second.path_id,
        "blocked",
        attempted_steps=tuple(step.step_id for step in second.steps),
        reward=0.9 if second.path_id == "good" else 0.0,
    )

    # The dead arm blocked without progress and stays terminal; the good
    # arm made partial progress and is retryable, so the deterministic
    # retry branch selects it again.
    assert scheduler.next_path().path_id == "good"
    assert scheduler.state.attempts == {"dead": 1, "good": 1}
    assert scheduler.state.progress["good"] == 0.9
    assert scheduler.state.progress["dead"] == 0.0
    assert "dead" in scheduler.state.blocked
    assert "good" not in scheduler.state.blocked
    assert scheduler.state.outcomes["good"] == "retryable"


def test_blocked_without_progress_stays_terminal() -> None:
    paths = (make_path("dead"),)
    scheduler = CoverageDrivenScheduler(paths)
    scheduler.next_path()

    outcome = scheduler.record_outcome(
        "dead", "blocked", attempted_steps=("step:dead:0",), reward=0.1
    )

    assert outcome == "blocked"
    assert "dead" in scheduler.state.blocked
    assert scheduler.next_path() is None


def test_retryable_paths_become_terminal_after_two_retries() -> None:
    paths = (make_path("promising"),)
    scheduler = CoverageDrivenScheduler(paths)

    outcomes = []
    for _ in range(4):
        scheduler.next_path()
        outcomes.append(
            scheduler.record_outcome(
                "promising",
                "blocked",
                attempted_steps=("step:promising:0",),
                reward=0.9,
            )
        )

    assert outcomes == ["retryable", "retryable", "blocked", "blocked"]
    assert scheduler.state.attempts["promising"] == 4
    assert "promising" in scheduler.state.blocked
    assert scheduler.next_path() is None


def test_deterministic_order_selects_retried_arms() -> None:

    # Simulate retried arms: an arm that is never marked blocked can be
    # pulled again (chain-fuzz sessions do exactly this).
    promising = make_path("promising", steps=1)
    stale = make_path("stale", steps=1)
    scheduler = CoverageDrivenScheduler((promising, stale))

    scheduler.record_outcome(
        "promising", "unscoreable", attempted_steps=("step:promising:0",), reward=0.8
    )
    scheduler.record_outcome(
        "stale", "unscoreable", attempted_steps=("step:stale:0",), reward=0.1
    )

    assert scheduler.next_path().path_id == "promising"


def test_retry_order_uses_reward_state_after_exploration() -> None:
    low = make_path(
        "a-low",
        action_id="a",
        effect=allowed(Atom(value="action:a")),
    )
    high = make_path(
        "z-high",
        action_id="z",
        effect=allowed(Atom(value="action:z")),
    )
    scheduler = CoverageDrivenScheduler((high, low))

    assert scheduler.next_path().path_id == "a-low"
    scheduler.record_outcome(
        "a-low", "unscoreable", attempted_steps=("step:a-low:0",), reward=0.1
    )
    assert scheduler.next_path().path_id == "z-high"
    scheduler.record_outcome(
        "z-high", "unscoreable", attempted_steps=("step:z-high:0",), reward=0.9
    )
    assert scheduler.next_path().path_id == "z-high"
    assert (
        scheduler.state.cold_scores["z-high"].interest
        > scheduler.state.cold_scores["a-low"].interest
    )


def test_cold_score_multiplies_coverage_prior_and_reward_state() -> None:
    prioritizer = InterestPrioritizer(seed=0)

    base = prioritizer.score(
        "base",
        coverage_gain=1,
        bandit_prior=0.0,
        reward_state=0.0,
    )
    rich = prioritizer.score(
        "rich",
        coverage_gain=2,
        bandit_prior=1.0,
        reward_state=1.0,
    )

    assert base.interest == 2.0
    assert rich.interest == 12.0
    assert rich.rank < base.rank


def test_cold_score_is_deterministic_and_seedable() -> None:
    prioritizer = InterestPrioritizer(seed=7)

    first = prioritizer.score(
        "work-item",
        coverage_gain=1,
        bandit_prior=0.5,
        reward_state=0.5,
    )
    second = prioritizer.score(
        "work-item",
        coverage_gain=1,
        bandit_prior=0.5,
        reward_state=0.5,
    )
    unseeded = InterestPrioritizer().score(
        "work-item",
        coverage_gain=1,
        bandit_prior=0.5,
        reward_state=0.5,
    )

    assert first == second
    assert first.seed == 7
    assert first.seed_digest != 0
    assert unseeded.seed_digest == 0


def test_quarantined_cold_score_features_use_neutral_values() -> None:
    prioritizer = InterestPrioritizer(seed=0)
    trusted = prioritizer.score(
        "work-item",
        coverage_gain=3,
        bandit_prior=1.0,
        reward_state=1.0,
    )
    quarantined = prioritizer.score(
        "work-item",
        coverage_gain=3,
        bandit_prior=1.0,
        reward_state=1.0,
        quarantined_features=frozenset({"bandit_prior", "reward_state"}),
    )
    neutral = prioritizer.score(
        "work-item",
        coverage_gain=3,
        bandit_prior=0.0,
        reward_state=0.0,
    )

    assert quarantined.interest == neutral.interest
    assert quarantined.interest < trusted.interest


def test_untrusted_reward_cannot_win_retry_order() -> None:
    poisoned = make_path("z-poisoned", action_id="z")
    measured = make_path("a-measured", action_id="a")
    scheduler = CoverageDrivenScheduler((poisoned, measured))

    assert scheduler.next_path().path_id == "a-measured"
    scheduler.record_outcome(
        "a-measured",
        "unscoreable",
        attempted_steps=("step:a-measured:0",),
        reward=0.1,
        trusted=True,
    )
    assert scheduler.next_path().path_id == "z-poisoned"
    scheduler.record_outcome(
        "z-poisoned",
        "unscoreable",
        attempted_steps=("step:z-poisoned:0",),
        reward=0.9,
        trusted=False,
    )

    assert scheduler.state.quarantined_rewards == 1
    assert scheduler.state.quarantined_features["z-poisoned"] == frozenset(
        {"reward_state"}
    )
    assert scheduler.next_path().path_id == "a-measured"


def test_scheduler_logs_cold_score_components(caplog) -> None:
    scheduler = CoverageDrivenScheduler((make_path("logged"),))

    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime.scheduler"):
        scheduler.next_path()

    assert any(
        message.startswith("scheduler_cold_score")
        and "coverage_gain=1" in message
        and "interest=" in message
        and "seed=0" in message
        for message in caplog.messages
    )


def test_cold_start_prioritizes_new_canonical_coverage() -> None:
    marker = reached(Atom(value="action:get"), Atom(value="sink:interpreter"))
    external = reached(Atom(value="action:get"), Atom(value="sink:external"))
    scheduler = CoverageDrivenScheduler(
        (make_path("duplicate", effect=marker), make_path("unique", effect=external))
    )

    assert scheduler.next_path().path_id == "duplicate"
    scheduler.record_outcome(
        "duplicate", "completed", attempted_steps=("step:duplicate:0",)
    )

    scheduler.add_paths((make_path("duplicate:pv2", effect=marker),))

    assert scheduler.next_path().path_id == "unique"


def test_cold_start_interleaves_action_outcomes_and_effect_classes() -> None:
    """A differential arm cannot monopolise its action or effect class."""

    changed_first = make_path(
        "a-changed-first",
        action_id="get",
        effect=changed(Atom(value="resource:card"), Atom(value="amount")),
    )
    changed_second = make_path(
        "b-changed-second",
        action_id="get",
        effect=changed(Atom(value="resource:card"), Atom(value="total")),
    )
    allowed_path = make_path(
        "z-allowed",
        action_id="get",
        effect=allowed(Atom(value="action:get")),
    )
    duration_path = make_path(
        "z-duration",
        action_id="list",
        effect=duration(Atom(value="action:list"), Atom(value=100)),
    )
    scheduler = CoverageDrivenScheduler(
        (changed_first, changed_second, allowed_path, duration_path),
        has_latency_baseline=lambda _: True,
    )

    assert scheduler.next_path().path_id == "a-changed-first"
    assert scheduler.next_path().path_id == "z-allowed"
    assert scheduler.next_path().path_id == "z-duration"


def test_changed_multiactions_do_not_starve_action_and_primitive_coverage() -> None:
    """Regression for the 300-check live campaign budget allocation.

    The observed campaign had nine changed norms (28 bound paths, up to seven
    actions per norm) opposite 39 allowed paths.  Changed paths consumed 271
    of 300 checks and left every allowed, duration, external-call, and
    identity norm unexecuted.  The model below preserves those proportions:
    changed paths cost 271 checks in total, while every other effect costs
    one check.
    """

    max_checks = 300
    actions = tuple(f"action-{index:02d}" for index in range(39))
    paths: list[QdlExecutionPath] = []
    costs: dict[str, int] = {}

    # Nine multi-action changed norms with 28 path variants in total.
    changed_variant_counts = (7, 7, 5, 2, 2, 2, 1, 1, 1)
    changed_index = 0
    for norm_index, variant_count in enumerate(changed_variant_counts):
        for variant_index in range(variant_count):
            action = actions[(norm_index * 3 + variant_index) % len(actions)]
            path_id = f"a-changed:{norm_index:02d}:{variant_index:02d}"
            paths.append(
                make_path(
                    path_id,
                    action_id=action,
                    effect=changed(
                        Atom(value=f"resource:{norm_index}"),
                        Atom(value=f"field:{variant_index}"),
                    ),
                )
            )
            # Seven expensive paths, ten medium paths, and eleven cheaper
            # paths sum to the observed 271 changed checks.
            costs[path_id] = (
                15 if changed_index < 7 else 10 if changed_index < 17 else 6
            )
            changed_index += 1

    # One action-outcome arm per distinct action, as in the observed campaign.
    for index, action in enumerate(actions):
        path_id = f"z-allowed:{index:02d}"
        paths.append(
            make_path(
                path_id,
                action_id=action,
                effect=allowed(Atom(value=f"action:{action}")),
            )
        )
        costs[path_id] = 1

    # Representatives of every other effect primitive that was starved.
    for index in range(12):
        action = actions[index]
        path_id = f"z-duration:{index:02d}"
        paths.append(
            make_path(
                path_id,
                action_id=action,
                effect=duration(Atom(value=f"action:{action}"), Atom(value=100)),
            )
        )
        costs[path_id] = 1
    for index in range(13):
        action = actions[(index + 12) % len(actions)]
        path_id = f"z-reached:{index:02d}"
        paths.append(
            make_path(
                path_id,
                action_id=action,
                effect=reached(
                    Atom(value=f"action:{action}"),
                    Atom(value=f"sink:{index}"),
                ),
            )
        )
        costs[path_id] = 1
    paths.append(
        make_path(
            "z-external",
            action_id=actions[0],
            effect=external_call(
                Atom(value=f"action:{actions[0]}"),
                Atom(value="sink:external"),
            ),
        )
    )
    costs["z-external"] = 1
    paths.append(
        make_path(
            "z-identity",
            action_id=actions[1],
            effect=identity(
                Atom(value="principal:attacker"),
                Atom(value="principal:victim"),
            ),
        )
    )
    costs["z-identity"] = 1

    scheduler = CoverageDrivenScheduler(
        tuple(paths),
        has_latency_baseline=lambda _: True,
    )
    paths_by_id = {path.path_id: path for path in paths}
    spent = 0
    executed: list[str] = []
    changed_checks = 0
    while spent < max_checks and scheduler.remaining:
        path = scheduler.next_path()
        cost = costs[path.path_id]
        if spent + cost > max_checks:
            scheduler.record_outcome(
                path.path_id, "blocked", attempted_steps=(), reward=0.0
            )
            break
        spent += cost
        executed.append(path.path_id)
        if path.path_id.startswith("a-changed:"):
            changed_checks += cost
        scheduler.record_outcome(
            path.path_id,
            "blocked",
            attempted_steps=tuple(step.step_id for step in path.steps),
            reward=0.9 if path.path_id.startswith("a-changed:") else 0.0,
        )

    executed_effects = {
        path.steps[0].invariant.norm_fact.args[1].name
        for path_id in executed
        if (path := paths_by_id[path_id]) is not None
    }
    allowed_actions = {
        path.steps[0].method.method_id
        for path_id, path in paths_by_id.items()
        if path_id.startswith("z-allowed:")
    }
    executed_allowed_actions = {
        path.steps[0].method.method_id
        for path_id, path in paths_by_id.items()
        if path_id in executed and path_id.startswith("z-allowed:")
    }

    # The changed arm is deliberately first in path-id order.  It still must
    # be followed by action-outcome and other-primitive coverage.
    assert executed[0].startswith("a-changed:")
    assert executed[1].startswith("z-allowed:")
    assert executed_allowed_actions == allowed_actions
    assert {"duration", "reached", "external_call", "identity"} <= executed_effects
    assert changed_checks < sum(
        cost for path_id, cost in costs.items() if path_id.startswith("a-changed:")
    )
    # 39 allowed + 12 duration + 13 reached + external_call + identity checks
    # are the minimum non-changed coverage floor in this campaign shape.
    assert changed_checks <= max_checks - 66
    assert spent <= max_checks


def test_retry_cap_is_shared_by_canonical_key() -> None:
    effect = reached(Atom(value="action:get"), Atom(value="sink:interpreter"))
    scheduler = CoverageDrivenScheduler(
        (
            make_path("first", effect=effect),
            make_path("second", effect=effect),
        )
    )

    outcomes = []
    scheduler.next_path()
    outcomes.append(
        scheduler.record_outcome(
            "first", "blocked", attempted_steps=("step:first:0",), reward=0.9
        )
    )
    scheduler.next_path()
    outcomes.append(
        scheduler.record_outcome(
            "second", "blocked", attempted_steps=("step:second:0",), reward=0.2
        )
    )
    scheduler.next_path()
    outcomes.append(
        scheduler.record_outcome(
            "first", "blocked", attempted_steps=("step:first:0",), reward=0.9
        )
    )

    assert outcomes == ["retryable", "retryable", "blocked"]
    assert "first" in scheduler.state.blocked
    assert scheduler.state.attempts == {"first": 2, "second": 1}
    assert "second" in scheduler.state.blocked
    assert scheduler.next_path() is None
    assert scheduler.remaining == 0
    assert set(scheduler.state.canonical_attempts.values()) == {3}


def test_retry_exhaustion_preserves_completed_superseded_and_in_flight_paths() -> None:
    scheduler = CoverageDrivenScheduler(
        tuple(make_path(name) for name in ("a", "b", "c", "d", "z"))
    )
    scheduler.supersede_paths({"c": "replacement"})
    assert scheduler.next_path().path_id == "a"
    assert scheduler.next_path().path_id == "b"
    scheduler.record_outcome("b", "completed", attempted_steps=())
    assert scheduler.next_path().path_id == "d"

    for path_id in ("a", "z", "a"):
        scheduler.record_outcome(
            path_id, "blocked", attempted_steps=(f"step:{path_id}:0",), reward=0.9
        )
        if path_id == "a" and scheduler.state.attempts[path_id] == 1:
            assert scheduler.next_path().path_id == "z"
        elif path_id == "z":
            assert scheduler.next_path().path_id == "a"

    assert scheduler.state.completed == {"b"}
    assert scheduler.state.superseded == {"c"}
    assert scheduler.state.in_flight == {"d"}
    assert scheduler.state.blocked == {"a", "z"}
    assert scheduler.terminal_reason("b") is None
    assert scheduler.terminal_reason("c") == "superseded by QDL path replacement"
    assert scheduler.terminal_reason("d") is None
    assert not scheduler.reopen_path("z")
    assert not scheduler.reopen_path("d")


def test_duration_paths_wait_for_latency_baseline() -> None:
    oracle = cloud_dast.verification.oracles.latency.Oracle()
    effect = duration(Atom(value="action:get"), Atom(value=100))
    scheduler = CoverageDrivenScheduler(
        (make_path("latency", effect=effect),),
        has_latency_baseline=oracle.has_baseline,
    )

    assert scheduler.remaining == 0
    assert scheduler.next_path() is None
    assert scheduler.state.prewarmed == {"latency"}

    oracle.update_baseline("get", (90.0, 100.0, 110.0))

    assert scheduler.remaining == 1
    assert scheduler.next_path().path_id == "latency"
    assert scheduler.state.prewarmed == set()


def test_duration_bootstrap_waits_for_other_action_work() -> None:
    oracle = cloud_dast.verification.oracles.latency.Oracle()
    latency = make_path(
        "latency", effect=duration(Atom(value="action:get"), Atom(value=100))
    )
    ordinary = make_path("ordinary", effect=allowed(Atom(value="action:get")))
    scheduler = CoverageDrivenScheduler(
        (latency, ordinary),
        has_latency_baseline=oracle.has_baseline,
    )

    assert scheduler.bootstrap_prewarmed(("get",)) == 0
    scheduler.record_outcome(
        "ordinary", "completed", attempted_steps=("step:ordinary:0",)
    )

    assert scheduler.bootstrap_prewarmed(("get",)) == 1
    assert scheduler.remaining == 1
    assert scheduler.next_path().path_id == "latency"


def test_duration_paths_without_gate_stay_prewarmed_until_released() -> None:
    effect = duration(Atom(value="action:get"), Atom(value=100))
    scheduler = CoverageDrivenScheduler((make_path("latency", effect=effect),))

    assert scheduler.next_path() is None
    assert scheduler.state.prewarmed == {"latency"}

    assert scheduler.release_prewarmed(("action:get",)) == 1

    assert scheduler.state.prewarmed == set()
    assert scheduler.next_path().path_id == "latency"


def test_supersession_keeps_sorted_prefix_when_later_path_is_in_flight() -> None:
    parked = make_path(
        "a",
        action_id="latency",
        effect=duration(Atom(value="action:latency"), Atom(value=100)),
    )
    scheduler = CoverageDrivenScheduler((make_path("z"), make_path("b"), parked))
    assert scheduler.next_path().path_id == "b"
    assert scheduler.bootstrap_prewarmed(("latency",)) == 1

    with pytest.raises(RuntimeError, match="cannot supersede in-flight path 'b'"):
        scheduler.supersede_paths({"z": "new-z", "b": "new-b", "a": "new-a"})

    assert scheduler.state.superseded == {"a"}
    assert scheduler.terminal_reason("a") == "superseded by QDL path new-a"
    assert scheduler.terminal_reason("b") is None
    assert scheduler.terminal_reason("z") is None
    assert scheduler.state.prewarmed == set()
    assert scheduler.state.latency_bootstrap_paths == set()
    assert scheduler.state.in_flight == {"b"}
    assert scheduler.next_path().path_id == "z"


def test_unknown_outcome_consumes_steps_after_attempt_and_quarantine_changes() -> None:
    scheduler = CoverageDrivenScheduler((make_path("known"),))
    consumed = []

    def steps():
        assert scheduler.state.attempts == {"unknown": 1}
        assert scheduler.state.quarantined_features == {
            "unknown": frozenset({"reward_state"})
        }
        consumed.append("step")
        yield "unknown-step"

    with pytest.raises(StopIteration):
        scheduler.record_outcome(
            "unknown", "completed", attempted_steps=steps(), reward=0.9, trusted=False
        )

    assert consumed == ["step"]
    assert scheduler.state.attempts == {"unknown": 1}
    assert scheduler.state.quarantined_rewards == 1
    assert scheduler.state.canonical_attempts == {}
    assert scheduler.state.progress == {}
    assert scheduler.state.outcomes == {}
    assert scheduler.state.completed == set()
    assert scheduler.state.effect_reward_counts == {}
    # Trusted feedback clears an earlier quarantine even if lookup then fails.
    with pytest.raises(StopIteration):
        scheduler.record_outcome("unknown", "completed", attempted_steps=())
    assert scheduler.state.attempts == {"unknown": 2}
    assert scheduler.state.quarantined_features == {}
    assert scheduler.state.quarantined_rewards == 1
    assert scheduler.next_path().path_id == "known"


def test_throwing_steps_retain_attempt_and_bootstrap_flight_changes() -> None:
    path = make_path(
        "latency", effect=duration(Atom(value="action:get"), Atom(value=100))
    )
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.bootstrap_prewarmed(("get",)) == 1
    assert scheduler.next_path() == path
    covered = set(scheduler.state.covered)

    def steps():
        assert scheduler.state.attempts == {"latency": 1}
        assert scheduler.state.in_flight == set()
        assert scheduler.state.latency_bootstrap_paths == set()
        assert scheduler.state.latency_bootstrapped_paths == {"latency"}
        yield path.steps[0].step_id
        raise RuntimeError("steps failed")

    with pytest.raises(RuntimeError, match="steps failed"):
        scheduler.record_outcome(
            "latency", "completed", attempted_steps=steps(), trusted=False
        )

    assert scheduler.state.attempts == {"latency": 1}
    assert scheduler.state.in_flight == set()
    assert scheduler.state.latency_bootstrapped_paths == {"latency"}
    assert scheduler.state.canonical_attempts == {}
    assert scheduler.state.progress == {}
    assert scheduler.state.outcomes == {}
    assert scheduler.state.completed == set()
    assert scheduler.state.effect_reward_counts == {}
    assert scheduler.state.quarantined_features == {
        "latency": frozenset({"reward_state"})
    }
    assert scheduler.state.quarantined_rewards == 1
    assert scheduler.state.covered == covered
    assert scheduler.release_prewarmed(("get",)) == 1
    assert scheduler.next_path() == path
    scheduler.record_outcome(
        "latency", "completed", attempted_steps=(path.steps[0].step_id,)
    )
    assert scheduler.state.attempts == {"latency": 2}
    assert set(scheduler.state.canonical_attempts.values()) == {1}


def test_failed_prioritizer_keeps_earlier_scores_without_selecting(monkeypatch) -> None:
    prioritizer = InterestPrioritizer()
    score = prioritizer.score
    calls = []

    def fail_second(work_item_id, **features):
        calls.append(work_item_id)
        if work_item_id == "a":
            raise RuntimeError("score failed")
        return score(work_item_id, **features)

    monkeypatch.setattr(prioritizer, "score", fail_second)
    scheduler = CoverageDrivenScheduler(
        (make_path("z"), make_path("a")), interest_prioritizer=prioritizer
    )

    with pytest.raises(RuntimeError, match="score failed"):
        scheduler.next_path()

    assert calls == ["z", "a"]
    assert scheduler.state.cold_scores == {
        "z": score("z", coverage_gain=1, bandit_prior=0.5, reward_state=0.0)
    }
    assert scheduler.state.in_flight == set()
    assert scheduler.state.selections == []
    assert scheduler.state.covered == set()
    assert scheduler.state.effect_selections == {}
    assert scheduler.state.action_selections == {}
    assert scheduler.remaining == 2
    monkeypatch.setattr(prioritizer, "score", score)
    assert scheduler.next_path().path_id == "a"


@pytest.mark.parametrize("transition", ["release", "reopen"])
@pytest.mark.parametrize("exhausted", [False, True])
def test_release_and_reopen_preserve_bootstrap_retry_history(
    transition, exhausted
) -> None:
    baseline = [True]
    path = make_path(
        "latency", effect=duration(Atom(value="action:get"), Atom(value=100))
    )
    scheduler = CoverageDrivenScheduler(
        (path,), has_latency_baseline=lambda _: baseline[0]
    )
    if exhausted:
        for _ in range(2):
            assert scheduler.next_path() == path
            assert (
                scheduler.record_outcome(
                    "latency",
                    "blocked",
                    attempted_steps=(path.steps[0].step_id,),
                    reward=0.9,
                )
                == "retryable"
            )
    baseline[0] = False
    assert scheduler.bootstrap_prewarmed(("get",)) == 1
    assert scheduler.next_path() == path
    scheduler.record_outcome(
        "latency", "blocked", attempted_steps=(path.steps[0].step_id,), trusted=False
    )
    if not exhausted:
        scheduler.block_prerequisite("latency", "waiting for evidence")
    reason = scheduler.terminal_reason("latency")
    attempts = dict(scheduler.state.attempts)
    canonical = dict(scheduler.state.canonical_attempts)
    progress = dict(scheduler.state.progress)
    covered = set(scheduler.state.covered)

    if transition == "release":
        baseline[0] = True
        # Prerequisite blocking already removed the non-exhausted path from prewarm.
        assert scheduler.release_prewarmed(("action:get",)) == int(exhausted)
        assert scheduler.state.blocked == set()
        assert scheduler.state.outcomes == {}
        assert scheduler.terminal_reason("latency") == reason
        assert not scheduler.is_latency_bootstrap("get")
        assert scheduler.state.latency_bootstrapped_paths == set()
    else:
        assert scheduler.reopen_path("latency") is (not exhausted)
        assert scheduler.state.blocked == ({"latency"} if exhausted else set())
        assert scheduler.state.outcomes == ({"latency": "blocked"} if exhausted else {})
        assert scheduler.terminal_reason("latency") == (reason if exhausted else None)
        assert scheduler.is_latency_bootstrap("get")
        assert scheduler.state.latency_bootstrapped_paths == {"latency"}

    assert scheduler.state.attempts == attempts
    assert scheduler.state.canonical_attempts == canonical
    assert set(canonical.values()) == ({3} if exhausted else {1})
    assert scheduler.state.progress == progress
    assert scheduler.state.covered == covered
    assert scheduler.state.quarantined_features == {
        "latency": frozenset({"reward_state"})
    }
    assert scheduler.state.quarantined_rewards == 1
    if exhausted or transition == "reopen":
        assert scheduler.next_path() is None
    else:
        assert scheduler.next_path() == path


@pytest.mark.parametrize("outcome", ["completed", "blocked"])
def test_baseline_release_cannot_reopen_nonbootstrap_terminal_path(outcome) -> None:
    path = make_path(
        "latency", effect=duration(Atom(value="action:get"), Atom(value=100))
    )
    scheduler = CoverageDrivenScheduler((path,), has_latency_baseline=lambda _: True)
    assert scheduler.next_path() == path
    scheduler.record_outcome(
        "latency", outcome, attempted_steps=(path.steps[0].step_id,), trusted=False
    )

    assert scheduler.release_prewarmed(("get",)) == 0
    assert scheduler.state.outcomes == {"latency": outcome}
    assert scheduler.next_path() is None
    assert scheduler.reopen_path("latency")
    assert scheduler.next_path() == path
    assert scheduler.state.attempts == {"latency": 1}
    assert set(scheduler.state.canonical_attempts.values()) == {1}
    assert scheduler.state.quarantined_features == {
        "latency": frozenset({"reward_state"})
    }
    assert scheduler.state.quarantined_rewards == 1


def test_baseline_callback_observes_recorded_retry_before_prewarm_sync() -> None:
    path = make_path(
        "latency", effect=duration(Atom(value="action:get"), Atom(value=100))
    )
    observing = False
    observed = []

    def has_baseline(action):
        if observing:
            observed.append(action)
            assert scheduler.is_latency_bootstrap(action)
            assert scheduler.terminal_reason("latency") is None
            assert scheduler.state.outcomes == {"latency": "retryable"}
            assert scheduler.state.attempts == {"latency": 1}
            assert set(scheduler.state.canonical_attempts.values()) == {1}
            assert scheduler.state.in_flight == set()
            assert scheduler.state.latency_bootstrap_paths == set()
            assert scheduler.state.latency_bootstrapped_paths == {"latency"}
            assert scheduler.state.progress == {"latency": 0.0}
            assert scheduler.state.quarantined_rewards == 1
        return False

    scheduler = CoverageDrivenScheduler((path,), has_latency_baseline=has_baseline)
    assert scheduler.bootstrap_prewarmed(("get",)) == 1
    assert scheduler.next_path() == path
    observing = True
    assert (
        scheduler.record_outcome(
            "latency",
            "blocked",
            attempted_steps=(path.steps[0].step_id,),
            trusted=False,
        )
        == "retryable"
    )
    assert observed == ["get"]
    assert scheduler.state.prewarmed == {"latency"}


def test_reserve_release_preserves_attempted_paths_and_retry_history() -> None:
    from cloud_dast.runtime.differential.campaign import Runner

    scheduler = CoverageDrivenScheduler(
        tuple(make_path(name) for name in ("a", "b", "c"))
    )
    attempted = scheduler.next_path()
    assert attempted is not None
    scheduler.record_outcome(
        attempted.path_id,
        "blocked",
        attempted_steps=(step.step_id for step in attempted.steps),
        trusted=False,
    )
    deferred = scheduler.block_remaining()
    assert len(deferred) == 2
    history = (
        dict(scheduler.state.attempts),
        dict(scheduler.state.canonical_attempts),
        set(scheduler.state.covered),
        dict(scheduler.state.quarantined_features),
        scheduler.state.quarantined_rewards,
    )
    reasons = {path_id: scheduler.terminal_reason(path_id) for path_id in deferred}

    assert Runner.release_budget_deferred_paths(scheduler) == 2
    assert Runner.release_budget_deferred_paths(scheduler) == 0
    assert scheduler.state.blocked == {attempted.path_id}
    assert scheduler.remaining == 2
    assert history == (
        scheduler.state.attempts,
        scheduler.state.canonical_attempts,
        scheduler.state.covered,
        scheduler.state.quarantined_features,
        scheduler.state.quarantined_rewards,
    )
    assert reasons == {
        path_id: scheduler.terminal_reason(path_id) for path_id in deferred
    }
    assert scheduler.next_path().path_id in deferred


def test_scheduler_does_not_retain_itself_through_readiness() -> None:
    import gc
    import weakref

    enabled = gc.isenabled()
    gc.disable()
    try:
        scheduler = CoverageDrivenScheduler(())
        reference = weakref.ref(scheduler)
        del scheduler
        assert reference() is None
    finally:
        if enabled:
            gc.enable()
        gc.collect()


@pytest.mark.parametrize(
    ("method_id", "expected"),
    [
        (None, ("other", "chain", "target")),
        ("target", ("chain", "target")),
        ("absent", ()),
    ],
)
def test_method_selection_preserves_whole_nonempty_paths(method_id, expected):
    from dataclasses import replace

    from cloud_dast.contracts.plan import QdlExecutionView

    other = make_path("other", action_id="other")
    target = make_path("target", action_id="target")
    chain = replace(
        make_path("chain"), steps=(other.steps[0], target.steps[0], other.steps[0])
    )
    empty = make_path("empty", steps=0, action_id="target")
    paths = (empty, other, chain, target)
    selected = QdlExecutionView(graph_hash="graph", paths=paths, invariants={}).select(
        method_id
    )
    assert tuple(path.path_id for path in selected) == expected
    if "chain" in expected:
        assert next(path for path in selected if path.path_id == "chain") is chain


@pytest.mark.parametrize(
    ("method_id", "expected"),
    [
        (None, frozenset({"other", "target", "backlog"})),
        ("target", frozenset({"target", "backlog"})),
    ],
)
def test_active_path_ids_follow_binding_and_preserve_backlog(method_id, expected):
    from types import SimpleNamespace

    from cloud_dast.contracts.plan import QdlExecutionView
    from cloud_dast.runtime.campaign.state import RuntimeState

    view = QdlExecutionView(
        graph_hash="graph",
        paths=(
            make_path("other", action_id="other"),
            make_path("target", action_id="target"),
            make_path("empty", steps=0),
        ),
        invariants={},
    )
    campaign = RuntimeState(
        scope=None,
        differential=None,
        grounding=None,
        binding=SimpleNamespace(execution=view),
        request=SimpleNamespace(method_id=method_id),
        execution=SimpleNamespace(
            branch_backlog=(make_path("backlog", steps=0),),
            scheduler=SimpleNamespace(paths=(make_path("unrelated"),)),
        ),
    )
    assert campaign.active_path_ids == expected
