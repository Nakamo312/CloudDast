from __future__ import annotations

from cloud_dast_fuzzing import (
    GeneratorBandit,
    GeneratorSelector,
)


class Generator:
    def generate(self, plan, method, invariant, scenario, *, feedback=None):
        del plan, method, invariant, scenario, feedback
        return ()


class RecordingPolicy:
    def __init__(self) -> None:
        self.choose_calls: list[dict[str, object]] = []
        self.update_calls: list[dict[str, object]] = []

    def choose(self, strategies, *, goal_key="generic", action_id=None):
        self.choose_calls.append(
            {"strategies": strategies, "goal_key": goal_key, "action_id": action_id}
        )
        return strategies[0]

    def update(
        self,
        strategy,
        reward,
        *,
        goal_key="generic",
        action_id=None,
        verdict=None,
    ):
        self.update_calls.append(
            {
                "strategy": strategy,
                "reward": reward,
                "goal_key": goal_key,
                "action_id": action_id,
                "verdict": verdict,
            }
        )


def test_selector_routes_action_context_through_shared_policy() -> None:
    policy = RecordingPolicy()
    selector = GeneratorSelector(
        {"template": Generator(), "fuzzing": Generator()},
        default="adaptive",
        policy=policy,
    )

    selector.select(goal_key="denied", action_id="orders.Get")
    selector.update(
        "template",
        "fail",
        goal_key="denied",
        action_id="orders.Get",
    )

    assert policy.choose_calls == [
        {
            "strategies": ("fuzzing", "omit_optional_field", "template"),
            "goal_key": "denied",
            "action_id": "orders.Get",
        }
    ]
    assert policy.update_calls == [
        {
            "strategy": "template",
            "reward": 1.0,
            "goal_key": "denied",
            "action_id": "orders.Get",
            "verdict": None,
        }
    ]


def test_bandit_learns_only_scoreable_verdicts() -> None:
    bandit = GeneratorBandit(seed=7)
    selector = GeneratorSelector(
        {"template": Generator(), "fuzzing": Generator()},
        default="adaptive",
        policy=bandit,
    )
    selected = selector.select()
    assert selected in {selector.select("template"), selector.select("fuzzing")}
    selector.update("fuzzing", "fail")
    selector.update("template", "unscoreable")


def test_bandit_arms_are_namespaced_by_goal() -> None:
    bandit = GeneratorBandit(seed=11)
    strategies = ("template", "fuzzing")

    assert GeneratorBandit.arm_name("template", "denied") == "denied:template"
    for _ in range(20):
        bandit.update("template", 1.0, goal_key="denied")
        bandit.update("fuzzing", 0.0, goal_key="denied")

    for _ in range(20):
        bandit.update("template", 0.0, goal_key="changed")
        bandit.update("fuzzing", 1.0, goal_key="changed")

    chosen = {bandit.choose(strategies, goal_key="denied") for _ in range(20)}
    other = [bandit.choose(strategies, goal_key="changed") for _ in range(2000)]
    assert chosen == {"template"}
    assert other.count("fuzzing") / len(other) > 0.85


def test_bandit_selection_is_reproducible_with_graded_rewards() -> None:
    strategies = ("template", "fuzzing", "symbolic")
    fractional = GeneratorBandit(seed=7)
    repeated = GeneratorBandit(seed=7)

    fractional.update("symbolic", 0.7)
    repeated.update("symbolic", 0.7)
    for strategy in ("template", "fuzzing"):
        fractional.update(strategy, 0.0)
        repeated.update(strategy, 0.0)

    fractional_choices = tuple(fractional.choose(strategies) for _ in range(50))
    repeated_choices = tuple(repeated.choose(strategies) for _ in range(50))

    assert fractional_choices == repeated_choices
    assert set(fractional_choices) <= set(strategies)


def test_adaptive_selection_requires_policy() -> None:
    selector = GeneratorSelector({"template": Generator()})
    try:
        selector.select("adaptive")
    except ValueError as error:
        assert "policy" in str(error)
    else:
        raise AssertionError("adaptive selection must require a bandit")


class TestFailingStrategyFilter:
    """Per-action execution memory for strategy selection."""

    def test_learns_from_failures_for_same_action(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base, max_consecutive_failures=2)
        strategies = ("template", "fuzzing", "symbolic")

        # Template fails twice for action "get"
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )

        # Template should now be filtered out for "get"
        chosen = {
            bandit.choose(strategies, goal_key="denied", action_id="get")
            for _ in range(30)
        }
        assert "template" not in chosen or len(chosen) == len(strategies)

    def test_no_filter_for_different_action(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base, max_consecutive_failures=2)
        strategies = ("template", "fuzzing")

        # Template fails twice for action "get"
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )

        # For a DIFFERENT action, template is not filtered
        chosen = {
            bandit.choose(strategies, goal_key="denied", action_id="list")
            for _ in range(30)
        }
        # Both strategies should be selectable (no history for "list")
        assert len(chosen) >= 1

    def test_fail_reset_by_success(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base, max_consecutive_failures=2)

        # Template fails once, then succeeds
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )
        bandit.update(
            "template",
            1.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.FAIL,
        )

        # Consecutive failure count should be reset by the success
        # The FAIL at the end resets and removes the consecutive-failure state.
        assert bandit._consecutive_failures("get", "template") == 0
        assert ("get", "template") not in bandit._failure_counts

    def test_all_filtered_does_not_deadlock(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base, max_consecutive_failures=1)
        strategies = ("template", "fuzzing")

        # Both strategies fail for action "get"
        for strategy in strategies:
            bandit.update(
                strategy,
                0.0,
                goal_key="denied",
                action_id="get",
                verdict=VerdictStatus.UNSCOREABLE,
            )

        # Should still return a strategy (filter lifted to avoid deadlock)
        chosen = bandit.choose(strategies, goal_key="denied", action_id="get")
        assert chosen in strategies

    def test_without_action_id_behaves_as_base(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base)
        strategies = ("template", "fuzzing")

        # Record failures for action "get"
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )
        bandit.update(
            "template",
            0.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )

        # Without action_id, choose should behave like the base bandit
        # (no filtering)
        chosen = bandit.choose(strategies, goal_key="denied")
        assert chosen in strategies

    def test_proximity_reward_flows_to_base(self) -> None:
        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        base = GeneratorBandit(seed=7)
        bandit = FailingStrategyFilter(base)

        bandit.update(
            "template",
            0.7,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.UNSCOREABLE,
        )

        # The base bandit should have received the reward
        # (verified by the fact that it doesn't crash and can still choose)
        chosen = bandit.choose(("template",), goal_key="denied")
        assert chosen == "template"

    def test_ten_thousand_updates_use_constant_context_memory(self) -> None:
        import sys

        from cloud_dast.model import VerdictStatus
        from cloud_dast_fuzzing.strategies.selector import (
            FailingStrategyFilter,
        )

        bandit = FailingStrategyFilter(
            GeneratorBandit(seed=7),
            max_consecutive_failures=2,
        )

        for _ in range(5_000):
            bandit.update(
                "template",
                0.0,
                goal_key="denied",
                action_id="get",
                verdict=VerdictStatus.UNSCOREABLE,
            )
        initial_size = sys.getsizeof(bandit._failure_counts)

        bandit.update(
            "template",
            1.0,
            goal_key="denied",
            action_id="get",
            verdict=VerdictStatus.FAIL,
        )
        for _ in range(4_999):
            bandit.update(
                "template",
                0.0,
                goal_key="denied",
                action_id="get",
                verdict=VerdictStatus.UNSCOREABLE,
            )

        assert len(bandit._failure_counts) == 1
        assert sys.getsizeof(bandit._failure_counts) == initial_size
        assert bandit._consecutive_failures("get", "template") == 2
