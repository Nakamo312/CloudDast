from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.candidates import goal_key
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, denied
from cloud_dast_fuzzing import FuzzSession
from cloud_dast_fuzzing.strategies.selector import (
    FailingStrategyFilter,
    GeneratorBandit,
)
from tests.application.verification.fuzzing.test_session import (
    AllowAll,
    StaticGenerator,
    invariant,
    method,
    plan,
    scenario,
)


def selection_share(bandit, *, action_id=None, goal="generic") -> float:
    choices = [
        bandit.choose(("fuzzing", "template"), goal_key=goal, action_id=action_id)
        for _ in range(2000)
    ]
    return choices.count("fuzzing") / len(choices)


@pytest.mark.parametrize("seed", [0, 7, 23])
def test_reward_magnitude_changes_selection_preference(seed) -> None:
    assert Path(cloud_dast.__file__).is_relative_to(Path(__file__).resolve().parents[1])
    weak = GeneratorBandit(seed=seed)
    strong = GeneratorBandit(seed=seed)
    for _ in range(30):
        weak.update("fuzzing", 0.01)
        strong.update("fuzzing", 1.0)
        weak.update("template", 0.5)
        strong.update("template", 0.5)

    # Compare learned preference against a fixed intermediate control, rather
    # than requiring two random traces to differ by chance.
    assert selection_share(weak) < 0.15
    assert selection_share(strong) > 0.85


@pytest.mark.parametrize(
    ("verdict", "grounded", "proximity", "preferred"),
    [
        (VerdictStatus.UNSCOREABLE, False, 0.02, False),
        (VerdictStatus.FAIL, True, 0.02, True),
        (VerdictStatus.FAIL, False, 0.9, False),
    ],
)
def test_session_reward_reaches_river(verdict, grounded, proximity, preferred) -> None:
    base = GeneratorBandit(seed=7)
    filtered = FailingStrategyFilter(base)
    norm = invariant().model_copy(
        update={
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:1"),
                    denied(Atom(value=canonical_action_id(method().method_id))),
                ),
            )
        }
    )
    goal = goal_key(norm)
    for _ in range(30):
        fuzz = FuzzSession(
            plan=plan(),
            method=method(),
            invariant=norm,
            scenario=scenario(),
            generators={"fuzzing": StaticGenerator(("a",))},
            policy=filtered,
            guardrail=AllowAll(),
        )
        check = fuzz.next()
        assert check is not None
        fuzz.record(check, verdict, grounded=grounded, proximity=proximity)
        base.update("template", 0.5, goal_key=goal)
        if verdict is VerdictStatus.FAIL and not grounded:
            assert fuzz.state.reward == 0.0
            assert fuzz.state.failures == 0
            assert fuzz.state.best_proximity == 0.0

    share = selection_share(base, goal=goal)
    assert share > 0.85 if preferred else share < 0.15


def test_action_filter_excludes_learned_best_arm_and_resets() -> None:
    base = GeneratorBandit(seed=7)
    filtered = FailingStrategyFilter(base)
    for _ in range(30):
        base.update("fuzzing", 1.0)
        base.update("template", 0.0)
    for _ in range(2):
        filtered.update(
            "fuzzing", 0.0, action_id="get", verdict=VerdictStatus.UNSCOREABLE
        )

    assert selection_share(filtered, action_id="get") == 0.0
    assert selection_share(filtered, action_id="list") > 0.85
    filtered.update("fuzzing", 1.0, action_id="get", verdict=VerdictStatus.FAIL)
    assert selection_share(filtered, action_id="get") > 0.85


def test_clamps_reward_and_rejects_empty_selection() -> None:
    policy = GeneratorBandit(seed=7)
    for _ in range(30):
        policy.update("fuzzing", -5.0)
        policy.update("fuzzing", 5.0)
        policy.update("template", 0.7)
    # Saturated endpoints contribute balanced success/failure evidence.
    assert selection_share(policy) < 0.15
    assert policy.choose(("fuzzing",), goal_key="fresh") == "fuzzing"
    with pytest.raises(ValueError, match="at least one strategy"):
        policy.choose(())
