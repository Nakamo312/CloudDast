"""Pure deterministic path ranking and coverage fairness."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.runtime.prioritization import ColdScore, InterestPrioritizer
from cloud_dast.runtime.scheduler.model import CoverageKey, State


def rank_path(
    path: QdlExecutionPath,
    path_keys: Mapping[str, tuple[CoverageKey, ...]],
    state: State,
    prioritizer: InterestPrioritizer,
    pending_outcomes: frozenset[str],
) -> tuple[tuple[int, int, int, float, int, int, int, str], ColdScore]:
    """Return the deterministic ordering key for one executable path."""

    keys = set(path_keys[path.path_id])
    new_coverage = len(keys - state.covered)
    class_deficit = min(
        (
            min(
                state.effect_selections.get(key.effect_name, 0),
                state.primitive_selections.get(key.primitive, 0),
            )
            for key in keys
        ),
        default=0,
    )
    supplies_missing_outcome = any(
        key.primitive == "outcome" and key.action_id in pending_outcomes for key in keys
    )
    outcome_debt = 0 if supplies_missing_outcome else 1
    action_deficit = min(
        (
            min(
                state.action_selections.get(key.action_id, 0),
                state.action_primitive_selections.get(
                    (key.action_id, key.primitive), 0
                ),
            )
            for key in keys
        ),
        default=0,
    )
    cold_score = prioritizer.score(
        path.path_id,
        coverage_gain=new_coverage,
        bandit_prior=_effect_prior(keys, state),
        reward_state=state.progress.get(path.path_id, 0.0),
        quarantined_features=state.quarantined_features.get(path.path_id, frozenset()),
    )
    return (
        (
            outcome_debt,
            class_deficit,
            action_deficit,
            -cold_score.interest,
            len(path.steps),
            0 if path.kind == "invariant" else 1,
            cold_score.seed_digest,
            path.path_id,
        ),
        cold_score,
    )


def _effect_prior(keys: set[CoverageKey], state: State) -> float:
    """Return the trusted mean reward over the path's effect classes."""

    rewards = []
    for effect_name in {key.effect_name for key in keys}:
        count = state.effect_reward_counts.get(effect_name, 0)
        if count:
            rewards.append(state.effect_reward_totals[effect_name] / count)
    return sum(rewards) / len(rewards) if rewards else 0.5


def pending_outcomes(
    paths: Sequence[QdlExecutionPath],
    path_keys: Mapping[str, tuple[CoverageKey, ...]],
    state: State,
) -> frozenset[str]:
    """Return actions whose outcome arm has selection priority."""

    available_allowed = {
        key.action_id
        for path in paths
        for key in path_keys[path.path_id]
        if key.effect_name == "allowed" and key.action_id not in state.action_allowed
    }
    available_effects = {
        key.effect_name for path in paths for key in path_keys[path.path_id]
    }
    frontier_complete = all(
        state.effect_selections.get(effect_name, 0) > 0
        for effect_name in available_effects
    )
    if frontier_complete:
        return frozenset(available_allowed)
    return frozenset(available_allowed & state.actions_without_outcome)


__all__ = ["pending_outcomes", "rank_path"]
