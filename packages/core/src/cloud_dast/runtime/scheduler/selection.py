"""Deterministic path selection and coverage fairness."""

from __future__ import annotations

import logging

from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.scheduler.coverage import feature_names
from cloud_dast.runtime.scheduler.model import CoverageKey

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class Chooser:
    """Choose eligible paths using shared retry limits and coverage fairness."""

    @property
    def remaining(self) -> int:
        self._sync_prewarmed()
        return sum(1 for path in self._paths if self._eligible(path))

    def next_path(self) -> QdlExecutionPath | None:
        """Return the next best eligible path, or ``None`` when done."""

        self._sync_prewarmed()
        eligible = [path for path in self._paths if self._eligible(path)]
        if not eligible:
            return None

        candidates = [
            path for path in eligible if not self._state.attempts.get(path.path_id)
        ] or eligible
        pending_outcomes = self._pending_outcome_actions(candidates)
        best = min(
            candidates,
            key=lambda path: self._cold_score(path, pending_outcomes),
        )
        self._state.in_flight.add(best.path_id)
        self._state.selections.append(best.path_id)
        self._record_coverage_selection(best.path_id)
        cold_score = self._state.cold_scores[best.path_id]
        logger.info(
            "scheduler_cold_score path=%s coverage_gain=%d bandit_prior=%.3f "
            "reward_state=%.3f interest=%.3f seed=%d seed_digest=%d "
            "quarantined=%s",
            cold_score.work_item_id,
            cold_score.coverage_gain,
            cold_score.bandit_prior,
            cold_score.reward_state,
            cold_score.interest,
            cold_score.seed,
            cold_score.seed_digest,
            feature_names(cold_score.quarantined_features),
        )
        logger.debug(
            "scheduler_selected path=%s remaining=%d",
            best.path_id,
            self.remaining,
        )
        return best

    def _cold_score(
        self,
        path: QdlExecutionPath,
        pending_outcomes: frozenset[str],
    ) -> tuple[int, int, int, float, int, int, int, str]:
        """Return the deterministic ordering key for one executable path."""

        keys = set(self._path_keys[path.path_id])
        new_coverage = len(keys - self._state.covered)
        class_deficit = min(
            (
                min(
                    self._state.effect_selections.get(key.effect_name, 0),
                    self._state.primitive_selections.get(key.primitive, 0),
                )
                for key in keys
            ),
            default=0,
        )
        supplies_missing_outcome = any(
            key.primitive == "outcome" and key.action_id in pending_outcomes
            for key in keys
        )
        outcome_debt = 0 if supplies_missing_outcome else 1
        action_deficit = min(
            (
                min(
                    self._state.action_selections.get(key.action_id, 0),
                    self._state.action_primitive_selections.get(
                        (key.action_id, key.primitive), 0
                    ),
                )
                for key in keys
            ),
            default=0,
        )
        cold_score = self._interest.score(
            path.path_id,
            coverage_gain=new_coverage,
            bandit_prior=self._effect_prior(keys),
            reward_state=self._state.progress.get(path.path_id, 0.0),
            quarantined_features=self._state.quarantined_features.get(
                path.path_id, frozenset()
            ),
        )
        self._state.cold_scores[path.path_id] = cold_score
        return (
            outcome_debt,
            class_deficit,
            action_deficit,
            -cold_score.interest,
            len(path.steps),
            0 if path.kind == "invariant" else 1,
            cold_score.seed_digest,
            path.path_id,
        )

    def _effect_prior(self, keys: set[CoverageKey]) -> float:
        """Return the trusted mean reward over the path's effect classes."""

        rewards = []
        for effect_name in {key.effect_name for key in keys}:
            count = self._state.effect_reward_counts.get(effect_name, 0)
            if count:
                rewards.append(self._state.effect_reward_totals[effect_name] / count)
        return sum(rewards) / len(rewards) if rewards else 0.5

    def _record_coverage_selection(self, path_id: str) -> None:
        """Record one selection in every canonical coverage dimension."""

        keys = set(self._path_keys.get(path_id, ()))
        self._state.covered.update(keys)
        self._state.action_outcomes.update(
            key.action_id for key in keys if key.primitive == "outcome"
        )
        self._state.action_allowed.update(
            key.action_id for key in keys if key.effect_name == "allowed"
        )
        self._state.actions_without_outcome.update(
            key.action_id for key in keys if key.primitive != "outcome"
        )
        for key in keys:
            self._state.effect_selections[key.effect_name] = (
                self._state.effect_selections.get(key.effect_name, 0) + 1
            )
            self._state.primitive_selections[key.primitive] = (
                self._state.primitive_selections.get(key.primitive, 0) + 1
            )
            self._state.action_selections[key.action_id] = (
                self._state.action_selections.get(key.action_id, 0) + 1
            )
            action_primitive = (key.action_id, key.primitive)
            self._state.action_primitive_selections[action_primitive] = (
                self._state.action_primitive_selections.get(action_primitive, 0) + 1
            )

    def _pending_outcome_actions(
        self, paths: tuple[QdlExecutionPath, ...] | list[QdlExecutionPath]
    ) -> frozenset[str]:
        """Return actions whose outcome arm has selection priority."""

        available_allowed = {
            key.action_id
            for path in paths
            for key in self._path_keys[path.path_id]
            if key.effect_name == "allowed"
            and key.action_id not in self._state.action_allowed
        }
        available_effects = {
            key.effect_name for path in paths for key in self._path_keys[path.path_id]
        }
        frontier_complete = all(
            self._state.effect_selections.get(effect_name, 0) > 0
            for effect_name in available_effects
        )
        if frontier_complete:
            return frozenset(available_allowed)
        return frozenset(available_allowed & self._state.actions_without_outcome)

    def _eligible(self, path: QdlExecutionPath) -> bool:
        return (
            path.path_id not in self._state.completed
            and path.path_id not in self._state.blocked
            and path.path_id not in self._state.superseded
            and path.path_id not in self._state.in_flight
            and (
                path.path_id not in self._state.prewarmed
                or path.path_id in self._state.latency_bootstrap_paths
            )
            and not self._canonical_exhausted(path.path_id)
        )


__all__ = ["Chooser"]
