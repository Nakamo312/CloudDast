"""Outcome, retry, and reward state transitions for the scheduler."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from cloud_dast.runtime.scheduler.coverage import step_coverage_key
from cloud_dast.runtime.scheduler.model import PathOutcome

logger = logging.getLogger("cloud_dast.runtime.scheduler")

_RETRY_REWARD_THRESHOLD = 0.1
_MAX_RETRIES = 2


class OutcomePolicy:
    """Record path attempts and apply bounded retry semantics."""

    def record_outcome(
        self,
        path_id: str,
        outcome: PathOutcome,
        *,
        attempted_steps: Iterable[str],
        reward: float | None = None,
        trusted: bool = True,
    ) -> PathOutcome:
        """Record one path execution and its bounded retry progress.

        ``reward`` is the best proximity the path reached in [0, 1];
        ``None`` falls back to the outcome prior (completed 1.0, blocked
        0.0).  A blocked path with partial progress (reward above the
        retry threshold) is recorded as ``retryable`` instead of terminal.
        Retries share a canonical-key budget, so path re-versions cannot
        keep the same action/effect/primitive cell alive indefinitely.
        ``attempted_steps`` names only steps with execution observations in
        this attempt; steps skipped by setup, preflight or replay are not charged.
        Each canonical cell is charged once per attempt, regardless of the
        number of fuzz candidates or duplicate steps.
        Returns the effective outcome.
        """
        reward = self._prepare_reward(path_id, outcome, reward, trusted)
        was_latency_bootstrap = self._record_attempt(
            path_id,
            attempted_steps,
            reward,
            trusted,
        )
        if outcome in ("completed", "goal_reached"):
            return self._complete(path_id, outcome)

        if self._canonical_exhausted(path_id):
            self._block_exhausted(path_id)
            if not was_latency_bootstrap:
                self._block_canonical_neighbors(path_id)
            return "blocked"

        if outcome == "blocked" and (
            self._retry_allowed(path_id, reward) or was_latency_bootstrap
        ):
            # Non-terminal: bounded retry work remains eligible under the
            # deterministic coverage order.  A bootstrap path stays prewarmed
            # until its delivered response creates the missing baseline.
            return self._retry(path_id, reward)

        return self._record_terminal(path_id, outcome, was_latency_bootstrap)

    def _prepare_reward(
        self,
        path_id: str,
        outcome: PathOutcome,
        reward: float | None,
        trusted: bool,
    ) -> float:
        if reward is None:
            reward = 1.0 if outcome in ("completed", "goal_reached") else 0.0
        if trusted:
            self._state.quarantined_features.pop(path_id, None)
            return reward
        self._state.quarantined_features[path_id] = frozenset({"reward_state"})
        self._state.quarantined_rewards += 1
        logger.warning(
            "scheduler_reward_quarantined path=%s outcome=%s",
            path_id,
            outcome,
        )
        return 0.0

    def _record_attempt(
        self,
        path_id: str,
        attempted_steps: Iterable[str],
        reward: float,
        trusted: bool,
    ) -> bool:
        was_bootstrap = path_id in self._state.latency_bootstrap_paths
        self._state.in_flight.discard(path_id)
        if was_bootstrap:
            self._state.latency_bootstrap_paths.discard(path_id)
            self._state.latency_bootstrapped_paths.add(path_id)
        self._state.attempts[path_id] = self._state.attempts.get(path_id, 0) + 1
        attempted_ids = set(attempted_steps)
        path = next(path for path in self._paths if path.path_id == path_id)
        attempted_keys = {
            step_coverage_key(step)
            for step in path.steps
            if step.step_id in attempted_ids
        }
        for key in attempted_keys:
            self._state.canonical_attempts[key] = (
                self._state.canonical_attempts.get(key, 0) + 1
            )
        self._state.progress[path_id] = max(
            self._state.progress.get(path_id, 0.0), reward
        )
        if trusted:
            self._record_effect_reward(path_id, reward)
        return was_bootstrap

    def _complete(self, path_id: str, outcome: PathOutcome) -> PathOutcome:
        self._state.completed.add(path_id)
        self._state.outcomes[path_id] = outcome
        return outcome

    def _block_exhausted(self, path_id: str) -> None:
        self._state.outcomes[path_id] = "blocked"
        self._state.blocked.add(path_id)
        self._state.terminal_reasons[path_id] = (
            "canonical coverage retry budget exhausted"
        )

    def _retry(self, path_id: str, reward: float) -> PathOutcome:
        self._state.outcomes[path_id] = "retryable"
        logger.info(
            "scheduler_path_retryable path=%s attempts=%d reward=%.3f remaining=%d",
            path_id,
            self._state.attempts[path_id],
            reward,
            self.remaining,
        )
        return "retryable"

    def _record_terminal(
        self,
        path_id: str,
        outcome: PathOutcome,
        was_latency_bootstrap: bool,
    ) -> PathOutcome:
        self._state.outcomes[path_id] = outcome
        if outcome != "blocked":
            return outcome
        self._state.blocked.add(path_id)
        if not was_latency_bootstrap:
            self._block_canonical_neighbors(path_id)
        logger.info(
            "scheduler_path_blocked path=%s remaining=%d",
            path_id,
            self.remaining,
        )
        return outcome

    def _retry_allowed(self, path_id: str, reward: float) -> bool:
        """Whether one more bounded retry may be granted to a blocked arm."""

        return reward > _RETRY_REWARD_THRESHOLD and not self._canonical_exhausted(
            path_id
        )

    def _record_effect_reward(self, path_id: str, reward: float) -> None:
        for effect_name in {
            key.effect_name for key in self._path_keys.get(path_id, ())
        }:
            self._state.effect_reward_totals[effect_name] = (
                self._state.effect_reward_totals.get(effect_name, 0.0) + reward
            )
            self._state.effect_reward_counts[effect_name] = (
                self._state.effect_reward_counts.get(effect_name, 0) + 1
            )

    def _canonical_exhausted(self, path_id: str) -> bool:
        return any(
            self._state.canonical_attempts.get(key, 0) > _MAX_RETRIES
            for key in self._path_keys.get(path_id, ())
        )

    def _block_canonical_neighbors(self, path_id: str) -> None:
        exhausted = {
            key
            for key in self._path_keys.get(path_id, ())
            if self._state.canonical_attempts.get(key, 0) > _MAX_RETRIES
        }
        if not exhausted:
            return
        protected = (
            self._state.completed | self._state.superseded | self._state.in_flight
        )
        for path in self._paths:
            if path.path_id in protected or not exhausted.intersection(
                self._path_keys.get(path.path_id, ())
            ):
                continue
            self._state.outcomes[path.path_id] = "blocked"
            self._state.blocked.add(path.path_id)
            self._state.terminal_reasons[path.path_id] = (
                "canonical coverage neighbor blocked after retry budget exhaustion"
            )
            self._state.prewarmed.discard(path.path_id)
