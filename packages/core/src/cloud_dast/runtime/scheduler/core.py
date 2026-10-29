"""Coordinate coverage selection, path discovery and explicit lifecycle transitions."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.runtime.prioritization import InterestPrioritizer
from cloud_dast.runtime.scheduler import selection
from cloud_dast.runtime.scheduler.coverage import feature_names, step_coverage_key
from cloud_dast.runtime.scheduler.model import PathOutcome, State
from cloud_dast.runtime.scheduler.prewarm import LatencyPrewarm
from cloud_dast.runtime.scheduler.registry import PathRegistry

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class CoverageDrivenScheduler:
    """Select paths through pure ranking and one mutable lifecycle owner."""

    def __init__(
        self,
        paths: tuple[QdlExecutionPath, ...],
        *,
        has_latency_baseline: Callable[[str], bool] | None = None,
        seed: int = 0,
        interest_prioritizer: InterestPrioritizer | None = None,
    ) -> None:
        if interest_prioritizer is not None and seed != 0:
            raise ValueError("pass either seed or interest_prioritizer")
        self._registry = PathRegistry(paths)
        self._state = State()
        self._latency = LatencyPrewarm(
            self._state, self._registry.snapshot, has_latency_baseline
        )
        self._interest = interest_prioritizer or InterestPrioritizer(seed=seed)
        self._latency.sync()

    @property
    def state(self) -> State:
        return self._state

    @property
    def paths(self) -> tuple[QdlExecutionPath, ...]:
        return self._registry.snapshot()

    def add_paths(self, paths: tuple[QdlExecutionPath, ...]) -> int:
        added = self._registry.add(paths)
        if added:
            self._latency.sync()
        return added

    def reopen_path(self, path_id: str) -> bool:
        return self._state.reopen(path_id, self._registry.coverage)

    def supersede_paths(self, replacements: Mapping[str, str]) -> int:
        return self._state.retire(replacements, self.paths)

    def supersede_replaced_paths(
        self, replacement_paths: tuple[QdlExecutionPath, ...]
    ) -> int:
        return self.supersede_paths(self._registry.replacements(replacement_paths))

    def block_remaining(self) -> tuple[str, ...]:
        return self._state.block_remaining(self.paths, self._registry.coverage)

    def block_prerequisite(self, path_id: str, reason: str) -> None:
        self._state.block_prerequisite(path_id, reason)

    def terminal_reason(self, path_id: str) -> str | None:
        return self._state.terminal_reasons.get(path_id)

    def is_prewarmed(self, path_id: str) -> bool:
        return self._latency.is_prewarmed(path_id)

    def release_prewarmed(self, action_ids: Iterable[str]) -> int:
        return self._latency.release_prewarmed(action_ids)

    def bootstrap_prewarmed(self, action_ids: Iterable[str]) -> int:
        return self._latency.bootstrap_prewarmed(action_ids)

    def is_latency_bootstrap(self, action_id: str) -> bool:
        return self._latency.is_latency_bootstrap(action_id)

    @property
    def remaining(self) -> int:
        self._latency.sync()
        return sum(
            self._state.eligible(path, self._registry.coverage) for path in self.paths
        )

    def next_path(self) -> QdlExecutionPath | None:
        self._latency.sync()
        eligible = [
            path
            for path in self.paths
            if self._state.eligible(path, self._registry.coverage)
        ]
        if not eligible:
            return None
        candidates = [
            path for path in eligible if not self._state.attempts.get(path.path_id)
        ] or eligible
        pending = selection.pending_outcomes(
            candidates, self._registry.coverage, self._state
        )

        def rank(path: QdlExecutionPath):
            order, score = selection.rank_path(
                path, self._registry.coverage, self._state, self._interest, pending
            )
            self._state.record_score(path.path_id, score)
            return order

        best = min(candidates, key=rank)
        self._state.select(best.path_id, self._registry.coverage)
        score = self._state.cold_scores[best.path_id]
        logger.info(
            "scheduler_cold_score path=%s coverage_gain=%d bandit_prior=%.3f "
            "reward_state=%.3f interest=%.3f seed=%d seed_digest=%d quarantined=%s",
            score.work_item_id,
            score.coverage_gain,
            score.bandit_prior,
            score.reward_state,
            score.interest,
            score.seed,
            score.seed_digest,
            feature_names(score.quarantined_features),
        )
        logger.debug(
            "scheduler_selected path=%s remaining=%d", best.path_id, self.remaining
        )
        return best

    def record_outcome(
        self,
        path_id: str,
        outcome: PathOutcome,
        *,
        attempted_steps: Iterable[str],
        reward: float | None = None,
        trusted: bool = True,
    ) -> PathOutcome:
        def attempted_keys():
            attempted = set(attempted_steps)
            path = next(path for path in self.paths if path.path_id == path_id)
            return {
                step_coverage_key(step)
                for step in path.steps
                if step.step_id in attempted
            }

        return self._state.record_outcome(
            path_id,
            outcome,
            self._registry.snapshot,
            self._registry.coverage,
            attempted_keys=attempted_keys,
            reward=reward,
            trusted=trusted,
            remaining=lambda: self.remaining,
        )
