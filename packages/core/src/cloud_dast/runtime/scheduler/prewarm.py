"""Latency-baseline holding and bootstrap policy for scheduling."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from cloud_dast.model.events import normalize_action
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.scheduler.coverage import latency_actions, path_actions

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class LatencyPrewarm:
    """Keep latency-only paths parked until a comparable baseline exists."""

    def is_prewarmed(self, path_id: str) -> bool:
        """Whether a path is waiting for a latency baseline."""

        self._sync_prewarmed()
        return path_id in self._state.prewarmed

    def release_prewarmed(self, action_ids: Iterable[str]) -> int:
        """Release duration paths whose actions now have a baseline."""

        before = set(self._state.prewarmed)
        released_actions = {normalize_action(action_id) for action_id in action_ids}
        for path in self._paths:
            if path.path_id not in self._state.latency_bootstrapped_paths:
                continue
            if path.path_id not in self._state.blocked:
                continue
            if not any(action in released_actions for action in latency_actions(path)):
                continue
            self._state.blocked.discard(path.path_id)
            self._state.outcomes.pop(path.path_id, None)
        self._released_latency_actions.update(released_actions)
        self._state.latency_bootstrap_actions.difference_update(released_actions)
        self._state.latency_bootstrap_paths.difference_update(
            path.path_id
            for path in self._paths
            if any(action in released_actions for action in latency_actions(path))
        )
        self._state.latency_bootstrapped_paths.difference_update(
            path.path_id
            for path in self._paths
            if any(action in released_actions for action in latency_actions(path))
        )
        self._sync_prewarmed()
        released = before - self._state.prewarmed
        if released:
            logger.info(
                "scheduler_prewarm_released paths=%d actions=%s",
                len(released),
                ",".join(sorted(self._released_latency_actions)),
            )
        return len(released)

    def bootstrap_prewarmed(self, action_ids: Iterable[str]) -> int:
        """Mark one prewarmed path per action for a baseline bootstrap call."""

        self._sync_prewarmed()
        bootstrapped = 0
        for action in sorted({normalize_action(action_id) for action_id in action_ids}):
            if action in self._state.latency_bootstrap_actions:
                continue
            if self._has_latency_baseline is not None and self._has_latency_baseline(
                action
            ):
                continue
            if self._has_unprewarmed_work(action):
                continue
            candidates = [
                path
                for path in self._paths
                if path.path_id in self._state.prewarmed
                and path.path_id not in self._state.completed
                and path.path_id not in self._state.blocked
                and path.path_id not in self._state.superseded
                and path.path_id not in self._state.in_flight
                and action in latency_actions(path)
            ]
            if not candidates:
                continue
            path = min(candidates, key=lambda item: item.path_id)
            self._state.latency_bootstrap_actions.add(action)
            self._state.latency_bootstrap_paths.add(path.path_id)
            bootstrapped += 1
        if bootstrapped:
            logger.info(
                "scheduler_latency_bootstrap paths=%d actions=%s",
                len(
                    {
                        path.path_id
                        for path in self._paths
                        if path.path_id in self._state.latency_bootstrap_paths
                    }
                ),
                ",".join(sorted(self._state.latency_bootstrap_actions)),
            )
        return bootstrapped

    def is_latency_bootstrap(self, action_id: str) -> bool:
        """Whether one action is allowed a single-sample initial baseline."""

        return normalize_action(action_id) in self._state.latency_bootstrap_actions

    def _sync_prewarmed(self) -> None:
        for path in self._paths:
            if (
                path.path_id in self._state.completed
                or path.path_id in self._state.blocked
                or path.path_id in self._state.superseded
            ):
                self._state.prewarmed.discard(path.path_id)
                continue
            if not latency_actions(path):
                self._state.prewarmed.discard(path.path_id)
                continue
            if self._missing_latency_actions(path):
                self._state.prewarmed.add(path.path_id)
            else:
                self._state.prewarmed.discard(path.path_id)

    def _missing_latency_actions(self, path: QdlExecutionPath) -> tuple[str, ...]:
        actions = latency_actions(path)
        if self._has_latency_baseline is not None:
            return tuple(
                action for action in actions if not self._has_latency_baseline(action)
            )
        normalized = {normalize_action(action) for action in actions}
        return tuple(sorted(normalized - self._released_latency_actions))

    def _has_unprewarmed_work(self, action: str) -> bool:
        """Whether another executable path can still produce action evidence."""

        return any(
            path.path_id not in self._state.prewarmed
            and path.path_id not in self._state.completed
            and path.path_id not in self._state.blocked
            and path.path_id not in self._state.superseded
            and action in path_actions(path)
            for path in self._paths
        )


__all__ = ["LatencyPrewarm"]
