"""Latency-baseline holding and bootstrap policy for scheduling."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.model.events import normalize_action
from cloud_dast.runtime.scheduler.coverage import latency_actions, path_actions
from cloud_dast.runtime.scheduler.model import State

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class LatencyPrewarm:
    """Keep latency-only paths parked until a comparable baseline exists."""

    def __init__(
        self,
        state: State,
        paths: Callable[[], tuple[QdlExecutionPath, ...]],
        has_latency_baseline: Callable[[str], bool] | None,
    ) -> None:
        self._state = state
        self._paths = paths
        self._has_latency_baseline = has_latency_baseline

    def is_prewarmed(self, path_id: str) -> bool:
        """Whether a path is waiting for a latency baseline."""

        self.sync()
        return path_id in self._state.prewarmed

    def release_prewarmed(self, action_ids: Iterable[str]) -> int:
        """Release duration paths whose actions now have a baseline."""

        before = set(self._state.prewarmed)
        released_actions = {normalize_action(action_id) for action_id in action_ids}
        self._state.release_latency(released_actions, self._paths(), latency_actions)
        self.sync()
        released = before - self._state.prewarmed
        if released:
            logger.info(
                "scheduler_prewarm_released paths=%d actions=%s",
                len(released),
                ",".join(sorted(self._state.released_latency_actions)),
            )
        return len(released)

    def bootstrap_prewarmed(self, action_ids: Iterable[str]) -> int:
        """Mark one prewarmed path per action for a baseline bootstrap call."""

        self.sync()
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
                for path in self._paths()
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
            self._state.bootstrap(path.path_id, action)
            bootstrapped += 1
        if bootstrapped:
            logger.info(
                "scheduler_latency_bootstrap paths=%d actions=%s",
                len(
                    {
                        path.path_id
                        for path in self._paths()
                        if path.path_id in self._state.latency_bootstrap_paths
                    }
                ),
                ",".join(sorted(self._state.latency_bootstrap_actions)),
            )
        return bootstrapped

    def is_latency_bootstrap(self, action_id: str) -> bool:
        """Whether one action is allowed a single-sample initial baseline."""

        return normalize_action(action_id) in self._state.latency_bootstrap_actions

    def sync(self) -> None:
        for path in self._paths():
            if (
                path.path_id in self._state.completed
                or path.path_id in self._state.blocked
                or path.path_id in self._state.superseded
            ):
                self._state.hold(path.path_id, False)
                continue
            if not latency_actions(path):
                self._state.hold(path.path_id, False)
                continue
            if self._missing_latency_actions(path):
                self._state.hold(path.path_id, True)
            else:
                self._state.hold(path.path_id, False)

    def _missing_latency_actions(self, path: QdlExecutionPath) -> tuple[str, ...]:
        actions = latency_actions(path)
        if self._has_latency_baseline is not None:
            return tuple(
                action for action in actions if not self._has_latency_baseline(action)
            )
        normalized = {normalize_action(action) for action in actions}
        return tuple(sorted(normalized - self._state.released_latency_actions))

    def _has_unprewarmed_work(self, action: str) -> bool:
        """Whether another executable path can still produce action evidence."""

        return any(
            path.path_id not in self._state.prewarmed
            and path.path_id not in self._state.completed
            and path.path_id not in self._state.blocked
            and path.path_id not in self._state.superseded
            and action in path_actions(path)
            for path in self._paths()
        )


__all__ = ["LatencyPrewarm"]
