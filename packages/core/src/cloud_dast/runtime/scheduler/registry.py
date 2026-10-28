"""Path registry and terminal lifecycle for coverage scheduling."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.scheduler.coverage import keys_for, path_family_id
from cloud_dast.runtime.scheduler.model import State

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class PathRegistry:
    """Own discovered paths and their durable terminal transitions."""

    def add_paths(self, paths: tuple[QdlExecutionPath, ...]) -> int:
        """Add paths discovered mid-campaign; return the new count.

        Known identities refresh their path snapshot without renewing attempts.
        Re-planning an unchanged view adds no work; content-versioned identities
        (for example, new probe fields) are treated as new work.
        """

        known = {path.path_id for path in self._paths}
        replacements = {path.path_id: path for path in paths}
        self._paths = [replacements.get(path.path_id, path) for path in self._paths]
        added = 0
        for path in paths:
            if path.path_id in known:
                continue
            known.add(path.path_id)
            self._paths.append(path)
            self._path_keys[path.path_id] = keys_for(path)
            added += 1
        if added:
            logger.info(
                "scheduler_paths_added added=%d total=%d", added, len(self._paths)
            )
            self._sync_prewarmed()
        return added

    def reopen_path(self, path_id: str) -> bool:
        """Invalidate a terminal decision without renewing execution budgets."""

        if (
            path_id in self._state.superseded
            or path_id in self._state.in_flight
            or self._canonical_exhausted(path_id)
        ):
            return False
        self._state.completed.discard(path_id)
        self._state.blocked.discard(path_id)
        self._state.outcomes.pop(path_id, None)
        self._state.terminal_reasons.pop(path_id, None)
        return True

    def supersede_paths(self, replacements: Mapping[str, str]) -> int:
        """Retire executable path versions while retaining their history."""

        known = {path.path_id for path in self._paths}
        superseded = 0
        for old_path_id, replacement_id in sorted(replacements.items()):
            if old_path_id == replacement_id or old_path_id not in known:
                continue
            if old_path_id in self._state.in_flight:
                raise RuntimeError(f"cannot supersede in-flight path {old_path_id!r}")
            self._state.superseded.add(old_path_id)
            self._state.in_flight.discard(old_path_id)
            self._state.prewarmed.discard(old_path_id)
            self._state.latency_bootstrap_paths.discard(old_path_id)
            self._state.terminal_reasons[old_path_id] = (
                f"superseded by QDL path {replacement_id}"
            )
            superseded += 1
        if superseded:
            logger.info("scheduler_paths_superseded count=%d", superseded)
        return superseded

    def supersede_replaced_paths(
        self,
        replacement_paths: tuple[QdlExecutionPath, ...],
    ) -> int:
        """Retire old content versions replaced by ``replacement_paths``."""

        replacements_by_family = {
            path_family_id(path.path_id): path.path_id for path in replacement_paths
        }
        replacements = {
            path.path_id: replacements_by_family[path_family_id(path.path_id)]
            for path in self._paths
            if path_family_id(path.path_id) in replacements_by_family
        }
        return self.supersede_paths(replacements)

    @property
    def state(self) -> State:
        return self._state

    @property
    def paths(self) -> tuple[QdlExecutionPath, ...]:
        """All paths known to this scheduler, in discovery order."""

        return tuple(self._paths)

    def block_remaining(self) -> tuple[str, ...]:
        """Mark every eligible path blocked without selecting it."""

        path_ids = tuple(path.path_id for path in self._paths if self._eligible(path))
        for path_id in path_ids:
            self._state.outcomes[path_id] = "blocked"
            self._state.blocked.add(path_id)
            self._state.terminal_reasons[path_id] = (
                "campaign check budget exhausted before path execution"
            )
        return path_ids

    def block_prerequisite(self, path_id: str, reason: str) -> None:
        """Park an unexecutable path without charging probe retries."""

        self._state.in_flight.discard(path_id)
        self._state.prewarmed.discard(path_id)
        self._state.blocked.add(path_id)
        self._state.outcomes[path_id] = "blocked"
        self._state.terminal_reasons[path_id] = reason

    def terminal_reason(self, path_id: str) -> str | None:
        """Return the durable reason for a scheduler-side terminal outcome."""

        return self._state.terminal_reasons.get(path_id)


__all__ = ["PathRegistry"]
