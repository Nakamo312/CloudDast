"""Discovered executable path snapshots and their canonical coverage identities."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.runtime.scheduler.coverage import CoverageKey, keys_for, path_family_id

logger = logging.getLogger("cloud_dast.runtime.scheduler")


class PathRegistry:
    """Own path versions independently of scheduling transitions."""

    def __init__(self, paths: tuple[QdlExecutionPath, ...]) -> None:
        self._paths = list(paths)
        self._path_keys = {path.path_id: keys_for(path) for path in paths}
        self.coverage: Mapping[str, tuple[CoverageKey, ...]] = MappingProxyType(
            self._path_keys
        )

    def add(self, paths: tuple[QdlExecutionPath, ...]) -> int:
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
        return added

    def replacements(
        self, replacement_paths: tuple[QdlExecutionPath, ...]
    ) -> dict[str, str]:
        by_family = {
            path_family_id(path.path_id): path.path_id for path in replacement_paths
        }
        return {
            path.path_id: by_family[path_family_id(path.path_id)]
            for path in self._paths
            if path_family_id(path.path_id) in by_family
        }

    def snapshot(self) -> tuple[QdlExecutionPath, ...]:
        return tuple(self._paths)
