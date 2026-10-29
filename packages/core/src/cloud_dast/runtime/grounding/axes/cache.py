"""Cache lifecycle for validated axis-grounding results."""

from __future__ import annotations

import logging
from collections.abc import Callable

from cloud_dast.ports import CampaignMetricsRecorder, GroundingCache
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.axes.filtering import _filter_grounding_graph
from cloud_dast.runtime.grounding.results import AxisResult

logger = logging.getLogger("cloud_dast.runtime.grounding.cache")


class AxisResultCache:
    """Own cache identity, storage, filtering, and cache telemetry."""

    def __init__(
        self,
        cache: GroundingCache | None,
        *,
        namespace: str,
        metrics: CampaignMetricsRecorder | None,
        key_for: Callable[[str, str, str], str],
    ) -> None:
        self._cache = cache
        self._namespace = namespace
        self._metrics = metrics
        self._key_for = key_for

    def load(
        self,
        axis: str,
        action_ids: tuple[str, ...],
        *,
        slice_hash: str,
        has_evidence: bool,
    ) -> AxisResult | None:
        """Return a filtered cached result or ``None`` on a miss."""

        if self._cache is None:
            return None
        key = self._key_for(axis, self._namespace, slice_hash)
        cached_graph = self._cache.load(key)
        if cached_graph is None or not cached_graph.facts:
            if self._metrics is not None:
                self._metrics.record_grounding_cache_miss(axis)
            return None

        if self._metrics is not None:
            self._metrics.record_grounding_cache_hit(axis)
        logger.info(
            "grounding_cache_hit axis=%s actions=%d key=%s",
            axis,
            len(action_ids),
            key,
        )
        cached_graph, dropped = _filter_grounding_graph(
            axis,
            cached_graph,
            has_evidence=has_evidence,
        )
        return AxisResult(
            axis=axis,
            graph=cached_graph,
            issue_count=len(dropped),
            action_count=len(action_ids),
            cache_hit=True,
            issues=dropped,
        )

    def save(
        self,
        axis: str,
        *,
        slice_hash: str,
        graph: QdlGraph | None,
    ) -> None:
        """Persist only non-empty validated proposals."""

        if self._cache is None or graph is None:
            return
        key = self._key_for(axis, self._namespace, slice_hash)
        self._cache.save(key, graph)


__all__ = ["AxisResultCache"]
