"""Startup grounding: staged axis batches and model response decoding."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from contextlib import closing
from dataclasses import replace
from typing import Any

from cloud_dast.contracts.axes import NORMS_AXIS, SEMANTIC_AXES, Axis
from cloud_dast.contracts.proposals import FormalModelOutputValidator
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.axes.cache import AxisResultCache
from cloud_dast.runtime.grounding.axes.filtering import _actions
from cloud_dast.runtime.grounding.axes.projection import (
    batch_key,
    build_axis_result,
    intersect_axis_batch_proposals,
    log_grounding_uncertainties,
    uncertainty_items,
)
from cloud_dast.runtime.grounding.axes.projection import proposals as axis_proposals
from cloud_dast.runtime.grounding.axes.scheduler import AxisTaskScheduler
from cloud_dast.runtime.grounding.axes.slicing import build_axis_slice
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import BoundedSlice

logger = logging.getLogger("cloud_dast.runtime.grounding.parallel")


class Bootstrap:
    """Own startup batch scheduling, staged enrichment, and response decoding."""

    def __init__(
        self,
        *,
        options: GrounderOptions | None = None,
        **values: object,
    ) -> None:
        settings = GrounderOptions.from_legacy(options, values)
        if settings.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if settings.max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if settings.axis_timeout is not None and settings.axis_timeout <= 0:
            raise ValueError("axis_timeout must be positive when set")
        if settings.grounding_dispatcher is None:
            raise ValueError("grounding_dispatcher must be injected")
        self._validator = settings.validator or FormalModelOutputValidator()
        self._batch_size = settings.batch_size
        self._slice_budget = settings.slice_budget
        self._grounding_dispatcher = settings.grounding_dispatcher
        self._axis_cache = AxisResultCache(
            settings.cache,
            namespace=settings.cache_namespace,
            metrics=settings.metrics,
            key_for=settings.grounding_dispatcher.cache_key,
        )
        self._axis_scheduler = AxisTaskScheduler(
            self._ground_axis_batch,
            task_runner=settings.task_runner,
            max_workers=settings.max_workers,
            axis_timeout=settings.axis_timeout,
        )

    def ground(
        self,
        graph: QdlGraph,
        *,
        cache_source: QdlGraph | None = None,
        evidence: EvidenceView | None = None,
    ) -> QdlGraph:
        """Run all axis batches and merge comparable intersections."""

        proposals = self.ground_batches(
            graph,
            cache_source=cache_source,
            evidence=evidence,
        )
        return merge_graphs(*intersect_axis_batch_proposals(proposals))

    def ground_batches(
        self,
        graph: QdlGraph,
        *,
        cache_source: QdlGraph | None = None,
        evidence: EvidenceView | None = None,
    ) -> tuple[tuple[Axis, str, QdlGraph], ...]:
        """Collect the staged results and report aggregate batch telemetry."""

        results = [
            replace(result, batch_key=batch_key(axis, batch))
            for axis, batch, result in self._staged_results(
                graph, cache_source=cache_source, evidence=evidence, streaming=False
            )
        ]
        if not results:
            return ()
        valid = [result for result in results if result.graph is not None]
        logger.info(
            "axis_grounding_completed tasks=%d valid=%d invalid=%d facts=%d "
            "cache_hits=%d",
            len(results),
            len(valid),
            len(results) - len(valid),
            sum(len(result.graph.facts) for result in valid),
            sum(result.cache_hit for result in results),
        )
        return tuple(axis_proposals(results))

    def ground_stream(
        self,
        graph: QdlGraph,
        *,
        cache_source: QdlGraph | None = None,
        evidence: EvidenceView | None = None,
    ) -> Iterator[tuple[Axis, str, QdlGraph]]:
        """Yield each valid proposal in completion order across both stages."""

        with closing(
            self._staged_results(
                graph, cache_source=cache_source, evidence=evidence, streaming=True
            )
        ) as results:
            for axis, batch, result in results:
                if result.graph is not None:
                    yield axis, batch_key(axis, batch), result.graph

    def _staged_results(
        self,
        graph: QdlGraph,
        *,
        cache_source: QdlGraph | None,
        evidence: EvidenceView | None,
        streaming: bool,
    ) -> Iterator[tuple[Axis, tuple[str, ...], AxisResult]]:
        """Own batching and the semantic barrier before scheduling norms."""

        actions = _actions(graph)
        batches = [
            actions[index : index + self._batch_size]
            for index in range(0, len(actions), self._batch_size)
        ]
        if not batches:
            return
        semantic_tasks = [(axis, batch) for axis in SEMANTIC_AXES for batch in batches]
        if streaming:
            logger.info(
                "axis_grounding_staged_stream_started semantic_axes=%d batches=%d",
                len(SEMANTIC_AXES),
                len(batches),
            )
        else:
            logger.info(
                "axis_grounding_staged_started semantic_axes=%d batches=%d tasks=%d "
                "batch_size=%d workers=%d",
                len(SEMANTIC_AXES),
                len(batches),
                len(semantic_tasks),
                self._batch_size,
                self._axis_scheduler.max_workers,
            )
        semantic_graphs: list[QdlGraph] = []
        completed = 0
        for axis, batch, result in self._axis_scheduler.stream(
            semantic_tasks,
            graph,
            cache_source or graph,
            evidence=None,
        ):
            if result.graph is not None:
                semantic_graphs.append(result.graph)
                completed += 1
            yield axis, batch, result

        enriched_graph = merge_graphs(graph, *semantic_graphs)
        enriched_cache = merge_graphs(cache_source or graph, *semantic_graphs)
        norms_tasks = [(NORMS_AXIS, batch) for batch in batches]
        for axis, batch, result in self._axis_scheduler.stream(
            norms_tasks,
            enriched_graph,
            enriched_cache,
            evidence=evidence,
        ):
            if result.graph is not None:
                completed += 1
            yield axis, batch, result
        if streaming:
            logger.info(
                "axis_grounding_staged_stream_completed valid=%d semantic_tasks=%d "
                "norms_tasks=%d",
                completed,
                len(semantic_tasks),
                len(norms_tasks),
            )

    def _ground_axis_batch(
        self,
        axis: Axis,
        action_ids: tuple[str, ...],
        graph: QdlGraph,
        cache_source: QdlGraph,
        evidence: EvidenceView | None = None,
    ) -> AxisResult:
        """Ground one startup axis batch, using its cache slice."""

        from cloud_dast.runtime.grounding.axes.filtering import _action_atoms

        if not _action_atoms(graph, action_ids):
            return AxisResult(axis, None, 0, 0)
        slice_ = build_axis_slice(
            axis,
            graph,
            action_ids,
            evidence=evidence,
            budget=self._slice_budget,
        )
        cache_slice = build_axis_slice(
            axis,
            cache_source,
            action_ids,
            evidence=evidence,
            budget=self._slice_budget,
        )
        cached = self._axis_cache.load(
            axis,
            action_ids,
            slice_hash=cache_slice.slice_hash,
            has_evidence=evidence is not None,
        )
        if cached is not None:
            return cached
        result = self._ground_slice(
            axis,
            action_ids,
            slice_,
            background=cache_slice.graph,
            evidence=evidence,
        )
        self._axis_cache.save(
            axis,
            slice_hash=cache_slice.slice_hash,
            graph=result.graph,
        )
        return result

    def _ground_slice(
        self,
        axis: Axis,
        action_ids: tuple[str, ...],
        slice_: BoundedSlice,
        *,
        background: QdlGraph,
        context_extra: Mapping[str, Any] | None = None,
        evidence: EvidenceView | None = None,
    ) -> AxisResult:
        """Dispatch and validate one already-built startup slice."""

        context: dict[str, Any] = slice_.context()
        if context_extra is not None:
            context.update(context_extra)
        response = self._grounding_dispatcher.dispatch(axis, context)
        payload = (
            response.structured if isinstance(response.structured, Mapping) else {}
        )
        uncertainties = uncertainty_items(payload)
        log_grounding_uncertainties(axis, action_ids, uncertainties)
        result = self._validator.salvage(payload, background=background)
        return build_axis_result(
            axis,
            action_ids,
            slice_,
            evidence=evidence,
            proposal=result.graph,
            issue_count=len(result.issues),
            uncertainties=tuple(uncertainties),
            validation_issues=result.issues,
            raw_response=getattr(response, "content", ""),
        )


__all__ = ["Bootstrap"]
