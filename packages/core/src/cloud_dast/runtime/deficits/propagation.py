"""Semantic propagation of promoted work-item results through the queue."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits.closure import (
    deficit_is_stale,
    grounding_result_closes_deficit,
)
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
    WorkItemPropagation,
    WorkItemWavePropagation,
    _work_item_id,
)

logger = logging.getLogger("cloud_dast.runtime.deficits")


def propagate_item(
    queue,
    work_item: WorkItem,
    result: QdlGraph | None,
    *,
    observation: Observation | None = None,
    active_path_ids: frozenset[str] | None = None,
) -> WorkItemPropagation:
    """Re-derive pending deficits after one promoted work item."""

    if result is None or not result.facts:
        return WorkItemPropagation(work_item.work_item_id, (), (), 0)
    closed_ids: list[str] = []
    stale_ids: list[str] = []
    unchanged = 0
    for entry in sorted(
        queue._entries.values(), key=lambda item: item.deficit.work_item_key
    ):
        key = entry.deficit.key
        if key in queue._closed or key in queue._stale or entry.in_flight:
            continue
        if grounding_result_closes_deficit(
            entry.deficit,
            result,
            observation=observation,
        ):
            queue._closed.add(key)
            closed_ids.append(entry.deficit.consultation_id)
        elif deficit_is_stale(
            entry.deficit,
            result,
            active_path_ids=active_path_ids,
        ):
            queue._stale.add(key)
            stale_ids.append(entry.deficit.consultation_id)
        else:
            unchanged += 1
    propagation = WorkItemPropagation(
        work_item.work_item_id,
        tuple(closed_ids),
        tuple(stale_ids),
        unchanged,
    )
    logger.info(
        "work_item_closure_propagated work_item_id=%s closed=%d stale=%d unchanged=%d",
        propagation.work_item_id,
        len(propagation.closed_deficit_ids),
        len(propagation.stale_deficit_ids),
        propagation.unchanged_count,
    )
    return propagation


def propagate_wave(
    queue,
    outcomes: Mapping[str, WorkItemGrounding],
    *,
    base_graph: QdlGraph | None = None,
    active_path_ids: frozenset[str] | None = None,
) -> WorkItemWavePropagation:
    """Re-derive pending deficits against one merged wave graph."""

    promoted = [
        outcome.result
        for outcome in outcomes.values()
        if outcome.promoted and outcome.result is not None
    ]
    if not promoted:
        return WorkItemWavePropagation(tuple(sorted(outcomes)), (), (), 0)

    from cloud_dast.qdl.graph_ops import merge_graphs

    merged = merge_graphs(base_graph or QdlGraph(), *promoted)
    observations = {
        work_item_id: outcome.observation for work_item_id, outcome in outcomes.items()
    }
    closed_ids: list[str] = []
    stale_ids: list[str] = []
    unchanged = 0
    for entry in sorted(
        queue._entries.values(), key=lambda item: item.deficit.work_item_key
    ):
        key = entry.deficit.key
        if key in queue._closed or key in queue._stale or entry.in_flight:
            continue
        observation = observations.get(_work_item_id(entry.deficit.work_item_key))
        if grounding_result_closes_deficit(
            entry.deficit,
            merged,
            observation=observation,
        ):
            queue._closed.add(key)
            closed_ids.append(entry.deficit.consultation_id)
        elif deficit_is_stale(
            entry.deficit,
            merged,
            active_path_ids=active_path_ids,
        ):
            queue._stale.add(key)
            stale_ids.append(entry.deficit.consultation_id)
        else:
            unchanged += 1

    propagation = WorkItemWavePropagation(
        tuple(sorted(outcomes)),
        tuple(closed_ids),
        tuple(stale_ids),
        unchanged,
    )
    logger.info(
        "work_item_wave_closure_propagated work_items=%d closed=%d stale=%d "
        "unchanged=%d",
        len(propagation.work_item_ids),
        len(propagation.closed_deficit_ids),
        len(propagation.stale_deficit_ids),
        propagation.unchanged_count,
    )
    return propagation


__all__ = ["propagate_item", "propagate_wave"]
