"""Semantic propagation of promoted work-item results through the queue."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits.closure import (
    deficit_is_stale,
    grounding_result_closes_deficit,
)
from cloud_dast.runtime.deficits.model import Deficit, DeficitKey
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
    WorkItemPropagation,
    WorkItemWavePropagation,
    _work_item_id,
)

logger = logging.getLogger("cloud_dast.runtime.deficits")


def propagate_item(
    pending: Iterable[Deficit],
    work_item: WorkItem,
    result: QdlGraph | None,
    *,
    close: Callable[[DeficitKey], None],
    stale: Callable[[DeficitKey], None],
    observation: Observation | None = None,
    active_path_ids: frozenset[str] | None = None,
) -> WorkItemPropagation:
    """Re-derive pending deficits after one promoted work item."""

    if result is None or not result.facts:
        return WorkItemPropagation(work_item.work_item_id, (), (), 0)
    propagation = WorkItemPropagation(
        work_item.work_item_id,
        *_propagate(
            pending, result, lambda deficit: observation, close, stale, active_path_ids
        ),
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
    pending: Iterable[Deficit],
    outcomes: Mapping[str, WorkItemGrounding],
    *,
    close: Callable[[DeficitKey], None],
    stale: Callable[[DeficitKey], None],
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
    propagation = WorkItemWavePropagation(
        tuple(sorted(outcomes)),
        *_propagate(
            pending,
            merged,
            lambda deficit: observations.get(_work_item_id(deficit.work_item_key)),
            close,
            stale,
            active_path_ids,
        ),
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


def _propagate(
    pending: Iterable[Deficit],
    graph: QdlGraph,
    observation_for: Callable[[Deficit], Observation | None],
    close: Callable[[DeficitKey], None],
    stale: Callable[[DeficitKey], None],
    active_path_ids: frozenset[str] | None,
) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    closed_ids: list[str] = []
    stale_ids: list[str] = []
    unchanged = 0
    for deficit in pending:
        key = deficit.key
        if grounding_result_closes_deficit(
            deficit, graph, observation=observation_for(deficit)
        ):
            close(key)
            closed_ids.append(deficit.consultation_id)
        elif deficit_is_stale(deficit, graph, active_path_ids=active_path_ids):
            stale(key)
            stale_ids.append(deficit.consultation_id)
        else:
            unchanged += 1
    return tuple(closed_ids), tuple(stale_ids), unchanged


__all__ = ["propagate_item", "propagate_wave"]
