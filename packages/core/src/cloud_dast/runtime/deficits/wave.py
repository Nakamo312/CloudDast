"""Wave and single-item dispatch orchestration for the deficit queue."""

from __future__ import annotations

import logging
from collections.abc import Callable

from cloud_dast.runtime.deficits.dispatch import (
    interest_score,
    priority,
    select_next_group,
    select_wave_groups,
)
from cloud_dast.runtime.deficits.work_items import WorkItem, WorkItemGraph

logger = logging.getLogger("cloud_dast.runtime.deficits")

WorkItemReady = Callable[[WorkItem], bool]


def pop_wave(
    queue,
    *,
    graph_snapshot: str = "",
    ready: WorkItemReady | None = None,
) -> tuple[WorkItem, ...]:
    """Dispatch one independent work-item wave when budget allows."""

    queue._deterministic_dispatched = 0
    groups = queue._eligible_groups()
    if not groups:
        return ()
    planned = {
        group.work_item_id: queue._work_item(group, graph_snapshot) for group in groups
    }
    if ready is not None:
        planned = {
            work_item_id: item for work_item_id, item in planned.items() if ready(item)
        }
        if not planned:
            return ()
    graph = WorkItemGraph.build(
        planned.values(),
        dispatch_order=tuple(
            group.work_item_id
            for group in sorted(
                groups, key=lambda item: priority(item, queue._interest)
            )
        ),
    )
    first_wave = graph.first_wave()
    if not first_wave:
        return ()
    wave_ids = {item.work_item_id for item in first_wave}
    candidates = sorted(
        (group for group in groups if group.work_item_id in wave_ids),
        key=lambda item: priority(item, queue._interest),
    )
    ready_groups = [group for group in groups if group.work_item_id in planned]
    selected = select_wave_groups(
        candidates,
        pending_groups=ready_groups,
        state=queue._dispatch_state(),
        max_tasks=queue._max_tasks,
        deterministic_dispatch_limit=queue._deterministic_dispatch_limit,
        prioritizer=queue._interest,
    )
    if not selected:
        queue._deterministic_dispatched = 0
        logger.info(
            "work_item_wave_budget_blocked pending=%d dispatched=%d max_tasks=%s "
            "classes=%d",
            len(groups),
            queue._dispatched,
            "all" if queue._max_tasks is None else queue._max_tasks,
            len({group.predicate_class for group in groups}),
        )
        return ()

    wave: list[WorkItem] = []
    for group in selected:
        queue._dispatch_group(group)
        item = planned[group.work_item_id]
        wave.append(item)
        cold_score = interest_score(group, queue._interest)
        logger.info(
            "work_item_dispatched work_item_id=%s class=%s action=%s axis=%s "
            "deficits=%d fan_out=%d snapshot=%s dispatched=%d max_tasks=%s",
            item.work_item_id,
            item.predicate_class,
            item.action,
            item.axis or "-",
            len(item.deficit_ids),
            item.fan_out,
            graph_snapshot or "-",
            queue._dispatched,
            "all" if queue._max_tasks is None else queue._max_tasks,
        )
        _log_cold_score("work_item", item.work_item_id, cold_score, queue)
    if graph.supersedes:
        logger.info(
            "work_item_supersedes pairs=%s",
            ",".join(f"{new}>{old}" for new, old in graph.supersedes),
        )
    return tuple(wave)


def pop_next(queue) -> object | None:
    """Dispatch the highest-priority actionable work item."""

    groups = queue._eligible_groups()
    if not groups:
        queue._deterministic_dispatched = 0
        return None
    best = select_next_group(
        groups,
        state=queue._dispatch_state(),
        max_tasks=queue._max_tasks,
        deterministic_dispatch_limit=queue._deterministic_dispatch_limit,
        prioritizer=queue._interest,
    )
    if best is None:
        queue._deterministic_dispatched = 0
        logger.info(
            "deficit_budget_blocked pending=%d dispatched=%d max_tasks=%s classes=%d",
            len(groups),
            queue._dispatched,
            "all" if queue._max_tasks is None else queue._max_tasks,
            len({group.predicate_class for group in groups}),
        )
        return None
    queue._dispatch_group(best)
    representative = best.representative.deficit
    cold_score = interest_score(best, queue._interest)
    logger.info(
        "deficit_popped deficit_id=%s class=%s action=%s axis=%s dispatched=%d "
        "max_tasks=%s",
        representative.consultation_id,
        representative.predicate_class,
        representative.action,
        representative.axis or "-",
        queue._dispatched,
        "all" if queue._max_tasks is None else queue._max_tasks,
    )
    _log_cold_score("deficit", cold_score.work_item_id, cold_score, queue)
    return representative


def _log_cold_score(kind: str, identifier: str, score, queue) -> None:
    logger.info(
        "%s_cold_score work_item_id=%s coverage_gain=%d bandit_prior=%.3f "
        "reward_state=%.3f interest=%.3f seed=%d quarantined=%s",
        kind,
        identifier,
        score.coverage_gain,
        score.bandit_prior,
        score.reward_state,
        score.interest,
        score.seed,
        _feature_names(score.quarantined_features),
    )


def _feature_names(features: frozenset[str]) -> str:
    return ",".join(sorted(features)) if features else "-"


__all__ = ["pop_next", "pop_wave"]
