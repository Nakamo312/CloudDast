"""Independent-wave selection and dispatch telemetry over explicit inputs."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence

from cloud_dast.runtime.deficits.dispatch import priority, select_wave_groups
from cloud_dast.runtime.deficits.queue_state import DispatchState, WorkGroup
from cloud_dast.runtime.deficits.work_items import WorkItem, WorkItemGraph
from cloud_dast.runtime.prioritization import ColdScore, InterestPrioritizer

logger = logging.getLogger("cloud_dast.runtime.deficits")


def plan(
    groups: Sequence[WorkGroup],
    project: Callable[[WorkGroup, str], WorkItem],
    *,
    graph_snapshot: str,
    ready: Callable[[WorkItem], bool] | None,
    state: Callable[[], DispatchState],
    limit: int | None,
    prioritizer: InterestPrioritizer,
) -> tuple[WorkItemGraph, tuple[WorkGroup, ...], dict[str, WorkItem]] | None:
    """Plan against projections; read counters only after readiness callbacks."""
    planned = {group.work_item_id: project(group, graph_snapshot) for group in groups}
    if ready is not None:
        planned = {key: item for key, item in planned.items() if ready(item)}
        if not planned:
            return None
    graph = WorkItemGraph.build(
        planned.values(),
        dispatch_order=tuple(
            group.work_item_id
            for group in sorted(groups, key=lambda item: priority(item, prioritizer))
        ),
    )
    first_wave = graph.first_wave()
    if not first_wave:
        return None
    wave_ids = {item.work_item_id for item in first_wave}
    candidates = sorted(
        (group for group in groups if group.work_item_id in wave_ids),
        key=lambda item: priority(item, prioritizer),
    )
    selected = select_wave_groups(
        candidates,
        pending_groups=[group for group in groups if group.work_item_id in planned],
        state=state(),
        max_tasks=limit,
        deterministic_dispatch_limit=limit,
        prioritizer=prioritizer,
    )
    return graph, selected, planned


def log_score(kind: str, identifier: str, score: ColdScore) -> None:
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
