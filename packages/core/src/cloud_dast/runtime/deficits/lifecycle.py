"""State transitions for completed, failed, and deferred deficit work."""

from __future__ import annotations

import logging

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits.closure import grounding_result_closes_deficit
from cloud_dast.runtime.deficits.model import Deficit, DeficitKey
from cloud_dast.runtime.deficits.queue_state import QueueEntry
from cloud_dast.runtime.deficits.work_items import WorkItem, WorkItemResult

logger = logging.getLogger("cloud_dast.runtime.deficits")


def record_item_result(
    queue,
    work_item: WorkItem,
    result: QdlGraph | None,
    *,
    observation: Observation | None = None,
    trusted: bool = True,
) -> WorkItemResult:
    """Record one grounding result for every deficit in a work item."""

    entries = queue._entries_for_key(work_item.dispatch_key)
    for entry in entries:
        entry.in_flight = False
    if not trusted:
        _quarantine(entries)
        logger.warning(
            "work_item_result_quarantined work_item_id=%s", work_item.work_item_id
        )
        return WorkItemResult(work_item.work_item_id, ())

    closed_ids: list[str] = []
    failed = False
    for entry in sorted(entries, key=lambda item: item.deficit.work_item_key):
        if entry.deficit.key in queue._closed or entry.deficit.key in queue._stale:
            continue
        if grounding_result_closes_deficit(
            entry.deficit,
            result,
            observation=observation,
        ):
            entry.successes += 1
            entry.quarantined_features = frozenset()
            queue._closed.add(entry.deficit.key)
            closed_ids.append(entry.deficit.consultation_id)
        else:
            entry.quarantined_features = frozenset()
            queue._record_entry_failure(entry)
            failed = True
    if failed:
        queue._charge_work_item_attempt(work_item.dispatch_key)
    outcome = WorkItemResult(work_item.work_item_id, tuple(closed_ids))
    logger.info(
        "work_item_result work_item_id=%s closed=%d remaining=%d",
        work_item.work_item_id,
        len(closed_ids),
        sum(
            1
            for entry in entries
            if entry.deficit.key not in queue._closed
            and entry.deficit.key not in queue._stale
        ),
    )
    return outcome


def mark_item_success(queue, work_item: WorkItem, *, trusted: bool = True) -> bool:
    """Close every deficit covered by one verified work item."""

    entries = queue._entries_for_key(work_item.dispatch_key)
    for entry in entries:
        entry.in_flight = False
    if not trusted:
        _quarantine(entries)
        logger.warning(
            "work_item_result_quarantined work_item_id=%s", work_item.work_item_id
        )
        return False
    for entry in entries:
        if entry.deficit.key in queue._closed or entry.deficit.key in queue._stale:
            continue
        entry.successes += 1
        entry.quarantined_features = frozenset()
        queue._closed.add(entry.deficit.key)
    return True


def mark_item_failure(queue, work_item: WorkItem, *, trusted: bool = True) -> None:
    """Record one failed grounding call for the whole work item."""

    entries = queue._entries_for_key(work_item.dispatch_key)
    for entry in entries:
        entry.in_flight = False
    if not trusted:
        _quarantine(entries)
        logger.warning(
            "work_item_failure_quarantined work_item_id=%s", work_item.work_item_id
        )
        return
    failed = False
    for entry in entries:
        if entry.deficit.key in queue._closed or entry.deficit.key in queue._stale:
            continue
        entry.quarantined_features = frozenset()
        queue._record_entry_failure(entry)
        failed = True
    if failed:
        queue._charge_work_item_attempt(work_item.dispatch_key)
    logger.info(
        "work_item_failure work_item_id=%s remaining=%d",
        work_item.work_item_id,
        sum(
            1
            for entry in entries
            if entry.deficit.key not in queue._closed
            and entry.deficit.key not in queue._stale
        ),
    )


def defer_item(queue, work_item: WorkItem) -> None:
    """Wait for new evidence without closing the unsatisfied subgoal."""

    for entry in queue._entries_for_key(work_item.dispatch_key):
        entry.in_flight = False
    queue._work_item_state(work_item.dispatch_key).deferred = True


def absorb_item(queue, work_item: WorkItem) -> None:
    """Close the current evidence revision of an absorbing outcome."""

    entries = queue._entries_for_key(work_item.dispatch_key)
    for entry in entries:
        entry.in_flight = False
    state = queue._work_item_state(work_item.dispatch_key)
    saturated_keys = [
        entry.deficit.key
        for entry in entries
        if entry.deficit.key not in queue._closed
        and entry.deficit.key not in queue._stale
    ]
    state.saturated = True
    state.saturation_closed_keys = frozenset(saturated_keys)
    queue._closed.update(saturated_keys)
    logger.info(
        "work_item_absorbed work_item_id=%s deficits=%d",
        work_item.work_item_id,
        len(saturated_keys),
    )


def record_success(
    queue,
    deficit: Deficit,
    *,
    gap_closed: bool,
    trusted: bool = True,
) -> bool:
    """Close a deficit only when its semantic gap is verified."""

    key = deficit.key
    entry = queue._entries.get(key)
    if entry is None:
        queue._entries[key] = QueueEntry(deficit, queue._next_order)
        queue._next_order += 1
        entry = queue._entries[key]
    for sibling in queue._entries_for_key(deficit.work_item_key):
        sibling.in_flight = False
    if not trusted:
        entry.quarantined_signals += 1
        entry.quarantined_features = frozenset({"reward_state"})
        logger.warning(
            "deficit_result_quarantined deficit_id=%s gap_closed=%s",
            deficit.consultation_id,
            gap_closed,
        )
        return False
    entry.quarantined_features = frozenset()
    if not gap_closed:
        return False
    entry.successes += 1
    queue._closed.add(key)
    return True


def close_key(queue, key: DeficitKey) -> None:
    """Close one canonical deficit without dispatching an LLM task."""

    if key in queue._stale:
        return
    entry = queue._entries.get(key)
    if entry is not None:
        entry.in_flight = False
    queue._closed.add(key)


def record_failure(queue, deficit: Deficit, *, trusted: bool = True) -> None:
    """Retry a failed deficit or close it after the attempt budget."""

    entry = queue._entries.get(deficit.key)
    if entry is None:
        return
    charged = entry.in_flight
    for sibling in queue._entries_for_key(deficit.work_item_key):
        sibling.in_flight = False
    if not trusted:
        entry.quarantined_signals += 1
        entry.quarantined_features = frozenset({"reward_state"})
        logger.warning(
            "deficit_failure_quarantined deficit_id=%s", deficit.consultation_id
        )
        return
    entry.quarantined_features = frozenset()
    queue._record_entry_failure(entry)
    if charged:
        queue._charge_work_item_attempt(deficit.work_item_key)


def _quarantine(entries) -> None:
    for entry in entries:
        entry.quarantined_signals += 1
        entry.quarantined_features = frozenset({"reward_state"})


__all__ = [
    "absorb_item",
    "close_key",
    "defer_item",
    "mark_item_failure",
    "mark_item_success",
    "record_failure",
    "record_item_result",
    "record_success",
]
