"""Canonical mutable entries and evidence-revision transitions for deficit work."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits.closure import grounding_result_closes_deficit
from cloud_dast.runtime.deficits.model import Deficit, DeficitKey
from cloud_dast.runtime.deficits.queue_state import QueueEntry, WorkGroup, WorkItemState
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemResult,
    _consultation_kind,
    _effect_neighborhood,
    _evidence_signature,
    _missing_fact_signature,
    _work_item_id,
)

logger = logging.getLogger("cloud_dast.runtime.deficits")


class QueueState:
    """Own entry lifecycle; selection and campaign budgets remain outside."""

    def __init__(self, max_attempts: int) -> None:
        self._max_attempts = max_attempts
        self._entries: dict[DeficitKey, QueueEntry] = {}
        self._closed: set[DeficitKey] = set()
        self._stale: set[DeficitKey] = set()
        self._work_items: dict[DeficitKey, WorkItemState] = {}
        self._next_order = 0

    def add(self, deficits: Iterable[Deficit]) -> int:
        """Add deficits and return how many canonical keys are new."""

        added = 0
        for deficit in deficits:
            key = deficit.key
            state = self._work_item_state(deficit.work_item_key)
            evidence = _evidence_signature(deficit)
            new_evidence = evidence - state.evidence_signature
            if new_evidence:
                # A genuinely new evidence signature reopens a saturated
                # work item (fresh observation = new information).  This
                # is the S33 contract: saturation is per-evidence, not
                # per-identity.
                state.evidence_signature = state.evidence_signature | new_evidence
                self._reset_work_item_evidence(state)
                state.deferred = False
            if key in self._closed or key in self._stale:
                continue
            entry = self._entries.get(key)
            if entry is not None:
                if new_evidence:
                    entry.deficit = deficit
                entry.fan_out += 1
                continue
            self._entries[key] = QueueEntry(deficit, self._next_order)
            self._next_order += 1
            added += 1
            logger.info(
                "deficit_enqueued deficit_id=%s class=%s action=%s axis=%s fan_out=%d",
                deficit.consultation_id,
                deficit.predicate_class,
                deficit.action,
                deficit.axis or "-",
                1,
            )
        return added

    def groups(self, axes: frozenset[str]) -> list[WorkGroup]:
        """Group every dispatchable entry by its work-item key."""

        entries = [
            entry
            for entry in self._entries.values()
            if self._active(entry)
            and not entry.in_flight
            and entry.deficit.axis in axes
        ]
        grouped: dict[DeficitKey, list[QueueEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.deficit.work_item_key, []).append(entry)
        dispatchable_groups = [
            group
            for group in grouped
            if not self._work_item_state(group).saturated
            and not self._work_item_state(group).deferred
        ]
        return [
            WorkGroup(
                key=key,
                predicate_class=members[0].deficit.predicate_class,
                action=members[0].deficit.action,
                axis=members[0].deficit.axis,
                entries=tuple(
                    sorted(
                        members,
                        key=lambda item: (item.order, item.deficit.work_item_key),
                    )
                ),
            )
            for key, members in sorted(
                (key, grouped[key]) for key in dispatchable_groups
            )
        ]

    def project(self, group: WorkGroup, graph_snapshot: str) -> WorkItem:
        """Project one work group onto its immutable planning record."""

        deficits = tuple(entry.deficit for entry in group.entries)
        state = self._work_item_state(group.key)
        return WorkItem(
            work_item_id=group.work_item_id,
            predicate_class=group.predicate_class,
            action=group.action,
            axis=group.axis,
            consultation_kind=_consultation_kind(group.axis),
            missing_fact_signature=frozenset().union(
                *(_missing_fact_signature(deficit) for deficit in deficits)
            ),
            effect_neighborhood=frozenset().union(
                *(_effect_neighborhood(deficit) for deficit in deficits)
            ),
            evidence_signature=frozenset().union(
                *(_evidence_signature(deficit) for deficit in deficits)
            ),
            deficit_ids=tuple(
                dict.fromkeys(deficit.consultation_id for deficit in deficits)
            ),
            deficits=deficits,
            graph_snapshot=graph_snapshot,
            fan_out=group.fan_out,
            order=group.order,
            attempts=state.attempts,
            saturated=state.saturated,
            max_attempts=self._max_attempts,
        )

    def _entries_for_key(self, key: DeficitKey) -> list[QueueEntry]:
        """Return every current entry sharing one work-item key."""

        return [
            entry
            for entry in self._entries.values()
            if entry.deficit.work_item_key == key
        ]

    def _work_item_state(self, key: DeficitKey) -> WorkItemState:
        """Return mutable scheduling state for one consultation identity."""

        state = self._work_items.get(key)
        if state is None:
            state = WorkItemState()
            self._work_items[key] = state
        return state

    def _reset_work_item_evidence(self, state: WorkItemState) -> None:
        """Reopen a saturated work item only because its evidence changed."""

        if not state.saturated:
            state.attempts = 0
            return
        for key in state.saturation_closed_keys:
            self._closed.discard(key)
        state.saturation_closed_keys = frozenset()
        state.saturated = False
        state.attempts = 0

    def _charge_work_item_attempt(self, key: DeficitKey) -> None:
        """Charge one failed grounding call to the whole work item."""

        state = self._work_item_state(key)
        if state.saturated:
            return
        state.attempts += 1
        if state.attempts < self._max_attempts:
            return
        count = self._saturate(key)
        logger.info(
            "work_item_saturated work_item_id=%s attempts=%d max_attempts=%d "
            "deficits=%d",
            _work_item_id(key),
            state.attempts,
            self._max_attempts,
            count,
        )

    def _record_entry_failure(self, entry: QueueEntry) -> None:
        """Record one failed call on a covered deficit."""

        entry.attempts += 1
        entry.failures += 1

    def record_item_result(
        self,
        work_item: WorkItem,
        result: QdlGraph | None,
        *,
        observation: Observation | None = None,
        trusted: bool = True,
    ) -> WorkItemResult:
        """Record one grounding result for every deficit in a work item."""

        entries = self._release(work_item.dispatch_key)
        if not trusted:
            self._quarantine(entries)
            logger.warning(
                "work_item_result_quarantined work_item_id=%s", work_item.work_item_id
            )
            return WorkItemResult(work_item.work_item_id, ())

        closed_ids, failed = self._settle(
            sorted(entries, key=lambda item: item.deficit.work_item_key),
            lambda deficit: grounding_result_closes_deficit(
                deficit, result, observation=observation
            ),
        )
        if failed:
            self._charge_work_item_attempt(work_item.dispatch_key)
        outcome = WorkItemResult(work_item.work_item_id, tuple(closed_ids))
        logger.info(
            "work_item_result work_item_id=%s closed=%d remaining=%d",
            work_item.work_item_id,
            len(closed_ids),
            sum(self._active(entry) for entry in entries),
        )
        return outcome

    def mark_item_success(self, work_item: WorkItem, *, trusted: bool = True) -> bool:
        """Close every deficit covered by one verified work item."""

        entries = self._release(work_item.dispatch_key)
        if not trusted:
            self._quarantine(entries)
            logger.warning(
                "work_item_result_quarantined work_item_id=%s", work_item.work_item_id
            )
            return False
        self._settle(entries, lambda deficit: True)
        return True

    def mark_item_failure(self, work_item: WorkItem, *, trusted: bool = True) -> None:
        """Record one failed grounding call for the whole work item."""

        entries = self._release(work_item.dispatch_key)
        if not trusted:
            self._quarantine(entries)
            logger.warning(
                "work_item_failure_quarantined work_item_id=%s", work_item.work_item_id
            )
            return
        _, failed = self._settle(entries, lambda deficit: False)
        if failed:
            self._charge_work_item_attempt(work_item.dispatch_key)
        logger.info(
            "work_item_failure work_item_id=%s remaining=%d",
            work_item.work_item_id,
            sum(self._active(entry) for entry in entries),
        )

    def defer_item(self, work_item: WorkItem) -> None:
        """Wait for new evidence without closing the unsatisfied subgoal."""

        self._release(work_item.dispatch_key)
        self._work_item_state(work_item.dispatch_key).deferred = True

    def absorb_item(self, work_item: WorkItem) -> None:
        """Close the current evidence revision of an absorbing outcome."""

        self._release(work_item.dispatch_key)
        count = self._saturate(work_item.dispatch_key)
        logger.info(
            "work_item_absorbed work_item_id=%s deficits=%d",
            work_item.work_item_id,
            count,
        )

    def record_success(
        self,
        deficit: Deficit,
        *,
        gap_closed: bool,
        trusted: bool = True,
    ) -> bool:
        """Close a deficit only when its semantic gap is verified."""

        key = deficit.key
        entry = self._entries.get(key)
        if entry is None:
            self._entries[key] = QueueEntry(deficit, self._next_order)
            self._next_order += 1
            entry = self._entries[key]
        self._release(deficit.work_item_key)
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
        self._closed.add(key)
        return True

    def close_key(self, key: DeficitKey) -> None:
        """Close one canonical deficit without dispatching an LLM task."""

        if key in self._stale:
            return
        entry = self._entries.get(key)
        if entry is not None:
            entry.in_flight = False
        self._closed.add(key)

    def record_failure(self, deficit: Deficit, *, trusted: bool = True) -> None:
        """Retry a failed deficit or close it after the attempt budget."""

        entry = self._entries.get(deficit.key)
        if entry is None:
            return
        charged = entry.in_flight
        self._release(deficit.work_item_key)
        if not trusted:
            entry.quarantined_signals += 1
            entry.quarantined_features = frozenset({"reward_state"})
            logger.warning(
                "deficit_failure_quarantined deficit_id=%s", deficit.consultation_id
            )
            return
        entry.quarantined_features = frozenset()
        self._record_entry_failure(entry)
        if charged:
            self._charge_work_item_attempt(deficit.work_item_key)

    def _quarantine(self, entries: Iterable[QueueEntry]) -> None:
        for entry in entries:
            entry.quarantined_signals += 1
            entry.quarantined_features = frozenset({"reward_state"})

    @property
    def pending_count(self) -> int:
        """Return deficits waiting for selection (in-flight work excluded)."""

        return sum(
            1
            for entry in self._entries.values()
            if self._active(entry) and not entry.in_flight
        )

    @property
    def closed_count(self) -> int:
        """Return permanently closed deficits."""

        return len(self._closed)

    @property
    def stale_count(self) -> int:
        """Return deficits removed because their path is no longer active."""

        return len(self._stale)

    @property
    def saturated_count(self) -> int:
        """Return saturated work items."""

        return sum(1 for state in self._work_items.values() if state.saturated)

    @property
    def quarantined_signals(self) -> int:
        """Return the number of ignored untrusted feedback signals."""

        return sum(entry.quarantined_signals for entry in self._entries.values())

    def pending(self) -> Iterator[Deficit]:
        """Read eligibility at each yield so earlier propagation commits are visible."""
        for entry in sorted(
            self._entries.values(), key=lambda item: item.deficit.work_item_key
        ):
            if self._active(entry) and not entry.in_flight:
                yield entry.deficit

    def confirm(self, key: DeficitKey) -> None:
        """Commit semantic closure without changing dispatch or stale state."""
        self._closed.add(key)

    def mark_stale(self, key: DeficitKey) -> None:
        self._stale.add(key)

    def dispatch(self, group: WorkGroup) -> None:
        for entry in group.entries:
            entry.in_flight = True

    def _active(self, entry: QueueEntry) -> bool:
        return (
            entry.deficit.key not in self._closed
            and entry.deficit.key not in self._stale
        )

    def _release(self, key: DeficitKey) -> list[QueueEntry]:
        entries = self._entries_for_key(key)
        for entry in entries:
            entry.in_flight = False
        return entries

    def _saturate(self, key: DeficitKey) -> int:
        state = self._work_item_state(key)
        state.saturated = True
        keys = frozenset(
            entry.deficit.key
            for entry in self._entries_for_key(key)
            if self._active(entry)
        )
        state.saturation_closed_keys = keys
        self._closed.update(keys)
        return len(keys)

    def _settle(
        self,
        entries: Iterable[QueueEntry],
        closes: Callable[[Deficit], bool],
    ) -> tuple[tuple[str, ...], bool]:
        closed_ids = []
        failed = False
        for entry in entries:
            if not self._active(entry):
                continue
            closed = closes(entry.deficit)
            entry.quarantined_features = frozenset()
            if closed:
                entry.successes += 1
                self._closed.add(entry.deficit.key)
                closed_ids.append(entry.deficit.consultation_id)
            else:
                self._record_entry_failure(entry)
                failed = True
        return tuple(closed_ids), failed
