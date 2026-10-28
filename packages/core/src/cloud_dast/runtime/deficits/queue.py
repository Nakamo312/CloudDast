"""Queue state and lifecycle for reactive runtime deficits.

The queue owns mutable dispatch lifecycle: deduplication, waves, attempt
budgets, saturation, in-flight state, and closure propagation. Pure fair-share
selection lives in :mod:`cloud_dast.runtime.deficits.dispatch`; deficit
construction and semantic closure live in their own modules.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.consultation.axes import DETERMINISTIC_AXES, LLM_AXES
from cloud_dast.runtime.deficits.dispatch import (
    deterministic_slots,
    select_next_group,
)
from cloud_dast.runtime.deficits.lifecycle import (
    absorb_item as lifecycle_absorb_item,
)
from cloud_dast.runtime.deficits.lifecycle import (
    close_key as lifecycle_close_key,
)
from cloud_dast.runtime.deficits.lifecycle import (
    defer_item as lifecycle_defer_item,
)
from cloud_dast.runtime.deficits.lifecycle import (
    mark_item_failure as lifecycle_mark_item_failure,
)
from cloud_dast.runtime.deficits.lifecycle import (
    mark_item_success as lifecycle_mark_item_success,
)
from cloud_dast.runtime.deficits.lifecycle import (
    record_failure as lifecycle_record_failure,
)
from cloud_dast.runtime.deficits.lifecycle import (
    record_item_result as lifecycle_record_item_result,
)
from cloud_dast.runtime.deficits.lifecycle import (
    record_success as lifecycle_record_success,
)
from cloud_dast.runtime.deficits.model import (
    Deficit,
    DeficitKey,
    PredicateClass,
)
from cloud_dast.runtime.deficits.propagation import propagate_item, propagate_wave
from cloud_dast.runtime.deficits.queue_state import (
    DispatchState,
    QueueEntry,
    WorkGroup,
    WorkItemState,
)
from cloud_dast.runtime.deficits.wave import (
    pop_next as dispatch_next,
)
from cloud_dast.runtime.deficits.wave import (
    pop_wave as dispatch_wave,
)
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
    WorkItemPropagation,
    WorkItemResult,
    WorkItemWavePropagation,
    _consultation_kind,
    _effect_neighborhood,
    _evidence_signature,
    _missing_fact_signature,
    _work_item_id,
)
from cloud_dast.runtime.prioritization import InterestPrioritizer

_DISPATCHABLE_AXES: frozenset[str] = LLM_AXES | DETERMINISTIC_AXES

# Internal aliases preserve the queue implementation's vocabulary while the
# state records themselves have one owner in ``queue_state``.
_QueueEntry = QueueEntry
_WorkItemState = WorkItemState
_WorkGroup = WorkGroup
_DispatchState = DispatchState

logger = logging.getLogger("cloud_dast.runtime.deficits")


class DeficitQueue:
    """Deduplicate, coalesce, prioritize, and budget reactive deficits.

    S26R selection is a generic constrained optimization.  For every ready
    work item, ``information_gain`` is the deterministic cold score and
    ``deficit_class`` is its QDL predicate class.  Selection maximizes
    information gain among allocations that are max-min fair over cumulative
    per-class service.  There are no class quotas or named exceptions: a class
    with pending ready work receives its next slot before any class with more
    service receives another one.  Deterministic baseline repairs remain a
    resource boundary and never consume an LLM slot.

    S30 v2 adds the work-item projection on top of per-deficit dedup:
    pending deficits that share one consultation identity (kind, action,
    axis, and the blocked effect or measured diff) coalesce into one
    ``WorkItem``.  ``pop_wave`` dispatches one wave of mutually independent
    work items planned against a single immutable graph snapshot, while
    ``pop_next`` keeps the single-item dispatch contract for callers that
    ground one item at a time.  Attempts are accounted per work item: one
    grounding call is one attempt for every deficit it covered.  S33
    absorption closes the current work-item evidence revision immediately;
    only genuinely new evidence reopens it.
    """

    def __init__(
        self,
        *,
        max_tasks: int | None = 8,
        # Direct construction keeps the pre-S33 compatibility default;
        # LiveWorkflow passes the environment-configured default of three.
        max_attempts: int = 2,
        seed: int = 0,
        interest_prioritizer: InterestPrioritizer | None = None,
    ) -> None:
        if interest_prioritizer is not None and seed != 0:
            raise ValueError("pass either seed or interest_prioritizer")
        if max_tasks is not None and max_tasks < 0:
            raise ValueError("max_tasks must be a non-negative integer or None")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        self._max_tasks = max_tasks
        self._max_attempts = max_attempts
        self._interest = interest_prioritizer or InterestPrioritizer(seed=seed)
        self._deterministic_dispatch_limit = max_tasks
        self._entries: dict[DeficitKey, _QueueEntry] = {}
        self._closed: set[DeficitKey] = set()
        self._stale: set[DeficitKey] = set()
        self._work_items: dict[DeficitKey, _WorkItemState] = {}
        self._class_dispatches: dict[PredicateClass, int] = {}
        self._dispatched = 0
        self._deterministic_dispatched = 0
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
            self._entries[key] = _QueueEntry(deficit, self._next_order)
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

    def pop_wave(
        self,
        *,
        graph_snapshot: str = "",
        ready: Callable[[WorkItem], bool] | None = None,
    ) -> tuple[WorkItem, ...]:
        """Dispatch one independent work-item wave."""

        return dispatch_wave(
            self,
            graph_snapshot=graph_snapshot,
            ready=ready,
        )

    def pop_next(self) -> Deficit | None:
        """Dispatch the highest-priority actionable work item."""

        return dispatch_next(self)

    def record_work_item_result(
        self,
        work_item: WorkItem,
        result: QdlGraph | None,
        *,
        observation: Observation | None = None,
        trusted: bool = True,
    ) -> WorkItemResult:
        """Record one grounding result for every deficit in a work item."""

        return lifecycle_record_item_result(
            self, work_item, result, observation=observation, trusted=trusted
        )

    def propagate_work_item_result(
        self,
        work_item: WorkItem,
        result: QdlGraph | None,
        *,
        observation: Observation | None = None,
        active_path_ids: frozenset[str] | None = None,
    ) -> WorkItemPropagation:
        """Propagate one promoted result through pending queue entries."""

        return propagate_item(
            self,
            work_item,
            result,
            observation=observation,
            active_path_ids=active_path_ids,
        )

    def propagate_wave_results(
        self,
        outcomes: Mapping[str, WorkItemGrounding],
        *,
        base_graph: QdlGraph | None = None,
        active_path_ids: frozenset[str] | None = None,
    ) -> WorkItemWavePropagation:
        """Propagate one merged wave result through pending queue entries."""

        return propagate_wave(
            self,
            outcomes,
            base_graph=base_graph,
            active_path_ids=active_path_ids,
        )

    def record_work_item_success(
        self, work_item: WorkItem, *, trusted: bool = True
    ) -> bool:
        """Close every deficit covered by one verified work item."""

        return lifecycle_mark_item_success(self, work_item, trusted=trusted)

    def record_work_item_failure(
        self, work_item: WorkItem, *, trusted: bool = True
    ) -> None:
        """Record one failed grounding call for the whole work item."""

        lifecycle_mark_item_failure(self, work_item, trusted=trusted)

    def defer_work_item(self, work_item: WorkItem) -> None:
        """Wait for new evidence without closing the unsatisfied subgoal."""

        lifecycle_defer_item(self, work_item)

    def absorb_work_item(self, work_item: WorkItem) -> None:
        """Close the current evidence revision of an absorbing outcome."""

        lifecycle_absorb_item(self, work_item)

    def record_success(
        self, deficit: Deficit, *, gap_closed: bool, trusted: bool = True
    ) -> bool:
        """Close a deficit only when its semantic gap is verified."""

        return lifecycle_record_success(
            self, deficit, gap_closed=gap_closed, trusted=trusted
        )

    def close_key(self, key: DeficitKey) -> None:
        """Close one canonical deficit without dispatching an LLM task."""

        lifecycle_close_key(self, key)

    def record_failure(self, deficit: Deficit, *, trusted: bool = True) -> None:
        """Retry a failed deficit or close it after the attempt budget."""

        lifecycle_record_failure(self, deficit, trusted=trusted)

    @property
    def pending_count(self) -> int:
        """Return deficits waiting for selection (in-flight work excluded)."""

        return sum(
            1
            for entry in self._entries.values()
            if entry.deficit.key not in self._closed
            and entry.deficit.key not in self._stale
            and not entry.in_flight
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
    def dispatchable(self) -> bool:
        """Return whether one more work item fits the fair dispatch policy."""

        groups = self._eligible_groups()
        if not groups:
            return False
        return (
            deterministic_slots(self._deterministic_dispatch_limit, 0)
            and any(group.axis in DETERMINISTIC_AXES for group in groups)
        ) or select_next_group(
            groups,
            state=self._dispatch_state(),
            max_tasks=self._max_tasks,
            deterministic_dispatch_limit=self._deterministic_dispatch_limit,
            prioritizer=self._interest,
        ) is not None

    @property
    def budget_exhausted(self) -> bool:
        """Return whether every LLM task slot is consumed."""

        return self._max_tasks is not None and self._dispatched >= self._max_tasks

    @property
    def dispatched(self) -> int:
        """Return the number of LLM work items selected for dispatch."""

        return self._dispatched

    @property
    def deterministic_dispatched(self) -> int:
        """Return the number of deterministic tasks selected in this drain."""

        return self._deterministic_dispatched

    @property
    def quarantined_signals(self) -> int:
        """Return the number of ignored untrusted feedback signals."""

        return sum(entry.quarantined_signals for entry in self._entries.values())

    def _eligible_groups(self) -> list[_WorkGroup]:
        """Group every dispatchable entry by its work-item key."""

        entries = [
            entry
            for entry in self._entries.values()
            if entry.deficit.key not in self._closed
            and entry.deficit.key not in self._stale
            and not entry.in_flight
            and entry.deficit.axis in _DISPATCHABLE_AXES
        ]
        grouped: dict[DeficitKey, list[_QueueEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.deficit.work_item_key, []).append(entry)
        dispatchable_groups = [
            group
            for group in grouped
            if not self._work_item_state(group).saturated
            and not self._work_item_state(group).deferred
        ]
        return [
            _WorkGroup(
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

    def _work_item(self, group: _WorkGroup, graph_snapshot: str) -> WorkItem:
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

    def _entries_for_key(self, key: DeficitKey) -> list[_QueueEntry]:
        """Return every current entry sharing one work-item key."""

        return [
            entry
            for entry in self._entries.values()
            if entry.deficit.work_item_key == key
        ]

    def _work_item_state(self, key: DeficitKey) -> _WorkItemState:
        """Return mutable scheduling state for one consultation identity."""

        state = self._work_items.get(key)
        if state is None:
            state = _WorkItemState()
            self._work_items[key] = state
        return state

    def _reset_work_item_evidence(self, state: _WorkItemState) -> None:
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
        state.saturated = True
        saturated_keys = [
            entry.deficit.key
            for entry in self._entries_for_key(key)
            if entry.deficit.key not in self._closed
            and entry.deficit.key not in self._stale
        ]
        state.saturation_closed_keys = frozenset(saturated_keys)
        self._closed.update(saturated_keys)
        logger.info(
            "work_item_saturated work_item_id=%s attempts=%d max_attempts=%d "
            "deficits=%d",
            _work_item_id(key),
            state.attempts,
            self._max_attempts,
            len(saturated_keys),
        )

    def _dispatch_state(self) -> _DispatchState:
        return _DispatchState(
            dispatched=self._dispatched,
            deterministic_dispatched=self._deterministic_dispatched,
            class_dispatches=dict(self._class_dispatches),
        )

    def _dispatch_group(self, group: _WorkGroup) -> None:
        """Mark one work item in-flight and consume its budget slot."""

        for entry in group.entries:
            entry.in_flight = True
        if not group.axis or group.axis in DETERMINISTIC_AXES:
            self._deterministic_dispatched += 1
        else:
            self._dispatched += 1
            self._class_dispatches[group.predicate_class] = (
                self._class_dispatches.get(group.predicate_class, 0) + 1
            )

    def _record_entry_failure(self, entry: _QueueEntry) -> None:
        """Record one failed call on a covered deficit."""

        entry.attempts += 1
        entry.failures += 1
