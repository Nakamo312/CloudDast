"""Fair selection and dispatch budgets over canonical deficit lifecycle state."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable, Iterable, Mapping

from cloud_dast.contracts.axes import DETERMINISTIC_AXES, LLM_AXES
from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits import wave
from cloud_dast.runtime.deficits.dispatch import (
    deterministic_slots,
    interest_score,
    select_next_group,
)
from cloud_dast.runtime.deficits.lifecycle import QueueState
from cloud_dast.runtime.deficits.model import Deficit, DeficitKey
from cloud_dast.runtime.deficits.propagation import propagate_item, propagate_wave
from cloud_dast.runtime.deficits.queue_state import DispatchState, WorkGroup
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
    WorkItemPropagation,
    WorkItemResult,
    WorkItemWavePropagation,
)
from cloud_dast.runtime.prioritization import InterestPrioritizer

_DISPATCHABLE_AXES = LLM_AXES | DETERMINISTIC_AXES
logger = logging.getLogger("cloud_dast.runtime.deficits")


class DeficitQueue:
    """Select independent work fairly; QueueState owns entry transitions."""

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
        self._interest = interest_prioritizer or InterestPrioritizer(seed=seed)
        self._state = QueueState(max_attempts)
        self._dispatch = DispatchState(0, 0, {})

    def add(self, deficits: Iterable[Deficit]) -> int:
        return self._state.add(deficits)

    def record_work_item_result(
        self,
        work_item: WorkItem,
        result: QdlGraph | None,
        *,
        observation: Observation | None = None,
        trusted: bool = True,
    ) -> WorkItemResult:
        """Record one grounding result for every deficit in a work item."""

        return self._state.record_item_result(
            work_item, result, observation=observation, trusted=trusted
        )

    def record_work_item_success(
        self, work_item: WorkItem, *, trusted: bool = True
    ) -> bool:
        """Close every deficit covered by one verified work item."""

        return self._state.mark_item_success(work_item, trusted=trusted)

    def record_work_item_failure(
        self, work_item: WorkItem, *, trusted: bool = True
    ) -> None:
        """Record one failed grounding call for the whole work item."""

        self._state.mark_item_failure(work_item, trusted=trusted)

    def defer_work_item(self, work_item: WorkItem) -> None:
        """Wait for new evidence without closing the unsatisfied subgoal."""

        self._state.defer_item(work_item)

    def absorb_work_item(self, work_item: WorkItem) -> None:
        """Close the current evidence revision of an absorbing outcome."""

        self._state.absorb_item(work_item)

    def record_success(
        self, deficit: Deficit, *, gap_closed: bool, trusted: bool = True
    ) -> bool:
        """Close a deficit only when its semantic gap is verified."""

        return self._state.record_success(
            deficit, gap_closed=gap_closed, trusted=trusted
        )

    def close_key(self, key: DeficitKey) -> None:
        """Close one canonical deficit without dispatching an LLM task."""

        self._state.close_key(key)

    def record_failure(self, deficit: Deficit, *, trusted: bool = True) -> None:
        """Retry a failed deficit or close it after the attempt budget."""

        self._state.record_failure(deficit, trusted=trusted)

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
            self._state.pending(),
            work_item,
            result,
            observation=observation,
            active_path_ids=active_path_ids,
            close=self._state.confirm,
            stale=self._state.mark_stale,
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
            self._state.pending(),
            outcomes,
            base_graph=base_graph,
            active_path_ids=active_path_ids,
            close=self._state.confirm,
            stale=self._state.mark_stale,
        )

    @property
    def pending_count(self) -> int:
        """Return deficits waiting for selection (in-flight work excluded)."""

        return self._state.pending_count

    @property
    def closed_count(self) -> int:
        """Return permanently closed deficits."""

        return self._state.closed_count

    @property
    def stale_count(self) -> int:
        """Return deficits removed because their path is no longer active."""

        return self._state.stale_count

    @property
    def saturated_count(self) -> int:
        """Return saturated work items."""

        return self._state.saturated_count

    @property
    def quarantined_signals(self) -> int:
        """Return the number of ignored untrusted feedback signals."""

        return self._state.quarantined_signals

    @property
    def dispatchable(self) -> bool:
        """Return whether one more work item fits the fair dispatch policy."""

        groups = self._state.groups(_DISPATCHABLE_AXES)
        if not groups:
            return False
        return (
            deterministic_slots(self._max_tasks, 0)
            and any(group.axis in DETERMINISTIC_AXES for group in groups)
        ) or select_next_group(
            groups,
            state=self._dispatch_state(),
            max_tasks=self._max_tasks,
            deterministic_dispatch_limit=self._max_tasks,
            prioritizer=self._interest,
        ) is not None

    @property
    def budget_exhausted(self) -> bool:
        """Return whether every LLM task slot is consumed."""

        return (
            self._max_tasks is not None and self._dispatch.dispatched >= self._max_tasks
        )

    @property
    def dispatched(self) -> int:
        """Return the number of LLM work items selected for dispatch."""

        return self._dispatch.dispatched

    @property
    def deterministic_dispatched(self) -> int:
        """Return the number of deterministic tasks selected in this drain."""

        return self._dispatch.deterministic_dispatched

    def _dispatch_state(self) -> DispatchState:
        return dataclasses.replace(
            self._dispatch, class_dispatches=dict(self._dispatch.class_dispatches)
        )

    def _dispatch_group(self, group: WorkGroup) -> None:
        self._state.dispatch(group)
        self._dispatch.apply(group)

    def pop_wave(
        self,
        *,
        graph_snapshot: str = "",
        ready: Callable[[WorkItem], bool] | None = None,
    ) -> tuple[WorkItem, ...]:
        self._dispatch.deterministic_dispatched = 0
        groups = self._state.groups(_DISPATCHABLE_AXES)
        if not groups:
            return ()
        selection = wave.plan(
            groups,
            self._state.project,
            graph_snapshot=graph_snapshot,
            ready=ready,
            state=self._dispatch_state,
            limit=self._max_tasks,
            prioritizer=self._interest,
        )
        if selection is None:
            return ()
        graph, selected, planned = selection
        if not selected:
            self._dispatch.deterministic_dispatched = 0
            logger.info(
                "work_item_wave_budget_blocked pending=%d dispatched=%d max_tasks=%s classes=%d",
                len(groups),
                self.dispatched,
                "all" if self._max_tasks is None else self._max_tasks,
                len({group.predicate_class for group in groups}),
            )
            return ()
        items = []
        for group in selected:
            self._dispatch_group(group)
            item = planned[group.work_item_id]
            items.append(item)
            cold_score = interest_score(group, self._interest)
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
                self.dispatched,
                "all" if self._max_tasks is None else self._max_tasks,
            )
            wave.log_score("work_item", item.work_item_id, cold_score)
        if graph.supersedes:
            logger.info(
                "work_item_supersedes pairs=%s",
                ",".join(f"{new}>{old}" for new, old in graph.supersedes),
            )
        return tuple(items)

    def pop_next(self) -> Deficit | None:
        groups = self._state.groups(_DISPATCHABLE_AXES)
        if not groups:
            self._dispatch.deterministic_dispatched = 0
            return None
        best = select_next_group(
            groups,
            state=self._dispatch_state(),
            max_tasks=self._max_tasks,
            deterministic_dispatch_limit=self._max_tasks,
            prioritizer=self._interest,
        )
        if best is None:
            self._dispatch.deterministic_dispatched = 0
            logger.info(
                "deficit_budget_blocked pending=%d dispatched=%d max_tasks=%s classes=%d",
                len(groups),
                self.dispatched,
                "all" if self._max_tasks is None else self._max_tasks,
                len({group.predicate_class for group in groups}),
            )
            return None
        self._dispatch_group(best)
        representative = best.representative.deficit
        cold_score = interest_score(best, self._interest)
        logger.info(
            "deficit_popped deficit_id=%s class=%s action=%s axis=%s dispatched=%d max_tasks=%s",
            representative.consultation_id,
            representative.predicate_class,
            representative.action,
            representative.axis or "-",
            self.dispatched,
            "all" if self._max_tasks is None else self._max_tasks,
        )
        wave.log_score("deficit", cold_score.work_item_id, cold_score)
        return representative
