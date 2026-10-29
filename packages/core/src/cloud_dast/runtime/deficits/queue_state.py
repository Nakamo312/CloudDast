"""Value and mutable state records used by the deficit queue.

The queue policy remains in :mod:`cloud_dast.runtime.deficits.queue`; these records do not add
dispatch behavior or semantic deficit construction. Keeping them separate
makes the queue's mutable state explicit and prevents callers from confusing
queue state with the immutable deficit/work-item projections.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.contracts.axes import DETERMINISTIC_AXES
from cloud_dast.runtime.deficits.model import (
    Deficit,
    DeficitAxis,
    DeficitKey,
    PredicateClass,
)
from cloud_dast.runtime.deficits.work_items import _work_item_id


@dataclass(slots=True)
class QueueEntry:
    """Mutable scheduling state for one canonical deficit."""

    deficit: Deficit
    order: int
    fan_out: int = 1
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    quarantined_signals: int = 0
    quarantined_features: frozenset[str] = frozenset()
    in_flight: bool = False


@dataclass(slots=True)
class WorkItemState:
    """Mutable per-work-item attempt and saturation state."""

    attempts: int = 0
    saturated: bool = False
    deferred: bool = False
    evidence_signature: frozenset[str] = frozenset()
    saturation_closed_keys: frozenset[DeficitKey] = frozenset()


@dataclass(frozen=True, slots=True)
class WorkGroup:
    """Queue-side view of entries sharing one work-item key."""

    key: DeficitKey
    predicate_class: PredicateClass
    action: str
    axis: DeficitAxis | None
    entries: tuple[QueueEntry, ...]

    @property
    def work_item_id(self) -> str:
        return _work_item_id(self.key)

    @property
    def fan_out(self) -> int:
        return sum(entry.fan_out for entry in self.entries)

    @property
    def order(self) -> int:
        return min(entry.order for entry in self.entries)

    @property
    def representative(self) -> QueueEntry:
        return min(
            self.entries, key=lambda entry: (entry.order, entry.deficit.work_item_key)
        )

    @property
    def requires_model(self) -> bool:
        """Return whether this group consumes a model consultation slot."""

        return self.axis is not None and self.axis not in DETERMINISTIC_AXES


@dataclass(slots=True)
class DispatchState:
    """Simulated dispatch counters used by fair wave planning."""

    dispatched: int
    deterministic_dispatched: int
    class_dispatches: dict[PredicateClass, int]

    def apply(self, group: WorkGroup) -> None:
        if not group.axis or group.axis in DETERMINISTIC_AXES:
            self.deterministic_dispatched += 1
        else:
            self.dispatched += 1
            self.class_dispatches[group.predicate_class] = (
                self.class_dispatches.get(group.predicate_class, 0) + 1
            )


__all__ = [
    "DispatchState",
    "QueueEntry",
    "WorkGroup",
    "WorkItemState",
]
