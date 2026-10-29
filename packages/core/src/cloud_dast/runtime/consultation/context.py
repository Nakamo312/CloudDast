"""Immutable contracts shared by consultation-wave phases."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model.events import ComponentKind, EventScope
from cloud_dast.ports import GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.consultation.calls import PlannedItem
from cloud_dast.runtime.deficits.queue import DeficitQueue


@dataclass(frozen=True, slots=True)
class WaveExecution:
    """One committed wave's promotion count and merged QDL graph."""

    promoted: int
    graph: QdlGraph | None = None


@dataclass(frozen=True, slots=True)
class OutcomeMeta:
    """Optional event and evidence metadata for one consultation outcome."""

    scope: EventScope | None = None
    conflict: bool = False
    component: str | None = None
    kind: ComponentKind = "producer"
    evidence_available: bool | None = None


@dataclass(frozen=True, slots=True)
class WaveContext:
    """Pinned source and worker results for one deterministic merge."""

    request: LiveRequest
    planned: tuple[PlannedItem, ...]
    proposals: Mapping[int, Any]
    source: QdlGraph
    current_revision: QdlGraph | None
    lifecycle_revision: int
    grounding_runner: GroundingRunner
    deficits: DeficitQueue
    base_graph: QdlGraph | None
    active_path_ids: frozenset[str] | None
    scope: EventScope | None


__all__ = ["OutcomeMeta", "WaveContext", "WaveExecution"]
