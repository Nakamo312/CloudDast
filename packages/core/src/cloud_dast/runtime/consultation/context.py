"""Immutable contracts shared by consultation-wave phases."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cloud_dast.api import LiveRequest
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import ComponentKind, EventScope
from cloud_dast.ports import EventPublisher, GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import WorkItem
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.evidence_gate import Gate
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.slices import SiblingActionSlice


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
class Callbacks:
    """Capabilities required to execute one reactive consultation wave."""

    grounding: AutoGroundingService | None
    grounding_runner: GroundingRunner | None
    batch_timeout: float
    reactive_max_workers: int
    latency_oracle: LatencyOracle | None
    event_bus: EventPublisher | None
    metrics: CampaignMetrics | None
    evidence_gate: Gate


@dataclass(frozen=True, slots=True)
class PlannedItem:
    """Immutable inputs prepared for one worker call."""

    work_item: WorkItem
    observation: Observation | None
    check: Check | None
    evidence: EvidenceView | None
    siblings: SiblingActionSlice | None
    variance: VarianceRecord | None


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


__all__ = ["Callbacks", "OutcomeMeta", "PlannedItem", "WaveContext", "WaveExecution"]
