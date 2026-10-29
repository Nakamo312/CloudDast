"""Per-step runtime context shared by differential mode handlers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import QdlExecutionStep
from cloud_dast.model import MethodSpec
from cloud_dast.model.events import EventScope
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.execution.state import CampaignAccumulator


@dataclass(frozen=True, slots=True)
class ProbeContext:
    """Mutable runtime handles for one bound-step differential sweep."""

    request: LiveRequest
    step: QdlExecutionStep
    graph: QdlGraph
    method_pool: Mapping[str, MethodSpec]
    accumulator: CampaignAccumulator
    deficits: DeficitQueue
    variance_records: dict[tuple[str, ...], VarianceRecord]
    budget: CallLimits
    scope: EventScope
    paired_steps: set[tuple[str, ...]]
    diff_modes: frozenset[str]
    path_id: str | None
    evidence_store: Store[MeasurementKey]


__all__ = ["ProbeContext"]
