"""In-memory presentation events with immutable reporting snapshots.

These events are presentation projections, not durable runtime facts.  They
are dispatched on the event bus, but are intentionally not part of the JSONL
event-store schema.
"""

from __future__ import annotations

from typing import Literal

from cloud_dast.model.events import DomainEvent
from cloud_dast_reporting.service import (
    QdlCoverageModel,
    QdlPlanSnapshot,
)


class PlanReady(DomainEvent):
    """Immutable QDL plan projection ready for presentation."""

    event_type: Literal["plan_ready"] = "plan_ready"
    plan: QdlPlanSnapshot
    max_checks: int | None = None


class CoverageSnapshot(DomainEvent):
    """Immutable QDL coverage projection for presentation."""

    event_type: Literal["coverage_snapshot"] = "coverage_snapshot"
    coverage: QdlCoverageModel
