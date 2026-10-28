"""Composition adapter from core runtime projections to report events."""

from __future__ import annotations

from cloud_dast.ports import EventPublisher, ReportPublisher
from cloud_dast_reporting.events import CoverageSnapshot, PlanReady
from cloud_dast_reporting.service import ReportService


class EventReportPublisher(ReportPublisher):
    """Render runtime projections and publish them on the core event bus."""

    def __init__(self, event_bus: EventPublisher) -> None:
        self._event_bus = event_bus
        self._reports = ReportService()

    def publish_plan(self, execution, *, max_checks, scope) -> None:
        self._event_bus.publish(
            scope.apply(
                PlanReady(
                    plan=self._reports.qdl_plan(execution),
                    max_checks=max_checks,
                )
            )
        )

    def publish_coverage(self, coverage, *, scope) -> None:
        self._event_bus.publish(
            scope.apply(CoverageSnapshot(coverage=self._reports.qdl_coverage(coverage)))
        )


__all__ = ["EventReportPublisher"]
