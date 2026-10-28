from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.composition.formal_ingestion import QdlIngestionService
from cloud_dast.infrastructure.advisory import AdvisoryPreScanService
from cloud_dast.ports import EventPublisher, EventSubscriber
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.campaign import LiveWorkflow


@dataclass(frozen=True)
class CloudDastRuntime:
    live_workflow: LiveWorkflow
    event_bus: EventPublisher
    event_subscriber: EventSubscriber
    formal_ingestion: QdlIngestionService
    advisory_pre_scan: AdvisoryPreScanService

    def pre_scan_advisories(self, service: str) -> QdlGraph | None:
        """Run the deterministic external-knowledge pre-scan boundary."""

        return self.advisory_pre_scan.pre_scan(service)
