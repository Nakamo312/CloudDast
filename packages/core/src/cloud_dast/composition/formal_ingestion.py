"""Compose contract-graph ingestion into the canonical QDL repository."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cloud_dast.ports import ContractGraphRepository, FormalRepository
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.verification.contract_projection import (
    ClassificationProfile,
    ContractProjector,
)

_RESERVED_SOURCE_PREFIXES = (
    "accepted:",
    "accepted-batch:",
    "diff:",
    "observation:",
    "proposal:",
    "report:",
    "runtime:",
    "stand:",
    "state-machine:",
)


@dataclass(frozen=True, slots=True)
class FormalIngestionResult:
    """Summary of one deterministic contract-to-QDL ingestion."""

    service: str
    source_id: str
    graph_hash: str
    mapped: int
    unmapped: int
    ambiguous: int
    conflict: int
    classification_mapped: int = 0
    classification_unmapped: int = 0


class QdlIngestionService:
    """Materialize a formal projection of an existing contract graph.

    The service is intentionally separate from the live threat-modeling path.
    It gives operators an explicit, replayable migration step: load the current
    contract slice, project it into QDL, and persist the canonical graph with
    provenance and mapping issues.
    """

    def __init__(
        self,
        contract_graph: ContractGraphRepository,
        repository: FormalRepository,
        *,
        projector: ContractProjector | None = None,
        adapter_version: str = "contract-projection-v2",
        classification_profile: ClassificationProfile | None = None,
    ) -> None:
        if projector is not None and classification_profile is not None:
            raise ValueError(
                "classification_profile cannot override an explicit projector"
            )
        self._contract_graph = contract_graph
        self._repository = repository
        self._projector = projector or ContractProjector(classification_profile)
        self._adapter_version = adapter_version

    def ingest(
        self,
        service: str,
        *,
        source_id: str | None = None,
    ) -> FormalIngestionResult:
        """Project and persist one service contract slice."""

        normalized_service = service.strip()
        if not normalized_service:
            raise ValueError("service must not be empty")

        slice_ = self._contract_graph.load_slice(normalized_service)
        projection = self._projector.project(slice_)
        logical_source_id = (source_id or f"contract:{normalized_service}").strip()
        if not logical_source_id:
            raise ValueError("source_id must not be empty")
        if logical_source_id.startswith(_RESERVED_SOURCE_PREFIXES):
            raise ValueError("source_id must not use a reserved runtime namespace")

        classification_mapped = sum(
            1 for element in projection.report.mapped if element.kind == "annotation"
        )
        classification_unmapped = sum(
            1 for issue in projection.report.unmapped if issue.element == "annotation"
        )
        provenance: Mapping[str, Any] = {
            "service": normalized_service,
            "source_kind": "neo4j-contract-graph",
            "node_count": len(slice_.nodes),
            "edge_count": len(slice_.edges),
            "classification_mapped": classification_mapped,
            "classification_unmapped": classification_unmapped,
        }
        mapping_report: Mapping[str, Any] = projection.report.model_dump(mode="json")

        self._repository.save(
            logical_source_id,
            projection.graph,
            provenance=provenance,
            adapter_version=self._adapter_version,
            mapping_report=mapping_report,
        )

        return FormalIngestionResult(
            service=normalized_service,
            source_id=logical_source_id,
            graph_hash=projection.graph.content_hash,
            mapped=len(projection.report.mapped),
            unmapped=len(projection.report.unmapped),
            ambiguous=len(projection.report.ambiguous),
            conflict=len(projection.report.conflict),
            classification_mapped=classification_mapped,
            classification_unmapped=classification_unmapped,
        )

    def load(self, source_id: str) -> QdlGraph:
        """Return the latest canonical graph for a source."""

        return self._repository.load(source_id)
