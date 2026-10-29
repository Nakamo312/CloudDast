from __future__ import annotations

from typing import Any

import pytest

from cloud_dast.composition.formal_ingestion import QdlIngestionService
from cloud_dast.ports import ServiceGraphSlice
from cloud_dast.qdl.graph import QdlGraph


class FakeContractGraph:
    def load_slice(self, service: str) -> ServiceGraphSlice:
        return ServiceGraphSlice(service=service, nodes=(), edges=())


class FakeFormalRepository:
    def __init__(self) -> None:
        self.saved: list[dict[str, Any]] = []

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: dict[str, Any],
        adapter_version: str,
        mapping_report: dict[str, Any],
    ) -> None:
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id: str) -> QdlGraph:
        return QdlGraph()


@pytest.mark.parametrize(
    "source_id",
    (
        "accepted:lockbox",
        "accepted-batch:lockbox:roles",
        "diff:lockbox:campaign",
        "observation:obs-1",
        "proposal:lockbox:roles",
        "report:lockbox",
        "runtime:lockbox",
        "stand:lockbox",
        "state-machine:lockbox",
    ),
)
def test_ingestion_rejects_reserved_runtime_namespaces(source_id: str) -> None:
    repository = FakeFormalRepository()
    service = QdlIngestionService(FakeContractGraph(), repository)

    with pytest.raises(ValueError, match="reserved runtime namespace"):
        service.ingest("lockbox", source_id=source_id)

    assert repository.saved == []


def test_ingestion_allows_explicit_contract_namespace() -> None:
    repository = FakeFormalRepository()
    service = QdlIngestionService(FakeContractGraph(), repository)

    result = service.ingest("lockbox", source_id="contract:lockbox")

    assert result.source_id == "contract:lockbox"
    assert repository.saved[0]["source_id"] == "contract:lockbox"
