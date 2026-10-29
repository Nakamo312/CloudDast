from __future__ import annotations

from typing import Any

import pytest

from cloud_dast.composition.formal_ingestion import QdlIngestionService
from cloud_dast.ports import (
    GraphEdge,
    GraphNode,
    ServiceGraphSlice,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.verification.contract_projection import (
    ClassificationProfile,
    ContractProjector,
)


class FakeContractGraph:
    def __init__(self, slice_: ServiceGraphSlice) -> None:
        self._slice = slice_

    def load_slice(self, service: str) -> ServiceGraphSlice:
        assert service == self._slice.service
        return self._slice


class FakeFormalRepository:
    def __init__(self) -> None:
        self.saved: list[dict[str, Any]] = []
        self.graphs: dict[str, QdlGraph] = {}

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
        self.graphs[source_id] = graph

    def load(self, source_id: str) -> QdlGraph:
        return self.graphs.get(source_id, QdlGraph())


@pytest.fixture
def graph_slice() -> ServiceGraphSlice:
    return ServiceGraphSlice(
        service="lockbox",
        nodes=(
            GraphNode(
                node_id="service:lockbox",
                labels=("Service",),
                properties={"canonical_id": "lockbox"},
            ),
            GraphNode(
                node_id="api:payload",
                labels=("ApiSurface",),
                properties={"package": "lockbox.v1"},
            ),
            GraphNode(
                node_id="method:get",
                labels=("Method",),
                properties={
                    "method_id": "grpc:lockbox.v1.PayloadService.Get",
                    "input_fields": (
                        {
                            "name": "secret_id",
                            "type": "string",
                            "required": True,
                        },
                    ),
                },
            ),
            GraphNode(
                node_id="permission:payload.get",
                labels=("Permission",),
                properties={"permission_id": "lockbox.payload.get"},
            ),
            GraphNode(
                node_id="resource:secret",
                labels=("ResourceType",),
                properties={"resource_type": "lockbox.secret"},
            ),
        ),
        edges=(
            GraphEdge(
                edge_id="edge:exposes",
                source_id="api:payload",
                target_id="service:lockbox",
                kind="EXPOSES",
            ),
            GraphEdge(
                edge_id="edge:method",
                source_id="method:get",
                target_id="api:payload",
                kind="HAS_METHOD",
            ),
            GraphEdge(
                edge_id="edge:requires",
                source_id="method:get",
                target_id="permission:payload.get",
                kind="REQUIRES",
            ),
            GraphEdge(
                edge_id="edge:targets",
                source_id="method:get",
                target_id="resource:secret",
                kind="TARGETS",
            ),
        ),
    )


def test_ingestion_projects_and_persists_contract_slice(graph_slice) -> None:
    repository = FakeFormalRepository()
    service = QdlIngestionService(FakeContractGraph(graph_slice), repository)

    result = service.ingest("lockbox")

    assert result.service == "lockbox"
    assert result.source_id == "contract:lockbox"
    assert result.graph_hash == repository.saved[0]["graph"].content_hash
    assert len(repository.saved) == 1
    assert repository.saved[0]["adapter_version"] == "contract-projection-v2"
    assert repository.saved[0]["provenance"]["service"] == "lockbox"
    assert repository.saved[0]["provenance"]["source_kind"] == "neo4j-contract-graph"
    assert "mapped" in repository.saved[0]["mapping_report"]
    assert service.load("contract:lockbox") == repository.saved[0]["graph"]


def test_ingestion_rejects_empty_service(graph_slice) -> None:
    service = QdlIngestionService(
        FakeContractGraph(graph_slice), FakeFormalRepository()
    )

    with pytest.raises(ValueError, match="service must not be empty"):
        service.ingest("   ")


def test_ingestion_projects_classification_profile(graph_slice) -> None:
    graph_slice = graph_slice.model_copy(
        update={
            "nodes": (
                *graph_slice.nodes,
                GraphNode(
                    node_id="doc:lockbox",
                    labels=("DocPage",),
                    properties={
                        "page_id": "lockbox-docs",
                        "data_classification": {
                            "fields": (
                                {
                                    "action": "grpc:lockbox.v1.PayloadService.Get",
                                    "field": "secret_id",
                                    "classification": "secret",
                                },
                            ),
                        },
                    },
                ),
            ),
            "edges": (
                *graph_slice.edges,
                GraphEdge(
                    edge_id="edge:describes",
                    source_id="doc:lockbox",
                    target_id="service:lockbox",
                    kind="DESCRIBES",
                ),
            ),
        }
    )
    repository = FakeFormalRepository()
    service = QdlIngestionService(
        FakeContractGraph(graph_slice),
        repository,
        classification_profile=ClassificationProfile(roles={"secret": ("sensitive",)}),
    )

    result = service.ingest("lockbox")

    assert result.classification_mapped == 1
    assert result.classification_unmapped == 0
    assert repository.saved[0]["provenance"]["classification_mapped"] == 1
    assert repository.saved[0]["provenance"]["classification_unmapped"] == 0
    assert any(
        fact.predicate.name == "has"
        and fact.args[1].value == "sensitive"
        and fact.args[0].name == "input_field"
        and fact.args[0].args[1].value == "secret_id"
        for fact in repository.saved[0]["graph"].facts
    )


def test_ingestion_rejects_projector_and_classification_profile(graph_slice) -> None:
    with pytest.raises(
        ValueError,
        match="classification_profile cannot override an explicit projector",
    ):
        QdlIngestionService(
            FakeContractGraph(graph_slice),
            FakeFormalRepository(),
            projector=ContractProjector(),
            classification_profile=ClassificationProfile(),
        )
