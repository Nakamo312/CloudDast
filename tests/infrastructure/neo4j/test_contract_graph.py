from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from cloud_dast.infrastructure import Neo4jContractGraphRepository


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class FakeSession:
    def __init__(
        self, node_rows: list[dict[str, Any]], edge_rows: list[dict[str, Any]]
    ) -> None:
        self.node_rows = node_rows
        self.edge_rows = edge_rows
        self.queries: list[str] = []
        self.params: list[dict[str, Any]] = []

    def run(self, query: str, **params: Any) -> FakeResult:
        self.queries.append(query)
        self.params.append(params)
        return FakeResult(self.edge_rows if "edge_id" in query else self.node_rows)


def make_factory(node_rows: list[dict[str, Any]], edge_rows: list[dict[str, Any]]):
    session = FakeSession(node_rows, edge_rows)

    @contextmanager
    def factory():
        yield session

    return factory, session


def test_load_slice_returns_contract_nodes_and_edges_without_live_graph() -> None:
    node_rows = [
        {
            "node_id": "service:catalog",
            "labels": ["Service"],
            "properties": {"canonical_id": "catalog"},
        },
        {
            "node_id": "api:catalog.v1",
            "labels": ["ApiSurface"],
            "properties": {"package": "catalog.v1"},
        },
        {
            "node_id": "method:catalog.Get",
            "labels": ["Method"],
            "properties": {"method_id": "grpc:catalog.v1.Catalog.Get"},
        },
        {
            "node_id": "param:resource_id",
            "labels": ["Param"],
            "properties": {"key": "resource_id"},
        },
        {
            "node_id": "permission:catalog.read",
            "labels": ["Permission"],
            "properties": {"permission_id": "catalog.read"},
        },
        {
            "node_id": "resource:catalog.item",
            "labels": ["ResourceType"],
            "properties": {"resource_type": "catalog.item"},
        },
        {
            "node_id": "live:item-1",
            "labels": ["LiveResource"],
            "properties": {"resource_id": "item-1"},
        },
        {
            "node_id": "threat:old",
            "labels": ["ThreatGraph", "Goal"],
            "properties": {"goal_id": "old"},
        },
    ]
    edge_rows = [
        {
            "edge_id": "edge:exposes",
            "source_id": "service:catalog",
            "target_id": "api:catalog.v1",
            "kind": "EXPOSES",
            "properties": {},
        },
        {
            "edge_id": "edge:method",
            "source_id": "api:catalog.v1",
            "target_id": "method:catalog.Get",
            "kind": "HAS_METHOD",
            "properties": {},
        },
        {
            "edge_id": "edge:param",
            "source_id": "method:catalog.Get",
            "target_id": "param:resource_id",
            "kind": "HAS_PARAM",
            "properties": {},
        },
        {
            "edge_id": "edge:requires",
            "source_id": "method:catalog.Get",
            "target_id": "permission:catalog.read",
            "kind": "REQUIRES",
            "properties": {},
        },
        {
            "edge_id": "edge:targets",
            "source_id": "method:catalog.Get",
            "target_id": "resource:catalog.item",
            "kind": "TARGETS",
            "properties": {},
        },
        {
            "edge_id": "edge:leaked",
            "source_id": "method:catalog.Get",
            "target_id": "live:item-1",
            "kind": "INSTANCE_OF",
            "properties": {},
        },
    ]
    factory, session = make_factory(node_rows, edge_rows)

    graph = Neo4jContractGraphRepository(factory).load_slice("catalog")

    assert {node.node_id for node in graph.nodes} == {
        "service:catalog",
        "api:catalog.v1",
        "method:catalog.Get",
        "param:resource_id",
        "permission:catalog.read",
        "resource:catalog.item",
    }
    assert {edge.kind for edge in graph.edges} == {
        "EXPOSES",
        "HAS_METHOD",
        "HAS_PARAM",
        "REQUIRES",
        "TARGETS",
    }
    assert all("LiveResource" not in node.labels for node in graph.nodes)
    assert all("ThreatGraph" not in node.labels for node in graph.nodes)
    assert session.params == [{"service": "catalog"}, {"service": "catalog"}]


def test_contract_slice_query_is_directional_and_excludes_runtime_labels() -> None:
    factory, session = make_factory([], [])

    Neo4jContractGraphRepository(factory).load_slice("catalog")

    nodes_query, edges_query = session.queries
    assert "MATCH p=" not in nodes_query
    assert ")-[:EXPOSES|HAS_METHOD|" not in nodes_query
    assert "NOT node:LiveResource" in nodes_query
    assert "NOT node:ThreatGraph" in nodes_query
    for relation in ("EXPOSES", "HAS_METHOD", "HAS_PARAM", "TARGETS", "REQUIRES"):
        assert relation in nodes_query
        assert relation in edges_query
    assert "(node:ResourceType)-[:PARENT_OF*1..5]->(source)" in nodes_query
    assert "(:ResourceType)-[relations:PARENT_OF*1..5]->(source)" in edges_query
    assert "-[:PARENT_OF*0..5]->(node:ResourceType)" not in nodes_query
    assert "(node:ResourceType)-[:PARENT_OF*1..5]->(source)" in nodes_query
    assert "(:ResourceType)-[relations:PARENT_OF*1..5]->(source)" in edges_query
    assert "(source)-[:PARENT_OF" not in nodes_query
    assert "(source)-[relations:PARENT_OF" not in edges_query
