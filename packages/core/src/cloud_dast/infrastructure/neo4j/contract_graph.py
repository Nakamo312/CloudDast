"""Neo4j adapter for abstract service graph slices."""

from __future__ import annotations

from cloud_dast.infrastructure.neo4j.common.repository import Neo4jRepository
from cloud_dast.ports import (
    GraphEdge,
    GraphNode,
    ServiceGraphSlice,
)


class Neo4jContractGraphRepository(Neo4jRepository):
    """Load the complete bounded contract neighborhood of one service."""

    _NODES_QUERY = """
        MATCH (service:Service {canonical_id: $service})
        CALL {
            WITH service
            RETURN service AS node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(node:ApiSurface)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(node:Method)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:HAS_PARAM|TARGETS|REQUIRES]->(node)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:HAS_PARAM]->(:Param)-[:REFERS_TO]->(node:ResourceType)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:REQUIRES]->(:Permission)-[:APPLIES_TO]->(node:ResourceType)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:TARGETS|HAS_PARAM|REQUIRES]->(source)
            MATCH (node:ResourceType)-[:PARENT_OF*1..5]->(source)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:OWNS]->(node:ResourceType)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(api:ApiSurface)<-[:SERVES]-(node:Endpoint)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:KNOWN_AS]->(node:Alias)
            RETURN node
            UNION
            WITH service
            MATCH (node:DocPage)-[:DESCRIBES]->(service)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:DEFINED_IN]->(node:Source)
            RETURN node
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:REQUIRES]->(permission:Permission)<-[:GRANTS]-(node:Role)
            RETURN node
        }
        WITH node
        WHERE NOT node:LiveResource AND NOT node:ThreatGraph
        RETURN DISTINCT elementId(node) AS node_id,
                        labels(node) AS labels,
                        properties(node) AS properties
        ORDER BY node_id
    """

    _EDGES_QUERY = """
        MATCH (service:Service {canonical_id: $service})
        CALL {
            WITH service
            MATCH (service)-[relation:EXPOSES]->(:ApiSurface)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[relation:HAS_METHOD]->(:Method)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[relation:HAS_PARAM|TARGETS|REQUIRES]->()
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:HAS_PARAM]->(:Param)-[relation:REFERS_TO]->(:ResourceType)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:REQUIRES]->(:Permission)-[relation:APPLIES_TO]->(:ResourceType)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:TARGETS|HAS_PARAM|REQUIRES]->(source)
            MATCH (:ResourceType)-[relations:PARENT_OF*1..5]->(source)
            UNWIND relations AS relation
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[relation:OWNS]->(:ResourceType)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(api:ApiSurface)<-[relation:SERVES]-(:Endpoint)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[relation:KNOWN_AS]->(:Alias)
            RETURN relation
            UNION
            WITH service
            MATCH (node:DocPage)-[relation:DESCRIBES]->(service)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[relation:DEFINED_IN]->(:Source)
            RETURN relation
            UNION
            WITH service
            MATCH (service)-[:EXPOSES]->(:ApiSurface)-[:HAS_METHOD]->(method:Method)
                  -[:REQUIRES]->(:Permission)<-[relation:GRANTS]-(:Role)
            RETURN relation
        }
        RETURN DISTINCT elementId(relation) AS edge_id,
                        elementId(startNode(relation)) AS source_id,
                        elementId(endNode(relation)) AS target_id,
                        type(relation) AS kind,
                        properties(relation) AS properties
        ORDER BY edge_id
    """

    def load_slice(self, service: str) -> ServiceGraphSlice:
        nodes = tuple(
            GraphNode(
                node_id=str(row.get("node_id", "")),
                labels=tuple(str(label) for label in row.get("labels", ())),
                properties=dict(row.get("properties") or {}),
            )
            for row in self._run(self._NODES_QUERY, service=service)
            if not {str(label) for label in row.get("labels", ())}.intersection(
                {"LiveResource", "ThreatGraph"}
            )
        )
        node_ids = {node.node_id for node in nodes}
        edges = tuple(
            GraphEdge(
                edge_id=str(row.get("edge_id", "")),
                source_id=str(row.get("source_id", "")),
                target_id=str(row.get("target_id", "")),
                kind=str(row.get("kind", "")),
                properties=dict(row.get("properties") or {}),
            )
            for row in self._run(self._EDGES_QUERY, service=service)
            if str(row.get("source_id", "")) in node_ids
            and str(row.get("target_id", "")) in node_ids
        )
        return ServiceGraphSlice(service=service, nodes=nodes, edges=edges)
