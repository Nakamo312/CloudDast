from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from cloud_dast.infrastructure.neo4j.common.repository import (
    Neo4jRepository,
    normalize_method_id,
)
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    RequestSchema,
    ResponseSchema,
)
from cloud_dast.ports import MessageSchemaResolver


def _parse_fields(raw_fields: Any) -> tuple[FieldSpec, ...]:
    if isinstance(raw_fields, str):
        raw_fields = json.loads(raw_fields)
    if not isinstance(raw_fields, list):
        return ()

    def parse(entries: list[dict[str, Any]]) -> Iterator[FieldSpec]:
        for entry in entries:
            yield FieldSpec(
                name=str(entry["name"]),
                type=str(entry.get("type", "unknown")),
                required=bool(entry.get("required", False)),
                repeated=bool(entry.get("repeated", False)),
                oneof=entry.get("oneof"),
                enum_values=tuple(str(value) for value in entry.get("enum_values", ())),
                minimum=entry.get("minimum"),
                maximum=entry.get("maximum"),
            )
            yield from parse(entry.get("fields", []))

    return tuple(parse(raw_fields))


def _to_method_spec(
    row: dict[str, Any],
    schema_resolver: MessageSchemaResolver | None = None,
) -> MethodSpec:
    method = dict(row.get("method") or {})
    method_id = str(method.get("method_id", ""))
    input_type = method.get("input_type")
    output_type = method.get("output_type")
    request_schema = RequestSchema(
        type_name=input_type if isinstance(input_type, str) else None,
        fields=_parse_fields(method.get("input_fields")),
    )
    response_schema = (
        ResponseSchema(type_name=output_type) if isinstance(output_type, str) else None
    )
    if schema_resolver is not None and isinstance(input_type, str):
        request_schema = schema_resolver.request_schema(input_type)
    if schema_resolver is not None and isinstance(output_type, str):
        response_schema = schema_resolver.response_schema(output_type)

    return MethodSpec(
        method_id=method_id,
        service=str(row.get("service") or method.get("service", "")),
        name=str(method.get("name", "")),
        layer=_layer(method_id, row.get("layer")),
        permissions=frozenset(row.get("permissions", ())),
        resource_types=frozenset(row.get("resource_types", ())),
        request_schema=request_schema,
        response_schema=response_schema,
    )


def _layer(method_id: str, raw_layer: Any) -> EndpointLayer:
    if isinstance(raw_layer, str):
        try:
            return EndpointLayer(raw_layer)
        except ValueError:
            pass
    if method_id.startswith("grpc-priv:"):
        return EndpointLayer.PRIVATE
    return EndpointLayer.PUBLIC


class Neo4jMethodRepository(Neo4jRepository):
    """Read method specifications from the existing contract graph."""

    def __init__(
        self,
        session_factory: Any,
        *,
        schema_resolver: MessageSchemaResolver | None = None,
    ) -> None:
        super().__init__(session_factory)
        self._schema_resolver = schema_resolver

    _METHOD_QUERY = """
        MATCH (m:Method {method_id: $method_id})
        MATCH (api:ApiSurface)-[:HAS_METHOD]->(m)
        OPTIONAL MATCH (svc:Service)-[:EXPOSES]->(api)
        OPTIONAL MATCH (m)-[:TARGETS]->(rt:ResourceType)
        OPTIONAL MATCH (m)-[:REQUIRES]->(perm:Permission)
        WITH m, api,
             collect(DISTINCT svc.canonical_id) AS services,
             collect(DISTINCT rt.resource_type) AS resource_types,
             collect(DISTINCT perm.permission_id) AS permissions
        RETURN properties(m) AS method,
               api.package AS package,
               api.layer AS layer,
               services,
               resource_types,
               permissions
        LIMIT 1
    """

    _SERVICE_METHODS_QUERY = """
        MATCH (svc:Service {canonical_id: $service})
              -[:EXPOSES]->(api:ApiSurface)-[:HAS_METHOD]->(m:Method)
        OPTIONAL MATCH (m)-[:TARGETS]->(rt:ResourceType)
        OPTIONAL MATCH (m)-[:REQUIRES]->(perm:Permission)
        WITH svc, api, m,
             collect(DISTINCT rt.resource_type) AS resource_types,
             collect(DISTINCT perm.permission_id) AS permissions
        RETURN properties(m) AS method,
               coalesce(svc.canonical_id, api.package) AS service,
               api.layer AS layer,
               resource_types,
               permissions
        ORDER BY method.method_id
    """

    def get_method(self, method_id: str) -> MethodSpec | None:
        row = self._run_one(
            self._METHOD_QUERY,
            method_id=normalize_method_id(method_id),
        )
        if row is None:
            return None

        services = [service for service in row.get("services", ()) if service]
        if services:
            row["service"] = services[0]
        elif not row.get("service"):
            row["service"] = row.get("package", "")

        return _to_method_spec(row, self._schema_resolver)

    def list_methods(self, service: str) -> tuple[MethodSpec, ...]:
        rows = self._run(self._SERVICE_METHODS_QUERY, service=service)
        return tuple(_to_method_spec(row, self._schema_resolver) for row in rows)
