from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from cloud_dast.infrastructure.neo4j.common.repository import (
    Neo4jRepository,
    SessionFactory,
    normalize_method_id,
)
from cloud_dast.ports import Invocation


class Neo4jInvocationRepository(Neo4jRepository):
    """Resolve invocation metadata from Method, ApiSurface and Endpoint nodes."""

    _QUERY = """
        MATCH (m:Method)
        WHERE m.method_id IN $method_ids
        MATCH (api:ApiSurface)-[:HAS_METHOD]->(m)
        OPTIONAL MATCH (endpoint:Endpoint)-[:SERVES]->(api)
        WITH m, api, endpoint,
             CASE WHEN m.method_id = $method_id THEN 0 ELSE 1 END AS method_rank
        WHERE endpoint IS NOT NULL
           AND endpoint.address IS NOT NULL
           AND ($environment IS NULL OR endpoint.environment = $environment)
        RETURN properties(m) AS method,
               api.package AS package,
               endpoint.address AS endpoint,
               endpoint.environment AS environment
        ORDER BY method_rank,
                 CASE
                     WHEN $environment IS NOT NULL
                          AND environment = $environment THEN 0
                     ELSE 1
                 END,
                 coalesce(environment, ''),
                 coalesce(endpoint, '')
        LIMIT 1
    """

    def __init__(
        self,
        session_factory: SessionFactory | None = None,
        *,
        environment: str | None = None,
        method_prefix_aliases: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(session_factory)
        self._environment = environment or os.environ.get(
            "CPA_NEO4J_ENDPOINT_ENVIRONMENT"
        )
        self._method_prefix_aliases = dict(method_prefix_aliases or {})

    def get_invocation(self, method_id: str) -> Invocation | None:
        normalized = normalize_method_id(method_id)
        if not normalized.startswith(("grpc:", "grpc-priv:", "http:")):
            return None
        row = self._run_one(
            self._QUERY,
            method_id=normalized,
            method_ids=_method_ids(normalized, self._method_prefix_aliases),
            environment=self._environment,
        )
        if row is None:
            return None
        if normalized.startswith("http:"):
            return self._http_invocation(normalized, row)
        method = dict(row.get("method") or {})
        package = str(row.get("package") or "")
        endpoint = row.get("endpoint")
        input_type = method.get("input_type")
        selected_method_id = str(method.get("method_id") or normalized)
        canonical = selected_method_id.split(":", 1)[-1]
        service, _, name = canonical.rpartition(".")
        if not package or not service or not name:
            return None
        if not isinstance(input_type, str) or not isinstance(endpoint, str):
            return None
        return Invocation(
            method_id=normalized,
            endpoint=endpoint,
            transport="grpc",
            input_type=input_type,
            rpc_path=f"/{service}/{name}",
            output_type=method.get("output_type")
            if isinstance(method.get("output_type"), str)
            else None,
        )

    @staticmethod
    def _http_invocation(method_id: str, row: dict[str, Any]) -> Invocation | None:
        method = dict(row.get("method") or {})
        endpoint = row.get("endpoint")
        http_method = method.get("http_method")
        path_template = method.get("path_template")
        if not all(
            isinstance(value, str) and value
            for value in (endpoint, http_method, path_template)
        ):
            return None
        return Invocation(
            method_id=method_id,
            endpoint=endpoint,
            transport="http-json",
            http_method=http_method,
            path_template=path_template,
            query_fields=_field_names(method.get("query_fields")) or (),
            header_fields=_field_names(method.get("header_fields")) or (),
            cookie_fields=_field_names(method.get("cookie_fields")) or (),
            body_fields=_field_names(method.get("body_fields")),
        )


def _method_ids(
    method_id: str,
    prefix_aliases: Mapping[str, str],
) -> tuple[str, ...]:
    """Return the exact ID and configured graph-compatible prefix aliases."""

    method_ids = [method_id]
    for prefix, replacement in prefix_aliases.items():
        if not prefix or not method_id.startswith(prefix):
            continue
        candidate = method_id.replace(prefix, replacement, 1)
        if candidate not in method_ids:
            method_ids.append(candidate)
    return tuple(method_ids)


def _field_names(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("HTTP invocation field locations are malformed") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("HTTP invocation field locations are malformed")
    return tuple(value)
