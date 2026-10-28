"""Application-scope repositories for one Cloud DAST container.

The default composition is Neo4j-free: the declared API contract comes from a
git-diffable ``contract.json`` launch fixture, the stand from ``stand.json``,
and the formal store from SQLite.  Neo4j remains an optional adapter selected
with ``CLOUD_DAST_STAND_SOURCE=neo4j`` for external graph-backed stands.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Self

from dishka import Provider, from_context, provide
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)

from cloud_dast.composition.scopes import AppScope
from cloud_dast.infrastructure.neo4j import (
    Neo4jContractGraphRepository,
    Neo4jFormalRepository,
    Neo4jInvocationRepository,
    Neo4jMethodRepository,
)
from cloud_dast.infrastructure.neo4j.common.repository import (
    SessionFactory,
    normalize_method_id,
)
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    RequestSchema,
    ResponseSchema,
)
from cloud_dast.ports import (
    ContractGraphRepository,
    EventStore,
    FormalRepository,
    GraphEdge,
    GraphNode,
    Invocation,
    InvocationRepository,
    MessageSchemaResolver,
    MethodRepository,
    ServiceGraphSlice,
    Target,
)


class ContractEndpointRecord(BaseModel):
    """One explicit endpoint that serves the manifest's API surface."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str = Field(min_length=1)
    environment: str | None = None


class ContractMethodRecord(BaseModel):
    """One declared method together with its transport metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    name: str = Field(min_length=1)
    layer: EndpointLayer = EndpointLayer.PUBLIC
    permissions: frozenset[str] = frozenset()
    resource_types: frozenset[str] = frozenset()
    fields: tuple[FieldSpec, ...] = ()
    input_type: str | None = None
    output_type: str | None = None
    http_method: str | None = Field(default=None, min_length=1)
    path_template: str | None = Field(default=None, min_length=1)
    query_fields: tuple[str, ...] = ()
    header_fields: tuple[str, ...] = ()
    cookie_fields: tuple[str, ...] = ()
    body_fields: tuple[str, ...] | None = None

    @field_validator("method_id")
    @classmethod
    def canonicalize_method_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("method ID must not be blank")
        return normalize_method_id(value)

    def to_method_spec(
        self,
        schema_resolver: MessageSchemaResolver | None = None,
    ) -> MethodSpec:
        request_schema = RequestSchema(
            type_name=self.input_type,
            fields=self.fields,
        )
        response_schema = (
            ResponseSchema(type_name=self.output_type)
            if self.output_type is not None
            else None
        )
        if schema_resolver is not None and self.input_type is not None:
            request_schema = schema_resolver.request_schema(self.input_type)
        if schema_resolver is not None and self.output_type is not None:
            response_schema = schema_resolver.response_schema(self.output_type)
        return MethodSpec(
            method_id=self.method_id,
            service=self.service,
            name=self.name,
            layer=self.layer,
            permissions=self.permissions,
            resource_types=self.resource_types,
            request_schema=request_schema,
            response_schema=response_schema,
        )


class ContractManifest(BaseModel):
    """A versioned contract launch fixture read by the file repositories."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str = Field(min_length=1)
    endpoints: tuple[ContractEndpointRecord, ...] = ()
    methods: tuple[ContractMethodRecord, ...] = ()

    @model_validator(mode="after")
    def validate_methods(self) -> Self:
        method_ids = [record.method_id for record in self.methods]
        if len(method_ids) != len(set(method_ids)):
            raise ValueError("contract manifest contains duplicate method IDs")
        return self


_MANIFEST_ADAPTER = TypeAdapter(ContractManifest)


def load_contract_manifest(path: str | Path) -> ContractManifest:
    """Read and validate one contract launch fixture."""

    return _MANIFEST_ADAPTER.validate_json(Path(path).read_text(encoding="utf-8"))


def configured_contract_file(contract_file: Path | None = None) -> Path:
    """Resolve the contract fixture path without coupling callers to Dishka."""

    return contract_file or Path(
        os.environ.get("CLOUD_DAST_CONTRACT_FILE", "contract.json")
    )


def _selected_stand_source(source: str | None = None) -> str:
    selected = (
        (
            source
            if source is not None
            else os.environ.get("CLOUD_DAST_STAND_SOURCE", "file")
        )
        .strip()
        .lower()
    )
    if selected not in {"file", "neo4j"}:
        raise RuntimeError("CLOUD_DAST_STAND_SOURCE must be one of: file, neo4j")
    return selected


def _aliased_method_ids(
    method_id: str,
    prefix_aliases: Mapping[str, str],
) -> tuple[str, ...]:
    """Return the exact ID and configured manifest-compatible aliases."""

    method_ids = [method_id]
    for prefix, replacement in prefix_aliases.items():
        if not prefix or not method_id.startswith(prefix):
            continue
        candidate = method_id.replace(prefix, replacement, 1)
        if candidate not in method_ids:
            method_ids.append(candidate)
    return tuple(method_ids)


class FileMethodRepository:
    """Read method specifications from a contract launch fixture."""

    def __init__(
        self,
        contract_file: str | Path,
        *,
        schema_resolver: MessageSchemaResolver | None = None,
    ) -> None:
        manifest = load_contract_manifest(contract_file)
        self._methods = tuple(
            record.to_method_spec(schema_resolver) for record in manifest.methods
        )
        self._methods_by_id = {method.method_id: method for method in self._methods}

    def get_method(self, method_id: str) -> MethodSpec | None:
        return self._methods_by_id.get(normalize_method_id(method_id))

    def list_methods(self, service: str) -> tuple[MethodSpec, ...]:
        return tuple(method for method in self._methods if method.service == service)


class FileInvocationRepository:
    """Resolve invocation metadata from a contract launch fixture."""

    def __init__(
        self,
        contract_file: str | Path,
        *,
        environment: str | None = None,
        method_prefix_aliases: Mapping[str, str] | None = None,
    ) -> None:
        self._manifest = load_contract_manifest(contract_file)
        self._environment = environment
        self._method_prefix_aliases = dict(method_prefix_aliases or {})
        self._records_by_id = {
            record.method_id: record for record in self._manifest.methods
        }

    def get_invocation(self, method_id: str) -> Invocation | None:
        normalized = normalize_method_id(method_id)
        if not normalized.startswith(("grpc:", "grpc-priv:", "http:")):
            return None
        record = self._find_record(normalized)
        if record is None:
            return None
        endpoint = self._select_endpoint()
        if endpoint is None:
            return None
        if normalized.startswith("http:"):
            return self._http_invocation(normalized, record, endpoint.address)
        return self._grpc_invocation(normalized, record, endpoint.address)

    def _find_record(self, method_id: str) -> ContractMethodRecord | None:
        for candidate in _aliased_method_ids(method_id, self._method_prefix_aliases):
            record = self._records_by_id.get(candidate)
            if record is not None:
                return record
        return None

    def _select_endpoint(self) -> ContractEndpointRecord | None:
        endpoints = self._manifest.endpoints
        if not endpoints:
            return None
        if self._environment is None:
            return endpoints[0]
        for endpoint in endpoints:
            if endpoint.environment == self._environment:
                return endpoint
        return None

    @staticmethod
    def _grpc_invocation(
        method_id: str,
        record: ContractMethodRecord,
        endpoint: str,
    ) -> Invocation | None:
        canonical = record.method_id.split(":", 1)[-1]
        service, _, name = canonical.rpartition(".")
        if not service or not name:
            return None
        if not record.input_type:
            return None
        return Invocation(
            method_id=method_id,
            endpoint=endpoint,
            transport="grpc",
            input_type=record.input_type,
            rpc_path=f"/{service}/{name}",
            output_type=record.output_type,
        )

    @staticmethod
    def _http_invocation(
        method_id: str,
        record: ContractMethodRecord,
        endpoint: str,
    ) -> Invocation | None:
        if not record.http_method or not record.path_template:
            return None
        return Invocation(
            method_id=method_id,
            endpoint=endpoint,
            transport="http-json",
            http_method=record.http_method,
            path_template=record.path_template,
            query_fields=record.query_fields,
            header_fields=record.header_fields,
            cookie_fields=record.cookie_fields,
            body_fields=record.body_fields,
        )


class FileContractGraphRepository:
    """Project a contract launch fixture into the ingestion graph slice."""

    def __init__(self, contract_file: str | Path) -> None:
        self._manifest = load_contract_manifest(contract_file)

    def load_slice(self, service: str) -> ServiceGraphSlice:
        if service != self._manifest.service:
            return ServiceGraphSlice(service=service)
        return _manifest_slice(self._manifest)


def _manifest_slice(manifest: ContractManifest) -> ServiceGraphSlice:
    """Build the same graph shape the Neo4j adapter returns for a stand."""

    service_node_id = f"service:{manifest.service}"
    nodes: dict[str, GraphNode] = {
        service_node_id: GraphNode(
            node_id=service_node_id,
            labels=("Service",),
            properties={"canonical_id": manifest.service},
        )
    }
    edges: list[GraphEdge] = []
    for record in manifest.methods:
        method_node_id = f"method:{record.method_id}"
        properties: dict[str, object] = {
            "method_id": record.method_id,
            "name": record.name,
            "layer": record.layer.value,
            "input_fields": [field.model_dump(mode="json") for field in record.fields],
        }
        if record.input_type is not None:
            properties["input_type"] = record.input_type
        if record.output_type is not None:
            properties["output_type"] = record.output_type
        nodes[method_node_id] = GraphNode(
            node_id=method_node_id,
            labels=("Method",),
            properties=properties,
        )
        edges.append(
            GraphEdge(
                edge_id=f"{service_node_id}:method:{record.method_id}",
                source_id=service_node_id,
                target_id=method_node_id,
                kind="EXPOSES_METHOD",
            )
        )
        for permission in sorted(record.permissions):
            permission_node_id = f"permission:{permission}"
            nodes.setdefault(
                permission_node_id,
                GraphNode(
                    node_id=permission_node_id,
                    labels=("Permission",),
                    properties={"permission_id": permission},
                ),
            )
            edges.append(
                GraphEdge(
                    edge_id=f"{method_node_id}:requires:{permission}",
                    source_id=method_node_id,
                    target_id=permission_node_id,
                    kind="REQUIRES",
                )
            )
        for resource_type in sorted(record.resource_types):
            resource_node_id = f"resource_type:{resource_type}"
            nodes.setdefault(
                resource_node_id,
                GraphNode(
                    node_id=resource_node_id,
                    labels=("ResourceType",),
                    properties={"resource_type": resource_type},
                ),
            )
            edges.append(
                GraphEdge(
                    edge_id=f"{method_node_id}:targets:{resource_type}",
                    source_id=method_node_id,
                    target_id=resource_node_id,
                    kind="TARGETS",
                )
            )
    return ServiceGraphSlice(
        service=manifest.service,
        nodes=tuple(nodes.values()),
        edges=tuple(edges),
    )


def select_method_repository(
    session_factory: SessionFactory | None = None,
    *,
    source: str | None = None,
    contract_file: Path | None = None,
    schema_resolver: MessageSchemaResolver | None = None,
) -> MethodRepository:
    """Select the configured method repository without coupling to Dishka."""

    selected = _selected_stand_source(source)
    if selected == "file":
        return FileMethodRepository(
            configured_contract_file(contract_file),
            schema_resolver=schema_resolver,
        )
    if session_factory is None:
        raise RuntimeError("the neo4j method repository requires a session factory")
    return Neo4jMethodRepository(session_factory, schema_resolver=schema_resolver)


def select_invocation_repository(
    session_factory: SessionFactory | None = None,
    *,
    source: str | None = None,
    contract_file: Path | None = None,
    environment: str | None = None,
    method_prefix_aliases: Mapping[str, str] | None = None,
) -> InvocationRepository:
    """Select the configured invocation repository without coupling to Dishka."""

    selected = _selected_stand_source(source)
    if selected == "file":
        return FileInvocationRepository(
            configured_contract_file(contract_file),
            environment=environment,
            method_prefix_aliases=method_prefix_aliases,
        )
    if session_factory is None:
        raise RuntimeError("the neo4j invocation repository requires a session factory")
    return Neo4jInvocationRepository(
        session_factory,
        environment=environment,
        method_prefix_aliases=method_prefix_aliases,
    )


def select_contract_graph_repository(
    session_factory: SessionFactory | None = None,
    *,
    source: str | None = None,
    contract_file: Path | None = None,
) -> ContractGraphRepository:
    """Select the configured contract graph repository."""

    selected = _selected_stand_source(source)
    if selected == "file":
        return FileContractGraphRepository(configured_contract_file(contract_file))
    if session_factory is None:
        raise RuntimeError(
            "the neo4j contract graph repository requires a session factory"
        )
    return Neo4jContractGraphRepository(session_factory)


class AppProvider(Provider):
    def __init__(
        self,
        *,
        endpoint_environment: str | None = None,
        method_prefix_aliases: Mapping[str, str] | None = None,
        schema_resolver: MessageSchemaResolver | None = None,
    ) -> None:
        super().__init__()
        self._endpoint_environment = endpoint_environment
        self._method_prefix_aliases = dict(method_prefix_aliases or {})
        self._schema_resolver = schema_resolver

    session_factory = from_context(SessionFactory, scope=AppScope)
    target = from_context(Target, scope=AppScope)
    event_store = from_context(EventStore, scope=AppScope)

    @provide(scope=AppScope, provides=MethodRepository)
    def method_repository(self, session_factory: SessionFactory) -> MethodRepository:
        return select_method_repository(
            session_factory,
            schema_resolver=self._schema_resolver,
        )

    @provide(scope=AppScope, provides=InvocationRepository)
    def invocation_repository(
        self, session_factory: SessionFactory
    ) -> InvocationRepository:
        return select_invocation_repository(
            session_factory,
            environment=self._endpoint_environment,
            method_prefix_aliases=self._method_prefix_aliases,
        )

    @provide(scope=AppScope, provides=ContractGraphRepository)
    def contract_graph_repository(
        self, session_factory: SessionFactory
    ) -> ContractGraphRepository:
        return select_contract_graph_repository(session_factory)

    @provide(scope=AppScope, provides=FormalRepository)
    def formal_repository(self, session_factory: SessionFactory) -> FormalRepository:
        return select_formal_repository(session_factory)


def select_formal_repository(
    session_factory: SessionFactory | None = None,
) -> FormalRepository:
    """Select the configured formal store without coupling callers to Dishka."""

    store = os.environ.get("CLOUD_DAST_FORMAL_STORE", "sqlite").strip().lower()
    if store == "sqlite":
        path = os.environ.get(
            "CLOUD_DAST_FORMAL_SQLITE_PATH",
            "cloud-dast-formal.sqlite3",
        )
        return SqliteFormalRepository(Path(path))
    if store == "neo4j":
        if session_factory is None:
            raise RuntimeError("the neo4j formal store requires a session factory")
        return Neo4jFormalRepository(session_factory)
    raise RuntimeError("CLOUD_DAST_FORMAL_STORE must be one of: sqlite, neo4j")


@contextmanager
def open_formal_repository(session_factory: SessionFactory | None = None):
    """Open the configured formal store and close its process-local resources."""

    store = os.environ.get("CLOUD_DAST_FORMAL_STORE", "sqlite").strip().lower()
    if store == "sqlite":
        path = os.environ.get(
            "CLOUD_DAST_FORMAL_SQLITE_PATH",
            "cloud-dast-formal.sqlite3",
        )
        with SqliteFormalRepository(Path(path)) as repository:
            yield repository
        return
    if store == "neo4j":
        if session_factory is None:
            raise RuntimeError("the neo4j formal store requires a session factory")
        repository = Neo4jFormalRepository(session_factory)
        try:
            yield repository
        finally:
            session_factory.close()
        return
    raise RuntimeError("CLOUD_DAST_FORMAL_STORE must be one of: sqlite, neo4j")
