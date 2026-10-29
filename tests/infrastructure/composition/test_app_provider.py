"""Wiring tests for the Neo4j-free file contract composition (B29)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from cloud_dast.composition import live as live_composition
from cloud_dast.composition.app_provider import (
    FileContractGraphRepository,
    FileInvocationRepository,
    FileMethodRepository,
    select_contract_graph_repository,
    select_invocation_repository,
    select_method_repository,
)
from cloud_dast.composition.live import make_live_container
from cloud_dast.composition.run_provider import FileScenarioRepository
from cloud_dast.infrastructure.neo4j import (
    Neo4jContractGraphRepository,
    Neo4jInvocationRepository,
    Neo4jMethodRepository,
)
from cloud_dast.infrastructure.neo4j.common.repository import Neo4jConfig
from cloud_dast.infrastructure.runtime import GrpcResult
from cloud_dast.model import FieldSpec, GrpcStatus, RequestSchema, ResponseSchema
from cloud_dast.ports import (
    ContractGraphRepository,
    InvocationRepository,
    MethodRepository,
    ScenarioRepository,
)
from cloud_dast.verification.contract_projection import (
    ContractProjector,
)
from tests.support.guardrails import AllowAllGuardrail

pytestmark = pytest.mark.usefixtures("file_contract_environment")


class Codec:
    def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
        return b"request"

    def decode(self, output_type: str, response: bytes) -> object:
        return object()


class Tokens:
    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]:
        return (("authorization", "Bearer test"),)


class Transport:
    def invoke(self, call) -> GrpcResult:
        return GrpcResult(GrpcStatus(code="OK"), "ok")


class SchemaResolver:
    def request_schema(self, name: str) -> RequestSchema:
        return RequestSchema(
            type_name=name,
            fields=(FieldSpec(name="from_descriptor", type="string"),),
        )

    def response_schema(self, name: str) -> ResponseSchema:
        return ResponseSchema(
            type_name=name,
            fields=(FieldSpec(name="response_value", type="string"),),
        )


class _EmptyEventStore:
    def append(self, event: object) -> None:
        return None

    def read(self) -> Iterator[object]:
        return iter(())

    def read_new(self, consumer_id: str) -> tuple[object, ...]:
        return ()


@pytest.fixture()
def contract_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def contract_file(contract_dir: Path) -> Path:
    path = contract_dir / "contract.json"
    path.write_text(
        json.dumps(
            {
                "service": "nsfy.shop.v1",
                "endpoints": [
                    {"address": "bench:50051", "environment": "bench"},
                    {"address": "preprod:443", "environment": "preprod"},
                ],
                "methods": [
                    {
                        "method_id": "grpc:nsfy.shop.v1.OrderService.GetOrder",
                        "service": "nsfy.shop.v1",
                        "name": "GetOrder",
                        "layer": "public",
                        "permissions": ["nsfy.order.get"],
                        "resource_types": ["order"],
                        "fields": [
                            {"name": "order_id", "type": "string", "required": True}
                        ],
                        "input_type": "nsfy.shop.v1.GetOrderRequest",
                        "output_type": "nsfy.shop.v1.GetOrderResponse",
                    },
                    {
                        "method_id": "grpc:nsfy.shop.v1.OrderService.CreateOrder",
                        "service": "nsfy.shop.v1",
                        "name": "CreateOrder",
                        "permissions": ["nsfy.order.create"],
                        "resource_types": ["order"],
                        "input_type": "nsfy.shop.v1.CreateOrderRequest",
                    },
                    {
                        "method_id": "http:orders.get",
                        "service": "nsfy.shop.v1",
                        "name": "get",
                        "layer": "public",
                        "http_method": "POST",
                        "path_template": "/orders/{order_id}",
                        "query_fields": ["limit"],
                        "body_fields": ["note"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_file_method_repository_uses_descriptor_schema_resolver(
    contract_file: Path,
) -> None:
    repository = FileMethodRepository(
        contract_file,
        schema_resolver=SchemaResolver(),
    )

    method = repository.get_method("grpc:nsfy.shop.v1.OrderService.GetOrder")

    assert method is not None
    assert method.request_schema.fields[0].name == "from_descriptor"
    assert method.response_schema is not None
    assert method.response_schema.fields[0].name == "response_value"


@pytest.fixture()
def stand_file(contract_dir: Path) -> Path:
    path = contract_dir / "stand.json"
    path.write_text(
        json.dumps(
            {
                "permissions": [
                    {
                        "subject": "attacker",
                        "action": "grpc:nsfy.shop.v1.OrderService.GetOrder",
                        "resource": "order",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def file_contract_environment(
    monkeypatch: pytest.MonkeyPatch,
    contract_file: Path,
    stand_file: Path,
    contract_dir: Path,
) -> None:
    for name in (
        "CPA_NEO4J_URI",
        "CPA_NEO4J_USER",
        "CPA_NEO4J_PASSWORD",
        "CPA_NEO4J_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(stand_file))
    monkeypatch.setenv("CLOUD_DAST_CONTRACT_FILE", str(contract_file))
    monkeypatch.setenv("CLOUD_DAST_FORMAL_STORE", "sqlite")
    monkeypatch.setenv(
        "CLOUD_DAST_FORMAL_SQLITE_PATH", str(contract_dir / "formal.sqlite3")
    )


def test_file_method_repository_reads_declared_methods(contract_file: Path) -> None:
    repository = FileMethodRepository(contract_file)

    methods = repository.list_methods("nsfy.shop.v1")

    assert tuple(method.method_id for method in methods) == (
        "grpc:nsfy.shop.v1.OrderService.GetOrder",
        "grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "http:orders.get",
    )
    method = repository.get_method("nsfy.shop.v1.OrderService.GetOrder")
    assert method is not None
    assert method.layer.value == "public"
    assert method.permissions == frozenset({"nsfy.order.get"})
    assert method.resource_types == frozenset({"order"})
    assert method.fields[0].name == "order_id"
    assert repository.get_method("grpc:nsfy.shop.v1.OrderService.Missing") is None
    assert repository.list_methods("other.service") == ()


def test_file_invocation_repository_selects_endpoint_by_environment(
    contract_file: Path,
) -> None:
    repository = FileInvocationRepository(
        contract_file,
        environment="bench",
    )

    invocation = repository.get_invocation("grpc:nsfy.shop.v1.OrderService.GetOrder")

    assert invocation is not None
    assert invocation.endpoint == "bench:50051"
    assert invocation.transport == "grpc"
    assert invocation.input_type == "nsfy.shop.v1.GetOrderRequest"
    assert invocation.output_type == "nsfy.shop.v1.GetOrderResponse"
    assert invocation.rpc_path == "/nsfy.shop.v1.OrderService/GetOrder"


def test_file_invocation_repository_without_environment_uses_first_endpoint(
    contract_file: Path,
) -> None:
    repository = FileInvocationRepository(contract_file)

    invocation = repository.get_invocation("grpc:nsfy.shop.v1.OrderService.GetOrder")

    assert invocation is not None
    assert invocation.endpoint == "bench:50051"


def test_file_invocation_repository_rejects_unknown_environment(
    contract_file: Path,
) -> None:
    repository = FileInvocationRepository(
        contract_file,
        environment="production",
    )

    assert repository.get_invocation("grpc:nsfy.shop.v1.OrderService.GetOrder") is None


def test_file_invocation_repository_resolves_http_methods(
    contract_file: Path,
) -> None:
    repository = FileInvocationRepository(contract_file, environment="bench")

    invocation = repository.get_invocation("http:orders.get")

    assert invocation is not None
    assert invocation.transport == "http-json"
    assert invocation.endpoint == "bench:50051"
    assert invocation.http_method == "POST"
    assert invocation.path_template == "/orders/{order_id}"
    assert invocation.query_fields == ("limit",)
    assert invocation.body_fields == ("note",)


def test_file_invocation_repository_applies_prefix_aliases(
    contract_file: Path,
) -> None:
    repository = FileInvocationRepository(
        contract_file,
        environment="bench",
        method_prefix_aliases={
            "grpc-priv:nsfy.shop.": "grpc:nsfy.shop.",
        },
    )

    invocation = repository.get_invocation(
        "grpc-priv:nsfy.shop.v1.OrderService.GetOrder"
    )

    assert invocation is not None
    assert invocation.method_id == "grpc-priv:nsfy.shop.v1.OrderService.GetOrder"
    assert invocation.input_type == "nsfy.shop.v1.GetOrderRequest"


def test_file_contract_graph_repository_builds_the_ingestion_slice(
    contract_file: Path,
) -> None:
    repository = FileContractGraphRepository(contract_file)

    graph_slice = repository.load_slice("nsfy.shop.v1")

    nodes = {node.node_id: node for node in graph_slice.nodes}
    edges = {(edge.source_id, edge.target_id, edge.kind) for edge in graph_slice.edges}

    assert set(nodes) == {
        "service:nsfy.shop.v1",
        "method:grpc:nsfy.shop.v1.OrderService.GetOrder",
        "method:grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "method:http:orders.get",
        "permission:nsfy.order.get",
        "permission:nsfy.order.create",
        "resource_type:order",
    }
    assert (
        "service:nsfy.shop.v1",
        "method:grpc:nsfy.shop.v1.OrderService.GetOrder",
        "EXPOSES_METHOD",
    ) in edges
    assert (
        "method:grpc:nsfy.shop.v1.OrderService.GetOrder",
        "permission:nsfy.order.get",
        "REQUIRES",
    ) in edges
    assert (
        "method:grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "resource_type:order",
        "TARGETS",
    ) in edges
    method = nodes["method:grpc:nsfy.shop.v1.OrderService.GetOrder"]
    assert method.properties["input_type"] == "nsfy.shop.v1.GetOrderRequest"
    assert method.properties["input_fields"][0]["name"] == "order_id"
    assert method.properties["input_fields"][0]["type"] == "string"
    assert method.properties["input_fields"][0]["required"] is True
    empty = repository.load_slice("other.service.v1")
    assert empty.nodes == ()
    assert empty.edges == ()


def test_file_contract_slice_projects_through_the_real_projector(
    contract_file: Path,
) -> None:
    repository = FileContractGraphRepository(contract_file)

    projection = ContractProjector().project(repository.load_slice("nsfy.shop.v1"))

    assert not projection.report.unmapped
    assert not projection.report.conflict
    predicates = {fact.predicate.name for fact in projection.graph.facts}
    assert {"is", "requires", "targets", "field_required"} <= predicates
    facts = {
        (
            fact.predicate.name,
            *(argument.value for argument in fact.args if hasattr(argument, "value")),
        )
        for fact in projection.graph.facts
    }
    assert (
        "requires",
        "action:grpc:nsfy.shop.v1.OrderService.GetOrder",
        "permission:nsfy.order.get",
    ) in facts
    assert (
        "targets",
        "action:grpc:nsfy.shop.v1.OrderService.GetOrder",
        "resource:order",
    ) in facts


def test_selectors_choose_file_repositories_by_default() -> None:
    assert isinstance(select_method_repository(None), FileMethodRepository)
    assert isinstance(select_invocation_repository(None), FileInvocationRepository)
    assert isinstance(
        select_contract_graph_repository(None), FileContractGraphRepository
    )


def test_selectors_require_a_session_factory_for_neo4j() -> None:
    with pytest.raises(RuntimeError, match="neo4j method repository"):
        select_method_repository(None, source="neo4j")
    with pytest.raises(RuntimeError, match="neo4j invocation repository"):
        select_invocation_repository(None, source="neo4j")
    with pytest.raises(RuntimeError, match="neo4j contract graph repository"):
        select_contract_graph_repository(None, source="neo4j")


def test_selectors_reject_unknown_sources() -> None:
    with pytest.raises(RuntimeError, match="CLOUD_DAST_STAND_SOURCE"):
        select_method_repository(None, source="csv")


def _fake_session_factory():
    @contextmanager
    def session_factory() -> Iterator[dict[str, Any]]:
        yield {}

    return session_factory


def test_selectors_use_neo4j_adapters_when_selected() -> None:
    session_factory = _fake_session_factory()

    assert isinstance(
        select_method_repository(session_factory, source="neo4j"),
        Neo4jMethodRepository,
    )
    assert isinstance(
        select_invocation_repository(session_factory, source="neo4j"),
        Neo4jInvocationRepository,
    )
    assert isinstance(
        select_contract_graph_repository(session_factory, source="neo4j"),
        Neo4jContractGraphRepository,
    )


def test_make_live_container_is_neo4j_free_for_file_stands(
    monkeypatch: pytest.MonkeyPatch,
    contract_dir: Path,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "bench:50051")
    monkeypatch.setattr(
        live_composition,
        "make_session_factory",
        lambda config: pytest.fail("file stands must not create a Neo4j session"),
    )

    container = make_live_container(
        Codec(),
        event_store=_EmptyEventStore(),
        tokens=Tokens(),
        transport=Transport(),
        guardrail=AllowAllGuardrail(),
        endpoint_environment="bench",
    )

    with container as app, app() as run:
        assert isinstance(run.get(MethodRepository), FileMethodRepository)
        assert isinstance(run.get(InvocationRepository), FileInvocationRepository)
        assert isinstance(run.get(ContractGraphRepository), FileContractGraphRepository)
        assert isinstance(run.get(ScenarioRepository), FileScenarioRepository)


def test_make_live_container_keeps_explicit_neo4j_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    session_factory = _fake_session_factory()
    monkeypatch.setattr(
        live_composition, "make_session_factory", lambda config: session_factory
    )

    container = make_live_container(
        Codec(),
        event_store=_EmptyEventStore(),
        config=Neo4jConfig("bolt://neo4j", "neo4j", "password"),
        tokens=Tokens(),
        transport=Transport(),
        guardrail=AllowAllGuardrail(),
    )

    with container as app, app() as run:
        assert isinstance(run.get(MethodRepository), Neo4jMethodRepository)
        assert isinstance(run.get(InvocationRepository), Neo4jInvocationRepository)
        assert isinstance(
            run.get(ContractGraphRepository), Neo4jContractGraphRepository
        )
