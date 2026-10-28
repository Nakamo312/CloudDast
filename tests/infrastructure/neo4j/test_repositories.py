from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from cloud_dast.infrastructure import Neo4jMethodRepository
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class FakeSession:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.queries: list[str] = []
        self.params: list[dict[str, Any]] = []

    def run(self, query: str, **params: Any) -> FakeResult:
        self.queries.append(query)
        self.params.append(params)
        return FakeResult(self.rows)


def make_session_factory(rows: list[dict[str, Any]]):
    session = FakeSession(rows)

    @contextmanager
    def factory():
        yield session

    return factory, session


def test_get_method_reads_existing_neo4j_contract_graph() -> None:
    row = {
        "method": {
            "method_id": "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
            "name": "Get",
            "input_type": "yandex.cloud.priv.lockbox.v1.GetPayloadRequest",
            "output_type": "yandex.cloud.priv.lockbox.v1.Payload",
            "input_fields": (
                '[{"name":"secret_id","type":"string","required":true,'
                '"repeated":false,"oneof":null},'
                '{"name":"page_token","type":"string","required":false,'
                '"repeated":false,"oneof":null}]'
            ),
        },
        "package": "yandex.cloud.priv.lockbox.v1",
        "services": ["lockbox"],
        "resource_types": ["lockbox.secret"],
        "permissions": ["lockbox.secrets.getPayload"],
    }
    factory, session = make_session_factory([row])
    repository = Neo4jMethodRepository(factory)

    method = repository.get_method("yandex.cloud.priv.lockbox.v1.PayloadService/Get")

    assert method is not None
    assert method.method_id == (
        "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
    )
    assert method.service == "lockbox"
    assert method.layer is EndpointLayer.PRIVATE
    assert method.resource_types == frozenset({"lockbox.secret"})
    assert method.permissions == frozenset({"lockbox.secrets.getPayload"})
    assert method.fields == (
        FieldSpec(name="secret_id", type="string", required=True),
        FieldSpec(name="page_token", type="string", required=False),
    )
    assert session.params[0]["method_id"] == (
        "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
    )


def test_get_method_maps_graph_gateway_layer() -> None:
    row = {
        "method": {
            "method_id": "grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            "name": "Get",
            "input_fields": "[]",
        },
        "package": "yandex.cloud.lockbox.v1",
        "layer": "gateway",
        "services": ["lockbox"],
        "resource_types": ["lockbox.secret"],
        "permissions": ["lockbox.secrets.getPayload"],
    }
    factory, _ = make_session_factory([row])
    repository = Neo4jMethodRepository(factory)

    method = repository.get_method("yandex.cloud.lockbox.v1.PayloadService/Get")

    assert method is not None
    assert method.layer is EndpointLayer.GATEWAY


def test_get_method_reads_field_constraints() -> None:
    row = {
        "method": {
            "method_id": "grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            "name": "Get",
            "input_fields": (
                '[{"name":"limit","type":"int32","required":true,'
                '"minimum":5,"maximum":10},'
                '{"name":"mode","type":"string","required":true,'
                '"enum_values":["read","write"]}]'
            ),
        },
        "package": "yandex.cloud.lockbox.v1",
        "layer": "private",
        "services": ["lockbox"],
        "resource_types": [],
        "permissions": [],
    }
    factory, _ = make_session_factory([row])
    repository = Neo4jMethodRepository(factory)

    method = repository.get_method("yandex.cloud.lockbox.v1.PayloadService.Get")

    assert method is not None
    assert method.fields == (
        FieldSpec(
            name="limit",
            type="int32",
            required=True,
            minimum=5,
            maximum=10,
        ),
        FieldSpec(
            name="mode",
            type="string",
            required=True,
            enum_values=("read", "write"),
        ),
    )


def test_get_method_falls_back_to_prefix_when_layer_is_invalid() -> None:
    row = {
        "method": {
            "method_id": "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
            "name": "Get",
            "input_fields": "[]",
        },
        "package": "yandex.cloud.priv.lockbox.v1",
        "layer": "unknown-layer",
        "services": ["lockbox"],
        "resource_types": [],
        "permissions": [],
    }
    factory, _ = make_session_factory([row])
    repository = Neo4jMethodRepository(factory)

    method = repository.get_method("yandex.cloud.priv.lockbox.v1.PayloadService/Get")

    assert method is not None
    assert method.layer is EndpointLayer.PRIVATE


def test_list_methods_reads_all_methods_for_service() -> None:
    rows = [
        {
            "method": {
                "method_id": "grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
                "name": "Get",
                "input_type": "GetPayloadRequest",
                "output_type": "Payload",
                "input_fields": "[]",
            },
            "service": "lockbox",
            "resource_types": ["lockbox.secret"],
            "permissions": ["lockbox.secrets.getPayload"],
        },
        {
            "method": {
                "method_id": "grpc:yandex.cloud.lockbox.v1.PayloadService.GetEx",
                "name": "GetEx",
                "input_type": "GetExRequest",
                "output_type": "GetExResponse",
                "input_fields": "[]",
            },
            "service": "lockbox",
            "resource_types": ["lockbox.secret"],
            "permissions": ["lockbox.secrets.getPayload"],
        },
    ]
    factory, session = make_session_factory(rows)
    repository = Neo4jMethodRepository(factory)

    methods = repository.list_methods("lockbox")

    assert [method.name for method in methods] == ["Get", "GetEx"]
    assert session.params == [{"service": "lockbox"}]


def test_get_method_returns_none_when_graph_has_no_method() -> None:
    factory, _ = make_session_factory([])
    repository = Neo4jMethodRepository(factory)

    assert repository.get_method("missing") is None
