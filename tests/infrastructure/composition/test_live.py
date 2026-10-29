from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from cloud_dast.composition import (
    check_live_prerequisites,
    make_live_container,
    make_live_target,
)
from cloud_dast.composition import live as live_composition
from cloud_dast.infrastructure.neo4j.common.repository import Neo4jConfig
from cloud_dast.infrastructure.runtime import GrpcResult
from cloud_dast.infrastructure.runtime.http_json import HttpCall, HttpResult
from cloud_dast.model import (
    AccessOutcome,
    Check,
    GrpcStatus,
    HttpStatus,
    JsonValue,
    ResponseData,
)
from cloud_dast.ports import (
    Invocation,
    InvocationRepository,
    Target,
)
from tests.support.guardrails import AllowAllGuardrail


class Codec:
    def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
        return b"request"

    def decode(self, output_type: str, response: bytes) -> ResponseData:
        return ResponseData()

    def decode_full(
        self, output_type: str, response: bytes
    ) -> tuple[tuple[str, JsonValue], ...]:
        return ()


class Tokens:
    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]:
        return (("authorization", "Bearer test"),)


class Transport:
    def __init__(self) -> None:
        self.calls = []

    def invoke(self, call) -> GrpcResult:
        self.calls.append(call)
        return GrpcResult(GrpcStatus(code="OK"), "ok")


class HttpTransport:
    def __init__(self, result: HttpResult) -> None:
        self.result = result
        self.calls: list[HttpCall] = []

    def send(self, call: HttpCall) -> HttpResult:
        self.calls.append(call)
        return self.result


class _Session:
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self.queries.append((query, dict(params)))
        return [self.row]


class _StaticMethodRepository:
    def get_method(self, method_id: str):
        return None

    def list_methods(self, service: str):
        return ()


class _StaticInvocationRepository:
    def __init__(self, invocation: Invocation | None) -> None:
        self.invocation = invocation

    def get_invocation(self, method_id: str) -> Invocation | None:
        if self.invocation is None:
            return None
        return self.invocation if self.invocation.method_id == method_id else None


class _EmptyEventStore:
    def append(self, event: object) -> None:
        return None

    def read(self) -> Iterator[object]:
        return iter(())

    def read_new(self, consumer_id: str) -> tuple[object, ...]:
        return ()


def _check() -> Check:
    return Check(
        invariant_id="invariant",
        method_id="grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
        scenario_id="scenario",
        request=(("secret_id", "secret"),),
        identities=("attacker",),
    )


def test_preflight_does_not_require_neo4j_for_file_stands(
    monkeypatch, tmp_path
) -> None:
    for name in ("CPA_NEO4J_URI", "CPA_NEO4J_USER", "CPA_NEO4J_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(tmp_path / "stand.json"))
    monkeypatch.setenv("CLOUD_DAST_CONTRACT_FILE", str(tmp_path / "contract.json"))
    (tmp_path / "stand.json").write_text("{}", encoding="utf-8")
    (tmp_path / "contract.json").write_text("{}", encoding="utf-8")

    result = check_live_prerequisites()

    assert not any("CPA_NEO4J" in item for item in result.missing)


def test_preflight_reports_missing_neo4j_configuration(monkeypatch) -> None:
    for name in ("CPA_NEO4J_URI", "CPA_NEO4J_USER", "CPA_NEO4J_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")

    result = check_live_prerequisites()

    assert "CPA_NEO4J_URI" in result.missing
    assert "CPA_NEO4J_USER" in result.missing
    assert "CPA_NEO4J_PASSWORD" in result.missing
    assert not any(item.startswith("stand file") for item in result.missing)
    assert not any(item.startswith("contract file") for item in result.missing)


def test_preflight_reports_missing_file_contract(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(tmp_path / "stand.json"))
    monkeypatch.setenv("CLOUD_DAST_CONTRACT_FILE", str(tmp_path / "contract.json"))
    (tmp_path / "stand.json").write_text("{}", encoding="utf-8")

    result = check_live_prerequisites()

    assert f"contract file {tmp_path / 'contract.json'}" in result.missing


def test_preflight_rejects_unknown_stand_source(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "csv")

    result = check_live_prerequisites()

    assert "CLOUD_DAST_STAND_SOURCE must be one of: file, neo4j" in result.missing


def test_preflight_reports_missing_file_stand(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(tmp_path / "missing-stand.json"))

    result = check_live_prerequisites()

    assert f"stand file {tmp_path / 'missing-stand.json'}" in result.missing


def test_preflight_reports_missing_external_oob_configuration(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_OOB_SERVER_URL", "https://collaborator.test")
    monkeypatch.delenv("CLOUD_DAST_OOB_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_OOB_TOKEN_FILE", raising=False)

    result = check_live_prerequisites()

    assert "CLOUD_DAST_OOB_TOKEN for CLOUD_DAST_OOB_SERVER_URL" in result.missing


def test_preflight_reports_invalid_external_oob_poll_interval(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_OOB_SERVER_URL", "https://collaborator.test")
    monkeypatch.setenv("CLOUD_DAST_OOB_TOKEN", "server-token")
    monkeypatch.setenv("CLOUD_DAST_OOB_POLL_INTERVAL", "not-a-number")

    result = check_live_prerequisites()

    assert "CLOUD_DAST_OOB_POLL_INTERVAL must be a number" in result.missing


def test_preflight_rejects_cleartext_external_oob_server(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_OOB_SERVER_URL", "http://collaborator.test")
    monkeypatch.setenv("CLOUD_DAST_OOB_TOKEN", "server-token")

    result = check_live_prerequisites()

    assert "CLOUD_DAST_OOB_SERVER_URL must be an HTTPS origin" in result.missing


def test_preflight_rejects_global_token_for_explicit_identity(monkeypatch) -> None:
    for name in (
        "CLOUD_DAST_TOKEN_ATTACKER",
        "CLOUD_DAST_TOKEN_ATTACKER_FILE",
        "CLOUD_DAST_TOKEN_ATTACKER_COMMAND",
        "CLOUD_DAST_IAM_TOKEN_FILE",
        "CLOUD_DAST_IAM_TOKEN_COMMAND",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUD_DAST_IAM_TOKEN", "t1.global")
    monkeypatch.setenv("CLOUD_DAST_IAM_TOKEN_COMMAND", "true")

    result = check_live_prerequisites("attacker")

    assert (
        "CLOUD_DAST_TOKEN_ATTACKER or CLOUD_DAST_TOKEN_ATTACKER_COMMAND"
        in result.missing
    )
    assert not any("CLOUD_DAST_IAM_TOKEN" in item for item in result.missing)


def _invocation() -> Invocation:
    return Invocation(
        method_id="grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
        input_type="GetPayloadRequest",
        rpc_path="/yandex.cloud.priv.lockbox.v1.PayloadService/Get",
        endpoint="payload.example:443",
    )


def _http_invocation() -> Invocation:
    return Invocation(
        method_id="http:orders.get",
        endpoint="https://api.example.test",
        transport="http-json",
        http_method="POST",
        path_template="/orders/{order_id}",
        query_fields=("limit",),
        body_fields=("note",),
    )


def _http_check() -> Check:
    return Check(
        invariant_id="invariant",
        method_id="http:orders.get",
        scenario_id="scenario",
        request=(("order_id", 42), ("limit", 10), ("note", "hello")),
        identities=("attacker",),
    )


def _http_result() -> HttpResult:
    return HttpResult(
        status_code=200,
        body=b'{"order":{"id":42}}',
        headers=(("content-type", "application/json"),),
        final_url="https://api.example.test/orders/42?limit=10",
    )


def test_preflight_skips_grpc_dependencies_for_http_json(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_TARGET", "http-json")

    result = check_live_prerequisites()

    assert not any(
        item in {"python package grpcio", "python package protobuf"}
        or item.startswith("descriptor file ")
        or item == "CLOUD_DAST_DESCRIPTOR_SET"
        for item in result.missing
    )


def test_target_kind_rejects_unknown_transport() -> None:
    with pytest.raises(RuntimeError, match="CLOUD_DAST_TARGET"):
        live_composition.resolve_target_kind("rest")


def test_live_target_injects_runtime_ports(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    target = make_live_target(
        _StaticMethodRepository(),
        _StaticInvocationRepository(_invocation()),
        Codec(),
        tokens=Tokens(),
        transport=Transport(),
        guardrail=AllowAllGuardrail(),
    )
    assert callable(target)


def test_live_target_routes_checks_through_guarded_grpc_target(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    transport = Transport()
    target = make_live_target(
        _StaticMethodRepository(),
        _StaticInvocationRepository(_invocation()),
        Codec(),
        tokens=Tokens(),
        transport=transport,
        guardrail=AllowAllGuardrail(),
    )
    observation = target(_check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert len(transport.calls) == 1
    assert transport.calls[0].endpoint == "payload.example:443"


def test_live_target_selects_http_json_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_TARGET", "http-json")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "https://api.example.test")
    transport = HttpTransport(_http_result())

    target = make_live_target(
        _StaticMethodRepository(),
        _StaticInvocationRepository(_http_invocation()),
        tokens=Tokens(),
        http_transport=transport,
        guardrail=AllowAllGuardrail(),
        safe_fields=("order.id",),
    )

    observation = target(_http_check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert observation.transport_status == HttpStatus(code=200)
    assert observation.output is not None
    assert observation.output.fields == (("order.id", 42),)
    assert len(transport.calls) == 1
    assert transport.calls[0].http_method == "POST"
    assert transport.calls[0].path == "/orders/42"
    assert transport.calls[0].query == (("limit", "10"),)


def test_live_container_assembles_target_from_durable_repository_ports(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    monkeypatch.delenv("CLOUD_DAST_MODEL_URL", raising=False)
    session = _Session(
        {
            "method": {"input_type": "GetPayloadRequest"},
            "package": "yandex.cloud.priv.lockbox.v1",
            "endpoint": "payload.example:443",
        }
    )

    @contextmanager
    def session_factory() -> Any:
        yield session

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
        endpoint_environment="preprod",
    )

    with container as app, app() as run:
        target = run.get(Target)
        observation = target(_check())
        invocations = run.get(InvocationRepository)
        invocation = invocations.get_invocation(
            "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
        )

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert invocation is not None
    assert invocation.endpoint == "payload.example:443"
    assert session.queries


def test_live_container_applies_profile_method_prefix_aliases(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    method_id = "grpc-priv:yandex.cloud.lockbox.v1.PayloadService.Get"
    graph_method_id = "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
    session = _Session(
        {
            "method": {"input_type": "GetPayloadRequest"},
            "package": "yandex.cloud.priv.lockbox.v1",
            "endpoint": "payload.example:443",
        }
    )

    @contextmanager
    def session_factory() -> Any:
        yield session

    monkeypatch.setattr(
        live_composition, "make_session_factory", lambda config: session_factory
    )
    container = make_live_container(
        event_store=_EmptyEventStore(),
        config=Neo4jConfig("bolt://neo4j", "neo4j", "password"),
        method_prefix_aliases={
            "grpc-priv:yandex.cloud.": "grpc-priv:yandex.cloud.priv."
        },
    )

    with container as app, app() as run:
        invocation = run.get(InvocationRepository).get_invocation(method_id)

    assert invocation is not None
    assert invocation.method_id == method_id
    assert session.queries[-1][1]["method_ids"] == (method_id, graph_method_id)


def test_live_container_routes_http_json_from_durable_repository(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "https://api.example.test")
    session = _Session(
        {
            "method": {
                "method_id": "http:orders.get",
                "http_method": "POST",
                "path_template": "/orders/{order_id}",
                "query_fields": ["limit"],
                "body_fields": ["note"],
            },
            "package": "orders",
            "endpoint": "https://api.example.test",
        }
    )

    @contextmanager
    def session_factory() -> Any:
        yield session

    monkeypatch.setattr(
        live_composition, "make_session_factory", lambda config: session_factory
    )
    transport = HttpTransport(_http_result())
    container = make_live_container(
        event_store=_EmptyEventStore(),
        config=Neo4jConfig("bolt://neo4j", "neo4j", "password"),
        tokens=Tokens(),
        http_transport=transport,
        guardrail=AllowAllGuardrail(),
        target_kind="http-json",
        safe_fields=("order.id",),
    )

    with container as app, app() as run:
        target = run.get(Target)
        observation = target(_http_check())
        invocations = run.get(InvocationRepository)
        invocation = invocations.get_invocation("http:orders.get")

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert observation.output is not None
    assert observation.output.fields == (("order.id", 42),)
    assert invocation is not None
    assert invocation.transport == "http-json"
    assert invocation.endpoint == "https://api.example.test"
    assert transport.calls[0].path == "/orders/42"


def test_live_container_requires_explicit_event_log(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_EVENT_LOG", raising=False)
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_SERVICES", raising=False)
    config = Neo4jConfig("bolt://neo4j", "neo4j", "password")
    try:
        make_live_container(
            Codec(), config=config, tokens=Tokens(), transport=Transport()
        )
    except RuntimeError as exc:
        assert "event_store or event_path" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("live container must require an explicit event store")
