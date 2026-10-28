from __future__ import annotations

import sys
from contextlib import contextmanager
from types import ModuleType
from typing import Any

import pytest

from cloud_dast.composition import make_grpc_target
from cloud_dast.infrastructure.neo4j.invocations import Neo4jInvocationRepository
from cloud_dast.infrastructure.neo4j.methods.method_repository import (
    Neo4jMethodRepository,
)
from cloud_dast.infrastructure.runtime import (
    GrpcCall,
    GrpcioTransport,
    GrpcResult,
    GrpcTarget,
)
from cloud_dast.infrastructure.runtime import grpc as grpc_runtime
from cloud_dast.model import (
    AccessOutcome,
    Check,
    GrpcStatus,
    JsonValue,
    ResponseData,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import Invocation
from tests.support.guardrails import AllowAllGuardrail


class Codec:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.full_trees: dict[bytes, tuple[tuple[str, JsonValue], ...]] = {}

    def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
        self.calls.append((input_type, request))
        return b"encoded"

    def decode(self, output_type: str, response: bytes) -> ResponseData:
        assert output_type == "GetPayloadResponse"
        assert response == b"response"
        return ResponseData(fields=(("secret_id", "secret"),))

    def decode_full(
        self, output_type: str, response: bytes
    ) -> tuple[tuple[str, JsonValue], ...]:
        assert output_type == "GetPayloadResponse"
        return self.full_trees.get(response, ())


class Tokens:
    def __init__(self) -> None:
        self.identities: list[str] = []

    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]:
        self.identities.append(identity)
        return (("authorization", f"Bearer {identity}"),)


class Transport:
    def __init__(self, result: GrpcResult) -> None:
        self.result = result
        self.calls: list[GrpcCall] = []

    def invoke(self, call: GrpcCall) -> GrpcResult:
        self.calls.append(call)
        return self.result


def check(*, identities: tuple[str, ...] = ("attacker",)) -> Check:
    return Check(
        invariant_id="invariant",
        method_id="grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
        scenario_id="scenario",
        request=(("secret_id", "secret"),),
        identities=identities,
    )


def freeze_clock(monkeypatch, elapsed_ms: float) -> None:
    ticks = iter((0.0, elapsed_ms / 1000))
    monkeypatch.setattr(grpc_runtime, "monotonic", lambda: next(ticks))


def test_target_stores_duration_for_completed_call(monkeypatch) -> None:
    freeze_clock(monkeypatch, 125.5)
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed")),
    )

    observation = target(check())

    assert observation.duration_ms == 125.5


def test_target_stores_duration_for_adapter_failure(monkeypatch) -> None:
    class FailingCodec(Codec):
        def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
            raise ValueError("bad payload")

    freeze_clock(monkeypatch, 12.5)

    observation = GrpcTarget(
        _Invocations(),
        FailingCodec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
    )(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.duration_ms == 12.5


def test_target_encodes_and_invokes_graph_resolved_method() -> None:
    codec = Codec()
    transport = Transport(GrpcResult(GrpcStatus(code="PERMISSION_DENIED"), "denied"))
    target = GrpcTarget(
        invocations=_Invocations(),
        codec=codec,
        tokens=Tokens(),
        transport=transport,
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.DENIED
    assert codec.calls == [("GetPayloadRequest", {"secret_id": "secret"})]
    assert transport.calls[0].endpoint == "payload.example:443"
    assert transport.calls[0].rpc_path == (
        "/yandex.cloud.priv.lockbox.v1.PayloadService/Get"
    )


class _DenyEndpointPolicy:
    def allows(self, endpoint: str) -> bool:
        return False


class _AllowPayloadEndpointPolicy:
    def allows(self, endpoint: str) -> bool:
        return endpoint == "payload.example:443"


def test_target_denies_endpoint_before_token_resolution() -> None:
    tokens = Tokens()
    transport = Transport(GrpcResult(GrpcStatus(code="OK"), "allowed"))
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        tokens,
        transport,
        endpoint_policy=_DenyEndpointPolicy(),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert "endpoint denied" in observation.response_summary
    assert observation.error_reason == (
        "CLOUD_DAST_ALLOWED_ENDPOINTS does not allow this endpoint"
    )
    assert tokens.identities == []
    assert transport.calls == []


def test_target_allows_endpoint_and_attaches_token() -> None:
    tokens = Tokens()
    transport = Transport(GrpcResult(GrpcStatus(code="OK"), "allowed"))
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        tokens,
        transport,
        endpoint_policy=_AllowPayloadEndpointPolicy(),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert tokens.identities == ["attacker"]
    assert len(transport.calls) == 1
    assert transport.calls[0].metadata == (("authorization", "Bearer attacker"),)


def test_target_maps_unauthenticated_to_infrastructure_error() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="UNAUTHENTICATED"), "unauthenticated")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.transport_status == GrpcStatus(code="UNAUTHENTICATED")
    assert observation.auth_failed is True


def test_target_decodes_safe_structured_output() -> None:
    target = GrpcTarget(
        _OutputInvocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed", response=b"response")),
    )

    observation = target(check())

    assert observation.output == ResponseData(fields=(("secret_id", "secret"),))


def test_target_retains_full_fidelity_response_tree_and_digest() -> None:
    codec = Codec()
    codec.full_trees[b"response"] = (
        ("debug.trace_id", "trace-1"),
        ("items.0.name", "widget"),
    )
    target = GrpcTarget(
        _OutputInvocations(),
        codec,
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed", response=b"response")),
    )

    observation = target(check())

    assert observation.response_tree == (
        ("debug.trace_id", "trace-1"),
        ("items.0.name", "widget"),
    )
    assert observation.response_digest == response_tree_digest(
        observation.response_tree
    )


def test_target_preserves_full_tree_when_safe_decode_fails() -> None:
    class InvalidSafePathCodec(Codec):
        def decode(self, output_type: str, response: bytes) -> ResponseData:
            raise ValueError("safe response field path is not declared")

    codec = InvalidSafePathCodec()
    codec.full_trees[b"response"] = (("debug.trace_id", "trace-1"),)
    target = GrpcTarget(
        _OutputInvocations(),
        codec,
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed", response=b"response")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "gRPC call failed"
    assert observation.response_tree == (("debug.trace_id", "trace-1"),)
    assert observation.response_digest == response_tree_digest(
        observation.response_tree
    )


def test_target_marks_response_tree_unavailable_without_output_type() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed", response=b"response")),
    )

    observation = target(check())

    assert observation.response_tree == (
        ("__response__.not_available", "output_type_missing"),
    )
    assert observation.response_digest == response_tree_digest(
        observation.response_tree
    )


def test_target_digests_an_empty_full_response_tree() -> None:
    codec = Codec()
    target = GrpcTarget(
        _OutputInvocations(),
        codec,
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "allowed", response=b"response")),
    )

    observation = target(check())

    assert observation.response_tree == ()
    assert observation.response_digest == response_tree_digest(())


def test_target_leaves_response_tree_empty_without_response() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="PERMISSION_DENIED"), "denied")),
    )

    observation = target(check())

    assert observation.response_tree == ()
    assert observation.response_digest is None


def test_target_returns_error_observation_for_missing_metadata() -> None:
    target = GrpcTarget(
        _MissingInvocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert "metadata" in observation.response_summary


def test_target_rejects_multiple_identities_without_invoking_transport() -> None:
    transport = Transport(GrpcResult(GrpcStatus(code="OK"), "ok"))
    target = GrpcTarget(_Invocations(), Codec(), Tokens(), transport)

    observation = target(check(identities=("attacker", "victim")))

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert "one identity" in observation.response_summary
    assert transport.calls == []


def test_target_maps_not_found_to_unknown() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="NOT_FOUND"), "missing")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN


def test_target_preserves_unimplemented_status_as_unknown() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="UNIMPLEMENTED"), "not implemented")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN
    assert observation.transport_status == GrpcStatus(code="UNIMPLEMENTED")
    assert "UNIMPLEMENTED" in observation.response_summary


def test_target_preserves_invalid_argument_status_as_unknown() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="INVALID_ARGUMENT"), "bad request")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN
    assert "INVALID_ARGUMENT" in observation.response_summary


def test_target_keeps_permission_denied_as_policy_observation() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="PERMISSION_DENIED"), "denied")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.DENIED
    assert observation.auth_failed is False


def test_target_preserves_unavailable_status_as_unknown() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="UNAVAILABLE"), "unavailable")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN
    assert "UNAVAILABLE" in observation.response_summary


def test_target_maps_unrecognised_status_to_unknown() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="NEW_STATUS"), "future")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN


def test_target_converts_codec_and_transport_failures_to_error() -> None:
    class FailingCodec(Codec):
        def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
            raise ValueError("bad payload")

    observation = GrpcTarget(
        _Invocations(),
        FailingCodec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
    )(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "gRPC call failed"


def test_target_converts_response_decode_failures_to_error() -> None:
    class FailingDecodeCodec(Codec):
        def decode(self, output_type: str, response: bytes) -> ResponseData:
            raise ValueError("malformed response")

    observation = GrpcTarget(
        _OutputInvocations(),
        FailingDecodeCodec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok", response=b"bad")),
    )(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "gRPC call failed"


def test_target_converts_unexpected_codec_failures_to_error() -> None:
    class CodecFailure(Exception):
        pass

    class BrokenCodec(Codec):
        def encode(self, input_type: str, request: dict[str, Any]) -> bytes:
            raise CodecFailure("wire decoder failure")

    observation = GrpcTarget(
        _Invocations(),
        BrokenCodec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
    )(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "gRPC call failed"


def test_target_propagates_error_reason_to_observation() -> None:
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        Transport(
            GrpcResult(
                GrpcStatus(code="NOT_FOUND"), "missing", error_reason="no such secret"
            )
        ),
    )

    observation = target(check())

    assert observation.error_reason == "no such secret"


def test_rpc_error_details_reach_observation_capped(monkeypatch) -> None:
    details = "d" * 600
    monkeypatch.setitem(
        sys.modules, "grpc", _fake_grpc_module(_FakeRpcError("NOT_FOUND", details))
    )
    target = GrpcTarget(
        _Invocations(),
        Codec(),
        Tokens(),
        GrpcioTransport(insecure=True),
    )

    observation = target(check())

    assert observation.error_reason == details[:512]
    assert len(observation.error_reason) == 512


def test_grpcio_transport_keeps_grpc_status_without_http_translation(
    monkeypatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "grpc",
        _fake_grpc_module(_FakeRpcError("DEADLINE_EXCEEDED", "deadline exceeded")),
    )

    result = GrpcioTransport(insecure=True).invoke(
        GrpcCall(
            endpoint="payload.example:443",
            rpc_path="/yandex.cloud.priv.lockbox.v1.PayloadService/Get",
            payload=b"request",
            metadata=(),
        )
    )

    assert result.status == GrpcStatus(code="DEADLINE_EXCEEDED")
    assert result.status.is_timeout()
    assert result.status.token == "grpc:DEADLINE_EXCEEDED"


def test_raising_transport_keeps_error_reason_in_error_observation() -> None:
    class RaisingTransport:
        def invoke(self, call: GrpcCall) -> GrpcResult:
            raise _FakeRpcError("PERMISSION_DENIED", "export denied for attacker")

    observation = GrpcTarget(_Invocations(), Codec(), Tokens(), RaisingTransport())(
        check()
    )

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.error_reason == "export denied for attacker"


class _FakeStatusCode:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeRpcError(Exception):
    def __init__(self, name: str, details: str) -> None:
        super().__init__(details)
        self._name = name
        self._details = details

    def code(self) -> _FakeStatusCode:
        return _FakeStatusCode(self._name)

    def details(self) -> str:
        return self._details


class _FakeChannel:
    def __init__(self, error: _FakeRpcError) -> None:
        self._error = error

    def unary_unary(self, rpc_path: str, **_: Any) -> Any:
        def invoke(payload: bytes, **__: Any) -> bytes:
            raise self._error

        return invoke

    def close(self) -> None:
        pass


def _fake_grpc_module(error: _FakeRpcError) -> ModuleType:
    module = ModuleType("grpc")
    module.RpcError = _FakeRpcError
    module.insecure_channel = lambda endpoint, options=(): _FakeChannel(error)
    module.secure_channel = lambda endpoint, credentials, options=(): _FakeChannel(
        error
    )
    module.ssl_channel_credentials = lambda: object()
    return module


class _Invocations:
    def get_invocation(self, method_id: str) -> Invocation | None:
        return Invocation(
            method_id=method_id,
            input_type="GetPayloadRequest",
            rpc_path="/yandex.cloud.priv.lockbox.v1.PayloadService/Get",
            endpoint="payload.example:443",
        )


class _MissingInvocations:
    def get_invocation(self, method_id: str) -> Invocation | None:
        return None


class _OutputInvocations(_Invocations):
    def get_invocation(self, method_id: str) -> Invocation | None:
        return Invocation(
            method_id=method_id,
            input_type="GetPayloadRequest",
            rpc_path="/yandex.cloud.priv.lockbox.v1.PayloadService/Get",
            endpoint="payload.example:443",
            output_type="GetPayloadResponse",
        )


class _Session:
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row
        self.query = ""
        self.params: dict[str, Any] = {}

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self.query = query
        self.params = params
        return [self.row]


def test_neo4j_invocation_reads_endpoint_node() -> None:
    session = _Session(
        {
            "method": {"input_type": "GetPayloadRequest"},
            "package": "yandex.cloud.priv.lockbox.v1",
            "endpoint": "payload.example:443",
        }
    )

    @contextmanager
    def factory() -> Any:
        yield session

    invocation = Neo4jInvocationRepository(factory).get_invocation(
        "yandex.cloud.priv.lockbox.v1.PayloadService/Get"
    )

    assert invocation is not None
    assert invocation.endpoint == "payload.example:443"
    assert "Endpoint" in session.query
    assert "SERVES" in session.query
    assert "coalesce(environment" in session.query


def test_neo4j_invocation_queries_only_the_exact_method_id_by_default() -> None:
    method_id = "grpc-priv:yandex.cloud.lockbox.v1.PayloadService.Get"
    session = _Session(
        {
            "method": {"input_type": "GetPayloadRequest"},
            "package": "yandex.cloud.priv.lockbox.v1",
            "endpoint": "payload.example:443",
        }
    )

    @contextmanager
    def factory() -> Any:
        yield session

    invocation = Neo4jInvocationRepository(factory).get_invocation(method_id)

    assert invocation is not None
    assert session.params["method_ids"] == (method_id,)


def test_neo4j_invocation_queries_configured_method_prefix_aliases() -> None:
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
    def factory() -> Any:
        yield session

    repository = Neo4jInvocationRepository(
        factory,
        method_prefix_aliases={
            "grpc-priv:yandex.cloud.": "grpc-priv:yandex.cloud.priv."
        },
    )
    invocation = repository.get_invocation(method_id)

    assert invocation is not None
    assert session.params["method_ids"] == (method_id, graph_method_id)


def test_composition_factory_wires_graph_repository_into_target(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    session = _Session(
        {
            "method": {"input_type": "GetPayloadRequest"},
            "package": "yandex.cloud.priv.lockbox.v1",
            "endpoint": "payload.example:443",
        }
    )

    @contextmanager
    def factory() -> Any:
        yield session

    target = make_grpc_target(
        Neo4jMethodRepository(factory),
        Neo4jInvocationRepository(factory),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
        guardrail=AllowAllGuardrail(),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert session.params["method_id"] == (
        "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
    )


def test_composition_factory_enforces_default_guardrail(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "payload.example:443")
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_SERVICES", raising=False)

    @contextmanager
    def factory() -> Any:
        yield
        raise AssertionError("the guardrail must block before invocation resolution")

    target = make_grpc_target(
        Neo4jMethodRepository(factory),
        Neo4jInvocationRepository(factory),
        Codec(),
        Tokens(),
        Transport(GrpcResult(GrpcStatus(code="OK"), "ok")),
    )

    with pytest.raises(PermissionError, match="denied by guardrail"):
        target(check())
