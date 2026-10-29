from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from cloud_dast.config import RESPONSE_TREE_MAX_DEPTH, RESPONSE_TREE_MAX_LEAVES
from cloud_dast.infrastructure.runtime import http_json
from cloud_dast.infrastructure.runtime.http_json import (
    HttpCall,
    HttpJsonTarget,
    HttpResult,
    JsonPayloadCodec,
    UrllibHttpTransport,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import Invocation


class Invocations:
    def __init__(self, invocation: Invocation | None = None) -> None:
        self.invocation = invocation

    def get_invocation(self, method_id: str) -> Invocation | None:
        if self.invocation is None:
            return None
        return self.invocation if self.invocation.method_id == method_id else None


class Tokens:
    def __init__(self) -> None:
        self.identities: list[str] = []

    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]:
        self.identities.append(identity)
        return (("authorization", f"Bearer {identity}"),)


class Transport:
    def __init__(self, result: HttpResult) -> None:
        self.result = result
        self.calls: list[HttpCall] = []

    def send(self, call: HttpCall) -> HttpResult:
        self.calls.append(call)
        return self.result


class DenyEndpointPolicy:
    def allows(self, endpoint: str) -> bool:
        return False


def invocation() -> Invocation:
    return Invocation(
        method_id="http:orders.get",
        endpoint="https://api.example.test",
        transport="http-json",
        http_method="POST",
        path_template="/orders/{order_id}",
        query_fields=("limit",),
        header_fields=("x-request-id",),
        cookie_fields=("session",),
    )


def check(**overrides: Any) -> Check:
    values: dict[str, Any] = {
        "invariant_id": "invariant",
        "method_id": "http:orders.get",
        "scenario_id": "scenario",
        "request": (
            ("order_id", 42),
            ("limit", 10),
            ("x-request-id", "request-1"),
            ("session", "session-value"),
            ("note", "hello"),
        ),
        "identities": ("attacker",),
    }
    values.update(overrides)
    return Check(**values)


def result(
    status_code: int = 200,
    body: bytes = b'{"order":{"id":42,"items":[{"sku":"sku-1","qty":2}]}}',
) -> HttpResult:
    return HttpResult(
        status_code=status_code,
        body=body,
        headers=(("content-type", "application/json"),),
        final_url="https://api.example.test/orders/42?limit=10",
    )


def freeze_clock(monkeypatch: pytest.MonkeyPatch, elapsed_ms: float) -> None:
    ticks = iter((0.0, elapsed_ms / 1000))
    monkeypatch.setattr(http_json, "monotonic", lambda: next(ticks))


def test_target_renders_request_and_projects_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze_clock(monkeypatch, 125.5)
    invocations = Invocations(invocation())
    tokens = Tokens()
    transport = Transport(result())
    target = HttpJsonTarget(
        invocations,
        JsonPayloadCodec(safe_fields=("order.id", "order.items.0.sku")),
        tokens,
        transport,
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert observation.transport_status == HttpStatus(code=200)
    assert observation.response_summary == "HTTP 200 OK"
    assert observation.duration_ms == 125.5
    assert observation.output is not None
    assert observation.output.fields == (
        ("order.id", 42),
        ("order.items.0.sku", "sku-1"),
    )
    assert observation.response_tree == (
        ("http.content_type", "application/json"),
        ("http.final_url", "https://api.example.test/orders/42?limit=10"),
        ("http.status_code", 200),
        ("order.id", 42),
        ("order.items.0.qty", 2),
        ("order.items.0.sku", "sku-1"),
    )
    assert observation.response_digest == response_tree_digest(
        observation.response_tree
    )

    call = transport.calls[0]
    assert call.http_method == "POST"
    assert call.path == "/orders/42"
    assert call.query == (("limit", "10"),)
    assert ("authorization", "Bearer attacker") in call.headers
    assert ("content-type", "application/json") in call.headers
    assert ("x-request-id", "request-1") in call.headers
    assert call.cookies == (("session", "session-value"),)
    assert json.loads(call.body) == {"note": "hello"}
    assert tokens.identities == ["attacker"]


def test_target_caps_response_tree_leaf_cardinality() -> None:
    body = json.dumps(
        {"items": [{"value": index} for index in range(RESPONSE_TREE_MAX_LEAVES + 1)]}
    ).encode()
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result(body=body)),
    )

    observation = target(check())

    body_leaves = tuple(
        leaf for leaf in observation.response_tree if not leaf[0].startswith("http.")
    )
    last_leaf = RESPONSE_TREE_MAX_LEAVES - 1
    assert len(body_leaves) == RESPONSE_TREE_MAX_LEAVES + 1
    assert ("items.0.value", 0) in body_leaves
    assert (f"items.{last_leaf}.value", last_leaf) in body_leaves
    assert ("__truncated__", True) in body_leaves


def test_target_caps_response_tree_depth() -> None:
    nested = "leaf"
    for _ in range(RESPONSE_TREE_MAX_DEPTH + 1):
        nested = {"child": nested}
    body = json.dumps({"payload": nested}).encode()
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result(body=body)),
    )

    observation = target(check())

    assert ("__truncated__", True) in observation.response_tree


def test_target_uses_only_configured_body_fields() -> None:
    configured = Invocation(
        method_id="http:orders.get",
        endpoint="https://api.example.test",
        transport="http-json",
        http_method="POST",
        path_template="/orders/{order_id}",
        body_fields=("note",),
    )
    transport = Transport(result())
    target = HttpJsonTarget(
        Invocations(configured),
        JsonPayloadCodec(),
        Tokens(),
        transport,
    )

    target(check())

    assert json.loads(transport.calls[0].body) == {"note": "hello"}


def test_target_denies_endpoint_before_token_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze_clock(monkeypatch, 12.5)
    tokens = Tokens()
    transport = Transport(result())
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        tokens,
        transport,
        endpoint_policy=DenyEndpointPolicy(),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "HTTP endpoint denied by destination policy"
    assert observation.error_reason == (
        "CLOUD_DAST_ALLOWED_ENDPOINTS does not allow this endpoint"
    )
    assert observation.duration_ms == 12.5
    assert tokens.identities == []
    assert transport.calls == []


@pytest.mark.parametrize(
    ("status_code", "outcome", "auth_failed"),
    [
        (200, AccessOutcome.ALLOWED, False),
        (201, AccessOutcome.ALLOWED, False),
        (401, AccessOutcome.ERROR, True),
        (403, AccessOutcome.DENIED, False),
        (404, AccessOutcome.UNKNOWN, False),
        (500, AccessOutcome.ERROR, False),
    ],
)
def test_target_maps_http_status_to_outcome(
    status_code: int,
    outcome: AccessOutcome,
    auth_failed: bool,
) -> None:
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result(status_code=status_code)),
    )

    observation = target(check())

    assert observation.observed_outcome is outcome
    assert observation.auth_failed is auth_failed
    assert observation.transport_status == HttpStatus(code=status_code)


def test_target_rejects_status_outside_http_range() -> None:
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result(status_code=999)),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.transport_status is None
    assert observation.error_reason == "HTTP status code is outside the valid range"


def test_target_retains_redirect_location_as_evidence() -> None:
    transport = Transport(
        HttpResult(
            status_code=302,
            body=b"",
            headers=(("location", "/login"),),
            final_url="https://api.example.test/orders/42",
        )
    )
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        transport,
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.UNKNOWN
    assert observation.transport_status == HttpStatus(code=302)
    assert ("http.location", "/login") in observation.response_tree


def test_target_rejects_more_than_one_identity() -> None:
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result()),
    )

    observation = target(check(identities=("attacker", "victim")))

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == (
        "an HTTP check requires at most one identity"
    )


def test_target_allows_anonymous_request() -> None:
    tokens = Tokens()
    transport = Transport(result())
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        tokens,
        transport,
    )

    observation = target(check(identities=()))

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert tokens.identities == []
    assert all(name != "authorization" for name, _ in transport.calls[0].headers)


def test_target_reports_missing_invocation() -> None:
    target = HttpJsonTarget(
        Invocations(),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result()),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "method invocation metadata is missing"


def test_target_converts_missing_path_field_to_error() -> None:
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result()),
    )
    request = tuple(
        (name, value) for name, value in check().request if name != "order_id"
    )

    observation = target(check(request=request))

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "HTTP call failed"
    assert observation.error_reason == "missing HTTP path field: order_id"


def test_target_converts_invalid_json_response_to_error() -> None:
    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        Transport(result(body=b"{invalid")),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "HTTP call failed"
    assert observation.error_reason == "response is not valid JSON"
    assert observation.response_tree == ()


def test_target_converts_transport_failure_to_error() -> None:
    class RaisingTransport:
        def send(self, call: HttpCall) -> HttpResult:
            raise RuntimeError("network unavailable")

    target = HttpJsonTarget(
        Invocations(invocation()),
        JsonPayloadCodec(),
        Tokens(),
        RaisingTransport(),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "HTTP call failed"
    assert observation.error_reason is None


def test_urllib_transport_builds_request_and_captures_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200
        headers = {"content-type": "application/json"}

        def __init__(self) -> None:
            self.body = b'{"ok":true}'
            self.url = "https://api.example.test/orders/42?limit=10"

        def read(self) -> bytes:
            return self.body

        def geturl(self) -> str:
            return self.url

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    requests: list[urllib.request.Request] = []
    handlers: list[object] = []

    class Opener:
        def open(
            self, request: urllib.request.Request, timeout: float | None
        ) -> Response:
            requests.append(request)
            return Response()

    def fake_build_opener(*handler: object) -> Opener:
        handlers.extend(handler)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    call = HttpCall(
        endpoint="https://api.example.test/",
        http_method="POST",
        path="/orders/42",
        query=(("limit", "10"),),
        headers=(("content-type", "application/json"),),
        cookies=(("session", "value"),),
        body=b'{"note":"hello"}',
        timeout=3.0,
    )

    response = UrllibHttpTransport().send(call)

    assert requests[0].full_url == "https://api.example.test/orders/42?limit=10"
    assert requests[0].method == "POST"
    assert requests[0].headers["Content-type"] == "application/json"
    assert requests[0].headers["Cookie"] == "session=value"
    assert response.status_code == 200
    assert response.body == b'{"ok":true}'
    assert response.final_url == "https://api.example.test/orders/42?limit=10"
    assert isinstance(handlers[0], http_json._NoRedirectHandler)


def test_urllib_transport_preserves_redirect_as_http_error() -> None:
    request = urllib.request.Request("https://allowed.example.test")

    with pytest.raises(urllib.error.HTTPError) as error:
        http_json._NoRedirectHandler().redirect_request(
            request,
            object(),
            302,
            "Found",
            {},
            "https://redirect.example.test",
        )

    assert error.value.code == 302
    assert error.value.url == "https://allowed.example.test"
