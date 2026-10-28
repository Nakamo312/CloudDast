"""Generic HTTP/JSON target adapter.

The adapter keeps the same callable shape as the existing transport-agnostic
``Target`` port.  It depends only on small infrastructure protocols, so JSON,
credentials, and the HTTP client remain replaceable without touching the core.
"""

from __future__ import annotations

import json
import logging
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.client import responses as http_reason_phrases
from time import monotonic
from typing import Any, Protocol

from cloud_dast.config import RESPONSE_TREE_MAX_DEPTH, RESPONSE_TREE_MAX_LEAVES
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    JsonValue,
    Observation,
    ResponseData,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import (
    EndpointPolicy,
    Invocation,
    InvocationRepository,
    TokenProvider,
)

logger = logging.getLogger("cloud_dast.http_json")

ERROR_REASON_MAX_LENGTH = 512
"""Maximum retained transport error text; longer evidence is truncated."""

_RESPONSE_TREE_TRUNCATED = "__truncated__"
_PATH_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MISSING = object()


class HttpTargetError(Exception):
    """An adapter failure whose reason is safe to retain as evidence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.safe_reason = reason


class HttpCodecError(HttpTargetError):
    """A JSON encoding or decoding failure."""


@dataclass(frozen=True)
class HttpCall:
    """One rendered HTTP request handed to the transport."""

    endpoint: str
    http_method: str
    path: str
    query: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[tuple[str, str], ...]
    body: bytes
    timeout: float | None


@dataclass(frozen=True)
class HttpResult:
    """One HTTP response or transport-level HTTP error."""

    status_code: int
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()
    final_url: str | None = None
    auth_failed: bool = False
    error_reason: str | None = None


class HttpTransport(Protocol):
    def send(self, call: HttpCall) -> HttpResult: ...


class HttpPayloadCodec(Protocol):
    """Encode request bodies and project HTTP responses."""

    def encode(self, request: Mapping[str, Any]) -> bytes: ...

    def decode(self, result: HttpResult) -> ResponseData: ...

    def decode_full(self, result: HttpResult) -> tuple[tuple[str, JsonValue], ...]: ...


@dataclass(frozen=True)
class _RenderedRequest:
    path: str
    query: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[tuple[str, str], ...]
    body: Mapping[str, Any]


class JsonPayloadCodec:
    """JSON codec with an explicit safe-field projection.

    ``decode`` retains only explicitly allowlisted body paths for workflow
    forwarding.  ``decode_full`` retains the complete decoded body plus stable
    transport metadata as evidence for isolated application copies.
    """

    def __init__(self, safe_fields: Sequence[str] = ()) -> None:
        self._safe_fields = tuple(sorted(set(safe_fields)))

    def encode(self, request: Mapping[str, Any]) -> bytes:
        try:
            return json.dumps(
                request,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise HttpCodecError("request is not valid JSON") from exc

    def decode(self, result: HttpResult) -> ResponseData:
        document = self._document(result)
        fields: list[tuple[str, JsonValue]] = []
        for path in self._safe_fields:
            value = _value_at_path(document, path)
            if value is _MISSING or not _scalar(value):
                continue
            fields.append((path, value))
        return ResponseData(
            fields=tuple(fields),
            field_names=tuple(self._safe_fields),
        )

    def decode_full(self, result: HttpResult) -> tuple[tuple[str, JsonValue], ...]:
        document = self._document(result)
        budget = _TreeBudget()
        _walk_json(document, "", 0, budget)
        if budget.truncated:
            budget.add(_RESPONSE_TREE_TRUNCATED, True)

        leaves: list[tuple[str, JsonValue]] = list(budget.leaves)
        leaves.append(("http.status_code", result.status_code))
        content_type = _header(result, "content-type")
        if content_type is not None:
            leaves.append(("http.content_type", content_type))
        location = _header(result, "location")
        if location is not None:
            leaves.append(("http.location", location))
        if result.final_url:
            leaves.append(("http.final_url", result.final_url))
        return tuple(sorted(leaves, key=lambda leaf: leaf[0]))

    @staticmethod
    def _document(result: HttpResult) -> Any:
        content_type = _header(result, "content-type") or ""
        if content_type and "json" not in content_type.lower():
            return {"body": result.body.decode("utf-8", errors="replace")}
        if not result.body:
            return {}
        try:
            document = json.loads(result.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HttpCodecError("response is not valid JSON") from exc
        if not isinstance(document, dict | list):
            return {"value": document}
        return document


def project_observation(
    check: Check,
    result: HttpResult,
    *,
    output: ResponseData,
    response_tree: tuple[tuple[str, JsonValue], ...],
    duration_ms: float,
) -> Observation:
    """Project one HTTP result into the transport-agnostic observation."""

    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=_outcome(result.status_code),
        response_summary=_summary(result.status_code),
        transport_status=HttpStatus(code=result.status_code),
        auth_failed=result.auth_failed or result.status_code == 401,
        output=output,
        duration_ms=duration_ms,
        error_reason=cap_error_reason(result.error_reason),
        response_tree=response_tree,
        response_digest=response_tree_digest(response_tree),
    )


class HttpJsonTarget:
    """Execute graph-described HTTP methods and project JSON observations."""

    def __init__(
        self,
        invocations: InvocationRepository,
        codec: HttpPayloadCodec,
        tokens: TokenProvider,
        transport: HttpTransport,
        *,
        endpoint_policy: EndpointPolicy | None = None,
        timeout: float | None = 30.0,
    ) -> None:
        self._invocations = invocations
        self._codec = codec
        self._tokens = tokens
        self._transport = transport
        self._endpoint_policy = endpoint_policy
        self._timeout = timeout

    def __call__(self, check: Check) -> Observation:
        started = monotonic()
        logger.debug(
            "http_check_started check_id=%s method_id=%s scenario_id=%s",
            check.check_id,
            check.method_id,
            check.scenario_id,
        )
        try:
            invocation = self._invocations.get_invocation(check.method_id)
            if invocation is None:
                duration_ms = _elapsed_ms(started)
                logger.warning(
                    "http_check_failed check_id=%s reason=missing_invocation "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "method invocation metadata is missing", duration_ms
                )
            if invocation.transport != "http-json":
                duration_ms = _elapsed_ms(started)
                logger.warning(
                    "http_check_failed check_id=%s reason=transport_mismatch "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "method invocation metadata is not HTTP/JSON", duration_ms
                )
            if invocation.http_method is None or invocation.path_template is None:
                duration_ms = _elapsed_ms(started)
                logger.warning(
                    "http_check_failed check_id=%s reason=incomplete_invocation "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "HTTP invocation metadata is incomplete", duration_ms
                )
            if self._endpoint_policy is not None and not self._endpoint_policy.allows(
                invocation.endpoint
            ):
                duration_ms = _elapsed_ms(started)
                logger.warning(
                    "http_check_failed check_id=%s reason=endpoint_policy_denied "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check,
                    "HTTP endpoint denied by destination policy",
                    duration_ms,
                    error_reason=(
                        "CLOUD_DAST_ALLOWED_ENDPOINTS does not allow this endpoint"
                    ),
                )
            if len(check.identities) > 1:
                duration_ms = _elapsed_ms(started)
                logger.warning(
                    "http_check_failed check_id=%s reason=identity_count "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "an HTTP check requires at most one identity", duration_ms
                )

            rendered = _render_request(invocation, check)
            payload = self._codec.encode(rendered.body)
            headers = {name.lower(): value for name, value in rendered.headers}
            if check.identities:
                headers.update(
                    (name.lower(), value)
                    for name, value in self._tokens.metadata(check.identities[0])
                )
            if payload and not any(name.lower() == "content-type" for name in headers):
                headers["content-type"] = "application/json"

            result = self._transport.send(
                HttpCall(
                    endpoint=invocation.endpoint,
                    http_method=invocation.http_method.upper(),
                    path=rendered.path,
                    query=rendered.query,
                    headers=tuple(sorted(headers.items())),
                    cookies=rendered.cookies,
                    body=payload,
                    timeout=self._timeout,
                )
            )
            if not 100 <= result.status_code <= 599:
                raise HttpTargetError("HTTP status code is outside the valid range")

            response_tree = self._codec.decode_full(result)
            output = self._codec.decode(result)
        except HttpTargetError as exc:
            duration_ms = _elapsed_ms(started)
            logger.warning(
                "http_check_failed check_id=%s reason=%s duration_ms=%.1f",
                check.check_id,
                exc.safe_reason,
                duration_ms,
            )
            return self._error(
                check,
                "HTTP call failed",
                duration_ms,
                error_reason=exc.safe_reason,
            )
        except Exception as exc:
            duration_ms = _elapsed_ms(started)
            logger.exception(
                "http_check_failed check_id=%s reason=adapter_error duration_ms=%.1f",
                check.check_id,
                duration_ms,
            )
            return self._error(
                check,
                "HTTP call failed",
                duration_ms,
                error_reason=_safe_error_reason(exc),
            )

        duration_ms = _elapsed_ms(started)
        logger.info(
            "http_check_completed check_id=%s method_id=%s status_code=%s "
            "duration_ms=%.1f",
            check.check_id,
            check.method_id,
            result.status_code,
            duration_ms,
        )
        return project_observation(
            check,
            result,
            output=output,
            response_tree=response_tree,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _error(
        check: Check,
        summary: str,
        duration_ms: float,
        *,
        error_reason: str | None = None,
        response_tree: tuple[tuple[str, JsonValue], ...] = (),
    ) -> Observation:
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ERROR,
            response_summary=summary,
            duration_ms=duration_ms,
            error_reason=cap_error_reason(error_reason),
            response_tree=response_tree,
            response_digest=(
                response_tree_digest(response_tree) if response_tree else None
            ),
        )


class UrllibHttpTransport:
    """Standard-library HTTP transport for the generic target contract."""

    def send(self, call: HttpCall) -> HttpResult:
        request = urllib.request.Request(
            _url(call),
            data=(
                call.body if call.http_method.upper() not in {"GET", "HEAD"} else None
            ),
            headers=_request_headers(call),
            method=call.http_method.upper(),
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=call.timeout) as response:
                return HttpResult(
                    status_code=response.status,
                    body=response.read(),
                    headers=tuple(response.headers.items()),
                    final_url=response.geturl(),
                    auth_failed=response.status == 401,
                )
        except urllib.error.HTTPError as exc:
            return HttpResult(
                status_code=exc.code,
                body=exc.read(),
                headers=tuple(exc.headers.items()),
                final_url=exc.geturl(),
                auth_failed=exc.code == 401,
                error_reason=str(exc.reason),
            )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep redirects as observations instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def _render_request(invocation: Invocation, check: Check) -> _RenderedRequest:
    values = dict(check.request)
    path = _render_path(invocation.path_template, values)
    query = tuple(
        sorted(
            (name, _query_value(values[name]))
            for name in invocation.query_fields
            if name in values
        )
    )
    headers = tuple(
        sorted(
            (name, _scalar_text(values[name]))
            for name in invocation.header_fields
            if name in values
        )
    )
    cookies = tuple(
        sorted(
            (name, _scalar_text(values[name]))
            for name in invocation.cookie_fields
            if name in values
        )
    )
    if invocation.body_fields is None:
        consumed = {
            *_path_fields(invocation.path_template),
            *invocation.query_fields,
            *invocation.header_fields,
            *invocation.cookie_fields,
        }
        body = {
            name: value
            for name, value in sorted(values.items())
            if name not in consumed
        }
    else:
        body = {
            name: values[name]
            for name in sorted(invocation.body_fields)
            if name in values
        }
    return _RenderedRequest(
        path=path,
        query=query,
        headers=headers,
        cookies=cookies,
        body=body,
    )


def _render_path(template: str, values: Mapping[str, Any]) -> str:
    fields = _path_fields(template)
    missing = [name for name in fields if name not in values]
    if missing:
        raise HttpTargetError("missing HTTP path field: " + ", ".join(sorted(missing)))

    def replace(match: re.Match[str]) -> str:
        return urllib.parse.quote(_scalar_text(values[match.group(1)]), safe="")

    path = _PATH_PLACEHOLDER.sub(replace, template)
    return path if path.startswith("/") else "/" + path


def _path_fields(template: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_PATH_PLACEHOLDER.findall(template)))


def _url(call: HttpCall) -> str:
    endpoint = call.endpoint.rstrip("/")
    path = call.path if call.path.startswith("/") else "/" + call.path
    url = f"{endpoint}{path}"
    if call.query:
        url += "?" + urllib.parse.urlencode(call.query)
    return url


def _request_headers(call: HttpCall) -> dict[str, str]:
    headers = dict(call.headers)
    if call.cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in call.cookies)
    return headers


def _outcome(status_code: int) -> AccessOutcome:
    if 200 <= status_code <= 299:
        return AccessOutcome.ALLOWED
    if status_code == 401:
        return AccessOutcome.ERROR
    if status_code == 403:
        return AccessOutcome.DENIED
    if 500 <= status_code <= 599:
        return AccessOutcome.ERROR
    return AccessOutcome.UNKNOWN


def _summary(status_code: int) -> str:
    reason = http_reason_phrases.get(status_code, "")
    return f"HTTP {status_code} {reason}".strip()


def cap_error_reason(reason: str | None) -> str | None:
    """Enforce the evidence cap for every error reason crossing the boundary."""

    if reason is None:
        return None
    return reason[:ERROR_REASON_MAX_LENGTH] or None


def _safe_error_reason(exc: Exception) -> str | None:
    reason = getattr(exc, "safe_reason", None)
    return reason if isinstance(reason, str) else None


def _elapsed_ms(started: float) -> float:
    return (monotonic() - started) * 1000


def _scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _query_value(value: Any) -> str:
    return _scalar_text(value)


def _header(result: HttpResult, name: str) -> str | None:
    normalized = name.lower()
    for header_name, value in result.headers:
        if header_name.lower() == normalized:
            return value
    return None


def _scalar(value: Any) -> bool:
    return isinstance(value, str | int | float | bool | None)


def _leaf_value(value: Any) -> JsonValue:
    if isinstance(value, float) and not math.isfinite(value):
        raise HttpCodecError("response contains a non-finite number")
    if not _scalar(value):
        raise HttpCodecError("response contains an unsupported JSON leaf")
    return value


def _value_at_path(document: Any, path: str) -> Any:
    current = document
    for segment in path.split("."):
        if isinstance(current, dict):
            if segment not in current:
                return _MISSING
            current = current[segment]
        elif isinstance(current, list):
            try:
                index = int(segment)
            except ValueError:
                return _MISSING
            if index < 0 or index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


class _TreeBudget:
    """Bounded accumulator for full-fidelity response leaves."""

    __slots__ = ("leaves", "truncated")

    def __init__(self) -> None:
        self.leaves: list[tuple[str, JsonValue]] = []
        self.truncated = False

    def exhausted(self) -> bool:
        if len(self.leaves) < RESPONSE_TREE_MAX_LEAVES:
            return False
        self.truncated = True
        return True

    def add(self, path: str, value: JsonValue) -> None:
        self.leaves.append((path, value))


def _walk_json(
    value: Any,
    prefix: str,
    depth: int,
    budget: _TreeBudget,
) -> None:
    if budget.exhausted():
        return
    if depth >= RESPONSE_TREE_MAX_DEPTH:
        budget.truncated = True
        return
    if isinstance(value, dict):
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            _walk_json(value[key], path, depth + 1, budget)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            _walk_json(item, path, depth + 1, budget)
    else:
        budget.add(prefix or "value", _leaf_value(value))
