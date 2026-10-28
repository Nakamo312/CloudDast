"""Socket target adapter for graph-described protocol messages."""

from __future__ import annotations

import json
import logging
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from time import monotonic
from typing import Any, Protocol

from cloud_dast.model import (
    AccessOutcome,
    Check,
    JsonValue,
    Observation,
    ResponseData,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import (
    EndpointPolicy,
    InvocationRepository,
)

logger = logging.getLogger("cloud_dast.socket")

ERROR_REASON_MAX_LENGTH = 512
RESPONSE_MAX_BYTES = 1_048_576
_MISSING = object()


class SocketTargetError(Exception):
    """An adapter failure whose reason is safe to retain as evidence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.safe_reason = reason


@dataclass(frozen=True)
class SocketCall:
    """One rendered protocol message."""

    endpoint: str
    message_type: str
    payload: bytes
    timeout: float | None


@dataclass(frozen=True)
class SocketResult:
    """One socket response or transport-level error."""

    response: bytes | None
    error_reason: str | None = None


class SocketTransport(Protocol):
    def send(self, call: SocketCall) -> SocketResult: ...


class SocketCodec(Protocol):
    """Encode protocol requests and project protocol responses."""

    def encode(
        self,
        message_type: str,
        request: Mapping[str, Any],
    ) -> bytes: ...

    def decode(
        self,
        message_type: str,
        response: bytes,
    ) -> ResponseData: ...

    def decode_full(
        self,
        message_type: str,
        response: bytes,
    ) -> tuple[tuple[str, JsonValue], ...]: ...


class JsonSocketCodec:
    """JSON protocol codec with explicit safe response-field projection."""

    def __init__(self, safe_fields: Sequence[str] = ()) -> None:
        self._safe_fields = tuple(sorted(set(safe_fields)))

    def encode(
        self,
        message_type: str,
        request: Mapping[str, Any],
    ) -> bytes:
        del message_type
        try:
            return json.dumps(
                dict(request),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise SocketTargetError("protocol message is not valid JSON") from error

    def decode(
        self,
        message_type: str,
        response: bytes,
    ) -> ResponseData:
        document = self._document(response)
        fields: list[tuple[str, JsonValue]] = []
        for path in self._safe_fields:
            value = _value_at_path(document, path)
            if value is _MISSING or not _is_scalar(value):
                continue
            fields.append((path, value))
        return ResponseData(
            fields=tuple(fields),
            field_names=tuple(self._safe_fields),
        )

    def decode_full(
        self,
        message_type: str,
        response: bytes,
    ) -> tuple[tuple[str, JsonValue], ...]:
        return (
            ("socket.message_type", message_type),
            ("socket.response", _decode_text(response)),
        )

    @staticmethod
    def _document(response: bytes) -> Any:
        if not response:
            return {}
        try:
            return json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}


class TcpSocketTransport:
    """TCP transport for one request/response protocol message."""

    def send(self, call: SocketCall) -> SocketResult:
        endpoint = _split_endpoint(call.endpoint)
        if endpoint is None:
            return SocketResult(
                response=None,
                error_reason="socket endpoint must be host:port",
            )
        host, port = endpoint
        try:
            with socket.create_connection(
                (host, port),
                timeout=call.timeout,
            ) as connection:
                if call.timeout is not None:
                    connection.settimeout(call.timeout)
                connection.sendall(call.payload)
                chunks: list[bytes] = []
                remaining = RESPONSE_MAX_BYTES
                while remaining:
                    chunk = connection.recv(min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                return SocketResult(response=b"".join(chunks))
        except OSError as error:
            return SocketResult(
                response=None,
                error_reason=f"socket call failed: {error}",
            )


class SocketTarget:
    """Execute graph-described protocol messages over a socket."""

    def __init__(
        self,
        invocations: InvocationRepository,
        codec: SocketCodec,
        transport: SocketTransport,
        *,
        endpoint_policy: EndpointPolicy | None = None,
        timeout: float | None = 30.0,
    ) -> None:
        self._invocations = invocations
        self._codec = codec
        self._transport = transport
        self._endpoint_policy = endpoint_policy
        self._timeout = timeout

    def __call__(self, check: Check) -> Observation:
        started = monotonic()
        logger.debug(
            "socket_check_started check_id=%s method_id=%s scenario_id=%s",
            check.check_id,
            check.method_id,
            check.scenario_id,
        )
        try:
            invocation = self._invocations.get_invocation(check.method_id)
            if invocation is None:
                return self._error(
                    check,
                    "method invocation metadata is missing",
                    _elapsed_ms(started),
                )
            if invocation.transport != "socket":
                return self._error(
                    check,
                    "method invocation metadata is not a socket message",
                    _elapsed_ms(started),
                )
            if not invocation.endpoint or not invocation.input_type:
                return self._error(
                    check,
                    "socket invocation metadata is incomplete",
                    _elapsed_ms(started),
                )
            if self._endpoint_policy is not None and not self._endpoint_policy.allows(
                invocation.endpoint,
            ):
                return self._error(
                    check,
                    "socket endpoint denied by destination policy",
                    _elapsed_ms(started),
                    error_reason=(
                        "CLOUD_DAST_ALLOWED_ENDPOINTS does not allow this endpoint"
                    ),
                )

            payload = self._codec.encode(
                invocation.input_type,
                dict(check.request),
            )
            result = self._transport.send(
                SocketCall(
                    endpoint=invocation.endpoint,
                    message_type=invocation.input_type,
                    payload=payload,
                    timeout=self._timeout,
                ),
            )
            if result.response is None:
                return self._error(
                    check,
                    "socket call failed",
                    _elapsed_ms(started),
                    error_reason=result.error_reason,
                )
            output = self._codec.decode(invocation.input_type, result.response)
            response_tree = self._codec.decode_full(
                invocation.input_type,
                result.response,
            )
        except SocketTargetError as error:
            return self._error(
                check,
                "socket call failed",
                _elapsed_ms(started),
                error_reason=error.safe_reason,
            )
        except Exception as error:
            logger.exception(
                "socket_check_failed check_id=%s reason=adapter_error",
                check.check_id,
            )
            reason = getattr(error, "safe_reason", None)
            return self._error(
                check,
                "socket call failed",
                _elapsed_ms(started),
                error_reason=reason if isinstance(reason, str) else None,
            )

        duration_ms = _elapsed_ms(started)
        logger.info(
            "socket_check_completed check_id=%s message_type=%s duration_ms=%.1f",
            check.check_id,
            invocation.input_type,
            duration_ms,
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="socket response received",
            output=output,
            duration_ms=duration_ms,
            error_reason=cap_error_reason(result.error_reason),
            response_tree=response_tree,
            response_digest=response_tree_digest(response_tree),
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


def cap_error_reason(reason: str | None) -> str | None:
    """Enforce the evidence cap for every error reason crossing the boundary."""

    if reason is None:
        return None
    return reason[:ERROR_REASON_MAX_LENGTH] or None


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        if closing == -1:
            return None
        host = endpoint[1:closing]
        remainder = endpoint[closing + 1 :]
        if not remainder.startswith(":"):
            return None
        port = remainder[1:]
    else:
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or ":" in host:
            return None
    if not port.isdigit():
        return None
    value = int(port)
    if not 1 <= value <= 65_535:
        return None
    return host, value


def _elapsed_ms(started: float) -> float:
    return (monotonic() - started) * 1000


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


def _is_scalar(value: Any) -> bool:
    return isinstance(value, str | int | float | bool | None)


def _decode_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


__all__ = [
    "JsonSocketCodec",
    "SocketCall",
    "SocketCodec",
    "SocketResult",
    "SocketTarget",
    "SocketTargetError",
    "SocketTransport",
    "TcpSocketTransport",
]
