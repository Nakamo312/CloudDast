from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Any, Protocol

from cloud_dast.model import (
    AccessOutcome,
    Check,
    GrpcStatus,
    JsonValue,
    Observation,
    ResponseData,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import EndpointPolicy, InvocationRepository, TokenProvider

logger = logging.getLogger("cloud_dast.grpc")

ERROR_REASON_MAX_LENGTH = 512
"""Maximum retained transport error text; longer evidence is truncated."""


@dataclass(frozen=True)
class GrpcCall:
    endpoint: str
    rpc_path: str
    payload: bytes
    metadata: tuple[tuple[str, str], ...]
    timeout: float | None = 30.0


@dataclass(frozen=True)
class GrpcResult:
    status: GrpcStatus
    summary: str
    response: bytes | None = None
    auth_failed: bool = False
    error_reason: str | None = None


class PayloadCodec(Protocol):
    """Encode requests and decode responses for one gRPC surface.

    ``decode`` projects only fields explicitly needed by a later workflow
    step into ``ResponseData``; that whitelist remains a dataflow-forwarding
    mechanism, not a security boundary.  ``decode_full`` returns the complete
    decoded leaf tree, which the engine retains as evidence because it runs
    against isolated application copies.
    """

    def encode(self, input_type: str, request: Mapping[str, Any]) -> bytes: ...

    def decode(self, output_type: str, response: bytes) -> ResponseData: ...

    def decode_full(
        self, output_type: str, response: bytes
    ) -> tuple[tuple[str, JsonValue], ...]: ...


class GrpcTransport(Protocol):
    def invoke(self, call: GrpcCall) -> GrpcResult: ...


class GrpcTarget:
    """Execute any graph-described unary gRPC method.

    The target deliberately depends on small runtime ports.  grpcio, protobuf,
    credentials, and descriptor loading remain infrastructure concerns and can
    be supplied without making the domain or application import them.
    """

    def __init__(
        self,
        invocations: InvocationRepository,
        codec: PayloadCodec,
        tokens: TokenProvider,
        transport: GrpcTransport,
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
            "grpc_check_started check_id=%s method_id=%s scenario_id=%s",
            check.check_id,
            check.method_id,
            check.scenario_id,
        )
        try:
            invocation = self._invocations.get_invocation(check.method_id)
            if invocation is None:
                duration_ms = (monotonic() - started) * 1000
                logger.warning(
                    "grpc_check_failed check_id=%s reason=missing_invocation duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "method invocation metadata is missing", duration_ms
                )
            if invocation.transport != "grpc":
                duration_ms = (monotonic() - started) * 1000
                logger.warning(
                    "grpc_check_failed check_id=%s reason=transport_mismatch "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "method invocation metadata is not gRPC", duration_ms
                )
            if invocation.input_type is None or invocation.rpc_path is None:
                duration_ms = (monotonic() - started) * 1000
                logger.warning(
                    "grpc_check_failed check_id=%s reason=incomplete_invocation "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "gRPC invocation metadata is incomplete", duration_ms
                )
            if self._endpoint_policy is not None and not self._endpoint_policy.allows(
                invocation.endpoint
            ):
                duration_ms = (monotonic() - started) * 1000
                logger.warning(
                    "grpc_check_failed check_id=%s reason=endpoint_policy_denied "
                    "duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check,
                    "gRPC endpoint denied by destination policy",
                    duration_ms,
                    error_reason="CLOUD_DAST_ALLOWED_ENDPOINTS does not allow this endpoint",
                )
            if len(check.identities) != 1:
                duration_ms = (monotonic() - started) * 1000
                logger.warning(
                    "grpc_check_failed check_id=%s reason=identity_count duration_ms=%.1f",
                    check.check_id,
                    duration_ms,
                )
                return self._error(
                    check, "a gRPC check requires one identity", duration_ms
                )
            request = dict(check.request)
            payload = self._codec.encode(invocation.input_type, request)
            result = self._transport.invoke(
                GrpcCall(
                    endpoint=invocation.endpoint,
                    rpc_path=invocation.rpc_path,
                    payload=payload,
                    metadata=self._tokens.metadata(check.identities[0]),
                    timeout=self._timeout,
                )
            )
            output = None
            response_tree: tuple[tuple[str, JsonValue], ...] = ()
            if result.response is not None:
                if invocation.output_type is None:
                    response_tree = (
                        ("__response__.not_available", "output_type_missing"),
                    )
                else:
                    response_tree = self._codec.decode_full(
                        invocation.output_type, result.response
                    )
                    try:
                        output = self._codec.decode(
                            invocation.output_type, result.response
                        )
                    except Exception as exc:
                        duration_ms = (monotonic() - started) * 1000
                        logger.exception(
                            "grpc_check_failed check_id=%s "
                            "reason=safe_decode_failed duration_ms=%.1f",
                            check.check_id,
                            duration_ms,
                        )
                        return self._error(
                            check,
                            "gRPC call failed",
                            duration_ms,
                            error_reason=_safe_error_reason(exc),
                            response_tree=response_tree,
                        )
        except Exception as exc:
            duration_ms = (monotonic() - started) * 1000
            logger.exception(
                "grpc_check_failed check_id=%s reason=adapter_error duration_ms=%.1f",
                check.check_id,
                duration_ms,
            )
            return self._error(
                check,
                "gRPC call failed",
                duration_ms,
                error_reason=rpc_error_details(exc) or _safe_error_reason(exc),
            )

        duration_ms = (monotonic() - started) * 1000
        logger.info(
            "grpc_check_completed check_id=%s method_id=%s status=%s duration_ms=%.1f",
            check.check_id,
            check.method_id,
            result.status.token,
            duration_ms,
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=_outcome(result.status),
            response_summary=f"gRPC status: {result.status.code.upper()}",
            transport_status=result.status,
            auth_failed=result.auth_failed or result.status.is_auth_failure(),
            output=output,
            duration_ms=duration_ms,
            error_reason=cap_error_reason(result.error_reason),
            response_tree=response_tree,
            response_digest=(
                response_tree_digest(response_tree)
                if result.response is not None
                else None
            ),
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


def _outcome(status: GrpcStatus) -> AccessOutcome:
    normalized = status.code.upper()
    if normalized in {"OK", "SUCCESS"}:
        return AccessOutcome.ALLOWED
    if normalized == "PERMISSION_DENIED":
        return AccessOutcome.DENIED
    if normalized == "UNAUTHENTICATED":
        # Authentication failure is an infrastructure error, not an
        # authorization decision. It must remain unscoreable for policy oracles.
        return AccessOutcome.ERROR
    if normalized in {"NOT_FOUND", "UNKNOWN", "UNIMPLEMENTED"}:
        return AccessOutcome.UNKNOWN
    return AccessOutcome.UNKNOWN


def cap_error_reason(reason: str | None) -> str | None:
    """Enforce the evidence cap for every error reason crossing the boundary."""

    if reason is None:
        return None
    return reason[:ERROR_REASON_MAX_LENGTH] or None


def rpc_error_details(exc: Exception) -> str | None:
    """Return gRPC error details when a transport raised ``RpcError`` itself."""

    details = getattr(exc, "details", None)
    if not callable(details):
        return None
    try:
        reason = details()
    except Exception:
        return None
    return reason if isinstance(reason, str) else None


def _safe_error_reason(exc: Exception) -> str | None:
    """Return only adapter reasons explicitly marked safe for retention."""

    reason = getattr(exc, "safe_reason", None)
    return reason if isinstance(reason, str) else None
