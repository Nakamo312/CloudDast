"""Optional grpcio transport for the generic target contract."""

from __future__ import annotations

from threading import Lock
from typing import Any

from cloud_dast.infrastructure.runtime.grpc import (
    GrpcCall,
    GrpcResult,
    cap_error_reason,
    rpc_error_details,
)
from cloud_dast.model import GrpcStatus


class GrpcioTransport:
    """Invoke raw unary gRPC calls using graph-provided method paths.

    Protobuf encoding remains the responsibility of ``PayloadCodec``.  This
    adapter deliberately deals only in bytes, so it can execute generated or
    dynamic protobuf codecs without coupling the runtime to a service package.
    ``grpcio`` is imported lazily to keep offline/core tests import-safe.
    """

    def __init__(
        self,
        *,
        options: tuple[tuple[str, Any], ...] = (),
        insecure: bool = False,
    ) -> None:
        self._options = options
        self._insecure = insecure
        self._channels: dict[str, Any] = {}
        self._lock = Lock()

    def invoke(self, call: GrpcCall) -> GrpcResult:
        try:
            import grpc
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "grpcio is required for live gRPC execution; install grpcio"
            ) from exc

        channel = self._channel(call.endpoint, grpc)
        unary = channel.unary_unary(
            call.rpc_path,
            request_serializer=_identity,
            response_deserializer=_identity,
        )
        try:
            response = unary(
                call.payload,
                metadata=call.metadata,
                timeout=call.timeout,
            )
        except grpc.RpcError as exc:
            code = exc.code().name if exc.code() is not None else "UNKNOWN"
            status = GrpcStatus(code=code)
            return GrpcResult(
                status=status,
                summary=f"gRPC status: {code}",
                auth_failed=status.is_auth_failure(),
                error_reason=cap_error_reason(rpc_error_details(exc)),
            )
        return GrpcResult(
            status=GrpcStatus(code="OK"),
            summary="gRPC call succeeded",
            response=response,
        )

    def close(self) -> None:
        with self._lock:
            channels = tuple(self._channels.values())
            self._channels.clear()
        for channel in channels:
            channel.close()

    def _channel(self, endpoint: str, grpc: Any) -> Any:
        with self._lock:
            channel = self._channels.get(endpoint)
            if channel is None:
                if self._insecure:
                    channel = grpc.insecure_channel(endpoint, options=self._options)
                else:
                    channel = grpc.secure_channel(
                        endpoint,
                        grpc.ssl_channel_credentials(),
                        options=self._options,
                    )
                self._channels[endpoint] = channel
            return channel


def _identity(payload: bytes) -> bytes:
    return payload
