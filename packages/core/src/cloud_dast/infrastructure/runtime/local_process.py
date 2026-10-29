"""Local process target adapter."""

from __future__ import annotations

import json
import logging
import re
import subprocess
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
    Invocation,
    InvocationRepository,
)

logger = logging.getLogger("cloud_dast.local_process")

ERROR_REASON_MAX_LENGTH = 512
OUTPUT_MAX_BYTES = 65_536
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MISSING = object()


class LocalProcessTargetError(Exception):
    """An adapter failure whose reason is safe to retain as evidence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.safe_reason = reason


@dataclass(frozen=True)
class LocalProcessCall:
    """One rendered local process invocation."""

    program: str
    argv: tuple[str, ...]
    stdin: bytes
    timeout: float | None


@dataclass(frozen=True)
class LocalProcessResult:
    """One process result or process-level transport error."""

    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    error_reason: str | None = None


class LocalProcessTransport(Protocol):
    def run(self, call: LocalProcessCall) -> LocalProcessResult: ...


class LocalProcessCodec(Protocol):
    """Encode process input and project process output."""

    def encode(self, request: Mapping[str, Any]) -> bytes: ...

    def decode(self, result: LocalProcessResult) -> ResponseData: ...

    def decode_full(
        self,
        result: LocalProcessResult,
    ) -> tuple[tuple[str, JsonValue], ...]: ...


class JsonLocalProcessCodec:
    """JSON stdin codec with explicit safe response-field projection."""

    def __init__(self, safe_fields: Sequence[str] = ()) -> None:
        self._safe_fields = tuple(sorted(set(safe_fields)))

    def encode(self, request: Mapping[str, Any]) -> bytes:
        try:
            return json.dumps(
                dict(request),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise LocalProcessTargetError("process input is not valid JSON") from error

    def decode(self, result: LocalProcessResult) -> ResponseData:
        document = self._document(result)
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
        result: LocalProcessResult,
    ) -> tuple[tuple[str, JsonValue], ...]:
        return (
            ("process.exit_code", result.exit_code),
            ("process.stdout", _decode_text(result.stdout)),
        )

    @staticmethod
    def _document(result: LocalProcessResult) -> Any:
        if not result.stdout:
            return {}
        try:
            return json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}


class SubprocessLocalProcessTransport:
    """Standard-library local process transport without a shell."""

    def run(self, call: LocalProcessCall) -> LocalProcessResult:
        try:
            completed = subprocess.run(
                [call.program, *call.argv],
                input=call.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=call.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return LocalProcessResult(
                exit_code=124,
                stdout=_cap_bytes(error.stdout or b""),
                stderr=_cap_bytes(error.stderr or b""),
                error_reason="process timeout",
            )
        except OSError as error:
            return LocalProcessResult(
                exit_code=127,
                error_reason=f"process failed to start: {error}",
            )
        return LocalProcessResult(
            exit_code=completed.returncode,
            stdout=_cap_bytes(completed.stdout),
            stderr=_cap_bytes(completed.stderr),
        )


class LocalProcessTarget:
    """Execute graph-described local process actions."""

    def __init__(
        self,
        invocations: InvocationRepository,
        codec: LocalProcessCodec,
        transport: LocalProcessTransport,
        *,
        timeout: float | None = 30.0,
    ) -> None:
        self._invocations = invocations
        self._codec = codec
        self._transport = transport
        self._timeout = timeout

    def __call__(self, check: Check) -> Observation:
        started = monotonic()
        logger.debug(
            "local_process_check_started check_id=%s method_id=%s scenario_id=%s",
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
            if invocation.transport != "local-process":
                return self._error(
                    check,
                    "method invocation metadata is not a local process",
                    _elapsed_ms(started),
                )
            if not invocation.endpoint:
                return self._error(
                    check,
                    "local process invocation metadata is incomplete",
                    _elapsed_ms(started),
                )

            values = dict(check.request)
            argv = _render_command(invocation.command_template, values)
            stdin_request = _stdin_request(invocation, values)
            payload = self._codec.encode(stdin_request)
            result = self._transport.run(
                LocalProcessCall(
                    program=invocation.endpoint,
                    argv=argv,
                    stdin=payload,
                    timeout=self._timeout,
                ),
            )
            output = self._codec.decode(result)
            response_tree = self._codec.decode_full(result)
        except LocalProcessTargetError as error:
            return self._error(
                check,
                "local process call failed",
                _elapsed_ms(started),
                error_reason=error.safe_reason,
            )
        except Exception as error:
            logger.exception(
                "local_process_check_failed check_id=%s reason=adapter_error",
                check.check_id,
            )
            reason = getattr(error, "safe_reason", None)
            return self._error(
                check,
                "local process call failed",
                _elapsed_ms(started),
                error_reason=reason if isinstance(reason, str) else None,
            )

        duration_ms = _elapsed_ms(started)
        logger.info(
            "local_process_check_completed check_id=%s exit_code=%s duration_ms=%.1f",
            check.check_id,
            result.exit_code,
            duration_ms,
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=(
                AccessOutcome.ALLOWED if result.exit_code == 0 else AccessOutcome.ERROR
            ),
            response_summary=f"process exit {result.exit_code}",
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


def _render_command(
    template: tuple[str, ...],
    values: Mapping[str, Any],
) -> tuple[str, ...]:
    rendered: list[str] = []
    for item in template:

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in values:
                raise LocalProcessTargetError(
                    f"missing local process argument: {name}",
                )
            return _scalar_text(values[name])

        rendered.append(_PLACEHOLDER.sub(replace, item))
    return tuple(rendered)


def _stdin_request(
    invocation: Invocation,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    if not invocation.stdin_fields:
        return dict(values)
    return {name: values[name] for name in invocation.stdin_fields if name in values}


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


def _cap_bytes(value: bytes) -> bytes:
    return value[:OUTPUT_MAX_BYTES]


__all__ = [
    "JsonLocalProcessCodec",
    "LocalProcessCall",
    "LocalProcessCodec",
    "LocalProcessResult",
    "LocalProcessTarget",
    "LocalProcessTargetError",
    "LocalProcessTransport",
    "SubprocessLocalProcessTransport",
]
