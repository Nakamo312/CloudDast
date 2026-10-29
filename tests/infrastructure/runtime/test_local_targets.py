from __future__ import annotations

from typing import Any

from cloud_dast.infrastructure.runtime.local_process import (
    JsonLocalProcessCodec,
    LocalProcessCall,
    LocalProcessResult,
    LocalProcessTarget,
)
from cloud_dast.infrastructure.runtime.socket import (
    JsonSocketCodec,
    SocketCall,
    SocketResult,
    SocketTarget,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    ResponseData,
)
from cloud_dast.ports import Invocation


class Invocations:
    def __init__(self, invocation: Invocation | None) -> None:
        self.invocation = invocation

    def get_invocation(self, method_id: str) -> Invocation | None:
        if self.invocation is None:
            return None
        return self.invocation if self.invocation.method_id == method_id else None


class ProcessTransport:
    def __init__(self, result: LocalProcessResult) -> None:
        self.result = result
        self.calls: list[LocalProcessCall] = []

    def run(self, call: LocalProcessCall) -> LocalProcessResult:
        self.calls.append(call)
        return self.result


class SocketTransport:
    def __init__(self, result: SocketResult) -> None:
        self.result = result
        self.calls: list[SocketCall] = []

    def send(self, call: SocketCall) -> SocketResult:
        self.calls.append(call)
        return self.result


class DenyEndpointPolicy:
    def allows(self, endpoint: str) -> bool:
        return False


def process_invocation() -> Invocation:
    return Invocation(
        method_id="local:configure",
        endpoint="/usr/bin/device-tool",
        transport="local-process",
        command_template=("--host", "{host}", "--port", "{port}"),
        stdin_fields=("payload",),
    )


def socket_invocation() -> Invocation:
    return Invocation(
        method_id="socket:send",
        endpoint="127.0.0.1:9000",
        transport="socket",
        input_type="ConfigureRequest",
        output_type="ConfigureResponse",
    )


def check(**overrides: Any) -> Check:
    values: dict[str, Any] = {
        "invariant_id": "invariant",
        "method_id": "local:configure",
        "scenario_id": "scenario",
        "request": (
            ("host", "example.test"),
            ("port", 443),
            ("payload", "marker"),
        ),
        "identities": ("attacker",),
    }
    values.update(overrides)
    return Check(**values)


def test_local_process_target_renders_command_and_stdin() -> None:
    invocations = Invocations(process_invocation())
    transport = ProcessTransport(
        LocalProcessResult(
            exit_code=0,
            stdout=b'{"status":"ok"}',
        )
    )
    target = LocalProcessTarget(
        invocations,
        JsonLocalProcessCodec(safe_fields=("status",)),
        transport,
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert observation.response_summary == "process exit 0"
    assert observation.output == ResponseData(
        fields=(("status", "ok"),),
        field_names=("status",),
    )
    assert observation.response_tree == (
        ("process.exit_code", 0),
        ("process.stdout", '{"status":"ok"}'),
    )
    process_call = transport.calls[0]
    assert process_call.program == "/usr/bin/device-tool"
    assert process_call.argv == ("--host", "example.test", "--port", "443")
    assert process_call.stdin == b'{"payload":"marker"}'


def test_local_process_target_reports_missing_invocation() -> None:
    target = LocalProcessTarget(
        Invocations(None),
        JsonLocalProcessCodec(),
        ProcessTransport(LocalProcessResult(exit_code=0)),
    )

    observation = target(check())

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == "method invocation metadata is missing"


def test_socket_target_sends_message_and_projects_response() -> None:
    invocations = Invocations(socket_invocation())
    transport = SocketTransport(SocketResult(response=b'{"status":"ok"}'))
    target = SocketTarget(
        invocations,
        JsonSocketCodec(safe_fields=("status",)),
        transport,
    )
    socket_check = check(
        method_id="socket:send",
        request=(("command", "configure"),),
    )

    observation = target(socket_check)

    assert observation.observed_outcome is AccessOutcome.ALLOWED
    assert observation.response_summary == "socket response received"
    assert observation.output == ResponseData(
        fields=(("status", "ok"),),
        field_names=("status",),
    )
    assert transport.calls[0].endpoint == "127.0.0.1:9000"
    assert transport.calls[0].message_type == "ConfigureRequest"
    assert transport.calls[0].payload == b'{"command":"configure"}'


def test_socket_target_enforces_endpoint_policy() -> None:
    target = SocketTarget(
        Invocations(socket_invocation()),
        JsonSocketCodec(),
        SocketTransport(SocketResult(response=b"{}")),
        endpoint_policy=DenyEndpointPolicy(),
    )

    observation = target(check(method_id="socket:send"))

    assert observation.observed_outcome is AccessOutcome.ERROR
    assert observation.response_summary == (
        "socket endpoint denied by destination policy"
    )
