from __future__ import annotations

import json

import pytest

from cloud_dast.infrastructure.runtime import (
    EbpfEvidenceAdapter,
    JsonlEvidenceChannel,
    MemoryEvidenceChannel,
)
from cloud_dast.ports import EvidenceEvent


def test_memory_channel_joins_by_correlation_id() -> None:
    channel = MemoryEvidenceChannel()
    channel.set_ready(True)
    response = EvidenceEvent(
        correlation_id="candidate-1",
        channel="response",
        event_type="http",
        source="target",
    )
    ebpf = EvidenceEvent(
        correlation_id="candidate-1",
        channel="ebpf",
        event_type="exec",
        source="ebpf",
    )

    channel.record(response)
    channel.record(ebpf)

    assert channel.wait_for("candidate-1", 0.0) == ebpf
    assert channel.wait_for("missing", 0.0) is None


def test_memory_channel_filters_by_evidence_channel() -> None:
    channel = MemoryEvidenceChannel()
    response = EvidenceEvent(
        correlation_id="candidate-1",
        channel="response",
    )
    oob = EvidenceEvent(
        correlation_id="candidate-1",
        channel="oob",
    )
    ebpf = EvidenceEvent(
        correlation_id="candidate-1",
        channel="ebpf",
    )

    channel.record(response)
    channel.record(oob)
    channel.record(ebpf)

    assert channel.wait_for("candidate-1", 0.0) == ebpf
    assert channel.wait_for("candidate-1", 0.0, channel="oob") == oob
    assert channel.wait_for("candidate-1", 0.0, channel="response") == response


def test_jsonl_channel_persists_evidence_across_instances(tmp_path) -> None:
    path = tmp_path / "evidence.jsonl"
    event = EvidenceEvent(
        correlation_id="candidate-1",
        channel="app-log",
        event_type="log",
        source="application",
        observed_at=12.5,
        attributes=(("message", "marker observed"),),
    )

    JsonlEvidenceChannel(path).record(event)

    assert JsonlEvidenceChannel(path).wait_for("candidate-1", 0.0) == event
    assert json.loads(path.read_text())["channel"] == "app-log"


def test_ebpf_adapter_records_direct_exec_witness() -> None:
    channel = MemoryEvidenceChannel()
    adapter = EbpfEvidenceAdapter(channel)

    event = adapter.record_exec(
        "rce-marker",
        executable="/usr/bin/tool",
        argv=("--input", "rce-marker"),
        process_id=42,
        timestamp=7.5,
    )

    assert channel.wait_for("rce-marker", 0.0) == event
    assert event.channel == "ebpf"
    assert event.event_type == "exec"
    assert ("argv", ("--input", "rce-marker")) in event.attributes


def test_ebpf_adapter_rejects_exec_without_marker() -> None:
    channel = MemoryEvidenceChannel()
    adapter = EbpfEvidenceAdapter(channel)

    with pytest.raises(ValueError, match="does not contain the marker"):
        adapter.record_exec(
            "rce-marker",
            executable="/usr/bin/tool",
            argv=("--input", "benign"),
        )


def test_ebpf_adapter_records_file_and_net_events() -> None:
    channel = MemoryEvidenceChannel()
    adapter = EbpfEvidenceAdapter(channel)

    file_event = adapter.record_file(
        "candidate-1",
        path="/tmp/candidate-1",
        process_id=42,
    )
    net_event = adapter.record_net(
        "candidate-1",
        remote_address="203.0.113.10:443",
        process_id=42,
    )

    assert channel.wait_for("candidate-1", 0.0) == net_event
    assert file_event.event_type == "file"
    assert net_event.event_type == "net"
