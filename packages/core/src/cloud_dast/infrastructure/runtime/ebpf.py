"""eBPF evidence adapter for local process and protocol targets."""

from __future__ import annotations

from cloud_dast.ports import EvidenceChannel, EvidenceEvent


class EbpfEvidenceAdapter:
    """Record normalized eBPF events into the generic evidence channel.

    The adapter does not attach probes or interpret kernel events.  An external
    eBPF agent supplies already-normalized events; this boundary only validates
    the correlation and projects the event into QDL-safe evidence metadata.
    """

    def __init__(self, channel: EvidenceChannel) -> None:
        self._channel = channel

    def record_exec(
        self,
        marker: str,
        *,
        executable: str,
        argv: tuple[str, ...],
        process_id: int | None = None,
        timestamp: float = 0.0,
    ) -> EvidenceEvent:
        """Record an exec event whose argv contains the probe marker.

        A marker observed in ``argv`` is a direct RCE witness: it proves that
        attacker-controlled data reached a process execution boundary without
        relying on an out-of-band callback.
        """

        if not marker:
            raise ValueError("eBPF exec evidence requires a marker")
        if not executable:
            raise ValueError("eBPF exec evidence requires an executable")
        if marker not in argv:
            raise ValueError("eBPF exec evidence does not contain the marker in argv")

        event = EvidenceEvent(
            correlation_id=marker,
            channel="ebpf",
            event_type="exec",
            source="ebpf",
            observed_at=timestamp,
            attributes=(
                ("argv", argv),
                ("executable", executable),
                *((("process_id", process_id),) if process_id is not None else ()),
            ),
        )
        self._channel.record(event)
        return event

    def record_file(
        self,
        marker: str,
        *,
        path: str,
        process_id: int | None = None,
        timestamp: float = 0.0,
    ) -> EvidenceEvent:
        """Record a file operation correlated to a probe marker."""

        if not marker:
            raise ValueError("eBPF file evidence requires a marker")
        if not path:
            raise ValueError("eBPF file evidence requires a path")
        event = EvidenceEvent(
            correlation_id=marker,
            channel="ebpf",
            event_type="file",
            source="ebpf",
            observed_at=timestamp,
            attributes=(
                ("path", path),
                *((("process_id", process_id),) if process_id is not None else ()),
            ),
        )
        self._channel.record(event)
        return event

    def record_net(
        self,
        marker: str,
        *,
        remote_address: str,
        process_id: int | None = None,
        timestamp: float = 0.0,
    ) -> EvidenceEvent:
        """Record a network operation correlated to a probe marker."""

        if not marker:
            raise ValueError("eBPF network evidence requires a marker")
        if not remote_address:
            raise ValueError("eBPF network evidence requires a remote address")
        event = EvidenceEvent(
            correlation_id=marker,
            channel="ebpf",
            event_type="net",
            source="ebpf",
            observed_at=timestamp,
            attributes=(
                ("remote_address", remote_address),
                *((("process_id", process_id),) if process_id is not None else ()),
            ),
        )
        self._channel.record(event)
        return event


__all__ = ["EbpfEvidenceAdapter"]
