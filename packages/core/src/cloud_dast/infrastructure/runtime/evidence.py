"""Generic evidence-channel adapters shared by all runtime sources."""

from __future__ import annotations

import json
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from pathlib import Path

from cloud_dast.infrastructure.jsonl import JsonlFile
from cloud_dast.ports import EvidenceChannelKind, EvidenceEvent

_CHANNELS: frozenset[str] = frozenset(
    {"response", "oob", "ebpf", "app-log"},
)
_MAX_CORRELATION_ID_LENGTH = 256
_MAX_EVENT_ID_LENGTH = 128
_MAX_EVENT_TYPE_LENGTH = 64
_MAX_SOURCE_LENGTH = 256
_MAX_ATTRIBUTES = 64
_MAX_ATTRIBUTE_NAME_LENGTH = 128
_MAX_ATTRIBUTE_VALUE_BYTES = 4096


class _BoundedEvidenceIndex:
    """Fixed-size event ring with an O(1) correlation-id lookup."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._events: deque[EvidenceEvent] = deque(maxlen=capacity)
        self._events_by_id: dict[str, deque[EvidenceEvent]] = {}

    def add(self, event: EvidenceEvent) -> None:
        capacity = self._events.maxlen
        if capacity is not None and len(self._events) == capacity:
            oldest = self._events[0]
            events = self._events_by_id[oldest.correlation_id]
            events.popleft()
            if not events:
                del self._events_by_id[oldest.correlation_id]
        self._events.append(event)
        self._events_by_id.setdefault(event.correlation_id, deque()).append(event)

    def latest(
        self,
        correlation_id: str,
        channel: EvidenceChannelKind | None = None,
    ) -> EvidenceEvent | None:
        events = self._events_by_id.get(correlation_id)
        if not events:
            return None
        if channel is None:
            return events[-1]
        return next(
            (event for event in reversed(events) if event.channel == channel),
            None,
        )

    def clear(self) -> None:
        self._events.clear()
        self._events_by_id.clear()

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        return tuple(self._events)


class _BoundedEventIds:
    """Fixed-size event-id membership used for duplicate protection."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._ids: OrderedDict[str, None] = OrderedDict()
        self._capacity = capacity

    def add(self, event_id: str) -> None:
        self._ids[event_id] = None
        if len(self._ids) > self._capacity:
            self._ids.popitem(last=False)

    def __contains__(self, event_id: object) -> bool:
        return event_id in self._ids

    def clear(self) -> None:
        self._ids.clear()


class MemoryEvidenceChannel:
    """Thread-safe, bounded in-memory evidence channel."""

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        *,
        capacity: int = 10_000,
    ) -> None:
        self._condition = threading.Condition()
        self._index = _BoundedEvidenceIndex(capacity)
        self._ready = False
        self._blocked_reason: str | None = None
        self._clock = clock

    def record(self, event: EvidenceEvent) -> None:
        validate_evidence_event(event)
        with self._condition:
            self._index.add(event)
            self._condition.notify_all()

    def wait_for(
        self,
        correlation_id: str,
        timeout: float,
        *,
        channel: EvidenceChannelKind | None = None,
    ) -> EvidenceEvent | None:
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        deadline = self._clock() + timeout
        with self._condition:
            while True:
                event = self._index.latest(correlation_id, channel)
                if event is not None:
                    return event
                remaining = deadline - self._clock()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)

    def ready(self) -> bool:
        with self._condition:
            return self._ready

    def set_ready(self, ready: bool) -> None:
        with self._condition:
            self._ready = ready
            self._blocked_reason = None if ready else "evidence channel is not ready"
            self._condition.notify_all()

    def block(self, reason: str) -> None:
        if not reason:
            raise ValueError("blocked reason must not be empty")
        with self._condition:
            self._ready = False
            self._blocked_reason = reason
            self._condition.notify_all()

    def blocked_reason(self) -> str | None:
        with self._condition:
            return self._blocked_reason

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        with self._condition:
            return self._index.events


class JsonlEvidenceChannel:
    """Append-only, cross-process evidence channel with a bounded index."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.monotonic,
        poll_interval: float = 0.05,
        sleep: Callable[[float], None] = time.sleep,
        capacity: int = 10_000,
    ) -> None:
        if poll_interval < 0:
            raise ValueError("poll_interval must not be negative")
        self._file = JsonlFile(path)
        self.path = self._file.path
        self._state_lock = threading.Lock()
        self._index = _BoundedEvidenceIndex(capacity)
        self._event_ids = _BoundedEventIds(capacity)
        self._offset = 0
        self._ready = False
        self._blocked_reason: str | None = None
        self._clock = clock
        self._poll_interval = poll_interval
        self._sleep = sleep
        with self._file.locked():
            self._file.ensure()
            self._refresh_unlocked()

    def record(self, event: EvidenceEvent) -> None:
        payload = evidence_event_payload(event)
        line = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        with self._file.locked():
            self._refresh_unlocked()
            self._file.truncate_incomplete_tail()
            if event.event_id in self._event_ids:
                raise ValueError(f"duplicate evidence event_id: {event.event_id}")
            self._file.append(line)
            self._index.add(event)
            self._event_ids.add(event.event_id)
            self._offset = self.path.stat().st_size

    def wait_for(
        self,
        correlation_id: str,
        timeout: float,
        *,
        channel: EvidenceChannelKind | None = None,
    ) -> EvidenceEvent | None:
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        deadline = self._clock() + timeout
        while True:
            with self._file.locked():
                self._refresh_unlocked()
                event = self._index.latest(correlation_id, channel)
                if event is None:
                    event = self._query_persisted_unlocked(correlation_id, channel)
                if event is not None:
                    return event
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None
            self._sleep(min(self._poll_interval, remaining))

    def ready(self) -> bool:
        with self._state_lock:
            return self._ready

    def set_ready(self, ready: bool) -> None:
        with self._state_lock:
            self._ready = ready
            self._blocked_reason = None if ready else "evidence channel is not ready"

    def block(self, reason: str) -> None:
        if not reason:
            raise ValueError("blocked reason must not be empty")
        with self._state_lock:
            self._ready = False
            self._blocked_reason = reason

    def blocked_reason(self) -> str | None:
        with self._state_lock:
            return self._blocked_reason

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        """Return the bounded recent window, not the entire ledger."""

        with self._file.locked():
            self._refresh_unlocked()
            return self._index.events

    def _refresh_unlocked(self) -> None:
        size = self.path.stat().st_size
        if size < self._offset:
            self._index.clear()
            self._event_ids.clear()
            self._offset = 0
        if size == self._offset:
            return

        tail, new_offset = self._file.complete_tail(self._offset)
        if not tail:
            return
        for raw_line in tail.splitlines():
            if not raw_line.strip():
                continue
            try:
                event = evidence_event_from_payload(json.loads(raw_line))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as error:
                raise ValueError(
                    f"invalid evidence event JSON in {self.path}"
                ) from error
            if event.event_id in self._event_ids:
                raise ValueError(f"duplicate evidence event_id: {event.event_id}")
            self._index.add(event)
            self._event_ids.add(event.event_id)
        self._offset = new_offset

    def _query_persisted_unlocked(
        self,
        correlation_id: str,
        channel: EvidenceChannelKind | None = None,
    ) -> EvidenceEvent | None:
        event: EvidenceEvent | None = None
        for number, raw_line in self._file.iter_lines():
            if not raw_line.endswith(b"\n"):
                continue
            try:
                candidate = evidence_event_from_payload(json.loads(raw_line))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as error:
                raise ValueError(
                    f"invalid evidence event JSON at line {number} in {self.path}"
                ) from error
            if candidate.correlation_id == correlation_id and (
                channel is None or candidate.channel == channel
            ):
                event = candidate
        if event is not None:
            self._index.add(event)
        return event


def validate_evidence_event(event: EvidenceEvent) -> None:
    """Validate one event before it enters an evidence channel."""

    _validate_text("correlation_id", event.correlation_id, _MAX_CORRELATION_ID_LENGTH)
    _validate_text("event_id", event.event_id, _MAX_EVENT_ID_LENGTH)
    if event.channel not in _CHANNELS:
        raise ValueError(f"unknown evidence channel: {event.channel}")
    if len(event.event_type) > _MAX_EVENT_TYPE_LENGTH:
        raise ValueError("event_type is too long")
    if len(event.source) > _MAX_SOURCE_LENGTH:
        raise ValueError("source is too long")
    if not math.isfinite(event.observed_at) or event.observed_at < 0:
        raise ValueError("observed_at must be a finite non-negative number")
    if len(event.attributes) > _MAX_ATTRIBUTES:
        raise ValueError("evidence event has too many attributes")

    names: set[str] = set()
    for name, value in event.attributes:
        _validate_text("attribute name", name, _MAX_ATTRIBUTE_NAME_LENGTH)
        if name in names:
            raise ValueError(f"duplicate evidence attribute: {name}")
        names.add(name)
        _validate_json_value(value)


def evidence_event_payload(event: EvidenceEvent) -> dict[str, object]:
    """Return the canonical JSON payload for one evidence event."""

    validate_evidence_event(event)
    return {
        "event_id": event.event_id,
        "correlation_id": event.correlation_id,
        "channel": event.channel,
        "event_type": event.event_type,
        "source": event.source,
        "observed_at": event.observed_at,
        "attributes": [
            [name, value]
            for name, value in sorted(event.attributes, key=lambda x: x[0])
        ],
    }


def evidence_event_from_payload(payload: object) -> EvidenceEvent:
    """Parse and validate one evidence event from a JSON payload."""

    if not isinstance(payload, dict):
        raise ValueError("evidence event must be a JSON object")
    required = {
        "event_id",
        "correlation_id",
        "channel",
        "event_type",
        "source",
        "observed_at",
        "attributes",
    }
    if set(payload) != required:
        raise ValueError("evidence event fields do not match the schema")

    raw_attributes = payload["attributes"]
    if not isinstance(raw_attributes, list):
        raise ValueError("evidence event attributes must be a list")
    attributes: list[tuple[str, object]] = []
    for item in raw_attributes:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("evidence event attribute must be a pair")
        name, value = item
        if not isinstance(name, str):
            raise ValueError("evidence event attribute name must be a string")
        attributes.append((name, value))

    raw_channel = payload["channel"]
    if not isinstance(raw_channel, str):
        raise ValueError("evidence event channel must be a string")
    raw_observed_at = payload["observed_at"]
    if not isinstance(raw_observed_at, int | float) or isinstance(
        raw_observed_at, bool
    ):
        raise ValueError("evidence event observed_at must be a number")

    event = EvidenceEvent(
        correlation_id=_required_text(payload, "correlation_id"),
        channel=raw_channel,  # type: ignore[arg-type]
        event_id=_required_text(payload, "event_id"),
        event_type=_required_text(payload, "event_type"),
        source=_required_text(payload, "source"),
        observed_at=float(raw_observed_at),
        attributes=tuple(attributes),  # type: ignore[arg-type]
    )
    validate_evidence_event(event)
    return event


def _required_text(payload: dict[str, object], name: str) -> str:
    value = payload[name]
    if not isinstance(value, str):
        raise ValueError(f"evidence event {name} must be a string")
    return value


def _validate_text(name: str, value: str, limit: int) -> None:
    if not value:
        raise ValueError(f"evidence event {name} must not be empty")
    if len(value) > limit:
        raise ValueError(f"evidence event {name} is too long")


def _validate_json_value(value: object) -> None:
    if value is None or isinstance(value, str | bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("evidence attribute contains a non-finite number")
    elif isinstance(value, tuple | list):
        for item in value:
            _validate_json_value(item)
    else:
        raise ValueError("evidence attribute contains an unsupported JSON value")

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("evidence attribute is not valid JSON") from error
    if len(encoded.encode("utf-8")) > _MAX_ATTRIBUTE_VALUE_BYTES:
        raise ValueError("evidence attribute is too large")


__all__ = [
    "EvidenceChannelKind",
    "JsonlEvidenceChannel",
    "MemoryEvidenceChannel",
    "evidence_event_from_payload",
    "evidence_event_payload",
    "validate_evidence_event",
]
