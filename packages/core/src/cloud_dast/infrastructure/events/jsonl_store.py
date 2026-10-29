from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from pydantic import TypeAdapter

from cloud_dast.infrastructure.jsonl import JsonlFile, redact_json_payload
from cloud_dast.model.events import DomainEvent, Event, is_replay_idempotent

_EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)
_CHAIN_VERSION = 1
_GENESIS_HASH = "0" * 64
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RECORD_KEYS = frozenset({"event", "integrity"})
_INTEGRITY_KEYS = frozenset({"version", "previous", "hash"})


class JsonlEventStore:
    """Append-only, hash-chained JSONL event store.

    Every persisted line is a wrapper around one domain event and an integrity
    block.  The record hash covers the canonical event JSON and the previous
    record hash, so deleting, reordering, editing, or replaying a line breaks
    verification.
    """

    def __init__(self, path: str | Path) -> None:
        self._file = JsonlFile(path)
        self.path = self._file.path
        self._ids: set[str] = set()
        self._semantic_keys: set[str] = set()
        self._events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}
        self._offset = 0
        self._line_count = 0
        self._chain_head = _GENESIS_HASH
        self._needs_separator = False
        with self._file.locked():
            self._file.ensure()
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_event,
                preserve_complete=True,
                label="event",
            )
            self._load_full_projection_unlocked()

    def append(self, event: DomainEvent) -> None:
        with self._file.locked():
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_event,
                preserve_complete=True,
                label="event",
            )
            # Another process may have appended since this instance was
            # constructed. Reconcile only the bytes after our last offset.
            self._refresh_index_unlocked()
            if event.event_id in self._ids:
                raise ValueError(f"duplicate event_id: {event.event_id}")
            if (
                is_replay_idempotent(event)
                and event.semantic_key in self._semantic_keys
            ):
                return

            event_payload = event.model_dump(mode="json")
            event_payload_json = json.dumps(
                event_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            event_payload = json.loads(redact_json_payload(event_payload_json))
            record = build_hash_chain_record(
                event_payload,
                self._chain_head,
            )
            payload = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            separator = b"\n" if self._needs_separator else b""
            self._file.append(payload, separator=separator, redact=False)
            self._needs_separator = False
            self._ids.add(event.event_id)
            if is_replay_idempotent(event):
                self._semantic_keys.add(event.semantic_key)
            self._events.append(_EVENT_ADAPTER.validate_python(event_payload))
            self._offset = self.path.stat().st_size
            self._chain_head = record["integrity"]["hash"]

    def append_many(self, events: Iterable[DomainEvent]) -> None:
        for event in events:
            self.append(event)

    def read(self) -> Iterator[DomainEvent]:
        with self._file.locked():
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_event,
                preserve_complete=True,
                label="event",
            )
            self._load_full_projection_unlocked()
        # Materialize before yielding so the lock is released while consumers
        # process the stream.
        yield from tuple(self._events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        """Return events appended since this consumer's previous read."""

        with self._file.locked():
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_event,
                preserve_complete=True,
                label="event",
            )
            self._refresh_index_unlocked()
            cursor = self._cursors.get(consumer_id, 0)
            events = tuple(self._events[cursor:])
            self._cursors[consumer_id] = len(self._events)
        return events

    def _load_full_projection_unlocked(self) -> None:
        """Verify and replace the complete in-memory projection."""

        events: list[DomainEvent] = []
        ids: set[str] = set()
        semantic_keys: set[str] = set()
        previous_hash = _GENESIS_HASH
        line_count = 0
        for number, raw_line in self._file.iter_lines():
            line_count += 1
            try:
                event, previous_hash = _decode_chain_record(
                    raw_line,
                    previous_hash,
                )
            except ValueError as exc:
                raise ValueError(f"invalid event JSON at line {number}") from exc
            events.append(event)
            ids.add(event.event_id)
            if is_replay_idempotent(event):
                semantic_keys.add(event.semantic_key)

        self._events = events
        self._ids = ids
        self._semantic_keys = semantic_keys
        self._offset = self.path.stat().st_size
        self._line_count = line_count
        self._chain_head = previous_hash

    def _refresh_index_unlocked(self) -> None:
        """Index newly appended event IDs without rereading the whole file."""

        size = self.path.stat().st_size
        if size < self._offset:
            self._ids.clear()
            self._semantic_keys.clear()
            self._events.clear()
            self._cursors.clear()
            self._offset = 0
            self._line_count = 0
            self._chain_head = _GENESIS_HASH
            self._load_full_projection_unlocked()
            return
        if size == self._offset:
            return

        tail, new_offset = self._file.complete_tail(self._offset)
        if not tail and size > self._offset:
            with self.path.open("rb") as stream:
                stream.seek(self._offset)
                candidate = stream.read()
            try:
                _decode_chain_record(candidate, self._chain_head)
            except ValueError:
                candidate = b""
            if candidate:
                tail = candidate
                new_offset = size
        if not tail:
            return
        start_line = self._line_count + 1
        previous_hash = self._chain_head
        new_events: list[DomainEvent] = []
        for relative_number, raw_line in enumerate(tail.splitlines()):
            line_number = start_line + relative_number
            if not raw_line.strip():
                continue
            try:
                event, previous_hash = _decode_chain_record(
                    raw_line,
                    previous_hash,
                )
            except ValueError as exc:
                raise ValueError(f"invalid event JSON at line {line_number}") from exc
            self._ids.add(event.event_id)
            if is_replay_idempotent(event):
                self._semantic_keys.add(event.semantic_key)
            new_events.append(event)
        self._events.extend(new_events)
        self._offset = new_offset
        self._line_count += tail.count(b"\n")
        self._chain_head = previous_hash


def _validate_event(raw_line: bytes) -> object:
    record = json.loads(raw_line)
    return _validate_event_record(record)


def _validate_event_record(record: object) -> DomainEvent:
    if not isinstance(record, dict):
        raise ValueError("event record must be a JSON object")
    if set(record) != _RECORD_KEYS:
        raise ValueError("event record has unsupported fields")
    integrity = record["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != _INTEGRITY_KEYS:
        raise ValueError("event record has invalid chain integrity metadata")
    if integrity["version"] != _CHAIN_VERSION:
        raise ValueError("event record chain version is unsupported")
    for name in ("previous", "hash"):
        value = integrity[name]
        if not isinstance(value, str) or not _HASH_PATTERN.fullmatch(value):
            raise ValueError(f"event record chain {name} must be a sha-256 digest")
    event_payload = record["event"]
    if not isinstance(event_payload, dict):
        raise ValueError("event record must contain an event object")
    event = _EVENT_ADAPTER.validate_python(event_payload)
    if event_payload != event.model_dump(mode="json"):
        raise ValueError("event record contains unsupported event fields")
    return event


def build_hash_chain_record(
    event_payload: Mapping[str, object],
    previous_hash: str,
) -> dict[str, object]:
    record_hash = _record_hash(event_payload, previous_hash)
    return {
        "event": dict(event_payload),
        "integrity": {
            "version": _CHAIN_VERSION,
            "previous": previous_hash,
            "hash": record_hash,
        },
    }


def verify_hash_chain_record(
    record: Mapping[str, object],
    expected_previous: str,
) -> str:
    """Verify one generic hash-chain record and return its hash."""

    if set(record) != _RECORD_KEYS:
        raise ValueError("hash-chain record has unsupported fields")
    integrity = record.get("integrity")
    if not isinstance(integrity, Mapping):
        raise ValueError("hash-chain record is missing integrity metadata")
    if set(integrity) != _INTEGRITY_KEYS:
        raise ValueError("hash-chain record has invalid integrity metadata")
    if integrity.get("version") != _CHAIN_VERSION:
        raise ValueError("hash-chain record version is unsupported")
    previous_hash = integrity.get("previous")
    record_hash = integrity.get("hash")
    if not isinstance(previous_hash, str) or not _HASH_PATTERN.fullmatch(previous_hash):
        raise ValueError("hash-chain previous hash must be a sha-256 digest")
    if not isinstance(record_hash, str) or not _HASH_PATTERN.fullmatch(record_hash):
        raise ValueError("hash-chain record hash must be a sha-256 digest")
    if previous_hash != expected_previous:
        raise ValueError("hash-chain previous hash does not match")
    event_payload = record.get("event")
    if not isinstance(event_payload, Mapping):
        raise ValueError("hash-chain record must contain an event object")
    if record_hash != _record_hash(event_payload, previous_hash):
        raise ValueError("hash-chain record hash does not match its event")
    return record_hash


def _decode_chain_record(
    raw_line: bytes,
    expected_previous: str,
) -> tuple[DomainEvent, str]:
    record = json.loads(raw_line)
    event = _validate_event_record(record)
    record_hash = verify_hash_chain_record(record, expected_previous)
    return event, record_hash


def _record_hash(event_payload: Mapping[str, object], previous_hash: str) -> str:
    payload = {
        "chain_version": _CHAIN_VERSION,
        "previous_hash": previous_hash,
        "event": event_payload,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
