"""JSONL Hypothesis ExampleDatabase for durable finding replay."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path

from hypothesis.database import ExampleDatabase

from cloud_dast.infrastructure.jsonl import JsonlFile

_RECORD_KEYS = frozenset({"key", "value"})


class JsonlExampleDatabase(ExampleDatabase):
    """Persist Hypothesis examples in a private JSONL sidecar.

    The database keeps the Hypothesis ``key -> set(values)`` contract while
    storing records as append-only JSON lines.  Fetch order is insertion
    order, which makes campaign replay deterministic.
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self._file = JsonlFile(path)
        self.path = self._file.path
        self._entries: dict[bytes, list[bytes]] = {}
        self._needs_separator = False
        with self._file.locked():
            self._file.ensure()
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_record,
                preserve_complete=True,
                label="example database record",
            )
            self._refresh_unlocked()

    def save(self, key: bytes, value: bytes) -> None:
        key = bytes(key)
        value = bytes(value)
        with self._file.locked():
            needs_separator = self._truncate_unlocked()
            self._refresh_unlocked()
            values = self._entries.setdefault(key, [])
            if value in values:
                return
            line = _encode_record(key, value)
            self._file.append(
                line,
                separator=b"\n" if needs_separator or self._needs_separator else b"",
                redact=False,
            )
            self._needs_separator = False
            values.append(value)
            self._broadcast_change(("save", (key, value)))

    def fetch(self, key: bytes) -> Iterable[bytes]:
        key = bytes(key)
        with self._file.locked():
            self._truncate_unlocked()
            self._refresh_unlocked()
            return tuple(self._entries.get(key, ()))

    def delete(self, key: bytes, value: bytes) -> None:
        key = bytes(key)
        value = bytes(value)
        with self._file.locked():
            self._truncate_unlocked()
            self._refresh_unlocked()
            values = self._entries.get(key, [])
            if value not in values:
                return
            values.remove(value)
            if not values:
                del self._entries[key]
            self._rewrite_unlocked()
            self._broadcast_change(("delete", (key, value)))

    def _start_listening(self) -> None:
        pass

    def _stop_listening(self) -> None:
        pass

    def _truncate_unlocked(self) -> bool:
        return self._file.truncate_incomplete_tail(
            validate=_validate_record,
            preserve_complete=True,
            label="example database record",
        )

    def _refresh_unlocked(self) -> None:
        entries: dict[bytes, list[bytes]] = {}
        for _line_number, raw_line in self._file.iter_lines():
            key, value = _decode_record(raw_line)
            values = entries.setdefault(key, [])
            if value not in values:
                values.append(value)
        self._entries = entries

    def _rewrite_unlocked(self) -> None:
        with self.path.open("wb") as stream:
            for key, values in self._entries.items():
                for value in values:
                    stream.write(_encode_record(key, value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._needs_separator = False


def _encode_record(key: bytes, value: bytes) -> bytes:
    record = {"key": key.hex(), "value": value.hex()}
    return json.dumps(
        record,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _validate_record(raw_line: bytes) -> tuple[bytes, bytes]:
    return _decode_record(raw_line)


def _decode_record(raw_line: bytes) -> tuple[bytes, bytes]:
    record = json.loads(raw_line)
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise ValueError("example database record has unsupported fields")
    try:
        key = bytes.fromhex(record["key"])
        value = bytes.fromhex(record["value"])
    except (TypeError, ValueError) as exc:
        raise ValueError("example database keys and values must be hex") from exc
    if not key or not value:
        raise ValueError("example database keys and values must not be empty")
    return key, value
