"""Hash-chained JSONL audit storage for classification approvals."""

from __future__ import annotations

import json
from pathlib import Path

from cloud_dast.infrastructure.events.jsonl_store import (
    build_hash_chain_record,
    verify_hash_chain_record,
)
from cloud_dast.infrastructure.jsonl import JsonlFile
from cloud_dast.model.events import ApprovalAuditRecord

_GENESIS_HASH = "0" * 64


class JsonlApprovalAuditLog:
    """Append operator approvals as a private, tamper-evident JSONL chain."""

    def __init__(self, path: str | Path) -> None:
        self._file = JsonlFile(path)
        self.path = self._file.path
        self._chain_head = _GENESIS_HASH
        self._needs_separator = False
        with self._file.locked():
            self._file.ensure()
            self._needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_record,
                preserve_complete=True,
                label="approval audit record",
            )
            self._refresh_unlocked()

    def append(self, record: ApprovalAuditRecord) -> None:
        payload = record.model_dump(mode="json")
        with self._file.locked():
            needs_separator = self._file.truncate_incomplete_tail(
                validate=_validate_record,
                preserve_complete=True,
                label="approval audit record",
            )
            self._refresh_unlocked()
            chained = build_hash_chain_record(payload, self._chain_head)
            line = json.dumps(
                chained,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            self._file.append(
                line,
                separator=b"\n" if needs_separator or self._needs_separator else b"",
                redact=False,
            )
            self._needs_separator = False
            self._chain_head = chained["integrity"]["hash"]

    def _refresh_unlocked(self) -> None:
        """Re-read the chain so concurrent processes cannot fork it."""

        chain_head = _GENESIS_HASH
        for _line_number, raw_line in self._file.iter_lines():
            _record, chain_head = _decode_record(raw_line, chain_head)
        self._chain_head = chain_head


def _validate_record(raw_line: bytes) -> ApprovalAuditRecord:
    record = json.loads(raw_line)
    if not isinstance(record, dict) or set(record) != {"event", "integrity"}:
        raise ValueError("approval audit record has unsupported fields")
    event_payload = record["event"]
    if not isinstance(event_payload, dict):
        raise ValueError("approval audit record must contain an event object")
    event = ApprovalAuditRecord.model_validate(event_payload)
    if event_payload != event.model_dump(mode="json"):
        raise ValueError("approval audit record contains unsupported event fields")
    return event


def _decode_record(
    raw_line: bytes,
    expected_previous: str,
) -> tuple[ApprovalAuditRecord, str]:
    record = json.loads(raw_line)
    if not isinstance(record, dict) or set(record) != {"event", "integrity"}:
        raise ValueError("approval audit record has unsupported fields")
    event_payload = record["event"]
    if not isinstance(event_payload, dict):
        raise ValueError("approval audit record must contain an event object")
    event = ApprovalAuditRecord.model_validate(event_payload)
    if event_payload != event.model_dump(mode="json"):
        raise ValueError("approval audit record contains unsupported event fields")
    record_hash = verify_hash_chain_record(record, expected_previous)
    return event, record_hash
