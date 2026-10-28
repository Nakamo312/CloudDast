"""Integrity guarantees for the operator approval audit log."""

from __future__ import annotations

import json

import pytest

from cloud_dast.infrastructure.approval_audit import JsonlApprovalAuditLog
from cloud_dast.infrastructure.events.jsonl_store import verify_hash_chain_record
from cloud_dast.ports import ApprovalAuditRecord


def _record(operator: str = "ridrapsody") -> ApprovalAuditRecord:
    return ApprovalAuditRecord(
        service="orders",
        fact_hash="a" * 64,
        operator=operator,
        reason="Service owner confirmed the credential classification.",
        accepted_graph_hash="b" * 64,
        promoted_facts=2,
        recorded_at="2026-10-20T12:00:00+00:00",
    )


def test_approval_audit_log_writes_a_hash_chain(tmp_path) -> None:
    path = tmp_path / "approvals.jsonl"
    audit_log = JsonlApprovalAuditLog(path)

    audit_log.append(_record())

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"]["fact_hash"] == "a" * 64
    assert verify_hash_chain_record(record, "0" * 64) == record["integrity"]["hash"]


def test_approval_audit_log_rejects_a_modified_record(tmp_path) -> None:
    path = tmp_path / "approvals.jsonl"
    JsonlApprovalAuditLog(path).append(_record())
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["event"]["operator"] = "attacker"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        JsonlApprovalAuditLog(path)


def test_approval_audit_log_preserves_complete_tail_without_newline(
    tmp_path,
) -> None:
    path = tmp_path / "approvals.jsonl"
    JsonlApprovalAuditLog(path).append(_record())
    raw = path.read_bytes()
    path.write_bytes(raw.rstrip(b"\n"))

    audit_log = JsonlApprovalAuditLog(path)
    audit_log.append(_record(operator="security-owner"))

    text = path.read_text(encoding="utf-8")
    assert len(text.splitlines()) == 2
    assert "\n\n" not in text
