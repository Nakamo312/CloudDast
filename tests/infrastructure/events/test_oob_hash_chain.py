from __future__ import annotations

import copy

import pytest

from cloud_dast.infrastructure.events.jsonl_store import (
    build_hash_chain_record,
    verify_hash_chain_record,
)


def _oob_payload(marker: str) -> dict[str, object]:
    return {
        "event_id": f"event:{marker}",
        "marker": marker,
        "method": "GET",
        "path": f"/{marker}",
        "source_ip": "203.0.113.10",
        "received_at": 1.0,
    }


def test_oob_hash_chain_links_records() -> None:
    first = build_hash_chain_record(_oob_payload("marker:first"), "0" * 64)
    first_hash = verify_hash_chain_record(first, "0" * 64)
    second = build_hash_chain_record(_oob_payload("marker:second"), first_hash)
    second_hash = verify_hash_chain_record(second, first_hash)

    assert second_hash != first_hash
    assert second["integrity"]["previous"] == first_hash


def test_oob_hash_chain_rejects_tampered_marker() -> None:
    record = build_hash_chain_record(_oob_payload("marker:first"), "0" * 64)
    tampered = copy.deepcopy(record)
    tampered["event"]["marker"] = "marker:attacker"

    with pytest.raises(ValueError, match="hash-chain record hash"):
        verify_hash_chain_record(tampered, "0" * 64)


def test_oob_hash_chain_rejects_uncovered_record_fields() -> None:
    record = build_hash_chain_record(_oob_payload("marker:first"), "0" * 64)
    record["uncovered"] = "outside the chain hash"

    with pytest.raises(ValueError, match="unsupported fields"):
        verify_hash_chain_record(record, "0" * 64)
