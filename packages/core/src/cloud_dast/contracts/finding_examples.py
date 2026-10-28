"""Canonical encoding and storage operations for finding examples.

The check redaction invariant is defined beside ``Check``.  This module owns
the durable example shape, serialization, and store interaction. Campaign
execution remains owned by ``cloud_dast.runtime``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_dast.model import Check
from cloud_dast.model.checks import is_replayable_check, replay_gaps

if TYPE_CHECKING:
    from cloud_dast.ports import FindingExampleStore

_EXAMPLE_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class FindingExample:
    """One replayable check for a previously observed finding."""

    check: Check


def finding_example_key(
    *,
    method_id: str,
    invariant_id: str,
    scenario_id: str,
) -> bytes:
    """Return the stable store key for one executable norm."""

    identity = {
        "invariant_id": invariant_id,
        "method_id": method_id,
        "scenario_id": scenario_id,
        "version": _EXAMPLE_SCHEMA_VERSION,
    }
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"cloud-dast:finding:v{_EXAMPLE_SCHEMA_VERSION}:".encode(
        "ascii"
    ) + digest.encode("ascii")


def encode_finding_example(example: FindingExample) -> bytes:
    """Encode one finding example as canonical JSON bytes."""

    return _canonical_json(
        {
            "version": _EXAMPLE_SCHEMA_VERSION,
            "check": example.check.model_dump(mode="json"),
        }
    ).encode("utf-8")


def decode_finding_example(value: bytes) -> FindingExample:
    """Decode and validate one persisted finding example."""

    record = json.loads(value)
    if not isinstance(record, dict) or set(record) != {"version", "check"}:
        raise ValueError("finding example record has unsupported fields")
    if record["version"] != _EXAMPLE_SCHEMA_VERSION:
        raise ValueError("finding example record version is unsupported")
    if not isinstance(record["check"], dict):
        raise ValueError("finding example record must contain a check object")
    check = Check.model_validate(record["check"])
    if record["check"] != check.model_dump(mode="json"):
        raise ValueError("finding example record contains unsupported check fields")
    return FindingExample(check=check)


def load_finding_examples(
    store: FindingExampleStore,
    *,
    method_id: str,
    invariant_id: str,
    scenario_id: str,
) -> tuple[Check, ...]:
    """Return persisted examples in deterministic insertion order."""

    key = finding_example_key(
        method_id=method_id,
        invariant_id=invariant_id,
        scenario_id=scenario_id,
    )
    return tuple(decode_finding_example(value).check for value in store.fetch(key))


def save_finding_example(store: FindingExampleStore, check: Check) -> None:
    """Persist one check under its executable-norm key."""

    store.save(
        finding_example_key(
            method_id=check.method_id,
            invariant_id=check.invariant_id,
            scenario_id=check.scenario_id,
        ),
        encode_finding_example(FindingExample(check=check)),
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


__all__ = [
    "FindingExample",
    "decode_finding_example",
    "encode_finding_example",
    "finding_example_key",
    "is_replayable_check",
    "load_finding_examples",
    "replay_gaps",
    "save_finding_example",
]
