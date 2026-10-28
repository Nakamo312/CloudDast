from __future__ import annotations

from pathlib import Path

import pytest

from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import FactVerified, QdlStepEvaluated
from cloud_dast.verification.evidence_facts import verified_fact


def test_semantically_identical_state_events_are_not_appended_twice(
    tmp_path: Path,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    first = FactVerified(fact=verified_fact("fact:resource"))
    duplicate = FactVerified(
        fact=verified_fact("fact:resource"),
        correlation_id="check:retry",
    )

    store.append(first)
    store.append(duplicate)

    restored = tuple(store.read())
    assert restored == (first,)


def test_semantically_identical_path_events_are_not_appended_twice(
    tmp_path: Path,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    first = _step_event()
    duplicate = QdlStepEvaluated(
        path_id=first.path_id,
        step_id=first.step_id,
        verdict=first.verdict,
        phase=first.phase,
        reason=first.reason,
        step_index=first.step_index,
        completed_steps=first.completed_steps,
        correlation_id="check:retry",
    )

    store.append(first)
    store.append(duplicate)

    assert tuple(store.read()) == (first,)


def test_semantic_idempotency_survives_store_reopen(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    first = FactVerified(fact=verified_fact("fact:resource"))
    JsonlEventStore(path).append(first)
    duplicate = FactVerified(
        fact=verified_fact("fact:resource"),
        correlation_id="check:retry",
    )

    JsonlEventStore(path).append(duplicate)

    assert tuple(JsonlEventStore(path).read()) == (first,)


def test_duplicate_event_id_still_fails_before_semantic_deduplication(
    tmp_path: Path,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    event = FactVerified(fact=verified_fact("fact:resource"))
    store.append(event)

    with pytest.raises(ValueError, match="duplicate event_id"):
        store.append(event)


def _step_event() -> QdlStepEvaluated:
    return QdlStepEvaluated(
        path_id=f"qdl-attack-{'a' * 64}:pv{'b' * 64}",
        step_id="step:identity",
        verdict=VerdictStatus.FAIL,
        phase="goal_reached",
        reason="invariant violated",
        step_index=0,
    )
