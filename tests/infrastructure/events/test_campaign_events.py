from __future__ import annotations

from pathlib import Path

from pydantic import TypeAdapter

from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import (
    Event,
    EvidenceRecorded,
    FactVerified,
    IntentProposed,
    QdlStepEvaluated,
)
from cloud_dast.qdl.intents import intent_graph
from cloud_dast.verification.evidence_facts import evidence_fact, verified_fact


def _campaign_events() -> tuple[Event, ...]:
    return (
        FactVerified(
            fact=verified_fact("fact:resource"),
        ),
        IntentProposed(
            intent=intent_graph("intent:read", prerequisites=("fact:resource",)),
        ),
        EvidenceRecorded(
            fact=evidence_fact("obs-1", "resource"),
        ),
        QdlStepEvaluated(
            path_id="path:read",
            step_id="step:read",
            verdict=VerdictStatus.FAIL,
            phase="goal_reached",
            reason="invariant violated",
            step_index=1,
            completed_steps=("step:read",),
        ),
    )


def test_campaign_events_are_polymorphically_replayable() -> None:
    events = _campaign_events()
    adapter = TypeAdapter(Event)
    restored = tuple(adapter.validate_json(event.model_dump_json()) for event in events)
    assert tuple(type(event) for event in restored) == tuple(
        type(event) for event in events
    )


def test_campaign_events_round_trip_through_jsonl_store(tmp_path: Path) -> None:
    events = _campaign_events()
    store = JsonlEventStore(tmp_path / "campaign-events.jsonl")

    store.append_many(events)

    restored = tuple(store.read())
    assert restored == events
    assert tuple(type(event) for event in restored) == tuple(
        type(event) for event in events
    )
