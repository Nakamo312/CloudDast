from __future__ import annotations

from cloud_dast.model.events import (
    EvidenceRecorded,
    FactVerified,
    IntentProposed,
)
from cloud_dast.qdl.intents import PlannedIntent, intent_graph
from cloud_dast.runtime.campaign.replay import EventGraph
from cloud_dast.verification.evidence_facts import evidence_fact, verified_fact


def test_campaign_state_replays_qdl_evidence() -> None:
    events = (
        FactVerified(fact=verified_fact("f1")),
        IntentProposed(intent=intent_graph("i1", prerequisites=("f1",))),
        IntentProposed(intent=intent_graph("i2", prerequisites=("missing",))),
        EvidenceRecorded(fact=evidence_fact("o1", "token")),
    )
    state = EventGraph.replay(events)
    assert state.verified_fact_ids == frozenset({"f1"})
    assert state.intents == (
        PlannedIntent(intent_id="i1", prerequisites=("f1",)),
        PlannedIntent(intent_id="i2", prerequisites=("missing",)),
    )
    assert [view.intent_id for view in state.admissible_intents()] == ["i1"]
    assert not hasattr(state, "rewards")


def test_campaign_replay_uses_latest_intent_definition() -> None:
    old = intent_graph("intent:path:goal:one:0:step:goal:one:0", effects=("fact:old",))
    new = intent_graph("intent:path:goal:one:0:step:goal:one:0", effects=("fact:new",))

    state = EventGraph.replay(
        (
            IntentProposed(intent=old),
            IntentProposed(intent=new),
            IntentProposed(intent=new),
        )
    )

    assert state.intents == (
        PlannedIntent(
            intent_id="intent:path:goal:one:0:step:goal:one:0",
            effects=("fact:new",),
        ),
    )
