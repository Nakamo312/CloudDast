from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from cloud_dast.model.events import (
    EvidenceRecorded,
    FactVerified,
    IntentProposed,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    source,
)
from cloud_dast.qdl.intents import INTENT_EFFECT, intent_graph
from cloud_dast.runtime.campaign.replay import EventGraph
from cloud_dast.verification.evidence_facts import evidence_fact, verified_fact


def test_semantic_key_ignores_occurrence_metadata() -> None:
    first = FactVerified(
        fact=verified_fact("fact:resource"),
        correlation_id="check:first",
    )
    second = FactVerified(
        fact=verified_fact("fact:resource"),
        correlation_id="check:second",
    )
    other = FactVerified(fact=verified_fact("fact:other"))

    assert first.event_id != second.event_id
    assert first.occurred_at != second.occurred_at
    assert first.semantic_key == second.semantic_key
    assert re.fullmatch(r"[0-9a-f]{64}", first.semantic_key)
    assert first.semantic_key != other.semantic_key


def test_campaign_replay_is_semantically_idempotent() -> None:
    fact_event = FactVerified(fact=verified_fact("fact:resource"))
    intent_event = IntentProposed(
        intent=intent_graph("intent:read", prerequisites=("fact:resource",))
    )
    evidence_event = EvidenceRecorded(fact=evidence_fact("observation:1", "resource"))
    duplicate_events = (
        fact_event,
        FactVerified(fact=verified_fact("fact:resource")),
        intent_event,
        IntentProposed(
            intent=intent_graph("intent:read", prerequisites=("fact:resource",))
        ),
        evidence_event,
        EvidenceRecorded(fact=evidence_fact("observation:1", "resource")),
    )
    unique_events = (fact_event, intent_event, evidence_event)

    replayed = EventGraph.replay(duplicate_events)
    unique = EventGraph.replay(unique_events)

    assert replayed.graph == unique.graph


def test_fact_verified_requires_runtime_verified_fact() -> None:
    with pytest.raises(ValidationError, match="runtime context"):
        FactVerified(
            fact=Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="fact:resource"), Atom(value="VerifiedFact")),
            )
        )

    with pytest.raises(ValidationError, match="VerifiedFact"):
        FactVerified(
            fact=Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="fact:resource"), Atom(value="Fact")),
            )
        )


def test_evidence_recorded_requires_runtime_source_evidence() -> None:
    with pytest.raises(ValidationError, match="runtime context"):
        EvidenceRecorded(
            fact=Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("evidence"),
                args=(
                    Atom(value="observation:1"),
                    source(Atom(value="response_field"), Atom(value="resource")),
                ),
            )
        )

    with pytest.raises(ValidationError, match="source provenance"):
        EvidenceRecorded(
            fact=Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("evidence"),
                args=(
                    Atom(value="observation:1"),
                    Struct(
                        name="field",
                        args=(
                            Atom(value="action:read"),
                            Atom(value="resource"),
                        ),
                    ),
                ),
            )
        )


def test_intent_proposed_requires_closed_proposal_graph() -> None:
    with pytest.raises(ValidationError, match="proposal context"):
        IntentProposed(
            intent=QdlGraph(
                facts=(
                    *intent_graph("intent:read").facts,
                    Fact(
                        context=Context.RUNTIME,
                        predicate=Predicate.from_name("is"),
                        args=(Atom(value="fact:runtime"), Atom(value="Fact")),
                    ),
                )
            )
        )

    with pytest.raises(ValidationError, match="declare an Intent"):
        IntentProposed(
            intent=QdlGraph(
                facts=(
                    Fact(
                        context=Context.PROPOSAL,
                        predicate=Predicate.from_name("is"),
                        args=(Atom(value="fact:resource"), Atom(value="Fact")),
                    ),
                )
            )
        )

    with pytest.raises(ValidationError, match="edge is not closed"):
        IntentProposed(
            intent=QdlGraph(
                facts=(
                    Fact(
                        context=Context.PROPOSAL,
                        predicate=Predicate.from_name("is"),
                        args=(Atom(value="intent:read"), Atom(value="Intent")),
                    ),
                    Fact(
                        context=Context.PROPOSAL,
                        predicate=Predicate.from_name("is"),
                        args=(Atom(value="intent:other"), Atom(value="Intent")),
                    ),
                    Fact(
                        context=Context.PROPOSAL,
                        predicate=INTENT_EFFECT,
                        args=(
                            Atom(value="intent:read"),
                            Atom(value="intent:other"),
                        ),
                    ),
                )
            )
        )
