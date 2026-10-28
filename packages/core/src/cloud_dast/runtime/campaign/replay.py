"""Replayable campaign state projection for event-sourced runs."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from cloud_dast.contracts.dag import CampaignDag
from cloud_dast.model.events import (
    DomainEvent,
    DownstreamDecision,
    EventScope,
    EvidenceRecorded,
    FactVerified,
    IntentProposed,
    QdlPathEvaluated,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import (
    atom_value,
    merge_facts,
)
from cloud_dast.qdl.intents import (
    PlannedIntent,
    intent_ids,
    planned_intents,
)
from cloud_dast.runtime.campaign.dag import build_campaign_dag
from cloud_dast.verification.evidence_facts import (
    verified_fact_ids as graph_verified_fact_ids,
)


@dataclass(slots=True)
class RoundReplay:
    """Event-derived metadata used while executing one scheduler round.

    This is deliberately separate from :class:`CampaignRoundState`: the
    latter accumulates observations produced by the current round, while this
    record describes what the event log says was already evaluated. The
    dictionaries remain mutable because terminalization may invalidate and
    re-record a path during the same round.
    """

    verified_fact_ids: set[str]
    evaluated_outcomes: dict[str, str]
    evaluated_signatures: dict[str, str | None]

    @classmethod
    def from_events(
        cls,
        events: Iterable[DomainEvent],
        *,
        scope: EventScope | None = None,
    ) -> "RoundReplay":
        """Restore round metadata from the scoped append-only event stream."""

        selected = scope.campaign_events(events) if scope is not None else tuple(events)
        campaign = EventGraph.replay(selected)
        outcomes: dict[str, str] = {}
        signatures: dict[str, str | None] = {}
        for event in selected:
            if isinstance(event, QdlPathEvaluated):
                outcomes[event.path_id] = event.outcome
                signatures[event.path_id] = event.evidence_signature
            elif (
                isinstance(event, DownstreamDecision)
                and event.component == "qdl_path"
                and event.by == "scheduler"
                and event.outcome == "evidence_invalidated"
                and event.consumed
            ):
                outcomes.pop(event.path_id, None)
                signatures.pop(event.path_id, None)
        return cls(
            verified_fact_ids=set(campaign.verified_fact_ids),
            evaluated_outcomes=outcomes,
            evaluated_signatures=signatures,
        )


@dataclass(frozen=True, slots=True)
class EventGraph:
    """Immutable projection of one QDL campaign graph.

    The QDL graph is the single source of truth: verified facts and evidence
    are merged into its ``runtime`` context, proposed intents into its
    ``proposal`` context.  Identifiers are stable across graph rebuilds, but
    their definitions may change.  Replay therefore treats a later intent
    proposal as the authoritative version of the same identifier.
    """

    graph: QdlGraph = field(default_factory=QdlGraph)

    def apply(self, event: DomainEvent) -> EventGraph:
        if isinstance(event, FactVerified):
            return self.add_fact(event.fact)
        if isinstance(event, IntentProposed):
            return self.add_intent_graph(event.intent)
        if isinstance(event, EvidenceRecorded):
            return self.add_fact(event.fact)
        return self

    @classmethod
    def replay(
        cls,
        events: Iterable[DomainEvent],
        *,
        scope: EventScope | None = None,
    ) -> EventGraph:
        selected = scope.campaign_events(events) if scope is not None else tuple(events)
        state = cls()
        semantic_keys: set[str] = set()
        for event in selected:
            if isinstance(event, (FactVerified, IntentProposed, EvidenceRecorded)):
                semantic_key = event.semantic_key
                if semantic_key in semantic_keys:
                    continue
                semantic_keys.add(semantic_key)
            state = state.apply(event)
        return state

    def add_fact(self, fact: Fact) -> EventGraph:
        """Merge one runtime fact or evidence fact into the graph."""

        return replace(self, graph=_with_campaign_fact(self.graph, fact))

    def add_intent_graph(self, intent: QdlGraph) -> EventGraph:
        """Merge one intent graph, replacing its previous definition."""

        replaced_ids = frozenset(intent_ids(intent))
        kept = tuple(
            fact for fact in self.graph.facts if not _is_intent_fact(fact, replaced_ids)
        )
        merged = merge_facts(QdlGraph(facts=kept, rules=self.graph.rules), intent.facts)
        return replace(self, graph=merged)

    @property
    def verified_fact_ids(self) -> frozenset[str]:
        return graph_verified_fact_ids(self.graph)

    @property
    def intents(self) -> tuple[PlannedIntent, ...]:
        """Derived intent views projected from the QDL graph."""

        return planned_intents(self.graph)

    def admissible_intents(self) -> tuple[PlannedIntent, ...]:
        """Return intents whose QDL prerequisites are all verified facts."""

        verified = self.verified_fact_ids
        return tuple(
            view for view in self.intents if set(view.prerequisites).issubset(verified)
        )

    def project_dag(
        self,
        events: Iterable[DomainEvent],
        *,
        scope: EventScope | None = None,
    ) -> CampaignDag:
        """Project the current graph and event log into a Campaign DAG."""

        selected = scope.campaign_events(events) if scope is not None else tuple(events)
        return build_campaign_dag(self.graph, selected)


def _is_intent_fact(fact: Fact, intent_ids_: frozenset[str]) -> bool:
    if fact.context is not Context.PROPOSAL:
        return False
    if fact.predicate.name not in {
        "is",
        "intent_prerequisite",
        "intent_effect",
        "intent_assumption",
    }:
        return False
    subject = fact.args[0] if fact.args else None
    return atom_value(subject) in intent_ids_


def _with_campaign_fact(graph: QdlGraph, fact: Fact) -> QdlGraph:
    """Merge one campaign fact and its required observation declaration."""

    additions = [fact]
    if fact.predicate.name == "evidence" and fact.args:
        observation_id = atom_value(fact.args[0])
        if observation_id is not None:
            additions.append(
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("is"),
                    args=(
                        Atom(value=observation_id),
                        Atom(value="Observation"),
                    ),
                )
            )
    return merge_facts(graph, additions)
