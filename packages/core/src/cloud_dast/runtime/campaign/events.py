"""Typed event-log indexes used by campaign projections."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_dast.model import Observation
from cloud_dast.model.events import (
    CheckCompleted,
    DiffPairComputed,
    DomainEvent,
    EvidenceRecorded,
    FactVerified,
    FindingRaised,
    IntentProposed,
    InvestigationActionExecuted,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.qdl.graph import QdlGraph


@dataclass(slots=True)
class EventIndex:
    """Stable projections of the event log needed by campaign read models."""

    paths: dict[str, QdlPathEvaluated] = field(default_factory=dict)
    steps: dict[str, QdlStepEvaluated] = field(default_factory=dict)
    observations: dict[str, Observation] = field(default_factory=dict)
    observation_methods: dict[str, str | None] = field(default_factory=dict)
    findings: list[FindingRaised] = field(default_factory=list)
    diffs: list[DiffPairComputed] = field(default_factory=list)
    intent_graphs: list[QdlGraph] = field(default_factory=list)
    verified_facts: list[FactVerified] = field(default_factory=list)
    evidence: list[EvidenceRecorded] = field(default_factory=list)

    @classmethod
    def from_events(cls, events: tuple[DomainEvent, ...]) -> EventIndex:
        """Index event variants without projecting campaign nodes or edges."""

        index = cls()
        for event in events:
            if isinstance(event, QdlPathEvaluated):
                index.paths[event.path_id] = event
            elif isinstance(event, QdlStepEvaluated):
                index.steps[event.step_id] = event
            elif isinstance(event, CheckCompleted):
                observation = event.observation
                index.observations[observation.observation_id] = observation
                index.observation_methods[observation.observation_id] = event.method_id
            elif isinstance(event, InvestigationActionExecuted):
                observation = event.observation
                index.observations[observation.observation_id] = observation
                index.observation_methods[observation.observation_id] = (
                    event.intent.method_id
                )
            elif isinstance(event, DiffPairComputed):
                index.diffs.append(event)
            elif isinstance(event, FindingRaised):
                index.findings.append(event)
                index.observation_methods.setdefault(
                    event.finding.observation_id,
                    event.finding.method_id,
                )
            elif isinstance(event, IntentProposed):
                index.intent_graphs.append(event.intent)
            elif isinstance(event, FactVerified):
                index.verified_facts.append(event)
            elif isinstance(event, EvidenceRecorded):
                index.evidence.append(event)
        return index


__all__ = ["EventIndex"]
