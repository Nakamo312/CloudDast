"""Stateful ledgers used by runtime grounding.

The grounding service performs promotion, persistence, and model lifecycle.
This module owns only the small pieces of state that decide whether a parked
lead or an evidence-backed consultation has changed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cloud_dast.qdl.graph import Context, Fact, QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.norm_view import LEAD_NORM_PREFIX
from cloud_dast.verification.promotion import lead_descriptor

_SINK_TYPE_VALUES = frozenset({"interpreter", "filesystem", "external_net"})


@dataclass(frozen=True, slots=True)
class ParkedLeadState:
    """One deduplicated lead with its current belief revision."""

    fact_key: str
    fact_hash: str
    action: str
    holder: str
    role: str
    evidence_signature: str
    evidence_refs: frozenset[str]
    confirmations: int

    @property
    def lead_key(self) -> tuple[str, str, str, str]:
        """Return the stable belief-revision key of this lead."""

        return (self.action, self.holder, self.role, self.evidence_signature)


def evidence_signature(evidence_refs: frozenset[str]) -> str:
    """Return the stable order- and duplicate-insensitive evidence hash."""

    encoded = "".join(
        f"{len(reference.encode('utf-8'))}:{reference}"
        for reference in sorted(evidence_refs)
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class LeadLifecycle:
    """Track belief revisions for parked proposal facts."""

    def __init__(self) -> None:
        self._leads: dict[tuple[str, str, str], ParkedLeadState] = {}

    def record(
        self,
        fact: Fact,
        evidence_refs: frozenset[str],
    ) -> ParkedLeadState:
        descriptor = lead_descriptor(fact)
        if descriptor is None:
            raise ValueError("parked fact has no lead coordinates")
        refs = frozenset(evidence_refs)
        identity = (descriptor.action, descriptor.holder, descriptor.role)
        previous = self._leads.get(identity)
        if previous is not None and refs <= previous.evidence_refs:
            return previous
        merged = refs if previous is None else previous.evidence_refs | refs
        state = ParkedLeadState(
            fact_key=descriptor.fact_key,
            fact_hash=descriptor.fact_hash,
            action=descriptor.action,
            holder=descriptor.holder,
            role=descriptor.role,
            evidence_signature=evidence_signature(merged),
            evidence_refs=merged,
            confirmations=len(merged),
        )
        self._leads[identity] = state
        return state

    def record_graph(self, graph: QdlGraph, evidence_refs: frozenset[str]) -> None:
        for fact in graph.facts:
            if not is_original_parked_fact(fact):
                continue
            if lead_descriptor(fact) is None:
                continue
            self.record(fact, evidence_refs)

    def snapshot(self) -> tuple[ParkedLeadState, ...]:
        return tuple(sorted(self._leads.values(), key=lambda lead: lead.lead_key))


@dataclass(frozen=True, slots=True)
class ConsultationKey:
    """Identity of one grounding consultation within a service."""

    service: str
    kind: str
    deficit_id: str
    action: str
    depth: int


class ConsultationLedger:
    """Record evidence absorbed by completed grounding consultations."""

    def __init__(self) -> None:
        self._evidence: dict[ConsultationKey, frozenset[str]] = {}

    def admits(
        self,
        key: ConsultationKey,
        evidence_refs: frozenset[str],
    ) -> bool:
        """Return whether a request carries evidence not seen for its key."""

        previous = self._evidence.get(key)
        return previous is None or not evidence_refs <= previous

    def record(
        self,
        key: ConsultationKey,
        evidence_refs: frozenset[str],
    ) -> None:
        """Absorb the evidence of one completed consultation."""

        previous = self._evidence.get(key)
        self._evidence[key] = (
            frozenset(evidence_refs)
            if previous is None
            else previous | frozenset(evidence_refs)
        )


def is_original_parked_fact(fact: Fact) -> bool:
    """Exclude supporting declarations and derived lead norms."""

    if fact.context is not Context.PROPOSAL:
        return False
    if fact.predicate.name == "is":
        return len(fact.args) == 2 and atom_value(fact.args[1]) in _SINK_TYPE_VALUES
    if fact.predicate.name == "prevents" and fact.args:
        norm_id = atom_value(fact.args[0])
        if isinstance(norm_id, str) and norm_id.startswith(LEAD_NORM_PREFIX):
            return False
    return True


__all__ = [
    "ConsultationLedger",
    "ConsultationKey",
    "LeadLifecycle",
    "ParkedLeadState",
    "evidence_signature",
    "is_original_parked_fact",
]
