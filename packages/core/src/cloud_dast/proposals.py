"""Public contracts crossing the formal proposal-promotion boundary."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from cloud_dast.qdl.graph import Fact, QdlGraph
from cloud_dast.qdl.validation import ValidationIssue

if TYPE_CHECKING:
    from cloud_dast.contracts.payload_proposals import (
        PayloadCorpusDelta,
        PayloadCorpusGuardrail,
    )
    from cloud_dast.contracts.payloads import PayloadCorpus


@dataclass(frozen=True, slots=True)
class ClassificationPromotionContext:
    """Immutable obligation carried from a classification deficit to promotion."""

    term: str
    allowed_values: frozenset[str]
    invariant_id: str
    evidence_refs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.term:
            raise ValueError("classification context term must be non-empty")
        if not self.allowed_values:
            raise ValueError("classification context alphabet must be non-empty")
        if not self.invariant_id:
            raise ValueError("classification context invariant_id must be non-empty")
        if any(
            not isinstance(value, str) or not value for value in self.allowed_values
        ):
            raise ValueError("classification context values must be non-empty strings")
        if any(not isinstance(ref, str) or not ref for ref in self.evidence_refs):
            raise ValueError(
                "classification context evidence_refs must be non-empty strings"
            )

    @classmethod
    def from_mapping(
        cls,
        context: Mapping[str, object] | None,
        *,
        evidence_refs: Iterable[str] = (),
    ) -> "ClassificationPromotionContext | None":
        """Parse bounded request context without retaining a mutable map."""

        if not context:
            return None
        term = context.get("classification_term")
        invariant_id = context.get("invariant_id")
        raw_values = context.get("allowed_values", ())
        if not isinstance(term, str) or not isinstance(invariant_id, str):
            return None
        if isinstance(raw_values, str):
            values = raw_values.split(",")
        elif isinstance(raw_values, Sequence):
            values = list(raw_values)
        else:
            return None
        normalized_values = frozenset(
            value for value in values if isinstance(value, str) and value
        )
        normalized_refs = frozenset(
            ref for ref in evidence_refs if isinstance(ref, str) and ref
        )
        context_refs = context.get("evidence_refs", ())
        if isinstance(context_refs, str):
            normalized_refs |= frozenset((context_refs,))
        elif isinstance(context_refs, Iterable):
            normalized_refs |= frozenset(
                ref for ref in context_refs if isinstance(ref, str) and ref
            )
        try:
            return cls(
                term=term,
                allowed_values=normalized_values,
                invariant_id=invariant_id,
                evidence_refs=normalized_refs,
            )
        except ValueError:
            return None

    def with_evidence_refs(
        self,
        evidence_refs: Iterable[str],
    ) -> "ClassificationPromotionContext":
        """Return this obligation with additional immutable evidence lineage."""

        return type(self)(
            term=self.term,
            allowed_values=self.allowed_values,
            invariant_id=self.invariant_id,
            evidence_refs=self.evidence_refs
            | frozenset(ref for ref in evidence_refs if isinstance(ref, str) and ref),
        )

    def to_mapping(self) -> dict[str, object]:
        """Return the stable request representation used by consultation glue."""

        return {
            "classification_term": self.term,
            "allowed_values": tuple(sorted(self.allowed_values)),
            "invariant_id": self.invariant_id,
            "evidence_refs": tuple(sorted(self.evidence_refs)),
        }


@dataclass(frozen=True, slots=True)
class ProposalPromotionResult:
    """Accepted facts produced by one explicit proposal promotion policy."""

    graph: QdlGraph
    promoted_norms: tuple[str, ...]
    rejected_norms: tuple[str, ...]
    promoted_semantic_facts: int = 0
    rejected_semantic_facts: int = 0
    parked_classifications: QdlGraph | None = None
    parked_semantics: QdlGraph | None = None
    parked_norms: QdlGraph | None = None
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def promoted(self) -> bool:
        return bool(self.promoted_norms) or self.promoted_semantic_facts > 0


@dataclass(frozen=True, slots=True)
class PayloadCorpusPromotionResult:
    """Result of promoting declarative payload data through the A15 boundary."""

    status: str
    delta: PayloadCorpusDelta | None
    promoted_productions: tuple[str, ...] = ()
    promoted_slot_alternatives: tuple[str, ...] = ()
    promoted_items: int = 0
    reasons: tuple[str, ...] = ()

    @property
    def promoted(self) -> bool:
        return self.status == "promoted" and self.promoted_items > 0


@dataclass(frozen=True, slots=True)
class ProposalPromotionRequest:
    """Immutable input contract for one executable proposal decision."""

    source: QdlGraph
    proposal: QdlGraph
    action_ids: frozenset[str] | tuple[str, ...] = ()
    duration_thresholds: Mapping[str, int] | None = None
    evidence_fields: frozenset[str] | None = None
    evidence_refs: frozenset[str] = frozenset()
    approved_classifications: frozenset[str] = frozenset()
    runtime_evidence_exempt_predicates: frozenset[str] = frozenset()
    classification_context: ClassificationPromotionContext | None = None

    def __post_init__(self) -> None:
        """Freeze mapping input before it crosses the policy boundary."""

        if self.duration_thresholds is not None:
            object.__setattr__(
                self,
                "duration_thresholds",
                MappingProxyType(dict(self.duration_thresholds)),
            )


@dataclass(frozen=True, slots=True)
class LeadDescriptor:
    """Coordinates of one parked proposal fact."""

    action: str
    holder: str
    role: str
    fact_key: str
    fact_hash: str
    fact: Fact


class ProposalPromoter(Protocol):
    """Callable policy boundary for promoting a validated QDL proposal."""

    def promote(self, request: ProposalPromotionRequest) -> ProposalPromotionResult:
        """Return accepted facts and typed parked/rejection evidence."""
        ...


@dataclass(frozen=True, slots=True)
class FormalThreatModelResult:
    """Result contract returned by an optional threat-model proposer."""

    proposal: QdlGraph | None
    issues: tuple[ValidationIssue, ...] = ()
    initial_issues: tuple[ValidationIssue, ...] = ()
    repair_issues: tuple[ValidationIssue, ...] = ()
    attempts: int = 1

    @property
    def valid(self) -> bool:
        return self.proposal is not None and not self.issues

    @property
    def repaired(self) -> bool:
        return bool(self.initial_issues) and self.valid


class ThreatModelProposer(Protocol):
    """Optional LLM boundary for proposing formal threat artefacts."""

    def propose(self, graph: QdlGraph) -> FormalThreatModelResult:
        """Return an unaccepted proposal over the supplied QDL graph."""
        ...


class PayloadCorpusPromoter(Protocol):
    """Policy boundary for promoting bounded payload-data proposals."""

    def promote_payload_corpus(
        self,
        source: QdlGraph,
        proposal: PayloadCorpusDelta,
        *,
        action_id: str,
        base_corpus: PayloadCorpus,
        guardrail: PayloadCorpusGuardrail | None = None,
    ) -> PayloadCorpusPromotionResult:
        """Validate and classify one payload corpus delta."""
        ...


__all__ = [
    "ClassificationPromotionContext",
    "FormalThreatModelResult",
    "LeadDescriptor",
    "PayloadCorpusPromotionResult",
    "PayloadCorpusPromoter",
    "ProposalPromotionRequest",
    "ProposalPromotionResult",
    "ProposalPromoter",
    "ThreatModelProposer",
]
