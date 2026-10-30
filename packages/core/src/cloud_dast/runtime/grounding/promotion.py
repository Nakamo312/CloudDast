"""Deterministic proposal promotion and persistence for runtime grounding.

The grounding lifecycle may be asynchronous or reactive, but every proposal
uses this one boundary for normalization, policy checks, parking, telemetry,
and content-addressed persistence.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from cloud_dast.config import DEFAULT_MAX_PROMOTED_NORMS, MAX_SEMANTIC_FACTS
from cloud_dast.consultation import current_consultation_telemetry
from cloud_dast.ports import FormalRepository
from cloud_dast.proposals import (
    ClassificationPromotionContext,
    PayloadCorpusPromotionResult,
    ProposalPromotionRequest,
    ProposalPromotionResult,
)
from cloud_dast.qdl.graph import Context, QdlGraph, canonical_json
from cloud_dast.qdl.graph_ops import append_supersession, merge_graphs
from cloud_dast.runtime.grounding.projection import (
    revision_source_id,
)
from cloud_dast.runtime.grounding.state import (
    LeadLifecycle,
    ParkedLeadState,
    is_original_parked_fact,
)
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.promotion import (
    park_proposal,
    promote_payload_corpus_proposal,
    promote_proposal,
)
from cloud_dast.verification.secret_shapes import secret_shape_graph

if TYPE_CHECKING:
    from cloud_dast.contracts.payload_proposals import (
        PayloadCorpusDelta,
        PayloadCorpusGuardrail,
    )
    from cloud_dast.contracts.payloads import PayloadCorpus


logger = logging.getLogger("cloud_dast.runtime.grounding.promotion")


@dataclass(frozen=True, slots=True)
class Activity:
    """Component identity for publishing one promotion decision."""

    component: str
    invocation_id: str
    correlation_id: str = ""
    depth: int = 0


def _parked_fact_count(promotion) -> int:
    """Count unique original facts parked by one promotion result."""

    seen: set[str] = set()
    for graph in (
        promotion.parked_classifications,
        promotion.parked_semantics,
        promotion.parked_norms,
    ):
        if graph is None:
            continue
        for fact in graph.facts:
            if not is_original_parked_fact(fact):
                continue
            key = canonical_json(fact)
            if key in seen:
                continue
            seen.add(key)
    return len(seen)


def _as_proposal_graph(graph: QdlGraph) -> QdlGraph:
    """Treat every fact entering promotion as untrusted model output."""

    return QdlGraph(
        facts=tuple(
            fact.model_copy(update={"context": Context.PROPOSAL})
            for fact in graph.facts
        )
    )


class PromotionPolicy:
    """Apply one deterministic promotion boundary with campaign-wide caps.

    The policy is deliberately mutable: startup, reactive, alternatives, and
    variance batches share one budget.  A cap is therefore a campaign limit,
    not a way for every model batch to receive its own allowance.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        max_norms: int | None = DEFAULT_MAX_PROMOTED_NORMS,
        max_semantic_facts: int = MAX_SEMANTIC_FACTS,
        max_payload_delta_items: int | None = None,
    ) -> None:
        if max_norms is not None and max_norms <= 0:
            raise ValueError("max_norms must be positive or None")
        if max_semantic_facts <= 0:
            raise ValueError("max_semantic_facts must be positive")
        if max_payload_delta_items is None:
            from cloud_dast.contracts.payload_proposals import (
                MAX_PAYLOAD_CORPUS_DELTA_ITEMS,
            )

            max_payload_delta_items = MAX_PAYLOAD_CORPUS_DELTA_ITEMS
        if max_payload_delta_items <= 0:
            raise ValueError("max_payload_delta_items must be positive")
        self._enabled = enabled
        self._max_norms = max_norms
        self._max_semantic_facts = max_semantic_facts
        self._max_payload_delta_items = max_payload_delta_items
        self._promoted_norms = 0
        self._promoted_semantic_facts = 0
        self._promoted_payload_delta_items = 0
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def max_norms(self) -> int | None:
        return self._max_norms

    @property
    def max_semantic_facts(self) -> int:
        return self._max_semantic_facts

    @property
    def promoted_norms(self) -> int:
        return self._promoted_norms

    @property
    def promoted_semantic_facts(self) -> int:
        return self._promoted_semantic_facts

    @property
    def max_payload_delta_items(self) -> int:
        return self._max_payload_delta_items

    @property
    def promoted_payload_delta_items(self) -> int:
        return self._promoted_payload_delta_items

    @property
    def exhausted(self) -> bool:
        return (
            self._max_norms is not None and self._promoted_norms >= self._max_norms
        ) or self._promoted_semantic_facts >= self._max_semantic_facts

    @property
    def payload_budget_exhausted(self) -> bool:
        return self._promoted_payload_delta_items >= self._max_payload_delta_items

    def promote(self, request: ProposalPromotionRequest) -> ProposalPromotionResult:
        """Promote one request and consume the shared campaign budget."""

        with self._lock:
            if not self._enabled:
                return park_proposal(
                    request.source,
                    request.proposal,
                    evidence_fields=request.evidence_fields,
                )
            remaining_norms = (
                None
                if self._max_norms is None
                else self._max_norms - self._promoted_norms
            )
            remaining_semantic_facts = (
                self._max_semantic_facts - self._promoted_semantic_facts
            )
            if remaining_norms == 0 or remaining_semantic_facts == 0:
                return park_proposal(
                    request.source,
                    request.proposal,
                    evidence_fields=request.evidence_fields,
                )

            result = promote_proposal(
                request,
                max_norms=remaining_norms,
                max_semantic_facts=remaining_semantic_facts,
            )
            self._promoted_norms += len(result.promoted_norms)
            self._promoted_semantic_facts += result.promoted_semantic_facts
            return result

    def promote_intersected_proposals(
        self,
        source: QdlGraph,
        proposals: Iterable[QdlGraph],
        *,
        action_ids: frozenset[str] | tuple[str, ...] = (),
        duration_thresholds: Mapping[str, int] | None = None,
        evidence_fields: frozenset[str] | None = None,
        evidence_refs: frozenset[str] = frozenset(),
        approved_classifications: frozenset[str] = frozenset(),
        runtime_evidence_exempt_predicates: frozenset[str] = frozenset(),
        classification_context: ClassificationPromotionContext | None = None,
    ) -> ProposalPromotionResult:
        """Intersect independent proposals, then apply the promotion boundary.

        The intersection is the only proposal that can reach this method's
        accepted graph.  A single proposal is valid input: S34R is an exact
        intersection, not a count threshold.  Existing source, evidence, and
        operator gates still run after the intersection.
        """

        from cloud_dast.consultation import (
            intersect_grounded_proposals,
        )

        proposal = intersect_grounded_proposals(proposals)
        return self.promote(
            ProposalPromotionRequest(
                source=source,
                proposal=proposal,
                action_ids=action_ids,
                duration_thresholds=duration_thresholds,
                evidence_fields=evidence_fields,
                evidence_refs=evidence_refs,
                approved_classifications=approved_classifications,
                runtime_evidence_exempt_predicates=(runtime_evidence_exempt_predicates),
                classification_context=classification_context,
            )
        )

    def promote_payload_corpus(
        self,
        source: QdlGraph,
        proposal: PayloadCorpusDelta,
        *,
        action_id: str,
        base_corpus: PayloadCorpus,
        guardrail: PayloadCorpusGuardrail | None = None,
    ) -> PayloadCorpusPromotionResult:
        """Promote one payload-data delta under the same explicit policy."""

        with self._lock:
            if not self._enabled:
                return PayloadCorpusPromotionResult(
                    "parked",
                    proposal,
                    reasons=("payload corpus promotion is disabled",),
                )
            remaining = self._max_payload_delta_items - (
                self._promoted_payload_delta_items
            )
            if remaining <= 0:
                return PayloadCorpusPromotionResult(
                    "parked",
                    proposal,
                    reasons=("payload corpus promotion budget is exhausted",),
                )
            result = promote_payload_corpus_proposal(
                source,
                proposal,
                action_id=action_id,
                base_corpus=base_corpus,
                guardrail=guardrail,
                max_items=remaining,
            )
            self._promoted_payload_delta_items += result.promoted_items
            return result


class ProposalPromoter:
    """Own proposal admission, parked leads, and graph persistence."""

    def __init__(
        self,
        repository: FormalRepository,
        *,
        promotion_policy: PromotionPolicy,
        lead_lifecycle: LeadLifecycle,
    ) -> None:
        self._repository = repository
        self._promotion_policy = promotion_policy
        self._lead_lifecycle = lead_lifecycle

    def promote(
        self,
        request: ProposalPromotionRequest,
        *,
        proposal_source_id: str | None = None,
        activity: Activity | None = None,
    ) -> QdlGraph | None:
        """Promote one proposal through the shared deterministic boundary."""

        proposal = _as_proposal_graph(request.proposal)
        evidence_refs = frozenset(request.evidence_refs)
        promotion = self._promotion_policy.promote(
            replace(
                request,
                proposal=proposal,
                action_ids=frozenset(request.action_ids),
                evidence_refs=evidence_refs,
            )
        )
        self._park_promotion_outputs(
            proposal_source_id,
            promotion,
            evidence_refs=evidence_refs,
        )
        if activity is not None:
            self._publish_activity(activity, promotion)
        if promotion.rejected_semantic_facts:
            logger.warning(
                "grounding_semantic_overflow rejected=%d",
                promotion.rejected_semantic_facts,
            )
        if not promotion.graph.facts:
            return None
        return promotion.graph

    def park_secret_shapes(
        self,
        source_id: str,
        action_ids: tuple[str, ...],
        evidence: EvidenceView | None,
        evidence_refs: frozenset[str] = frozenset(),
    ) -> None:
        """Persist deterministic secret-shape observations as reviewable leads."""

        secret = secret_shape_graph(action_ids, evidence)
        if secret is None:
            return
        self._lead_lifecycle.record_graph(secret, evidence_refs)
        try:
            source_id = revision_source_id(source_id, secret)
            self._repository.save(
                source_id,
                secret,
                provenance={
                    "source_kind": "secret-shape-lead",
                    "evidence_refs": sorted(evidence_refs),
                },
                adapter_version="axis-grounding-v1",
                mapping_report={"mapped": len(secret.facts), "unmapped": 0},
            )
            logger.info(
                "secret_shape_parked source_id=%s facts=%d",
                source_id,
                len(secret.facts),
            )
        except Exception:  # noqa: BLE001 - parking is best-effort
            logger.warning("secret_shape_parking_failed source_id=%s", source_id)

    def save_promoted_graph(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: Mapping[str, object],
        adapter_version: str,
        previous: QdlGraph | None = None,
        revision_addressed: bool = True,
    ) -> tuple[QdlGraph, str]:
        """Persist one promoted graph with deterministic mapping metadata."""

        persisted = append_supersession(graph, previous)
        if revision_addressed:
            source_id = revision_source_id(source_id, persisted)
        self._repository.save(
            source_id,
            persisted,
            provenance=dict(provenance),
            adapter_version=adapter_version,
            mapping_report={"mapped": len(persisted.facts), "unmapped": 0},
        )
        return persisted, source_id

    def accepted_semantics(self, service: str) -> QdlGraph:
        """Load every accepted semantic source for one service."""

        return merge_graphs(
            self._repository.load(f"accepted:{service}"),
            self._repository.load_merged(f"accepted-batch:{service}:"),
            self._repository.load_merged(f"diff:{service}:"),
        )

    def load_parked_proposals(self, service: str) -> QdlGraph:
        """Merge every latest parked proposal source for one service."""

        return self._repository.load_merged(f"proposal:{service}:")

    def parked_lead_states(self) -> tuple[ParkedLeadState, ...]:
        """Return the minimal deduplicated lead lifecycle state."""

        return self._lead_lifecycle.snapshot()

    def _park_promotion_outputs(
        self,
        source_id: str | None,
        promotion,
        *,
        evidence_refs: frozenset[str],
    ) -> None:
        parked_graphs = [
            graph
            for graph in (
                promotion.parked_classifications,
                promotion.parked_semantics,
                promotion.parked_norms,
            )
            if graph is not None
        ]
        for graph in parked_graphs:
            self._lead_lifecycle.record_graph(graph, evidence_refs)
        if not parked_graphs or source_id is None:
            return
        self._save_parked_proposal(
            source_id,
            merge_graphs(*parked_graphs),
            evidence_refs=evidence_refs,
        )

    def _save_parked_proposal(
        self,
        source_id: str,
        parked: QdlGraph,
        *,
        evidence_refs: frozenset[str],
    ) -> None:
        try:
            source_id = revision_source_id(source_id, parked)
            self._repository.save(
                source_id,
                parked,
                provenance={
                    "source_kind": "parked-proposal",
                    "evidence_refs": sorted(evidence_refs),
                },
                adapter_version="axis-grounding-v1",
                mapping_report={"mapped": len(parked.facts), "unmapped": 0},
            )
            logger.info(
                "proposal_parked source_id=%s facts=%d",
                source_id,
                len(parked.facts),
            )
        except Exception:  # noqa: BLE001 - parking is best-effort
            logger.warning("proposal_parking_failed source_id=%s", source_id)

    def _publish_activity(self, activity: Activity, promotion) -> None:
        telemetry = current_consultation_telemetry()
        if telemetry is None:
            return
        invocation_id = activity.invocation_id
        correlation_id = activity.correlation_id or None
        if telemetry.deficit_id:
            invocation_id = f"consultation:{telemetry.deficit_id}:{activity.depth}"
            correlation_id = telemetry.deficit_id
        event = {
            "parked": _parked_fact_count(promotion),
            "promoted": int(bool(promotion.graph.facts)),
            "promoted_facts": len(promotion.graph.facts),
        }
        from cloud_dast.model.events import ComponentOutput

        telemetry.publisher.publish(
            telemetry.scope.apply(
                ComponentOutput(
                    component=activity.component,
                    summary=event,
                    invocation_id=invocation_id,
                    correlation_id=correlation_id,
                )
            )
            if telemetry.scope is not None
            else ComponentOutput(
                component=activity.component,
                summary=event,
                invocation_id=invocation_id,
                correlation_id=correlation_id,
            )
        )


__all__ = ["ProposalPromoter", "Activity"]
