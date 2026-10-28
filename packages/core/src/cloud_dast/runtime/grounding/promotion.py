"""Deterministic proposal promotion and persistence for runtime grounding.

The grounding lifecycle may be asynchronous or reactive, but every proposal
uses this one boundary for normalization, policy checks, parking, telemetry,
and content-addressed persistence.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace

from cloud_dast.consultation import current_consultation_telemetry
from cloud_dast.ports import FormalRepository
from cloud_dast.proposals import (
    ProposalPromotionRequest,
)
from cloud_dast.qdl.graph import Context, QdlGraph, canonical_json
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.projection import (
    append_supersession,
    revision_source_id,
)
from cloud_dast.runtime.grounding.state import (
    LeadLifecycle,
    ParkedLeadState,
    is_original_parked_fact,
)
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast.verification.secret_shapes import secret_shape_graph

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
    ) -> str:
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
        return source_id

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
