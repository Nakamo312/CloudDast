"""Operator-reviewed classification grounding and approval persistence."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from cloud_dast.model.events import ApprovalAuditRecord
from cloud_dast.ports import ApprovalAuditLog, FormalRepository
from cloud_dast.proposals import (
    ProposalPromotionRequest,
)
from cloud_dast.qdl.graph import Context, Fact, QdlGraph, canonical_json
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.runtime.grounding.projection import (
    classification_action_id,
    classification_keys,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy, ProposalPromoter
from cloud_dast.verification.promotion import (
    PROTECTED_CLASSIFICATION_ROLES,
)

logger = logging.getLogger("cloud_dast.runtime.grounding.classification")


@dataclass(frozen=True, slots=True)
class ParkedClassification:
    """One reviewable protected-role fact from a parked proposal."""

    fact_hash: str
    holder: str
    role: str
    action_id: str | None
    fact: Fact


@dataclass(frozen=True, slots=True)
class ApprovalResult:
    """Durable result of one explicit operator classification approval."""

    fact_hash: str
    accepted_source_id: str
    accepted_graph_hash: str
    promoted_facts: int


class ApprovalFlow:
    """Own protected-role approval and its deterministic promotion boundary."""

    def __init__(
        self,
        repository: FormalRepository,
        promotion: ProposalPromoter,
        approval_audit_log: ApprovalAuditLog | None,
    ) -> None:
        self._repository = repository
        self._promotion = promotion
        self._approval_audit_log = approval_audit_log

    def list_approval_queue(
        self,
        service: str,
    ) -> tuple[ParkedClassification, ...]:
        """Return pending protected-role classifications in stable order."""

        _source, candidates = self._approval_state(service)
        return candidates

    def approve(
        self,
        service: str,
        fact_hash: str,
        *,
        operator: str,
        reason: str,
    ) -> ApprovalResult:
        """Promote exactly one operator-reviewed parked classification."""

        if self._approval_audit_log is None:
            raise RuntimeError("operator approval requires an audit log")
        source, candidates = self._approval_state(service)
        candidate = {item.fact_hash: item for item in candidates}.get(fact_hash)
        if candidate is None:
            raise ValueError("classification is not pending operator approval")
        promotion = self._promote(service, source, candidate, fact_hash)
        return self._save(
            service,
            source,
            candidate,
            promotion,
            fact_hash=fact_hash,
            operator=operator,
            reason=reason,
        )

    def _promote(
        self,
        service: str,
        source: QdlGraph,
        candidate: ParkedClassification,
        fact_hash: str,
    ):
        """Run the selected classification through the promotion boundary."""

        declarations = tuple(
            fact
            for fact in self._promotion.load_parked_proposals(service).facts
            if fact.context is Context.PROPOSAL and fact.predicate.name == "is"
        )
        promotion = PromotionPolicy(enabled=True, max_norms=None).promote(
            ProposalPromotionRequest(
                source=source,
                proposal=QdlGraph(facts=(*declarations, candidate.fact)),
                approved_classifications=frozenset((fact_hash,)),
            )
        )
        selected_key = canonical_json(candidate.fact.args)
        promoted_classification = any(
            fact.context is Context.ACCEPTED
            and fact.predicate.name == "has"
            and canonical_json(fact.args) == selected_key
            for fact in promotion.graph.facts
        )
        if not promoted_classification:
            raise ValueError("classification failed deterministic promotion checks")
        return promotion

    def _save(
        self,
        service: str,
        source: QdlGraph,
        candidate: ParkedClassification,
        promotion,
        *,
        fact_hash: str,
        operator: str,
        reason: str,
    ) -> ApprovalResult:
        """Persist the accepted graph and its operator audit record."""

        accepted_source_id = f"accepted-batch:{service}:operator-approval:{fact_hash}"
        record = ApprovalAuditRecord(
            service=service,
            fact_hash=fact_hash,
            operator=operator,
            reason=reason,
            accepted_graph_hash=promotion.graph.content_hash,
            promoted_facts=len(promotion.graph.facts),
            recorded_at=datetime.now(UTC).isoformat(),
        )
        _persisted, accepted_source_id = self._promotion.save_promoted_graph(
            accepted_source_id,
            promotion.graph,
            provenance={
                "source_kind": "operator-approval",
                "approved_fact_hash": fact_hash,
                "operator": operator,
                "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
            },
            adapter_version="operator-approval-v1",
            previous=source,
        )
        self._approval_audit_log.append(record)
        logger.info(
            "classification_approved service=%s fact_hash=%s facts=%d",
            service,
            fact_hash,
            len(promotion.graph.facts),
        )
        return ApprovalResult(
            fact_hash=fact_hash,
            accepted_source_id=accepted_source_id,
            accepted_graph_hash=promotion.graph.content_hash,
            promoted_facts=len(promotion.graph.facts),
        )

    def _approval_state(
        self,
        service: str,
    ) -> tuple[QdlGraph, tuple[ParkedClassification, ...]]:
        """Load source and pending classifications without best-effort fallback."""

        source = merge_graphs(
            self._repository.load(f"contract:{service}"),
            self._repository.load(f"stand:{service}"),
            self._promotion.accepted_semantics(service),
        )
        accepted = classification_keys(source)
        candidates: list[ParkedClassification] = []
        for fact in sorted(
            self._promotion.load_parked_proposals(service).facts,
            key=canonical_json,
        ):
            if fact.context is not Context.PROPOSAL or fact.predicate.name != "has":
                continue
            if len(fact.args) != 2:
                continue
            holder, role = fact.args
            role_name = atom_value(role)
            if not isinstance(role_name, str):
                continue
            if role_name not in PROTECTED_CLASSIFICATION_ROLES:
                continue
            if canonical_json(fact.args) in accepted:
                continue
            candidates.append(
                ParkedClassification(
                    fact_hash=fact.content_hash,
                    holder=canonical_json(holder),
                    role=role_name,
                    action_id=classification_action_id(holder),
                    fact=fact,
                )
            )
        return source, tuple(candidates)


__all__ = [
    "ApprovalResult",
    "ApprovalFlow",
    "ParkedClassification",
]
