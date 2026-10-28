"""Typed consultation flow for model-backed grounding."""

from __future__ import annotations

import logging
from collections.abc import Callable

from cloud_dast.consultation import (
    CONSULTATION_INSTRUCTIONS,
    ConsultationRequest,
    ConsultationResult,
    current_consultation_telemetry,
    rejected_outcome,
)
from cloud_dast.model.events import ComponentSkipped
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.promotion import (
    Activity,
    ProposalPromoter,
)
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.state import (
    ConsultationKey,
    ConsultationLedger,
)

logger = logging.getLogger("cloud_dast.runtime.grounding.consultation")


class DispatchFlow:
    """Dispatch, admit, and persist one typed grounding consultation."""

    def __init__(
        self,
        axis_grounding,
        promotion: ProposalPromoter,
        source: Loader,
        ledger: ConsultationLedger,
        reactive_capable: Callable[[], bool],
    ) -> None:
        self._axis_grounding = axis_grounding
        self._promotion = promotion
        self._source = source
        self._ledger = ledger
        self._reactive_capable = reactive_capable

    def run(
        self,
        service: str,
        request: ConsultationRequest,
    ) -> ConsultationResult:
        """Run one evidence-signed consultation through the promotion boundary."""

        if not self._reactive_capable():
            return self._rejected(request, "reactive grounding is disabled")
        source = self._source.load(
            service,
            failure_log="consultation_source_load_failed",
        )
        if source is None:
            return self._rejected(request, "consultation source load failed")

        refs = frozenset(request.observation_ids)
        key = ConsultationKey(
            service=service,
            kind=request.kind,
            deficit_id=request.deficit_id,
            action=request.action,
            depth=request.depth,
        )
        if not self._ledger.admits(key, refs):
            self._publish_suppressed(request, refs)
            return self._rejected(
                request,
                "lead preserved: consultation carries no new evidence",
            )

        outcome = self._axis_grounding.dispatch_consultation(request)
        self._ledger.record(key, refs)
        if outcome.proposal is None or not outcome.proposal.facts:
            return ConsultationResult(outcome, None)

        fixture = request.kind == "fixture"
        promoted = self._promotion.promote(
            ProposalPromotionRequest(
                evidence_fields=frozenset(),
                source=source,
                proposal=outcome.proposal,
                action_ids=() if fixture else (request.action,),
                evidence_refs=refs,
                runtime_evidence_exempt_predicates=frozenset({"refers_to", "targets"})
                if fixture
                else frozenset(),
            ),
            proposal_source_id=f"proposal:{service}:consultation:{request.deficit_id}",
            activity=Activity(
                component=f"consultation:{request.kind}",
                invocation_id=f"consultation:{request.deficit_id}:{request.depth}",
                correlation_id=request.deficit_id,
                depth=request.depth,
            ),
        )
        if promoted is None or not promoted.facts:
            return ConsultationResult(outcome, None)
        return self._save(
            service,
            source,
            request,
            outcome,
            promoted,
            evidence_refs=refs,
        )

    def _rejected(
        self,
        request: ConsultationRequest,
        reason: str,
    ) -> ConsultationResult:
        return ConsultationResult(
            rejected_outcome(
                request,
                CONSULTATION_INSTRUCTIONS.get(request.kind, ""),
                reason,
            ),
            None,
        )

    def _save(
        self,
        service: str,
        source: QdlGraph,
        request: ConsultationRequest,
        outcome,
        promoted: QdlGraph,
        *,
        evidence_refs: frozenset[str],
    ) -> ConsultationResult:
        provenance = outcome.provenance
        self._promotion.save_promoted_graph(
            f"accepted-batch:{service}:consultation:{request.deficit_id}",
            promoted,
            provenance={
                "source_kind": "consultation",
                "kind": request.kind,
                "deficit_id": request.deficit_id,
                "model_version": provenance.model_version,
                "prompt_hash": provenance.prompt_hash,
                "graph_slice_hash": provenance.graph_slice_hash,
                "input_tokens": provenance.input_tokens,
                "cached_input_tokens": provenance.cached_input_tokens,
                "output_tokens": provenance.output_tokens,
                "latency_ms": provenance.latency_ms,
                "depth": provenance.depth,
                "evidence_refs": sorted(evidence_refs),
            },
            adapter_version="consultation-v1",
            previous=source,
        )
        logger.info(
            "consultation_promoted service=%s kind=%s deficit=%s facts=%d",
            service,
            request.kind,
            request.deficit_id,
            len(promoted.facts),
        )
        return ConsultationResult(outcome, promoted)

    def _publish_suppressed(
        self,
        request: ConsultationRequest,
        evidence_refs: frozenset[str],
    ) -> None:
        telemetry = current_consultation_telemetry()
        if telemetry is None:
            return
        event = ComponentSkipped(
            component=f"consultation:{request.kind}",
            invocation_id=f"consultation:{request.deficit_id}:{request.depth}",
            reason="lead_preserved_without_new_evidence",
            input_completeness={
                "evidence_refs": len(evidence_refs),
                "new_evidence_refs": 0,
            },
        )
        telemetry.publisher.publish(
            telemetry.scope.apply(event) if telemetry.scope is not None else event
        )


__all__ = ["DispatchFlow"]
