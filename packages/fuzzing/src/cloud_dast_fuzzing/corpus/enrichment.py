"""Typed, entropy-only consultation that grows the deterministic payload corpus."""

from __future__ import annotations

import hashlib
import logging

from cloud_dast.consultation import (
    ConsultationBudget,
    ConsultationDispatcher,
    ConsultationRequest,
    SeedEnrichmentConsultationOutcome,
)
from cloud_dast.contracts.payload_proposals import (
    PayloadCorpusDelta,
    PayloadCorpusGuardrail,
)
from cloud_dast.extensions import (
    SaturatedHistory,
    SeedEnrichmentHook,
    SeedEnrichmentResult,
)
from cloud_dast.proposals import PayloadCorpusPromoter
from cloud_dast_fuzzing.corpus.store import (
    PayloadCorpusAuditRecord,
    PayloadCorpusStore,
)

logger = logging.getLogger("cloud_dast.fuzzing.seed_enrichment")


class SeedEnrichmentConsultant:
    """Consult a model only after candidate entropy and promote data, not code."""

    def __init__(
        self,
        consultation: ConsultationDispatcher,
        *,
        store: PayloadCorpusStore,
        promotion_policy: PayloadCorpusPromoter,
        guardrail: PayloadCorpusGuardrail | None = None,
        additional_checks: int = 8,
    ) -> None:
        if additional_checks <= 0:
            raise ValueError("additional_checks must be positive")
        self._dispatcher = consultation
        self._store = store
        self._promotion_policy = promotion_policy
        self._guardrail = guardrail or PayloadCorpusGuardrail()
        self._additional_checks = additional_checks

    def enrich(self, history: SaturatedHistory) -> SeedEnrichmentResult:
        deficit_id = (
            f"payload_entropy|{history.action_id}|"
            f"{history.invariant_id}|{history.scenario_id}"
        )
        if not history.sink_types:
            reason = "no source-declared sink types to enrich"
            self._record_rejection(history, deficit_id, reason)
            return SeedEnrichmentResult(False, reason)

        request = ConsultationRequest(
            kind="seed_enrichment",
            deficit_id=deficit_id,
            action=history.action_id,
            slice=history.source_graph,
            budget=ConsultationBudget(max_input_tokens=16384, max_output_tokens=4096),
            context={"saturated_history": history.to_model_dict()},
        )
        try:
            outcome = self._dispatcher.dispatch_seed_enrichment(request)
        except Exception as error:
            reason = f"model transport failed: {error}"
            logger.warning(
                "seed_enrichment_failed deficit=%s reason=%s",
                deficit_id,
                reason,
            )
            self._record_rejection(history, deficit_id, reason)
            return SeedEnrichmentResult(False, reason)

        delta = outcome.proposal
        if outcome.unscoreable or delta is None:
            reason = outcome.reason or "seed enrichment produced no proposal"
            self._record_rejection(history, deficit_id, reason, outcome=outcome)
            return SeedEnrichmentResult(False, reason)

        promotion = self._promotion_policy.promote_payload_corpus(
            history.source_graph,
            delta,
            action_id=history.action_id,
            base_corpus=self._store.corpus,
            guardrail=self._guardrail,
        )
        if not promotion.promoted:
            self._record_rejection(
                history,
                deficit_id,
                "; ".join(promotion.reasons) or "payload proposal parked",
                outcome=outcome,
                status=promotion.status,
            )
            return SeedEnrichmentResult(False, promotion.status)

        audit = self._audit_record(
            history,
            deficit_id,
            outcome=outcome,
            status="promoted",
            reason="",
            delta=promotion.delta,
            promoted_productions=promotion.promoted_productions,
            promoted_slot_alternatives=promotion.promoted_slot_alternatives,
            promoted_items=promotion.promoted_items,
        )
        applied = self._store.record(
            audit,
            delta=promotion.delta,
            guardrail=self._guardrail,
        )
        if not applied:
            return SeedEnrichmentResult(
                False,
                "payload delta was rejected while merging",
            )
        logger.info(
            "seed_enrichment_promoted deficit=%s productions=%d slot_updates=%d "
            "corpus_version=%s",
            deficit_id,
            len(promotion.promoted_productions),
            len(promotion.promoted_slot_alternatives),
            self._store.corpus.corpus_version,
        )
        return SeedEnrichmentResult(
            True,
            "payload corpus grew",
            additional_checks=self._additional_checks,
        )

    def _record_rejection(
        self,
        history: SaturatedHistory,
        deficit_id: str,
        reason: str,
        *,
        outcome: SeedEnrichmentConsultationOutcome | None = None,
        status: str | None = None,
    ) -> None:
        self._store.record(
            self._audit_record(
                history,
                deficit_id,
                outcome=outcome,
                status=status or ("unscoreable" if outcome is not None else "rejected"),
                reason=reason,
                delta=outcome.proposal if outcome is not None else None,
            )
        )

    def _audit_record(
        self,
        history: SaturatedHistory,
        deficit_id: str,
        *,
        outcome: SeedEnrichmentConsultationOutcome | None,
        status: str,
        reason: str,
        delta: PayloadCorpusDelta | None,
        promoted_productions: tuple[str, ...] = (),
        promoted_slot_alternatives: tuple[str, ...] = (),
        promoted_items: int = 0,
    ) -> PayloadCorpusAuditRecord:
        provenance = outcome.provenance if outcome is not None else None
        proposal_digest = _delta_digest(delta)
        record_id = hashlib.sha256(
            "|".join(
                (
                    deficit_id,
                    history.digest,
                    proposal_digest,
                    _corpus_digest(self._store.corpus),
                    status,
                    str(len(self._store.audit_trail)),
                )
            ).encode("utf-8")
        ).hexdigest()
        return PayloadCorpusAuditRecord(
            record_id=record_id,
            deficit_id=deficit_id,
            action=history.action_id,
            status=status,
            reason=reason,
            history_digest=history.digest,
            proposal_digest=proposal_digest,
            prompt_hash=provenance.prompt_hash if provenance else "",
            graph_slice_hash=provenance.graph_slice_hash if provenance else "",
            model_version=provenance.model_version if provenance else "",
            input_tokens=provenance.input_tokens if provenance else 0,
            cached_input_tokens=provenance.cached_input_tokens if provenance else 0,
            output_tokens=provenance.output_tokens if provenance else 0,
            latency_ms=provenance.latency_ms if provenance else 0.0,
            depth=provenance.depth if provenance else 0,
            base_corpus_version=self._store.corpus.corpus_version,
            next_corpus_version=self._store.corpus.corpus_version,
            promoted_productions=promoted_productions,
            promoted_slot_alternatives=promoted_slot_alternatives,
            promoted_items=promoted_items,
            rejected=() if status == "promoted" else (reason,),
            delta=delta,
        )


def _delta_digest(delta: PayloadCorpusDelta | None) -> str:
    if delta is None:
        return ""
    return hashlib.sha256(delta.model_dump_json().encode("utf-8")).hexdigest()


def _corpus_digest(corpus: object) -> str:
    return hashlib.sha256(str(corpus.model_dump_json()).encode("utf-8")).hexdigest()


__all__ = [
    "SeedEnrichmentConsultant",
    "SeedEnrichmentHook",
    "SeedEnrichmentResult",
]
