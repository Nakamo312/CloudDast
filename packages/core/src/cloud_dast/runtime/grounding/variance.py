"""Differential variance grounding and measured-evidence persistence."""

from __future__ import annotations

import logging
from collections.abc import Callable

from cloud_dast.model import Check, Observation
from cloud_dast.ports import FormalRepository
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.config import ReactiveGrounding
from cloud_dast.runtime.grounding.evidence import MeasuredEvidencePolicy
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.projection import timing_thresholds
from cloud_dast.runtime.grounding.promotion import (
    Activity,
    ProposalPromoter,
)
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.verification.differential.report import DiffReport, diff_campaign_key
from cloud_dast.verification.evidence import View, response_fields

logger = logging.getLogger("cloud_dast.runtime.grounding.variance")


class DifferentialFlow:
    """Own differential evidence projection and variance proposal flow."""

    def __init__(
        self,
        repository: FormalRepository,
        promotion: ProposalPromoter,
        reactive: ReactiveGrounding | None,
        measured_evidence_policy: MeasuredEvidencePolicy,
        reactive_capable: Callable[[], bool],
        source: Loader,
    ) -> None:
        self._repository = repository
        self._promotion = promotion
        self._reactive = reactive
        self._measured_evidence_policy = measured_evidence_policy
        self._reactive_capable = reactive_capable
        self._source = source

    def persist_measured_evidence(
        self,
        service: str,
        action_id: str,
        control: Observation,
        treatment: Observation,
        report: DiffReport,
        *,
        control_check: Check | None = None,
        treatment_check: Check | None = None,
    ) -> QdlGraph | None:
        """Persist deterministic canary-echo evidence without promoting it."""

        source = self._source.load(
            service,
            failure_log="variance_grounding_load_failed",
        )
        if source is None:
            return None
        measured = self._measured_evidence_policy.project(
            source,
            action_id,
            control_check=control_check,
            treatment_check=treatment_check,
            treatment=treatment,
            report=report,
        )
        if not measured.facts:
            return None

        campaign_key = diff_campaign_key(action_id, report)
        self._repository.save(
            f"diff:{service}:{campaign_key}:measured",
            measured,
            provenance={
                "source_kind": "diff-measured-evidence",
                "action": action_id,
                "diff": report.signature,
                "dimensions": list(report.dimensions),
                "control_observation_id": report.control_observation_id,
                "treatment_observation_id": report.treatment_observation_id,
            },
            adapter_version="measured-evidence-v1",
            mapping_report={"mapped": len(measured.facts), "unmapped": 0},
        )
        logger.info(
            "measured_variance_evidence_persisted service=%s action=%s facts=%d",
            service,
            action_id,
            len(measured.facts),
        )
        return measured

    def prepare_batch(
        self,
        request: PairInput,
    ) -> AxisResult | None:
        """Return a variance proposal for one measured differential pair."""

        if not self._reactive_capable():
            return None
        return self._reactive.ground_variance(
            request.source,
            request.action_id,
            control=request.control,
            treatment=request.treatment,
            report=request.report,
            control_check=request.control_check,
            treatment_check=request.treatment_check,
            oob_events=request.oob_events,
            evidence=request.evidence,
        )

    def commit_batch(
        self,
        service: str,
        source: QdlGraph,
        action_id: str,
        report: DiffReport,
        result: AxisResult,
        *,
        evidence: View,
    ) -> QdlGraph | None:
        """Promote and persist one admitted measured-variance proposal."""

        self._promotion.park_secret_shapes(
            f"proposal:{service}:variance:{action_id}:secret-shapes",
            (action_id,),
            evidence,
            evidence_refs=frozenset(result.observation_ids),
        )
        deficit_id = f"variance:{action_id}:{report.signature}"
        promoted = self._promotion.promote(
            ProposalPromotionRequest(
                source=source,
                proposal=result.graph,
                evidence_fields=frozenset(response_fields(evidence)),
                action_ids=(action_id,),
                duration_thresholds=timing_thresholds(action_id, report),
                evidence_refs=frozenset(result.observation_ids),
            ),
            proposal_source_id=f"proposal:{service}:variance:{action_id}",
            activity=Activity(
                component="consultation:variance",
                invocation_id=f"consultation:{deficit_id}:0",
                correlation_id=deficit_id,
            ),
        )
        if promoted is None or not promoted.facts:
            return None

        campaign_key = diff_campaign_key(action_id, report)
        self._promotion.save_promoted_graph(
            f"diff:{service}:{campaign_key}",
            promoted,
            provenance={
                "source_kind": "diff-campaign",
                "axis": "variance",
                "action": action_id,
                "diff": report.signature,
                "dimensions": list(report.dimensions),
                "control_observation_id": report.control_observation_id,
                "treatment_observation_id": report.treatment_observation_id,
                "evidence_refs": sorted(result.observation_ids),
            },
            adapter_version="diff-grounding-v1",
            revision_addressed=False,
        )
        logger.info(
            "variance_grounding_promoted service=%s action=%s facts=%d",
            service,
            action_id,
            len(promoted.facts),
        )
        return promoted


__all__ = ["DifferentialFlow"]
