"""Reactive grounding for deficit, blocked-path, and variance evidence."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, cast

from cloud_dast.consultation import (
    ConsultationKind,
    ConsultationOutcome,
    ConsultationRequest,
    current_consultation_telemetry,
)
from cloud_dast.ports import _bound_model_log_value
from cloud_dast.proposals import ClassificationPromotionContext
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.consultation.axes import Axis
from cloud_dast.runtime.grounding.axes.filtering import (
    _action_atoms,
    _filter_alternatives_grammar,
)
from cloud_dast.runtime.grounding.axes.projection import (
    build_axis_result,
    log_grounding_uncertainties,
    uncertainty_pairs,
)
from cloud_dast.runtime.grounding.inputs import BranchCall, PairInput, ReactiveCall
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import (
    EvidenceView,
    build_evidence_view,
    build_paired_evidence_view,
)
from cloud_dast.verification.slices import (
    BoundedSlice,
    SiblingActionSlice,
    build_sibling_action_slice,
    build_slice,
    estimate_tokens,
)


class Followup:
    """Own live-evidence consultations after startup grounding."""

    def dispatch_consultation(
        self, request: ConsultationRequest
    ) -> ConsultationOutcome:
        """Dispatch one consultation while recording model usage."""

        if self._metrics is not None:
            self._metrics.model_request_started(
                f"consultation {request.kind} ({request.action})"
            )
        outcome = None
        try:
            outcome = self._consultation.dispatch(
                request,
                telemetry=current_consultation_telemetry(),
            )
        finally:
            if self._metrics is not None:
                if outcome is not None:
                    self._metrics.record_tokens(
                        outcome.provenance.input_tokens,
                        outcome.provenance.output_tokens,
                        cached_input_tokens=outcome.provenance.cached_input_tokens,
                        phase=f"consultation:{request.kind}",
                    )
                    self._metrics.set_model_id(outcome.provenance.model_version)
                self._metrics.model_request_finished()
        return outcome

    def ground_reactive(
        self,
        axis: Axis,
        action_ids: tuple[str, ...],
        graph: QdlGraph,
        **values: object,
    ) -> AxisResult:
        """Ground one deficit-driven axis with current live evidence."""

        call = ReactiveCall(axis, action_ids, graph, **values)
        axis = call.axis  # type: ignore[assignment]
        action_ids = call.action_ids
        graph = call.graph
        context_extra = call.context_extra
        observation = call.observation
        check = call.check
        oob_events = call.oob_events
        evidence = call.evidence
        cache_source = call.cache_source

        resolved_actions = tuple(
            dict.fromkeys((*action_ids, *(f"action:{action}" for action in action_ids)))
        )
        if not _action_atoms(graph, resolved_actions):
            return AxisResult(axis, None, 0, 0)

        context = dict(context_extra or {})
        if evidence is None and (check is not None or observation is not None):
            evidence = build_evidence_view(
                check=check,
                observation=observation,
                oob_events=oob_events,
                label="reactive",
            )
        if evidence is not None:
            context["evidence"] = evidence.to_dict()
        slice_ = build_slice(
            graph,
            actions=resolved_actions,
            evidence=evidence,
            budget=self._slice_budget,
        )
        background = build_slice(
            cache_source or graph,
            actions=resolved_actions,
            evidence=evidence,
            budget=self._slice_budget,
        ).graph
        logger.info(
            "grounding_reactive axis=%s actions=%d slice_facts=%d slice_hash=%s "
            "truncated=%s live_observation=%s",
            axis,
            len(action_ids),
            len(slice_.graph.facts),
            slice_.slice_hash,
            slice_.truncated,
            observation is not None,
        )
        request = ConsultationRequest(
            kind=cast(ConsultationKind, axis),
            deficit_id=f"reactive:{axis}:{'+'.join(action_ids)}",
            action="+".join(action_ids),
            slice=slice_.graph,
            budget=self._consultation_budget,
            context=context,
            background=background,
            observation_ids=(
                (observation.observation_id,) if observation is not None else ()
            ),
        )
        return self._ground_result(
            axis,
            action_ids,
            slice_,
            request,
            evidence=evidence,
        )

    def ground_alternatives(
        self,
        graph: QdlGraph,
        blocked_action: str,
        **values: object,
    ) -> AxisResult:
        """Ground alternatives using only the deterministic sibling slice."""

        call = BranchCall(graph, blocked_action, **values)
        graph = call.graph
        blocked_action = call.blocked_action
        observation = call.observation
        evidence = call.evidence
        sibling_slice = call.sibling_slice

        resolved = (blocked_action, f"action:{blocked_action}")
        if not _action_atoms(graph, resolved):
            return AxisResult("alternatives", None, 0, 0)
        if sibling_slice is None:
            sibling_slice = build_sibling_action_slice(graph, action=blocked_action)
        if not sibling_slice.siblings:
            logger.info(
                "grounding_alternatives_deficit action=%s reason=no-sibling-relations",
                _bound_model_log_value(blocked_action),
            )
            from cloud_dast.qdl.validation import ValidationIssue

            return AxisResult(
                "alternatives",
                None,
                1,
                0,
                issues=(
                    ValidationIssue(
                        code="sibling_slice_deficit",
                        message=(
                            "no QDL relations connect the blocked action to "
                            "sibling actions"
                        ),
                        path=f"alternatives:{blocked_action}",
                    ),
                ),
            )

        action_ids = (
            sibling_slice.action,
            *(sibling.action for sibling in sibling_slice.siblings),
        )
        slice_ = BoundedSlice(
            graph=sibling_slice.graph,
            actions=action_ids,
            depth=1,
            token_estimate=estimate_tokens(sibling_slice.graph),
            truncated=sibling_slice.truncated,
            slice_hash=sibling_slice.slice_hash,
        )
        context, evidence = self._branch_context(call, sibling_slice, slice_)
        request = ConsultationRequest(
            kind="alternatives",
            deficit_id=f"blocked:{blocked_action}",
            action=blocked_action,
            slice=slice_.graph,
            budget=self._consultation_budget,
            context=context,
            background=slice_.graph,
            observation_ids=(
                (observation.observation_id,) if observation is not None else ()
            ),
        )
        result = self._ground_result(
            "alternatives",
            action_ids,
            slice_,
            request,
            evidence=evidence,
        )
        return _filter_alternatives_grammar(result, graph)

    def _branch_context(
        self,
        call: BranchCall,
        sibling_slice: SiblingActionSlice,
        slice_: BoundedSlice,
    ) -> tuple[dict[str, Any], EvidenceView | None]:
        """Build bounded branch evidence and consultation context."""

        context: dict[str, Any] = {
            "blocked_step": {
                "action": call.blocked_action,
                "effect_hint": call.effect_hint,
                "blocked_reason": call.blocked_reason,
            },
            "sibling_actions": [
                {
                    "action": sibling.action,
                    "relations": list(sibling.relations),
                    "shared_terms": list(sibling.shared_terms),
                }
                for sibling in sibling_slice.siblings
            ],
        }
        evidence = call.evidence
        if evidence is None and (
            call.check is not None or call.observation is not None
        ):
            evidence = build_evidence_view(
                check=call.check,
                observation=call.observation,
                oob_events=call.oob_events,
                label="blocked_step",
            )
        if evidence is not None:
            context["evidence"] = evidence.to_dict()
        logger.info(
            "grounding_alternatives action=%s siblings=%d slice_facts=%d "
            "slice_hash=%s truncated=%s live_observation=%s",
            _bound_model_log_value(call.blocked_action),
            len(sibling_slice.siblings),
            len(slice_.graph.facts),
            slice_.slice_hash,
            slice_.truncated,
            call.observation is not None,
        )
        return context, evidence

    def ground_variance(
        self,
        graph: QdlGraph,
        action_id: str,
        **values: object,
    ) -> AxisResult:
        """Formalize one measured control/treatment variance."""

        call = PairInput(source=graph, action_id=action_id, **values)
        graph = call.source
        action_id = call.action_id
        control = call.control
        treatment = call.treatment
        report = call.report
        control_check = call.control_check
        treatment_check = call.treatment_check
        oob_events = call.oob_events
        evidence = call.evidence

        resolved = (action_id, f"action:{action_id}")
        if not _action_atoms(graph, resolved):
            return AxisResult("variance", None, 0, 0)
        context: dict[str, Any] = {
            "diff_report": {
                "action": action_id,
                "control_observation_id": report.control_observation_id,
                "treatment_observation_id": report.treatment_observation_id,
                "dimensions": list(report.dimensions),
                "signature": report.signature,
            },
        }
        if evidence is None:
            evidence = build_paired_evidence_view(
                control_check=control_check,
                control=control,
                treatment_check=treatment_check,
                treatment=treatment,
                report=report,
                oob_events=oob_events,
            )
        context["evidence"] = evidence.to_dict()
        slice_ = build_slice(
            graph,
            actions=resolved,
            evidence=evidence,
            budget=self._slice_budget,
        )
        logger.info(
            "grounding_variance action=%s slice_facts=%d slice_hash=%s "
            "truncated=%s dimensions=%s",
            _bound_model_log_value(action_id),
            len(slice_.graph.facts),
            slice_.slice_hash,
            slice_.truncated,
            ",".join(report.dimensions) or "none",
        )
        request = ConsultationRequest(
            kind="variance",
            deficit_id=f"variance:{action_id}:{report.signature}",
            action=action_id,
            slice=slice_.graph,
            budget=self._consultation_budget,
            context=context,
            background=slice_.graph,
            observation_ids=(control.observation_id, treatment.observation_id),
        )
        return self._ground_result(
            "variance",
            (action_id,),
            slice_,
            request,
            evidence=evidence,
        )

    def _ground_result(
        self,
        label: Axis,
        action_ids: tuple[str, ...],
        slice_: BoundedSlice,
        request: ConsultationRequest,
        *,
        evidence: EvidenceView | None,
    ) -> AxisResult:
        """Dispatch and apply the shared reactive result boundary."""

        outcome = self.dispatch_consultation(request)
        uncertainties = uncertainty_pairs(outcome)
        log_grounding_uncertainties(label, action_ids, uncertainties)
        result = build_axis_result(
            label,
            action_ids,
            slice_,
            evidence=evidence,
            proposal=outcome.proposal,
            issue_count=outcome.issue_count,
            uncertainties=uncertainties,
            invalid_reason=outcome.reason or "empty proposal",
            require_response_grounding=True,
        )
        classification_context = None
        if label == "classification":
            classification_context = ClassificationPromotionContext.from_mapping(
                request.context,
                evidence_refs=(*request.observation_ids, *outcome.observation_ids),
            )
        return replace(
            result,
            observation_ids=outcome.observation_ids,
            classification_context=classification_context,
        )


logger = logging.getLogger("cloud_dast.runtime.grounding.parallel")

__all__ = ["Followup"]
