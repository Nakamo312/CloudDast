"""Evidence gating and per-item grounding calls."""

from __future__ import annotations

import logging

from cloud_dast.api import LiveRequest
from cloud_dast.consultation import bind_consultation_telemetry
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import EventScope
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.consultation.context import OutcomeMeta, PlannedItem
from cloud_dast.runtime.consultation.evidence import (
    EVIDENCE_REQUIRED_AXES,
    check_for_observation,
    observation_for_work_item,
)
from cloud_dast.runtime.deficits import Deficit, consultation_context
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import WorkItem, WorkItemGrounding
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import SiblingActionSlice

logger = logging.getLogger("cloud_dast.runtime.consultation")


class Invoker:
    """Gate evidence and invoke grounding for one planned work item."""

    def _plan_work_item_observation(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
        *,
        scope: EventScope | None = None,
    ) -> tuple[bool, Observation | None, Check | None]:
        """Resolve one work item's live evidence on the campaign thread.

        The S31 evidence-first gate also runs here, before any worker thread
        exists, because it mutates queue and evidence-deficit state.
        """

        observation = observation_for_work_item(work_item, accumulator)
        if observation is None and work_item.axis in EVIDENCE_REQUIRED_AXES:
            # S31 evidence-first gate: response semantics and variance answer
            # from live evidence.  Without it the model can only guess, so
            # record the evidence need and keep the model silent.
            self._evidence_gate.record_work_item(
                request,
                work_item,
                deficits,
                scope=scope,
                record_outcome=self._record_evidence_outcome,
            )
            return True, None, None
        if (
            observation is None
            and work_item.axis == "dataflows"
            and not self._evidence_gate.allows_dataflows(
                request,
                work_item.action,
            )
        ):
            # Dataflows evidence gate: a dataflow consultation needs either a
            # live observation or an already-declared sink/reaches fact in
            # the merged graph.  Without either, the model can only guess at
            # flow structure — the observed failure mode behind most empty
            # dataflow proposals — so park the deficit as an evidence need
            # and keep the model silent.
            self._evidence_gate.record_work_item(
                request,
                work_item,
                deficits,
                scope=scope,
                record_outcome=self._record_evidence_outcome,
            )
            return True, None, None
        return (
            False,
            observation,
            check_for_observation(
                observation,
                accumulator,
            ),
        )

    def _ground_work_item_call(
        self,
        request: LiveRequest,
        item: PlannedItem,
        *,
        source: QdlGraph,
        scope: EventScope | None = None,
    ) -> AxisResult | Exception | None:
        """Run only the model proposal on a worker, with owner-bound inputs."""

        work_item = item.work_item
        try:
            with bind_consultation_telemetry(
                self._event_bus,
                scope,
                deficit_id=work_item.work_item_id,
                work_item_id=work_item.work_item_id,
                deficit_ids=work_item.deficit_ids,
            ):
                if work_item.axis == "variance":
                    record = item.variance
                    if record is None:
                        return None
                    return self._grounding.prepare_variance_batch(
                        PairInput(
                            source=source,
                            action_id=work_item.action,
                            control=record.control,
                            treatment=record.treatment,
                            report=record.report,
                            control_check=record.control_check,
                            treatment_check=record.treatment_check,
                            evidence=item.evidence,
                        )
                    )
                return self._ground_reactive_deficit(
                    request,
                    work_item.representative,
                    source=source,
                    observation=item.observation,
                    check=item.check,
                    evidence=item.evidence,
                    sibling_slice=item.siblings,
                )
        except Exception as error:
            return error

    def _record_work_item_outcome(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        outcome: WorkItemGrounding,
        deficits: DeficitQueue,
        *,
        scope: EventScope | None = None,
        conflict: bool = False,
    ) -> int:
        """Record one grounding outcome on the campaign thread."""

        recorded = self._record_consultation_outcome(
            request,
            work_item,
            outcome,
            deficits,
            meta=OutcomeMeta(scope=scope, conflict=conflict),
        )
        if recorded != "promoted":
            if outcome.error is not None:
                self._log_work_item_exception(
                    request,
                    work_item,
                    outcome.error,
                )
            return 0
        result = deficits.record_work_item_result(
            work_item,
            outcome.result,
            observation=outcome.observation,
        )
        if result.closed_deficit_ids:
            if work_item.axis == "variance" and self._metrics is not None:
                self._metrics.record_diff_norm_promoted()
            logger.info(
                "reactive_work_item_closed service=%s class=%s action=%s "
                "work_item=%s closed=%d facts=%d",
                request.service,
                work_item.predicate_class,
                work_item.action,
                work_item.work_item_id,
                len(result.closed_deficit_ids),
                len(outcome.result.facts),
            )
        else:
            logger.info(
                "reactive_grounding_did_not_close service=%s class=%s action=%s "
                "work_item=%s facts=%d",
                request.service,
                work_item.predicate_class,
                work_item.action,
                work_item.work_item_id,
                len(outcome.result.facts),
            )
        return 1

    def _record_evidence_outcome(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        outcome: WorkItemGrounding,
        deficits: DeficitQueue,
        **kwargs,
    ):
        """Adapt the evidence-gate callback to the compact outcome contract."""

        return self._record_consultation_outcome(
            request,
            work_item,
            outcome,
            deficits,
            meta=OutcomeMeta(**kwargs),
        )

    def _ground_reactive_deficit(
        self,
        request: LiveRequest,
        deficit: Deficit,
        *,
        source: QdlGraph,
        observation,
        check: Check | None,
        evidence: EvidenceView | None,
        sibling_slice: SiblingActionSlice | None = None,
    ) -> AxisResult | None:
        """Prepare the proposal selected by the existing consultation routing."""

        if deficit.axis == "alternatives":
            context = dict(deficit.context)
            return self._grounding.prepare_branch_batch(
                source,
                deficit.action,
                observation=observation,
                check=check,
                evidence=evidence,
                sibling_slice=sibling_slice,
                effect_hint=context.get("effect", ""),
                blocked_reason=context.get("reason", ""),
            )
        return self._grounding.prepare_reactive_batch(
            source,
            deficit.axis,
            (deficit.action,),
            context=consultation_context(deficit),
            observation=observation,
            check=check,
            evidence=evidence,
        )

    @staticmethod
    def _log_work_item_exception(
        request: LiveRequest,
        work_item: WorkItem,
        error: BaseException,
    ) -> None:
        """Log one failed work item without exposing model error details."""

        logger.warning(
            "reactive_grounding_exception service=%s class=%s action=%s "
            "axis=%s work_item=%s error_type=%s error=%.240s",
            request.service,
            work_item.predicate_class,
            work_item.action,
            work_item.axis or "-",
            work_item.work_item_id,
            type(error).__name__,
            error,
        )
