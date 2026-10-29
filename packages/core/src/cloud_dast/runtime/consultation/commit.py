"""Owner-thread evidence gating, proposal admission and queue outcomes."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from cloud_dast.consultation import bind_consultation_telemetry
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import (
    ComponentKind,
    DomainEvent,
    DownstreamDecision,
    EventScope,
)
from cloud_dast.ports import EventPublisher
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.consultation.calls import PlannedItem
from cloud_dast.runtime.consultation.context import (
    OutcomeMeta,
    WaveContext,
    WaveExecution,
)
from cloud_dast.runtime.consultation.evidence import (
    EVIDENCE_REQUIRED_AXES,
    check_for_observation,
    classify,
    observation_for_work_item,
)
from cloud_dast.runtime.consultation.evidence import key as make_key
from cloud_dast.runtime.consultation.outcomes import (
    ConsultationOutcome,
    OutcomePolicy,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
)
from cloud_dast.runtime.evidence_gate import Gate
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding import BatchFlow
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.runtime.metrics import CampaignMetrics

logger = logging.getLogger("cloud_dast.runtime.consultation")


class Committer:
    """Apply evidence gates and worker results on the owner thread."""

    def __init__(
        self,
        grounding: BatchFlow | None,
        event_bus: EventPublisher | None,
        metrics: CampaignMetrics | None,
        evidence_gate: Gate,
        policy: OutcomePolicy,
        source: Loader | None,
        variance: DifferentialFlow | None,
    ) -> None:
        self._batches = grounding
        self._variance = variance
        self._source = source
        self._event_bus = event_bus
        self._metrics = metrics
        self._evidence_gate = evidence_gate
        self._consultation_outcomes = policy

    def commit(self, context: WaveContext) -> WaveExecution:
        """Apply worker results in canonical order and propagate the wave."""

        outcomes: dict[str, WorkItemGrounding] = {}
        with context.grounding_runner.commit(context.lifecycle_revision) as admitted:
            proposals = dict(context.proposals)
            if not admitted:
                proposals.clear()
            promoted = 0
            previous = context.source
            entries = {
                item.work_item.work_item_id: index
                for index, item in enumerate(context.planned)
            }
            current_revision = context.current_revision
            for planned in sorted(
                context.planned, key=lambda item: item.work_item.structural_priority
            ):
                index = entries[planned.work_item.work_item_id]
                item = context.planned[index]
                if (
                    index not in proposals
                    or current_revision is None
                    or self._source is None
                    or self._source.load(
                        context.request.service,
                        failure_log="reactive_grounding_load_failed",
                    )
                    != current_revision
                ):
                    self._record_timeout(
                        context.request,
                        item.work_item,
                        context.deficits,
                        observation=item.observation,
                        scope=context.scope,
                    )
                    continue
                proposal = proposals[index]
                error = proposal if isinstance(proposal, Exception) else None
                result = None
                if proposal is not None and error is None:
                    result, error = self._promote(
                        context,
                        item,
                        proposal,
                        previous=previous,
                    )
                outcome = WorkItemGrounding(
                    item.work_item.work_item_id,
                    result,
                    item.observation,
                    error,
                )
                outcomes[item.work_item.work_item_id] = outcome
                promoted += self.record_outcome(
                    context.request,
                    item.work_item,
                    outcome,
                    context.deficits,
                    scope=context.scope,
                )
                if outcome.promoted:
                    previous = merge_graphs(previous, result)
                current_revision = self._source.load(
                    context.request.service,
                    failure_log="reactive_grounding_load_failed",
                )
        if any(outcome.promoted for outcome in outcomes.values()):
            context.deficits.propagate_wave_results(
                outcomes,
                base_graph=context.base_graph,
                active_path_ids=context.active_path_ids,
            )
        return WaveExecution(
            promoted,
            self._merge_wave_graph(context.base_graph, outcomes),
        )

    def _promote(
        self,
        context: WaveContext,
        item: PlannedItem,
        proposal: Any,
        *,
        previous: QdlGraph,
    ) -> tuple[QdlGraph | None, BaseException | None]:
        """Commit one proposal through the axis-specific grounding port."""

        try:
            with bind_consultation_telemetry(
                self._event_bus,
                context.scope,
                deficit_id=item.work_item.work_item_id,
                work_item_id=item.work_item.work_item_id,
                deficit_ids=item.work_item.deficit_ids,
            ):
                if item.work_item.axis == "variance" and item.variance is not None:
                    result = self._variance.commit_batch(
                        context.request.service,
                        context.source,
                        item.work_item.action,
                        item.variance.report,
                        proposal,
                        evidence=item.evidence,
                    )
                else:
                    result = self._batches.commit(
                        context.request.service,
                        context.source,
                        item.work_item.axis,
                        (item.work_item.action,),
                        proposal,
                        evidence=item.evidence,
                        sibling_slice=item.siblings
                        if item.work_item.axis == "alternatives"
                        else None,
                        previous=previous,
                    )
        except Exception as error:
            return None, error
        return result, None

    def plan_observation(
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
                record_outcome=self._record_evidence,
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
                record_outcome=self._record_evidence,
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

    def record_outcome(
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

        recorded = self._record_decision(
            request,
            work_item,
            outcome,
            deficits,
            meta=OutcomeMeta(scope=scope, conflict=conflict),
        )
        if recorded != "promoted":
            if outcome.error is not None:
                self._log_error(
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

    def _record_evidence(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        outcome: WorkItemGrounding,
        deficits: DeficitQueue,
        **kwargs,
    ):
        """Adapt the evidence-gate callback to the compact outcome contract."""

        return self._record_decision(
            request,
            work_item,
            outcome,
            deficits,
            meta=OutcomeMeta(**kwargs),
        )

    def _publish_decision(
        self,
        work_item: WorkItem,
        outcome: ConsultationOutcome,
        *,
        scope: EventScope | None,
        component: str | None = None,
        kind: ComponentKind = "producer",
    ) -> None:
        """Publish one typed S33R consultation decision."""

        if self._event_bus is None:
            return
        self._publish(
            DownstreamDecision(
                component=component or f"consultation:{work_item.axis}",
                kind=kind,
                consumed=outcome == "promoted",
                by="consultation_outcome_policy",
                outcome=outcome,
                invocation_id=f"{component or 'consultation'}:{work_item.work_item_id}:0",
                correlation_id=work_item.work_item_id,
            ),
            scope,
        )

    def _record_timeout(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        deficits: DeficitQueue,
        *,
        observation: Observation | None,
        scope: EventScope | None = None,
    ) -> None:
        """Record an abandoned worker as a transient S33R outcome."""

        self._record_decision(
            request,
            work_item,
            WorkItemGrounding(
                work_item.work_item_id,
                None,
                observation,
                TimeoutError("grounding task timed out"),
            ),
            deficits,
            meta=OutcomeMeta(scope=scope),
        )
        logger.warning(
            "reactive_work_item_timed_out service=%s work_item=%s action=%s",
            request.service,
            work_item.work_item_id,
            work_item.action,
        )

    def _record_decision(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        outcome: WorkItemGrounding,
        deficits: DeficitQueue,
        *,
        meta: OutcomeMeta | None = None,
    ) -> ConsultationOutcome:
        """Record one absorbing consultation outcome on the campaign thread."""

        meta = meta or OutcomeMeta()
        identity = make_key(
            request.service,
            work_item,
            outcome.observation,
        )
        recorded = self._consultation_outcomes.record(
            identity,
            classify(
                work_item,
                outcome,
                conflict=meta.conflict,
                evidence_available=meta.evidence_available,
            ),
        )
        self._publish_decision(
            work_item,
            recorded,
            scope=meta.scope,
            component=meta.component,
            kind=meta.kind,
        )
        if recorded != "promoted":
            deficits.absorb_work_item(work_item)
        return recorded

    @staticmethod
    def _log_error(
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

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)

    @staticmethod
    def _merge_wave_graph(
        base_graph: QdlGraph | None,
        outcomes: Mapping[str, WorkItemGrounding],
    ) -> QdlGraph | None:
        """Return the pre-wave graph plus every promoted wave outcome."""

        promoted = [
            outcome.result
            for outcome in outcomes.values()
            if outcome.promoted and outcome.result is not None
        ]
        if not promoted:
            return base_graph
        return merge_graphs(base_graph or QdlGraph(), *promoted)
