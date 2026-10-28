"""Owner-thread commit and consultation outcome policy."""

from __future__ import annotations

import logging
from typing import Any

from cloud_dast.api import LiveRequest
from cloud_dast.consultation import bind_consultation_telemetry
from cloud_dast.model import Observation
from cloud_dast.model.events import (
    ComponentKind,
    DownstreamDecision,
    EventScope,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.consultation.context import (
    OutcomeMeta,
    PlannedItem,
    WaveContext,
    WaveExecution,
)
from cloud_dast.runtime.consultation.evidence import key as make_key
from cloud_dast.runtime.consultation.evidence import observation as make_observation
from cloud_dast.runtime.consultation.outcomes import ConsultationOutcome
from cloud_dast.runtime.deficits import consultation_context
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
    merge_work_item_results,
)

logger = logging.getLogger("cloud_dast.runtime.consultation")


class Committer:
    """Commit proposals and record absorbing consultation outcomes."""

    def _commit_wave(self, context: WaveContext) -> WaveExecution:
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
            merge = merge_work_item_results(
                [item.work_item for item in context.planned],
                entries,
            )
            current_revision = context.current_revision
            for work_item_id in merge.applied_order:
                index = entries[work_item_id]
                item = context.planned[index]
                if (
                    index not in proposals
                    or current_revision is None
                    or self._load_source(
                        context.request.service,
                        failure_log="reactive_grounding_load_failed",
                    )
                    != current_revision
                ):
                    self._record_timed_out_work_item(
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
                    result, error = self._commit_proposal(
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
                promoted += self._record_work_item_outcome(
                    context.request,
                    item.work_item,
                    outcome,
                    context.deficits,
                    scope=context.scope,
                )
                if outcome.promoted:
                    previous = merge_graphs(previous, result)
                current_revision = self._load_source(
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

    def _commit_proposal(
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
                    result = self._grounding.commit_variance_batch(
                        context.request.service,
                        context.source,
                        item.work_item.action,
                        item.variance.report,
                        proposal,
                        evidence=item.evidence,
                    )
                elif item.work_item.axis == "alternatives":
                    result = self._grounding.commit_branch_batch(
                        context.request.service,
                        context.source,
                        item.work_item.action,
                        proposal,
                        evidence=item.evidence,
                        sibling_slice=item.siblings,
                        previous=previous,
                    )
                else:
                    result = self._grounding.commit_reactive_batch(
                        context.request.service,
                        context.source,
                        item.work_item.axis,
                        (item.work_item.action,),
                        proposal,
                        evidence=item.evidence,
                        context=consultation_context(item.work_item.representative),
                        previous=previous,
                    )
        except Exception as error:
            return None, error
        return result, None

    def _publish_consultation_decision(
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

    def _record_timed_out_work_item(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        deficits: DeficitQueue,
        *,
        observation: Observation | None,
        scope: EventScope | None = None,
    ) -> None:
        """Record an abandoned worker as a transient S33R outcome."""

        self._record_consultation_outcome(
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

    def _record_consultation_outcome(
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
            make_observation(
                work_item,
                outcome,
                conflict=meta.conflict,
                evidence_available=meta.evidence_available,
            ),
        )
        self._publish_consultation_decision(
            work_item,
            recorded,
            scope=meta.scope,
            component=meta.component,
            kind=meta.kind,
        )
        if recorded != "promoted":
            deficits.absorb_work_item(work_item)
        return recorded
