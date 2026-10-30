"""Finalize one completed live campaign."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cloud_dast.contracts.execution import (
    EvaluationResult,
    ExecutionResult,
    LiveResult,
    ScenarioBinding,
)
from cloud_dast.model.events import (
    DomainEvent,
    EventScope,
    PhaseChanged,
)
from cloud_dast.ports import EventPublisher, GroundingHandle, GroundingRunner
from cloud_dast.runtime import oob
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.state import RuntimeState
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.coverage import build_matrix
from cloud_dast.verification.norm_coverage import build_norm_coverage

logger = logging.getLogger("cloud_dast.runtime.campaign.finalization")


@dataclass(frozen=True, slots=True)
class FinalizerDeps:
    """Dependencies used to close and evaluate one campaign."""

    binder: ScenarioBinder
    runner: BoundPathRunner
    evaluator: FindingEvaluator
    oob_collector: oob.Coordinator | None = None
    grounding_runner: GroundingRunner | None = None
    event_bus: EventPublisher | None = None
    metrics: CampaignMetrics | None = None


class Finalizer:
    """Close campaign resources and build its final read models."""

    def __init__(self, callbacks: FinalizerDeps) -> None:
        self._binder = callbacks.binder
        self._runner = callbacks.runner
        self._evaluator = callbacks.evaluator
        self._oob = callbacks.oob_collector
        self._grounding_runner = callbacks.grounding_runner
        self._event_bus = callbacks.event_bus
        self._metrics = callbacks.metrics

    def finish(self, campaign: RuntimeState) -> LiveResult:
        """Close lifecycle, reevaluate evidence, and return the final result."""

        request = campaign.request
        self.close_grounding_lifecycle(campaign.grounding.handle)
        logger.info(
            "reactive_loop_completed service=%s reactive_calls=%d closed=%d",
            request.service,
            campaign.grounding.deficits.dispatched,
            campaign.grounding.deficits.closed_count,
        )
        if (
            campaign.grounding.handle is not None
            and campaign.grounding.handle.error is not None
        ):
            logger.error(
                "live_grounding_failed service=%s error=%s",
                request.service,
                campaign.grounding.handle.error,
            )
        if not campaign.execution.scheduler.paths:
            logger.warning(
                "qdl_plan_has_no_executable_paths service=%s",
                request.service,
            )

        late_oob_verdicts = (
            self._oob.reevaluate_pending() if self._oob is not None else {}
        )
        if late_oob_verdicts:
            campaign.execution.accumulator.policy_verdicts.update(
                {
                    key: late_oob_verdicts[key[0]]
                    for key, verdict in campaign.execution.accumulator.policy_verdicts.items()
                    if key[0] in late_oob_verdicts
                    and verdict.model_id == late_oob_verdicts[key[0]].model_id
                }
            )
            logger.info(
                "oob_pending_reevaluated service=%s verdicts=%d",
                request.service,
                len(late_oob_verdicts),
            )

        self._publish(PhaseChanged(phase="evaluating"), campaign.scope)
        final_binding = self._binder.bind(request, formal_proposal=False)
        campaign.execution.accumulator.add(
            self._runner.readback_reevaluation.reevaluate(
                request,
                final_binding.execution.select(request.method_id),
                campaign.execution.accumulator.as_result(),
                scope=campaign.scope,
                evidence_store=campaign.differential.differential_evidence,
            )
        )
        execution = campaign.execution.accumulator.as_result()
        evaluation = self._evaluator.evaluate(
            execution,
            final_binding.invariants,
            graph=final_binding.graph,
        )
        self._publish(PhaseChanged(phase="finished"), campaign.scope)
        logger.info(
            "live_workflow_completed service=%s rounds=%d observations=%d "
            "findings=%d replayed=%d",
            request.service,
            campaign.execution.rounds,
            len(execution.observations),
            len(evaluation.findings),
            len(evaluation.replayed_observations),
        )
        return self._live_result(campaign, final_binding, execution, evaluation)

    def close_grounding_lifecycle(
        self,
        handle: GroundingHandle | None = None,
    ) -> None:
        """Close advisory task handoffs before the campaign becomes terminal."""

        if handle is not None and handle.enrichment_status == "pending":
            handle.mark_enrichment("discarded")
        if self._grounding_runner is not None:
            self._grounding_runner.close()

    def _live_result(
        self,
        campaign: RuntimeState,
        final_binding: ScenarioBinding,
        execution: ExecutionResult,
        evaluation: EvaluationResult,
    ) -> LiveResult:
        """Build the public result and final coverage projections."""

        request = campaign.request
        return LiveResult(
            scenario=final_binding.scenario,
            observations=execution.observations,
            findings=evaluation.findings,
            replayed_observations=evaluation.replayed_observations,
            replayed_findings=evaluation.replayed_findings,
            qdl_graph=final_binding.graph,
            qdl_plan=final_binding.plan,
            coverage=build_matrix(
                final_binding.graph,
                service=request.service,
                invariants=final_binding.invariants,
                events=self._evaluator.events,
                scope=campaign.scope,
            ),
            norm_coverage=build_norm_coverage(
                final_binding,
                execution,
                campaign.execution.scheduler,
                findings=evaluation.findings,
                events=campaign.scope.run_events(self._evaluator.events),
                budget_exhausted=campaign.execution.budget.exhausted,
            ),
            grounding_enrichment_status=(
                campaign.grounding.handle.enrichment_status
                if campaign.grounding.handle is not None
                else "not_started"
            ),
        )

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if isinstance(event, PhaseChanged) and self._metrics is not None:
            self._metrics.record_phase(event)
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)


__all__ = ["FinalizerDeps", "Finalizer"]
