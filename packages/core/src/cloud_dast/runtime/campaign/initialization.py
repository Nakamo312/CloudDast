"""Prepare initial binding and mutable campaign state."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cloud_dast.contracts.execution import LiveRequest, ScenarioBinding
from cloud_dast.model.events import DomainEvent, EventScope, PhaseChanged
from cloud_dast.ports import (
    EventPublisher,
    GroundingHandle,
    GroundingRunner,
    ReportPublisher,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.state import (
    DifferentialState,
    ExecutionState,
    GroundingState,
    RuntimeState,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.campaign import Runner
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.runner import build_event_scope
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding import BatchFlow
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.recovery import Coordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.coverage import build_matrix
from cloud_dast.verification.oracles.latency import LatencyOracle

logger = logging.getLogger("cloud_dast.runtime.campaign.initialization")

_REACTIVE_TRANSITIONS_PER_EVIDENCE = 1


@dataclass(frozen=True, slots=True)
class BootstrapDeps:
    """Capabilities and policy used to create one campaign runtime."""

    binder: ScenarioBinder
    evaluator: FindingEvaluator
    differential: Runner
    grounding: RunCoordinator | None = None
    reactive: BatchFlow | None = None
    grounding_runner: GroundingRunner | None = None
    reactive_budget: int | None = 8
    latency_oracle: LatencyOracle | None = None
    diff_mode: bool = False
    report_publisher: ReportPublisher | None = None
    event_bus: EventPublisher | None = None
    metrics: CampaignMetrics | None = None


class Bootstrap:
    """Own startup side effects and initial campaign-state construction."""

    def __init__(self, callbacks: BootstrapDeps) -> None:
        self._binder = callbacks.binder
        self._evaluator = callbacks.evaluator
        self._differential = callbacks.differential
        self._grounding = callbacks.grounding
        self._reactive = callbacks.reactive
        self._grounding_runner = callbacks.grounding_runner
        self._reactive_budget = callbacks.reactive_budget
        self._latency_oracle = callbacks.latency_oracle
        self._diff_mode = callbacks.diff_mode
        self._report_publisher = callbacks.report_publisher
        self._event_bus = callbacks.event_bus
        self._metrics = callbacks.metrics

    def prepare(self, request: LiveRequest) -> RuntimeState:
        """Snapshot history, publish startup and construct one campaign in order."""

        baseline_event_ids = frozenset(
            event.event_id for event in self._evaluator.events
        )
        self._publish(PhaseChanged(phase="qdl_planning"), None)
        handle = self.start_grounding(request)
        binding, scope = self.prepare_initial_binding(
            request,
            baseline_event_ids=baseline_event_ids,
        )
        return self.prepare_campaign(
            request,
            binding,
            scope,
            handle=handle,
        )

    def start_grounding(self, request: LiveRequest) -> GroundingHandle | None:
        """Start asynchronous grounding without blocking the first bind."""

        if self._grounding is None:
            return None
        grounding_runner = self._require_grounding_runner()
        handle = self._grounding.start_grounded(request.service, grounding_runner)
        logger.info(
            "live_grounding_started service=%s async=%s",
            request.service,
            handle is not None,
        )
        return handle

    def prepare_initial_binding(
        self,
        request: LiveRequest,
        *,
        baseline_event_ids: frozenset[str],
    ) -> tuple[ScenarioBinding, EventScope]:
        """Bind contract-only paths and publish their initial reports."""

        # The first bind must not call any model: contract-derived paths start
        # executing while background grounding is still in progress.
        binding = self._binder.bind(request, formal_proposal=False)
        scope = build_event_scope(
            request,
            binding.plan.graph_hash,
            baseline_event_ids=baseline_event_ids,
        )
        initial_coverage = build_matrix(
            binding.graph,
            service=request.service,
            invariants=binding.invariants,
            events=self._evaluator.events,
            scope=scope,
        )
        if self._report_publisher is not None:
            self._report_publisher.publish_plan(
                binding.execution,
                max_checks=request.max_checks,
                scope=scope,
            )
            self._report_publisher.publish_coverage(initial_coverage, scope=scope)
        self._publish(PhaseChanged(phase="executing"), scope)
        logger.info(
            "qdl_plan_ready service=%s graph_hash=%s attack_paths=%d "
            "forbidden_paths=%d invariants=%d runtime_paths=%d",
            request.service,
            binding.plan.graph_hash,
            len(binding.plan.attack_paths),
            len(binding.plan.forbidden_paths),
            len(binding.plan.invariants),
            len(binding.execution.paths),
        )
        return binding, scope

    def prepare_campaign(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        scope: EventScope,
        *,
        handle: GroundingHandle | None,
    ) -> RuntimeState:
        """Create scheduler, budget, queues, and campaign-wide state."""

        initial_paths = binding.execution.select(request.method_id)
        scheduler = CoverageDrivenScheduler(
            initial_paths,
            has_latency_baseline=(
                self._latency_oracle.has_baseline
                if self._latency_oracle is not None
                else None
            ),
        )
        deficits = DeficitQueue(
            max_tasks=self._reactive_budget,
            max_attempts=_REACTIVE_TRANSITIONS_PER_EVIDENCE,
        )
        campaign = RuntimeState(
            request=request,
            binding=binding,
            scope=scope,
            execution=ExecutionState(
                scheduler=scheduler,
                accumulator=CampaignAccumulator.empty(),
                budget=CallLimits.from_request(request),
            ),
            differential=DifferentialState(
                diff_budget_reserve=self._differential.budget_reserve(
                    request,
                    initial_paths,
                ),
                variance_records={},
                paired_steps=set(),
                differential_swept=False,
                differential_evidence=Store[MeasurementKey](),
            ),
            grounding=GroundingState(
                deficits=deficits,
                recovery=Coordinator(),
                handle=handle,
                grounding_finished=handle is None,
                reactive_active=(
                    self._reactive is not None and self._reactive.reactive_capable
                ),
            ),
        )
        if self._diff_mode and scheduler.paths:
            self._differential.run_initial(
                request,
                binding,
                scheduler,
                campaign.execution.accumulator,
                deficits,
                campaign.differential.variance_records,
                campaign.differential.paired_steps,
                campaign.execution.budget,
                reserve=campaign.differential.diff_budget_reserve,
                scope=scope,
                evidence_store=campaign.differential.differential_evidence,
            )
            campaign.differential.differential_swept = True
        return campaign

    def _require_grounding_runner(self) -> GroundingRunner:
        if self._grounding_runner is None:
            raise RuntimeError(
                "grounding_runner is required when grounding or reactive work runs"
            )
        return self._grounding_runner

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if isinstance(event, PhaseChanged) and self._metrics is not None:
            self._metrics.record_phase(event)
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)


__all__ = ["BootstrapDeps", "Bootstrap"]
