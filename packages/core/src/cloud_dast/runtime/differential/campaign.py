"""Run differential campaign experiments and route evidence."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cloud_dast.contracts.execution import LiveRequest, ScenarioBinding
from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model.events import EventScope
from cloud_dast.ports import EventPublisher, FormalRepository, ScenarioRepository
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.state import RuntimeState
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.context import ProbeContext
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.differential.outcomes import OutcomeRecorder
from cloud_dast.runtime.differential.probes import (
    ProbeCallbacks,
    ProbeRunner,
)
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.observation_matching import action_matches
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.differential.modes import (
    CONCURRENCY_PROBES,
    TIMING_REPEATS,
)
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles.latency import LatencyOracle

logger = logging.getLogger("cloud_dast.runtime.differential.campaign")


@dataclass(frozen=True, slots=True)
class ExperimentDeps:
    """External capabilities used by differential campaign experiments."""

    executor: ProbeExecutor
    diff_mode: bool
    diff_modes: frozenset[str]
    latency_oracle: LatencyOracle | None = None
    scenario_repository: ScenarioRepository | None = None
    formal_repository: FormalRepository | None = None
    event_bus: EventPublisher | None = None
    metrics: CampaignMetrics | None = None


class Runner:
    """Own differential experiments, baselines, and variance evidence."""

    def __init__(self, callbacks: ExperimentDeps) -> None:
        self._diff_mode = callbacks.diff_mode
        self._diff_modes = callbacks.diff_modes
        self._latency_oracle = callbacks.latency_oracle
        self._outcomes = OutcomeRecorder(
            formal_repository=callbacks.formal_repository,
            event_bus=callbacks.event_bus,
            metrics=callbacks.metrics,
        )
        self._probes = ProbeRunner(
            ProbeCallbacks(
                executor=callbacks.executor,
                outcomes=self._outcomes,
                latency_oracle=callbacks.latency_oracle,
                scenario_repository=callbacks.scenario_repository,
            )
        )

    def run_round(self, campaign: RuntimeState) -> None:
        """Run differential discovery after an ordinary campaign round."""

        first_sweep = not campaign.differential.differential_swept
        if first_sweep:
            campaign.differential.differential_swept = True
        campaign.execution.budget.begin_differential_round(
            reserve=(
                campaign.differential.diff_budget_reserve
                if first_sweep and campaign.differential.diff_budget_reserve
                else None
            )
        )
        try:
            self._run_differential_round(
                campaign.request,
                campaign.binding,
                campaign.execution.scheduler,
                campaign.execution.accumulator,
                campaign.grounding.deficits,
                campaign.differential.variance_records,
                campaign.differential.paired_steps,
                campaign.execution.budget,
                scope=campaign.scope,
                evidence_store=campaign.differential.differential_evidence,
            )
        finally:
            campaign.execution.budget.end_round()
        self.update_latency_baselines(
            campaign.execution.scheduler, campaign.execution.accumulator
        )
        self.release_latency_ready_paths(campaign.execution.scheduler)
        if first_sweep:
            campaign.execution.budget.release_differential_reserve()
            self.release_budget_deferred_paths(campaign.execution.scheduler)

    def _run_differential_round(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        paired_steps: set[tuple[str, ...]],
        budget: CallLimits,
        scope: EventScope,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> None:
        """Pair every planned action once per enabled mode and measure variance.

        This is the differential discovery source: for every action of the
        current execution plan — starting from the first stable action set
        and continuing as grounding promotes new paths — each enabled mode
        (RFC §9.1) executes its own isolated pair and compares the legs.
        ``paired_steps`` records completed measurements per mode and canonical
        resolved prerequisite revision. A deferred mode stays open; unrelated
        graph changes and path re-versioning never repeat a measured pair.  Grounding
        never gates the sweep, and a measured variance is persisted as
        runtime facts and queued as an ``unexplained_variance`` deficit — it
        is never a finding by itself; the finding can only come from a
        promoted norm verified by a deterministic oracle.
        """

        evidence_store = evidence_store or Store[MeasurementKey]()
        method_pool = {method.method_id: method for method in binding.methods}
        for path in scheduler.paths:
            if scheduler.is_prewarmed(path.path_id):
                continue
            for step in path.steps:
                self._probes.evaluate_step_modes(
                    ProbeContext(
                        request=request,
                        step=step,
                        graph=binding.graph,
                        method_pool=method_pool,
                        accumulator=accumulator,
                        deficits=deficits,
                        variance_records=variance_records,
                        budget=budget,
                        scope=scope,
                        paired_steps=paired_steps,
                        diff_modes=self._diff_modes,
                        path_id=path.path_id,
                        evidence_store=evidence_store,
                    )
                )

    def run_initial(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        paired_steps: set[tuple[str, ...]],
        budget: CallLimits,
        *,
        reserve: int,
        scope: EventScope,
        evidence_store: Store[MeasurementKey],
    ) -> None:
        """Run the first differential sweep before ordinary paths mutate state.

        Read-back and concurrency evidence must observe the pre-action state
        before another QDL path can change it.  The sweep uses the protected
        differential reserve as its cap, so ordinary execution keeps its share
        of the campaign budget.
        """

        budget.begin_differential_round(
            reserve=reserve if request.max_checks is not None and reserve else None
        )
        try:
            self._run_differential_round(
                request,
                binding,
                scheduler,
                accumulator,
                deficits,
                variance_records,
                paired_steps,
                budget,
                scope,
                evidence_store,
            )
        finally:
            budget.end_round()
            budget.release_differential_reserve()
        self.update_latency_baselines(scheduler, accumulator)
        self.release_latency_ready_paths(scheduler)
        logger.info(
            "differential_initial_sweep_completed positions=%d observations=%d",
            len(paired_steps),
            len(accumulator.observations),
        )

    def budget_reserve(
        self,
        request: LiveRequest,
        paths: tuple[QdlExecutionPath, ...],
    ) -> int:
        """Return the live checks protected for the first differential sweep.

        The reserve covers one pairing sweep of the initially planned
        ``(action, scenario)`` positions across the enabled modes, so every configured mode gets a chance to run
        before the budget is spent.  It is capped at half the campaign (with
        a floor large enough for one complete differential mode), keeping
        ordinary QDL execution its share of the budget.
        """

        if not self._diff_mode or request.max_checks is None:
            return 0
        steps_by_position: dict[tuple[str, str], QdlExecutionStep] = {}
        for path in paths:
            for step in path.steps:
                steps_by_position.setdefault(
                    (step.method.method_id, step.scenario.scenario_id),
                    step,
                )

        per_position = 0
        mode_costs: list[int] = []
        for step in steps_by_position.values():
            if "factors" in self._diff_modes:
                cost = 2
                mode_costs.append(cost)
                per_position += cost
            if "payload" in self._diff_modes:
                cost = 2
                mode_costs.append(cost)
                per_position += cost
            if "readback" in self._diff_modes:
                cost = 3
                mode_costs.append(cost)
                per_position += cost
            if "timing" in self._diff_modes:
                cost = TIMING_REPEATS * 2
                mode_costs.append(cost)
                per_position += cost
            if "concurrency" in self._diff_modes:
                cost = CONCURRENCY_PROBES + 2
                mode_costs.append(cost)
                per_position += cost
        sweep_checks = per_position * len(steps_by_position)
        minimum_mode = min(mode_costs, default=0)
        floor = (
            min(minimum_mode, request.max_checks)
            if minimum_mode <= request.max_checks
            else 0
        )
        return min(sweep_checks, max(request.max_checks // 2, floor))

    @staticmethod
    def release_budget_deferred_paths(scheduler: CoverageDrivenScheduler) -> int:
        """Re-queue paths blocked only by the differential reserve.

        ``execute_round`` marks every unselected path blocked when the
        protected pre-sweep policy runs out.  A blocked path with no attempts
        was never executed — it was cut by the reserve cap, not refuted by
        the target.  Once the first differential sweep has taken its
        protected share, those paths become eligible again and ordinary
        execution continues with whatever budget remains.
        """

        deferred = scheduler.state.release_unattempted()
        if deferred:
            logger.info(
                "differential_reserve_released deferred_paths=%d remaining=%d",
                deferred,
                scheduler.remaining,
            )
        return deferred

    def release_latency_ready_paths(
        self,
        scheduler: CoverageDrivenScheduler,
    ) -> int:
        """Release or bootstrap duration paths waiting for a baseline.

        An action with a baseline releases every matching path.  Without one,
        one still-prewarmed path is marked for a single bootstrap execution;
        its delivered response becomes the initial baseline.
        """

        if self._latency_oracle is None:
            return 0
        actions = self._latency_bound_actions(scheduler)
        ready = tuple(
            action
            for action in sorted(actions)
            if self._latency_oracle.has_baseline(action)
        )
        released = scheduler.release_prewarmed(ready) if ready else 0
        missing = tuple(
            action
            for action in sorted(actions)
            if not self._latency_oracle.has_baseline(action)
        )
        bootstrapped = scheduler.bootstrap_prewarmed(missing)
        return released + bootstrapped

    def update_latency_baselines(
        self,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
    ) -> int:
        """Create missing latency baselines from ordinary campaign evidence."""

        if self._latency_oracle is None:
            return 0
        updated = 0
        for action in sorted(self._latency_bound_actions(scheduler)):
            if self._latency_oracle.has_baseline(action):
                continue
            observations = tuple(
                observation
                for observation in accumulator.observations
                if action_matches(observation, action)
            )
            min_samples = 1 if scheduler.is_latency_bootstrap(action) else 3
            updated += int(
                self._latency_oracle.update_baseline_from_observations(
                    action,
                    observations,
                    min_samples=min_samples,
                )
            )
        if updated:
            logger.info(
                "latency_baselines_updated actions=%d",
                updated,
            )
        return updated

    @staticmethod
    def _latency_bound_actions(scheduler: CoverageDrivenScheduler) -> set[str]:
        return {
            step.method.method_id
            for path in scheduler.paths
            for step in path.steps
            if (norm := NormView.from_invariant(step.invariant)) is not None
            and norm.primitive == "latency_bound"
        }
