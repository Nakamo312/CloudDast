"""QDL-backed campaign runtime and orchestration."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass

from cloud_dast.contracts.execution import (
    EvaluationResult,
    ExecutionResult,
    LiveRequest,
    LiveResult,
)
from cloud_dast.ports import (
    EventPublisher,
    FormalRepository,
    GroundingRunner,
    ReportPublisher,
    ScenarioRepository,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.finalization import (
    Finalizer,
)
from cloud_dast.runtime.campaign.initialization import (
    Bootstrap,
)
from cloud_dast.runtime.campaign.state import RuntimeState
from cloud_dast.runtime.consultation.outcomes import (
    AttemptKey,
    ConsultationOutcome,
)
from cloud_dast.runtime.deficits import (
    Deficit,
)
from cloud_dast.runtime.deficits.collection import DeficitCollector
from cloud_dast.runtime.differential.campaign import (
    Runner,
)
from cloud_dast.runtime.evidence_gate import EvidenceDeficitRecord
from cloud_dast.runtime.execution.runner import (
    BoundPathRunner,
)
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.replanning import Coordinator
from cloud_dast.verification.oracles import latency

__all__ = [
    "BoundPathRunner",
    "EvaluationResult",
    "ExecutionResult",
    "FindingEvaluator",
    "LiveWorkflow",
    "LiveWorkflowOptions",
]

logger = logging.getLogger("cloud_dast.runtime.campaign")


@dataclass(frozen=True, slots=True)
class LiveWorkflowOptions:
    """Optional campaign policies and adapters used to assemble a workflow."""

    batch_timeout: float = 600.0
    reactive_budget: int | None = 8
    latency_oracle: latency.Oracle | None = None
    diff_mode: bool = False
    diff_modes: frozenset[str] | None = None
    scenario_repository: ScenarioRepository | None = None
    formal_repository: FormalRepository | None = None
    event_bus: EventPublisher | None = None
    report_publisher: ReportPublisher | None = None
    metrics: CampaignMetrics | None = None
    grounding_runner: GroundingRunner | None = None
    reactive_max_workers: int = 4


class LiveWorkflow:
    """Compose QDL planning, execution, and finding evaluation.

    The campaign is an event loop, not a pipeline: model grounding runs in
    the background while the scheduler executes every path already bound
    from the contract model.  Each promoted grounding batch triggers one
    incremental planner solve; newly derived paths (including probe-field
    versions of known paths) are added to the same scheduler and executed
    in the next round.  The fix-point is ``grounding done`` plus an empty
    scheduler.  Differential discovery is not gated by that fix-point: its
    first sweep runs as soon as the initial binding has been executed and
    continues per newly discovered action, with a protected share of the
    check budget, so grounding failures cannot starve it.
    """

    def __init__(
        self,
        scenario_binder: ScenarioBinder,
        path_runner: BoundPathRunner,
        deficit_collector: DeficitCollector,
        initializer: Bootstrap,
        differential: Runner,
        replanning: Coordinator,
        finalizer: Finalizer,
        *,
        options: LiveWorkflowOptions,
    ) -> None:
        self._binder = scenario_binder
        self._runner = path_runner
        self._deficits = deficit_collector
        self._initializer = initializer
        self._differential = differential
        self._replanning = replanning
        self._finalizer = finalizer
        self._batch_timeout = options.batch_timeout
        self._diff_mode = options.diff_mode

    @property
    def evidence_deficits(self) -> tuple[EvidenceDeficitRecord, ...]:
        """Return evidence deficits recorded instead of model guesses."""

        return tuple(self._replanning.evidence_deficits.values())

    @property
    def consultation_outcomes(
        self,
    ) -> Mapping[AttemptKey, ConsultationOutcome]:
        """Return the recorded S33R consultation-outcome states."""

        return self._replanning.consultation_outcomes.states

    def execute(self, request: LiveRequest) -> LiveResult:
        logger.info(
            "live_workflow_started service=%s method_id=%s max_checks=%s",
            request.service,
            request.method_id or "-",
            request.max_checks if request.max_checks is not None else "-",
        )
        campaign = self._initializer.prepare(request)

        while True:
            if campaign.execution.budget.can_spend():
                self._runner.reconsider_paths(
                    campaign.execution.scheduler,
                    scope=campaign.scope,
                    blocked_reasons=campaign.execution.blocked_reasons,
                )
            self._differential.release_latency_ready_paths(campaign.execution.scheduler)
            if self._should_run_round(campaign):
                self._run_campaign_round(campaign)
            self._differential.update_latency_baselines(
                campaign.execution.scheduler, campaign.execution.accumulator
            )
            reactive_promoted = self._replanning.drain_reactive(
                request,
                campaign.grounding.deficits,
                campaign.execution.accumulator,
                variance_records=campaign.differential.variance_records,
                scope=campaign.scope,
                graph=campaign.binding.graph,
                active_path_ids=campaign.active_path_ids,
            )
            self._differential.release_latency_ready_paths(campaign.execution.scheduler)

            if campaign.execution.budget.can_spend():
                self._runner.reconsider_paths(
                    campaign.execution.scheduler,
                    scope=campaign.scope,
                    blocked_reasons=campaign.execution.blocked_reasons,
                )
            if self._campaign_finished(campaign, reactive_promoted):
                break
            self._wait_for_grounding(campaign, block=reactive_promoted == 0)
            self._rebind_and_extend_paths(campaign)

        return self._finish_campaign(campaign)

    def _should_run_round(self, campaign: RuntimeState) -> bool:
        """Return whether another ordinary execution round is due."""

        return (
            campaign.execution.scheduler.remaining
            or campaign.execution.rounds == 0
            or (
                self._diff_mode
                and not campaign.differential.differential_swept
                and campaign.execution.scheduler.paths
            )
        )

    def _run_campaign_round(self, campaign: RuntimeState) -> None:
        """Execute one ordinary round and its follow-up discovery phases."""

        campaign.execution.rounds += 1
        logger.info(
            "live_round_started service=%s round=%d paths=%d remaining=%d",
            campaign.request.service,
            campaign.execution.rounds,
            len(campaign.execution.scheduler.paths),
            campaign.execution.scheduler.remaining,
        )
        pre_first_sweep = (
            self._diff_mode and not campaign.differential.differential_swept
        )
        campaign.execution.budget.begin_ordinary_round(
            limit=1 if pre_first_sweep else None,
            reserve=(
                campaign.differential.diff_budget_reserve if pre_first_sweep else 0
            ),
        )

        def queue_deficit(deficit: Deficit) -> None:
            if campaign.grounding.deficits.add((deficit,)):
                logger.info(
                    "deficit_detected service=%s class=%s action=%s path=%s",
                    campaign.request.service,
                    deficit.predicate_class,
                    deficit.action,
                    dict(deficit.context).get("path_id", "-"),
                )

        try:
            campaign.execution.accumulator.add(
                self._runner.execute_round(
                    campaign.request,
                    campaign.execution.scheduler,
                    budget=campaign.execution.budget,
                    scope=campaign.scope,
                    deficit_sink=queue_deficit,
                    blocked_reasons=campaign.execution.blocked_reasons,
                    evidence_store=campaign.differential.differential_evidence,
                )
            )
        finally:
            campaign.execution.budget.end_round()
        self._deficits.record_recovery(
            campaign.execution.scheduler,
            campaign.execution.accumulator,
            campaign.grounding.recovery,
            blocked_reasons=campaign.execution.blocked_reasons,
        )
        if self._diff_mode and campaign.execution.scheduler.paths:
            self._differential.run_round(campaign)
        self._deficits.collect_deficits(
            campaign.request,
            campaign.binding,
            campaign.execution.scheduler,
            campaign.execution.accumulator,
            campaign.grounding.deficits,
            campaign.grounding.classification,
            campaign.grounding.recovery,
            expand_graph=(
                not campaign.execution.scheduler.remaining
                and not campaign.execution.branch_backlog
            ),
        )
        # Deficit classification consumes the intents it can execute;
        # draining removes the remainder instead of leaving a log-only
        # recovery lifecycle.
        campaign.grounding.recovery.drain_recovery_intents()

    def _campaign_finished(
        self,
        campaign: RuntimeState,
        reactive_promoted: int,
    ) -> bool:
        """Return whether every campaign work source has drained."""

        return (
            campaign.grounding.grounding_finished
            and (
                not campaign.grounding.reactive_active
                or not campaign.grounding.deficits.dispatchable
            )
            and reactive_promoted == 0
            and not campaign.execution.scheduler.remaining
            and not campaign.execution.branch_backlog
        )

    def _wait_for_grounding(
        self, campaign: RuntimeState, *, block: bool = True
    ) -> None:
        """Wait for one promoted batch or the grounding finish sentinel."""

        if campaign.grounding.grounding_finished:
            return
        if (
            not block
            or self._should_run_round(campaign)
            or (
                campaign.grounding.reactive_active
                and campaign.grounding.deficits.dispatchable
            )
            or campaign.execution.branch_backlog
        ):
            try:
                batch = campaign.grounding.handle.wait_batch(timeout=0)
            except TimeoutError:
                return
        else:
            batch = self._wait_for_batch(campaign.grounding.handle)
        if batch is None:
            # The grounding worker finished: every batch was saved before
            # this sentinel, so the rebind below absorbs the remaining facts
            # and the next round drains them.
            campaign.grounding.grounding_finished = True
            return
        logger.info(
            "live_batch_promoted service=%s axis=%s batch=%s facts=%d",
            campaign.request.service,
            batch.axis,
            batch.batch_key,
            batch.fact_count,
        )

    def _rebind_and_extend_paths(self, campaign: RuntimeState) -> None:
        """Rebind promoted facts and add newly selected branch paths."""

        rebinding = self._binder.bind(
            campaign.request,
            formal_proposal=False,
        )
        campaign.binding = rebinding
        new_paths = rebinding.execution.select(campaign.request.method_id)
        campaign.execution.scheduler.supersede_replaced_paths(new_paths)
        # Refresh evidence snapshots even when structural path identities match.
        known_paths = {path.path_id for path in campaign.execution.scheduler.paths}
        campaign.execution.scheduler.add_paths(
            tuple(path for path in new_paths if path.path_id in known_paths)
        )
        known_path_ids = {path.path_id for path in campaign.execution.scheduler.paths}
        candidate_paths = tuple(
            path
            for path in (*campaign.execution.branch_backlog, *new_paths)
            if path.path_id not in known_path_ids
        )
        selection = campaign.grounding.recovery.select_next_paths(
            candidate_paths,
            completed=campaign.execution.scheduler.state.completed,
            blocked=(
                campaign.execution.scheduler.state.blocked
                | campaign.execution.scheduler.state.superseded
            ),
            in_flight=campaign.execution.scheduler.state.in_flight,
        )
        campaign.execution.branch_backlog = selection.remaining
        added = campaign.execution.scheduler.add_paths(selection.paths)
        if selection.decision is not None:
            logger.info(
                "backtracking_branch_selected service=%s blocked_path=%s "
                "path=%s reason=%s clue=%s backlog=%d",
                campaign.request.service,
                selection.decision.blocked_path_id,
                selection.decision.path_id,
                selection.decision.reason,
                selection.decision.clue.observation_id
                if selection.decision.clue is not None
                else "-",
                len(selection.remaining),
            )
        if added:
            logger.info(
                "live_paths_discovered service=%s added=%d total=%d",
                campaign.request.service,
                added,
                len(campaign.execution.scheduler.paths),
            )

        if self._diff_mode and campaign.execution.scheduler.paths:
            self._differential.run_round(campaign)

    def _finish_campaign(self, campaign: RuntimeState) -> LiveResult:
        """Delegate terminal evaluation to the campaign finalizer."""

        return self._finalizer.finish(campaign)

    def _wait_for_batch(self, handle):
        """Block until the next promoted batch or the finish sentinel.

        A timeout is not a termination signal by itself: unless the worker
        is done, the loop keeps waiting so slow model calls cannot spin the
        campaign.
        """

        while True:
            try:
                return handle.wait_batch(timeout=self._batch_timeout)
            except TimeoutError:
                if handle.done:
                    return None
