"""Sequence one campaign round around path execution."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cloud_dast.contracts.execution import (
    ExecutionResult,
    LiveRequest,
)
from cloud_dast.contracts.finding_examples import load_finding_examples
from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.model import Check
from cloud_dast.model.events import DomainEvent, EventScope
from cloud_dast.ports import FindingExampleStore
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.replay import RoundReplay
from cloud_dast.runtime.deficits import Deficit
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState, stride_letter
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.campaign.round")


@dataclass(frozen=True, slots=True)
class RunnerDeps:
    """Path-runner capabilities used by campaign sequencing."""

    reset_checks: Callable[[], None]
    refresh_events: Callable[[], tuple[DomainEvent, ...]]
    register_paths: Callable[[tuple[QdlExecutionPath, ...]], None]
    skip_evaluated_path: Callable[..., None]
    execute_path: Callable[..., bool]
    publish_scheduler_terminal_events: Callable[..., None]
    publish_missing_terminal_path_events: Callable[[EventScope | None], None]
    service_checks: Callable[[], tuple[Check, ...]]
    reconsider_paths: Callable[..., None] | None = None


class Runner:
    """Own budgeted round sequencing while delegating one-path execution."""

    def __init__(
        self,
        callbacks: RunnerDeps,
        *,
        metrics: CampaignMetrics | None = None,
        example_database: FindingExampleStore | None = None,
    ) -> None:
        self._callbacks = callbacks
        self._metrics = metrics
        self._example_database = example_database

    def run(
        self,
        request: LiveRequest,
        scheduler: CoverageDrivenScheduler,
        *,
        budget: CallLimits | None = None,
        scope: EventScope | None = None,
        deficit_sink: Callable[[Deficit], object] | None = None,
        blocked_reasons: dict[str, str] | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> Any:
        """Drain one scheduler round and return its execution result."""

        budget = CallLimits.from_request(request) if budget is None else budget
        self._callbacks.reset_checks()
        events = self._callbacks.refresh_events()
        state = self.replay_state(
            events,
            scheduler=scheduler,
            scope=scope,
            blocked_reasons=blocked_reasons,
            evidence_store=evidence_store,
        )
        state.deficit_sink = deficit_sink
        self._callbacks.register_paths(scheduler.paths)
        self._initialize_intent_states(scheduler, state)

        self._drain_paths(request, scheduler, state, budget, scope)

        logger.info(
            "scheduler_completed total=%d completed=%d blocked=%d remaining=%d",
            len(scheduler.paths),
            len(scheduler.state.completed),
            len(scheduler.state.blocked),
            scheduler.remaining,
        )
        if not budget.can_spend():
            self._callbacks.publish_missing_terminal_path_events(scope)
            self._callbacks.publish_scheduler_terminal_events(
                scheduler,
                scope=scope,
            )
        return ExecutionResult(
            observations=tuple(state.observations),
            checks=self._callbacks.service_checks(),
            provenance=state.provenance,
            policy_verdicts=state.policy_verdicts,
            minimal_checks=state.minimal_checks,
        )

    def _drain_paths(
        self,
        request: LiveRequest,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        budget: CallLimits,
        scope: EventScope | None,
    ) -> None:
        while True:
            if self._callbacks.reconsider_paths is not None and budget.can_spend():
                self._callbacks.reconsider_paths(scheduler, state, scope=scope)
            if not budget.can_spend():
                logger.info(
                    "qdl_path_budget_exhausted live_calls=%d max_checks=%s",
                    budget.live_calls,
                    budget.max_checks,
                )
                scheduler.block_remaining()
                self._callbacks.publish_scheduler_terminal_events(
                    scheduler,
                    scope=scope,
                )
                break
            path = scheduler.next_path()
            if path is None:
                break
            if path.path_id in state.replay.evaluated_outcomes:
                if not self._has_finding_examples(path):
                    self._callbacks.skip_evaluated_path(
                        path,
                        scheduler,
                        state,
                        scope=scope,
                    )
                    self._callbacks.publish_scheduler_terminal_events(
                        scheduler,
                        scope=scope,
                    )
                    continue
            self._mark_path_executing(path)
            self._callbacks.execute_path(
                request,
                path,
                scheduler,
                state,
                budget=budget,
                scope=scope,
            )
            self._callbacks.publish_scheduler_terminal_events(
                scheduler,
                scope=scope,
            )

    @staticmethod
    def replay_state(
        events: tuple[DomainEvent, ...],
        *,
        scheduler: CoverageDrivenScheduler,
        scope: EventScope | None,
        blocked_reasons: dict[str, str] | None,
        evidence_store: Store[MeasurementKey] | None,
    ) -> CampaignRoundState:
        """Restore round accumulators from the append-only event stream."""

        replay = RoundReplay.from_events(
            events, scope=scope, remember_evidence=scheduler.state.remember_evidence
        )
        return CampaignRoundState(
            observations=[],
            provenance={},
            policy_verdicts={},
            path_reasons={},
            path_history={},
            minimal_checks={},
            differential_evidence=evidence_store or Store[MeasurementKey](),
            replay=replay,
            blocked_reasons=blocked_reasons,
        )

    def _initialize_intent_states(
        self,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
    ) -> None:
        """Initialize intent states for paths not already terminal."""

        if self._metrics is None:
            return
        for path in scheduler.paths:
            if path.path_id in scheduler.state.superseded:
                continue
            if path.path_id in state.replay.evaluated_outcomes:
                continue
            if self._metrics.intent_state(path.path_id) is not None:
                # The path was already initialized in an earlier round (it
                # may be UNSCOREABLE or BLOCKED there).  Re-arming it to
                # PENDING would be an invalid lifecycle regression; the
                # scheduler keeps it eligible or terminal on its own.
                continue
            self._metrics.set_intent_state(
                path.path_id,
                IntentState.PENDING,
                letter=stride_letter(path),
            )

    def _mark_path_executing(self, path: QdlExecutionPath) -> None:
        """Advance an eligible campaign path into its execution phase."""

        if self._metrics is not None:
            self._metrics.set_intent_state(
                path.path_id,
                IntentState.EXECUTING,
                letter=stride_letter(path),
            )

    def _has_finding_examples(self, path: QdlExecutionPath) -> bool:
        """Return whether this path has a persisted finding to regression-replay."""

        if self._example_database is None:
            return False
        for step in path.steps:
            if load_finding_examples(
                self._example_database,
                method_id=step.method.method_id,
                invariant_id=step.invariant.invariant_id,
                scenario_id=step.scenario.scenario_id,
            ):
                return True
        return False


__all__ = ["RunnerDeps", "Runner"]
