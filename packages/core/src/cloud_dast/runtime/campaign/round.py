"""Sequence one campaign round around path execution."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cloud_dast.api import LiveRequest
from cloud_dast.contracts.execution import (
    ExecutionResult,
)
from cloud_dast.model import Check
from cloud_dast.model.events import DomainEvent, EventScope
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.replay import RoundReplay
from cloud_dast.runtime.deficits import Deficit
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.campaign.round")


@dataclass(frozen=True, slots=True)
class RunnerDeps:
    """Path-runner capabilities used by campaign sequencing."""

    reset_checks: Callable[[], None]
    refresh_events: Callable[[], tuple[DomainEvent, ...]]
    register_paths: Callable[[tuple[QdlExecutionPath, ...]], None]
    initialize_intents: Callable[[CoverageDrivenScheduler, CampaignRoundState], None]
    mark_executing: Callable[[QdlExecutionPath], None]
    has_finding_examples: Callable[[QdlExecutionPath], bool]
    skip_evaluated_path: Callable[..., None]
    execute_path: Callable[..., bool]
    publish_scheduler_terminal_events: Callable[..., None]
    publish_missing_terminal_path_events: Callable[[EventScope | None], None]
    service_checks: Callable[[], tuple[Check, ...]]
    evidence_signature: Callable[[QdlExecutionPath], str | None] | None = None
    reconsider_paths: Callable[..., None] | None = None


class Runner:
    """Own budgeted round sequencing while delegating one-path execution."""

    def __init__(self, callbacks: RunnerDeps) -> None:
        self._callbacks = callbacks

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
            scope=scope,
            blocked_reasons=blocked_reasons,
            evidence_store=evidence_store,
        )
        state.deficit_sink = deficit_sink
        self._callbacks.register_paths(scheduler.paths)
        self._callbacks.initialize_intents(scheduler, state)

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
            traces=state.traces,
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
                if not self._callbacks.has_finding_examples(path):
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
            self._callbacks.mark_executing(path)
            executed = self._callbacks.execute_path(
                request,
                path,
                scheduler,
                state,
                budget=budget,
                scope=scope,
            )
            # Prerequisite/symbolic exits can terminate before PathTerminalizer.finish.
            if (
                self._callbacks.evidence_signature is not None
                and path.path_id not in state.replay.evaluated_signatures
                and scheduler.state.outcomes.get(path.path_id)
                in {"completed", "blocked"}
            ):
                signature = self._callbacks.evidence_signature(path)
                state.replay.evaluated_signatures[path.path_id] = signature
                scheduler.state.evidence_signatures[path.path_id] = signature
            if not executed:
                self._callbacks.publish_scheduler_terminal_events(
                    scheduler,
                    scope=scope,
                )
                continue
            self._callbacks.publish_scheduler_terminal_events(
                scheduler,
                scope=scope,
            )

    @staticmethod
    def replay_state(
        events: tuple[DomainEvent, ...],
        *,
        scope: EventScope | None,
        blocked_reasons: dict[str, str] | None,
        evidence_store: Store[MeasurementKey] | None,
    ) -> CampaignRoundState:
        """Restore round accumulators from the append-only event stream."""

        replay = RoundReplay.from_events(events, scope=scope)
        return CampaignRoundState(
            observations=[],
            traces={},
            provenance={},
            policy_verdicts={},
            path_reasons={},
            path_history={},
            minimal_checks={},
            differential_evidence=(evidence_store or Store[MeasurementKey]()),
            replay=replay,
            blocked_reasons=blocked_reasons,
        )


__all__ = ["RunnerDeps", "Runner"]
