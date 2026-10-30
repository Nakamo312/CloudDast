"""Execution of QDL-derived paths against a live service."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable
from uuid import uuid4

from cloud_dast.contracts.execution import ExecutionResult, LiveRequest
from cloud_dast.contracts.plan import QdlExecutionView
from cloud_dast.model.events import (
    DomainEvent,
    EventScope,
)
from cloud_dast.ports import EventPublisher, EventStore
from cloud_dast.qdl.reasoning import QdlPlan
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.round import Runner
from cloud_dast.runtime.deficits import (
    Deficit,
)
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.terminal import PathTerminalizer
from cloud_dast.runtime.readback_reevaluation import Reevaluation
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.execution.runner")

__all__ = ["BoundPathRunner"]


def build_event_scope(
    request: LiveRequest,
    graph_hash: str,
    *,
    baseline_event_ids: frozenset[str] = frozenset(),
) -> EventScope:
    """Build the stable campaign and unique run identity for one execution."""

    return EventScope(
        campaign_id=(
            f"campaign:{request.service}:{request.principal_id}:"
            f"{request.resource_id}:{request.method_id or 'all'}:{graph_hash}"
        ),
        run_id=f"run:{uuid4().hex}",
        baseline_event_ids=baseline_event_ids,
    )


@dataclass(eq=False, slots=True)
class EventProjection:
    """Retain run-local history and publish scoped execution events.

    The campaign owner serializes refresh calls. Worker threads may publish
    through the event bus; this projection is not a concurrent-reader API.
    """

    publisher: EventPublisher
    store: EventStore
    _consumer: str = field(
        default_factory=lambda: f"path-runner:{uuid4().hex}", init=False
    )
    _events: list[DomainEvent] = field(default_factory=list, init=False)

    def publish(
        self,
        event: DomainEvent,
        scope: EventScope | None,
    ) -> None:
        """Publish one event, tagging it with the active campaign scope."""

        self.publisher.publish(scope.apply(event) if scope is not None else event)

    def refresh(self) -> tuple[DomainEvent, ...]:
        """Extend the runner's projection with newly appended events."""

        new_events = self.store.read_new(self._consumer)
        self._events.extend(new_events)
        return tuple(self._events)


@dataclass(eq=False)
class BoundPathRunner:
    """Execute QDL plan views using one assembled run-scoped dependency graph."""

    _checker: Checker
    _projection: EventProjection
    _path_terminal: PathTerminalizer
    _campaign_round: Runner
    differential: ProbeExecutor
    readback_reevaluation: Reevaluation

    def execute_plan(
        self,
        request: LiveRequest,
        plan: QdlPlan,
        view: QdlExecutionView,
    ) -> ExecutionResult:
        """Execute one QDL plan through its runtime execution view."""

        if plan.graph_hash != view.graph_hash:
            raise ValueError("QDL execution view does not match the supplied plan")

        self._checker.reset_checks()
        paths = view.select(request.method_id)
        if not paths:
            logger.warning("no_executable_qdl_paths service=%s", request.service)
            return ExecutionResult((), self._checker.checks, {}, {})

        events = self._projection.refresh()
        baseline_event_ids = frozenset(event.event_id for event in events)
        return self.execute_round(
            request,
            CoverageDrivenScheduler(paths),
            scope=build_event_scope(
                request,
                plan.graph_hash,
                baseline_event_ids=baseline_event_ids,
            ),
        )

    def execute_round(
        self,
        request: LiveRequest,
        scheduler: CoverageDrivenScheduler,
        *,
        budget: CallLimits | None = None,
        scope: EventScope | None = None,
        deficit_sink: Callable[[Deficit], object] | None = None,
        blocked_reasons: dict[str, str] | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> ExecutionResult:
        """Delegate campaign sequencing to the campaign round owner."""

        return self._campaign_round.run(
            request,
            scheduler,
            budget=budget,
            scope=scope,
            deficit_sink=deficit_sink,
            blocked_reasons=blocked_reasons,
            evidence_store=evidence_store,
        )

    def reconsider_paths(
        self,
        scheduler: CoverageDrivenScheduler,
        *,
        scope: EventScope | None = None,
        blocked_reasons: dict[str, str] | None = None,
    ) -> None:
        """Recheck terminal goals before the live campaign declares quiescence."""

        state = Runner.replay_state(
            self._projection.refresh(),
            scheduler=scheduler,
            scope=scope,
            blocked_reasons=blocked_reasons,
            evidence_store=None,
        )
        self._path_terminal.reconsider_paths(scheduler, state, scope=scope)
