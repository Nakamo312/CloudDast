"""Execution of QDL-derived paths against a live service."""

from __future__ import annotations

import logging
from typing import Callable
from uuid import uuid4

from cloud_dast.api import (
    LiveRequest,
)
from cloud_dast.contracts.execution import ExecutionResult
from cloud_dast.contracts.finding_examples import load_finding_examples
from cloud_dast.model import Observation
from cloud_dast.model.events import (
    DomainEvent,
    EventScope,
)
from cloud_dast.ports import EventPublisher, EventStore
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
from cloud_dast.runtime.execution.assembly import (
    BoundPathRunnerOptions,
    RunnerAssembly,
)
from cloud_dast.runtime.execution.calls import CallRunnerMixin
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionView,
)
from cloud_dast.runtime.execution.paths import PathRunnerMixin
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.metrics import IntentState, stride_letter
from cloud_dast.runtime.planning import QdlPlan
from cloud_dast.runtime.readback_reevaluation import Reevaluation
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict

logger = logging.getLogger("cloud_dast.runtime.execution.runner")

__all__ = ["BoundPathRunner", "BoundPathRunnerOptions"]


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


class BoundPathRunner(
    PathRunnerMixin,
    CallRunnerMixin,
    RunnerAssembly,
):
    """Execute QDL plan views and project observations back into QDL."""

    def __init__(
        self,
        checker: Checker,
        event_bus: EventPublisher,
        event_store: EventStore,
        options: BoundPathRunnerOptions | None = None,
        **legacy_options: object,
    ) -> None:
        settings = BoundPathRunnerOptions.from_legacy(options, legacy_options)
        self._initialize_core(checker, event_bus, event_store, settings)
        self._initialize_candidate_services(settings)
        self._initialize_observation_services(settings)
        self._initialize_round_services()

    @property
    def differential(self) -> ProbeExecutor:
        """Expose the owner of paired and concurrent probe execution."""

        return self._differential

    @property
    def readback_reevaluation(self) -> Reevaluation:
        """Expose reinterpretation of stored readback evidence."""

        return self._readback_reevaluation

    def reevaluate_oob_pending(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, PolicyVerdict]:
        """Return late OOB verdicts for observations timed out earlier."""

        if self._primitive_oracle is None:
            return {}
        return self._primitive_oracle.reevaluate_oob_pending(timeout=timeout)

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
        paths = paths_for_request(view.paths, request.method_id)
        if not paths:
            logger.warning("no_executable_qdl_paths service=%s", request.service)
            return ExecutionResult((), self._checker.checks, {}, {}, {})

        events = self._refresh_event_projection()
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
            self._refresh_event_projection(),
            scope=scope,
            blocked_reasons=blocked_reasons,
            evidence_store=None,
        )
        self._path_terminal.reconsider_paths(scheduler, state, scope=scope)

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

    def _executed_check_identities(self, observation: Observation) -> tuple[str, ...]:
        """Return the identity of the executed check behind one observation."""

        for check in reversed(self._checker.checks):
            if check.check_id == observation.check_id:
                return check.identities
        return ()

    def _publish(
        self,
        event: DomainEvent,
        scope: EventScope | None,
    ) -> None:
        """Publish one event, tagging it with the active campaign scope."""

        self._event_bus.publish(scope.apply(event) if scope is not None else event)

    def _refresh_event_projection(self) -> tuple[DomainEvent, ...]:
        """Extend the runner's projection with newly appended events."""

        new_events = self._events.read_new(self._event_consumer_id)
        self._projected_events.extend(new_events)
        return tuple(self._projected_events)


def paths_for_request(
    paths: tuple[QdlExecutionPath, ...],
    method_id: str | None,
) -> tuple[QdlExecutionPath, ...]:
    """Select paths that exercise the requested method.

    A method anywhere in the chain qualifies: the campaign targets the
    whole execution path through that call, not only paths that end on it.
    """

    if method_id is None:
        return tuple(path for path in paths if path.steps)
    return tuple(
        path
        for path in paths
        if path.steps and any(step.method.method_id == method_id for step in path.steps)
    )
