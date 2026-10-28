"""Terminal decisions and replay-visible events for campaign paths."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from cloud_dast.model import Observation
from cloud_dast.model.events import (
    DomainEvent,
    DownstreamDecision,
    EventScope,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.runtime.candidates.session import _PrefilteredPath
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState, stride_letter
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.execution.terminal")

_GENERIC_STEP_REASONS = frozenset({"QDL step evaluated", "QDL chain step evaluated"})


class PathAttemptView(Protocol):
    """Minimum execution result required by terminal path decisions."""

    path: QdlExecutionPath
    observations: list[Observation]
    effect_verified: bool
    best_proximity: float


@dataclass(slots=True)
class PathAttempt:
    """One scheduler path and the outcome accumulated by its candidates."""

    path: QdlExecutionPath
    observations: list[Observation] = field(default_factory=list)
    effect_verified: bool = False
    best_proximity: float = 0.0
    prefiltered: _PrefilteredPath | None = None


@dataclass(frozen=True, slots=True)
class Callbacks:
    """Runtime capabilities used to materialize terminal path decisions."""

    publish: Callable[[DomainEvent, EventScope | None], None]
    refresh_events: Callable[[], tuple[DomainEvent, ...]]
    path_definitions: Callable[[], Mapping[str, QdlExecutionPath]]
    metrics: CampaignMetrics | None
    evidence_signature: Callable[[QdlExecutionPath], str | None] | None = None


class PathTerminalizer:
    """Own terminal path outcomes, replay restoration, and terminal events."""

    def __init__(self, callbacks: Callbacks) -> None:
        self._callbacks = callbacks

    def reconsider_paths(
        self,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        *,
        scope: EventScope | None,
    ) -> None:
        """Invalidate decisions whose trusted semantic premises have changed."""

        signature = self._callbacks.evidence_signature
        if signature is None:
            return
        for path in scheduler.paths:
            path_id = path.path_id
            previous = state.replay.evaluated_signatures.get(
                path_id, scheduler.state.evidence_signatures.get(path_id)
            )
            if previous is None:
                continue
            if (
                path_id not in state.replay.evaluated_outcomes
                and path_id not in scheduler.state.completed
                and path_id not in scheduler.state.blocked
            ):
                continue
            current = signature(path)
            if current is None or current == previous:
                continue
            if not scheduler.reopen_path(path_id):
                continue
            event = DownstreamDecision(
                component="qdl_path",
                kind="gate",
                path_id=path_id,
                consumed=True,
                by="scheduler",
                outcome="evidence_invalidated",
            )
            self._callbacks.publish(event, scope)
            if self._callbacks.metrics is not None:
                self._callbacks.metrics.invalidate_intent(event)
            state.replay.evaluated_outcomes.pop(path_id, None)
            state.replay.evaluated_signatures.pop(path_id, None)
            scheduler.state.evidence_signatures.pop(path_id, None)
            state.path_reasons.pop(path_id, None)
            if state.blocked_reasons is not None:
                state.blocked_reasons.pop(path_id, None)

    def finish(
        self,
        attempt: PathAttemptView,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        *,
        scope: EventScope | None,
    ) -> None:
        """Record and publish the terminal outcome of one path attempt."""

        path = attempt.path
        signature = (
            self._callbacks.evidence_signature(path)
            if self._callbacks.evidence_signature is not None
            else None
        )
        scheduler.state.evidence_signatures[path.path_id] = signature
        state.replay.evaluated_signatures[path.path_id] = signature
        state.path_history.setdefault(path.path_id, []).extend(attempt.observations)
        previous_outcome = scheduler.state.outcomes.get(path.path_id)
        attempted_observation_ids = {o.observation_id for o in attempt.observations}
        attempted_steps = {
            provenance.step_id
            for (observation_id, _), provenance in state.provenance.items()
            if provenance.path_id == path.path_id
            and observation_id in attempted_observation_ids
        }
        if attempt.effect_verified:
            scheduler.record_outcome(
                path.path_id,
                "completed",
                attempted_steps=attempted_steps,
                reward=max(attempt.best_proximity, 1.0),
            )
            if self._callbacks.metrics is not None:
                self._callbacks.metrics.set_intent_state(
                    path.path_id, IntentState.VERIFIED
                )
        else:
            outcome = scheduler.record_outcome(
                path.path_id,
                "blocked",
                attempted_steps=attempted_steps,
                reward=attempt.best_proximity,
            )
            if outcome == "retryable":
                if self._callbacks.metrics is not None:
                    self._callbacks.metrics.set_intent_state(
                        path.path_id,
                        IntentState.UNSCOREABLE,
                    )
                logger.debug(
                    "qdl_path_retryable path=%s reward=%.3f",
                    path.path_id,
                    attempt.best_proximity,
                )
                return
            if self._callbacks.metrics is not None:
                self._callbacks.metrics.set_intent_state(
                    path.path_id, IntentState.BLOCKED
                )
        self._publish_path_evaluated(
            attempt,
            state,
            previous_outcome=previous_outcome,
            scope=scope,
        )

    def skip_evaluated_path(
        self,
        path: QdlExecutionPath,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        *,
        scope: EventScope | None,
    ) -> None:
        """Make an event-log replay skip visible and outcome-preserving."""

        outcome = state.replay.evaluated_outcomes[path.path_id]
        completed = outcome == "completed"
        if not completed and any(
            step.witness_requirement is not None and not step.plan.probe_fields
            for step in path.steps
        ):
            scheduler.block_prerequisite(path.path_id, "unprovable witness requirement")
        else:
            scheduler.record_outcome(
                path.path_id,
                "completed" if completed else "blocked",
                attempted_steps=(),
            )
        self.restore_intent_state(path, completed=completed)
        self._callbacks.publish(
            QdlPathEvaluated(
                path_id=path.path_id,
                outcome=outcome,
                evidence_signature=state.replay.evaluated_signatures.get(path.path_id),
                previous_outcome=outcome,
                retry_policy="none",
                attempted_steps=0,
                step_count=len(path.steps),
                probe_count=0,
                reason="already evaluated in the event log (cross-campaign replay)",
                action_id=path.steps[-1].method.method_id if path.steps else None,
            ),
            scope,
        )
        logger.debug("qdl_path_already_evaluated path=%s", path.path_id)

    def restore_intent_state(
        self,
        path: QdlExecutionPath,
        *,
        completed: bool,
    ) -> None:
        """Restore one replayed path's terminal intent state idempotently."""

        metrics = self._callbacks.metrics
        if metrics is None:
            return
        target = IntentState.VERIFIED if completed else IntentState.BLOCKED
        current = metrics.intent_state(path.path_id)
        if current is target:
            return
        letter = stride_letter(path)
        if current is None:
            metrics.set_intent_state(path.path_id, IntentState.PENDING, letter=letter)
        if completed and current in {
            None,
            IntentState.PENDING,
            IntentState.UNSCOREABLE,
        }:
            metrics.set_intent_state(path.path_id, IntentState.EXECUTING, letter=letter)
        metrics.set_intent_state(path.path_id, target, letter=letter)

    def publish_missing_terminal_path_events(
        self,
        scope: EventScope | None = None,
    ) -> None:
        """Close step-event paths left open when the campaign budget runs out."""

        events = self._callbacks.refresh_events()
        if scope is not None:
            events = scope.run_events(events)
        step_events: dict[str, list[QdlStepEvaluated]] = defaultdict(list)
        terminal_path_ids: set[str] = set()
        for event in events:
            if isinstance(event, QdlStepEvaluated):
                step_events[event.path_id].append(event)
            elif isinstance(event, QdlPathEvaluated):
                terminal_path_ids.add(event.path_id)

        for path_id, path_events in sorted(step_events.items()):
            if path_id in terminal_path_ids:
                continue
            path = self._callbacks.path_definitions().get(path_id)
            step_count = (
                len(path.steps)
                if path is not None
                else max(event.step_index + 1 for event in path_events)
            )
            last_reason = next(
                (
                    event.reason
                    for event in reversed(path_events)
                    if _specific_reason(event.reason)
                ),
                "",
            )
            reason = _specific_reason(last_reason) or (
                "campaign check budget exhausted during path execution"
            )
            last_event = path_events[-1]
            path_action = (
                path.steps[-1].method.method_id if path and path.steps else None
            )
            self._callbacks.publish(
                QdlPathEvaluated(
                    path_id=path_id,
                    outcome="blocked",
                    attempted_steps=len({event.step_id for event in path_events}),
                    step_count=step_count,
                    probe_count=len(path_events),
                    reason=reason,
                    correlation_id=next(
                        (
                            event.correlation_id
                            for event in reversed(path_events)
                            if event.correlation_id is not None
                        ),
                        None,
                    ),
                    action_id=path_action,
                    step_id=last_event.step_id,
                    check_id=last_event.check_id,
                    observation_id=last_event.observation_id,
                ),
                scope,
            )

    def publish_scheduler_terminal_events(
        self,
        scheduler: CoverageDrivenScheduler,
        *,
        scope: EventScope | None,
    ) -> None:
        """Persist scheduler-side terminal outcomes for deterministic replay."""

        events = self._callbacks.refresh_events()
        selected = scope.run_events(events) if scope is not None else events
        terminal_ids = {
            event.path_id for event in selected if isinstance(event, QdlPathEvaluated)
        }
        step_event_path_ids = {
            event.path_id for event in selected if isinstance(event, QdlStepEvaluated)
        }
        paths_by_id = {path.path_id: path for path in scheduler.paths}
        for path_id, outcome in sorted(scheduler.state.outcomes.items()):
            if (
                outcome not in {"completed", "blocked"}
                or path_id in terminal_ids
                or (
                    scheduler.state.attempts.get(path_id, 0) > 0
                    and scheduler.terminal_reason(path_id) is None
                )
                or (
                    path_id in step_event_path_ids
                    and scheduler.terminal_reason(path_id)
                    == "campaign check budget exhausted before path execution"
                )
            ):
                continue
            path = paths_by_id.get(path_id)
            if path is None:
                continue
            self._callbacks.publish(
                QdlPathEvaluated(
                    path_id=path_id,
                    outcome="completed" if outcome == "completed" else "blocked",
                    step_count=len(path.steps),
                    attempted_steps=0,
                    probe_count=0,
                    reason=(
                        scheduler.terminal_reason(path_id)
                        or "scheduler recorded a terminal path outcome"
                    ),
                    action_id=path.steps[-1].method.method_id if path.steps else None,
                ),
                scope,
            )

    def _publish_path_evaluated(
        self,
        attempt: PathAttemptView,
        state: CampaignRoundState,
        *,
        previous_outcome: str | None,
        scope: EventScope | None,
    ) -> None:
        """Publish the terminal event for a non-retryable path outcome."""

        path = attempt.path
        history = state.path_history.get(path.path_id, [])
        last_observation = history[-1] if history else None
        last_provenance = next(
            (
                provenance
                for (observation_id, _), provenance in state.provenance.items()
                if last_observation is not None
                and observation_id == last_observation.observation_id
                and provenance.path_id == path.path_id
            ),
            None,
        )
        last_step = next(
            (
                step
                for step in path.steps
                if last_provenance is not None
                and step.step_id == last_provenance.step_id
            ),
            None,
        )
        self._callbacks.publish(
            QdlPathEvaluated(
                path_id=path.path_id,
                outcome="completed" if attempt.effect_verified else "blocked",
                evidence_signature=state.replay.evaluated_signatures.get(path.path_id),
                previous_outcome=previous_outcome,
                retry_policy="none" if attempt.effect_verified else "bounded",
                attempted_steps=len(
                    {
                        provenance.step_id
                        for provenance in state.provenance.values()
                        if provenance.path_id == path.path_id
                    }
                ),
                step_count=len(path.steps),
                probe_count=len(history),
                reason=(
                    _specific_reason(state.path_reasons.get(path.path_id, ""))
                    or (
                        "QDL effect chain verified"
                        if attempt.effect_verified
                        else "QDL effect chain was not verified"
                    )
                ),
                correlation_id=last_observation.check_id if last_observation else None,
                action_id=last_step.method.method_id if last_step else None,
                step_id=last_provenance.step_id if last_provenance else None,
                check_id=last_observation.check_id if last_observation else None,
                observation_id=(
                    last_observation.observation_id if last_observation else None
                ),
            ),
            scope,
        )


def _specific_reason(reason: str) -> str:
    """Return a useful reason instead of a generic step placeholder."""

    return reason if reason and reason not in _GENERIC_STEP_REASONS else ""
