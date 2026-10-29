"""Campaign metrics: intent lifecycle, token usage, and campaign timing.

Reward machine states (DRLRM-PT): each intent has a lifecycle from creation
to terminal outcome.  Token usage (PrediQL): the campaign must be transparent
about LLM cost.  Both feed the progress dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from threading import RLock

from cloud_dast.contracts.metrics import (
    CampaignMetricsSnapshot,
    TokenUsageSnapshot,
    measure_campaign_timing,
    measure_component_activity,
)
from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import (
    ComponentLifecycleEvent,
    DownstreamDecision,
    PhaseChanged,
)
from cloud_dast.verification.taxonomy import DEFAULT_CATALOG


def stride_letter(path: QdlExecutionPath) -> str:
    """Project the bound QDL norm into the metrics taxonomy label."""

    invariant = path.steps[0].invariant if path.steps else None
    if invariant is None:
        return "unknown"
    classification = DEFAULT_CATALOG.classify_finding(invariant)
    return ",".join(classification.stride) or "unknown"


class IntentState(StrEnum):
    """RunCoordinator state of one verification intent (reward machine).

    See ``INTENT_TRANSITIONS`` for the explicit lifecycle table.  Invalid
    transitions are rejected rather than silently overwritten.
    """

    PENDING = "pending"
    READY = "ready"
    EXECUTING = "executing"
    OBSERVED = "observed"
    VERIFIED = "verified"
    UNSCOREABLE = "unscoreable"
    BLOCKED = "blocked"

    @property
    def is_terminal(self) -> bool:
        return self in {IntentState.VERIFIED, IntentState.BLOCKED}


INTENT_TRANSITIONS: dict[IntentState, frozenset[IntentState]] = {
    IntentState.PENDING: frozenset(
        {IntentState.READY, IntentState.EXECUTING, IntentState.BLOCKED}
    ),
    IntentState.READY: frozenset({IntentState.EXECUTING, IntentState.BLOCKED}),
    IntentState.EXECUTING: frozenset(
        {
            IntentState.OBSERVED,
            IntentState.VERIFIED,
            IntentState.UNSCOREABLE,
            IntentState.BLOCKED,
        }
    ),
    IntentState.OBSERVED: frozenset(
        {IntentState.VERIFIED, IntentState.UNSCOREABLE, IntentState.BLOCKED}
    ),
    IntentState.UNSCOREABLE: frozenset({IntentState.EXECUTING, IntentState.BLOCKED}),
    IntentState.VERIFIED: frozenset(),
    IntentState.BLOCKED: frozenset(),
}


@dataclass(slots=True)
class TokenUsage:
    """LLM token consumption for one request or aggregate."""

    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    request_count: int = 0

    def add(self, other: TokenUsage) -> None:
        self.input_tokens += other.input_tokens
        self.cached_input_tokens += other.cached_input_tokens
        self.output_tokens += other.output_tokens
        self.request_count += other.request_count

    def snapshot(self) -> TokenUsageSnapshot:
        return TokenUsageSnapshot(
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.request_count,
        )


@dataclass(slots=True)
class CampaignMetrics:
    """Thread-safe runtime campaign metrics.

    Tracks four dimensions:
    - Intent lifecycle: how many intents are in each reward machine state.
    - Token usage: LLM cost broken down by phase.
    - Generator performance: outcomes per strategy per action.
    - Campaign timing: wall time and elapsed time per campaign phase.

    The object belongs to runtime and may be updated by grounding
    workers.  Presentation code must consume :meth:`snapshot`, never mutable
    runtime state. Mutation goes through the record methods; all aggregate
    reads use the immutable snapshot.
    """

    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    # Intent states (reward machine).
    _intent_states: dict[str, IntentState] = field(
        default_factory=dict, init=False, repr=False
    )
    _intent_labels: dict[str, str] = field(  # id → letter
        default_factory=dict, init=False, repr=False
    )

    # Token usage.
    _tokens: TokenUsage = field(default_factory=TokenUsage, init=False, repr=False)
    _tokens_by_phase: dict[str, TokenUsage] = field(
        default_factory=dict, init=False, repr=False
    )
    _model_id: str = field(default="", init=False, repr=False)

    # Generator performance: (action_id, strategy) → outcome counts.
    _generator_stats: dict[tuple[str, str], dict[str, int]] = field(
        default_factory=dict, init=False, repr=False
    )

    # Live activity: what is happening RIGHT NOW (updated by workers).
    _current_activity: str = field(default="", init=False, repr=False)
    _model_requests_active: int = field(default=0, init=False, repr=False)
    _model_requests_completed: int = field(default=0, init=False, repr=False)

    # Totals.
    _total_checks: int = field(default=0, init=False, repr=False)
    _total_findings: int = field(default=0, init=False, repr=False)
    _grounding_cache_hits: int = field(default=0, init=False, repr=False)
    _grounding_cache_misses: int = field(default=0, init=False, repr=False)

    # Differential discovery: measured control/treatment pairs and the
    # norms their variance produced.
    _diff_pairs_evaluated: int = field(default=0, init=False, repr=False)
    _diff_pairs_by_mode: dict[str, int] = field(
        default_factory=dict, init=False, repr=False
    )
    _diff_norms_promoted: int = field(default=0, init=False, repr=False)

    # Campaign timing: phase events are replayed into an immutable snapshot.
    _phase_events: list[PhaseChanged] = field(
        default_factory=list, init=False, repr=False
    )

    # Component lifecycle telemetry projected into the reporting snapshot.
    _component_events: list[ComponentLifecycleEvent] = field(
        default_factory=list, init=False, repr=False
    )

    # ------------------------------------------------------------------
    # Intent lifecycle
    # ------------------------------------------------------------------

    def set_intent_state(
        self,
        intent_id: str,
        state: IntentState,
        *,
        letter: str = "",
    ) -> None:
        with self._lock:
            current = self._intent_states.get(intent_id)
            if current is None and state is not IntentState.PENDING:
                raise ValueError("intent lifecycle must start at PENDING")
            if current is IntentState.PENDING and state is IntentState.PENDING:
                # PathRunner re-initializes every currently eligible path at
                # the start of a campaign round.  Re-registering an already
                # pending intent is idempotent; it is not a lifecycle
                # regression.
                if letter:
                    self._intent_labels[intent_id] = letter
                return
            if current is not None and state not in INTENT_TRANSITIONS[current]:
                raise ValueError(
                    "invalid intent transition: "
                    f"{current.value} -> {state.value} for {intent_id}"
                )
            self._intent_states[intent_id] = state
            if letter:
                self._intent_labels[intent_id] = letter

    def invalidate_intent(self, event: DownstreamDecision) -> None:
        """Reopen a terminal intent only for an explicit evidence invalidation."""

        if (
            event.component != "qdl_path"
            or event.by != "scheduler"
            or event.outcome != "evidence_invalidated"
            or not event.consumed
            or event.path_id is None
        ):
            raise ValueError("intent invalidation requires changed path evidence")
        with self._lock:
            current = self._intent_states.get(event.path_id)
            if current is None or current.is_terminal:
                self._intent_states[event.path_id] = IntentState.PENDING

    def intent_state(self, intent_id: str) -> IntentState | None:
        """Return one intent state without exposing mutable runtime state."""

        with self._lock:
            return self._intent_states.get(intent_id)

    def snapshot(self) -> CampaignMetricsSnapshot:
        """Build an immutable presentation snapshot under one lock."""

        with self._lock:
            return CampaignMetricsSnapshot(
                intent_states={
                    intent_id: state.value
                    for intent_id, state in self._intent_states.items()
                },
                intent_labels=dict(self._intent_labels),
                tokens=self._tokens.snapshot(),
                tokens_by_phase={
                    phase: usage.snapshot()
                    for phase, usage in self._tokens_by_phase.items()
                },
                model_id=self._model_id,
                generator_stats={
                    key: dict(outcomes)
                    for key, outcomes in self._generator_stats.items()
                },
                current_activity=self._current_activity,
                model_requests_active=self._model_requests_active,
                model_requests_completed=self._model_requests_completed,
                total_checks=self._total_checks,
                total_findings=self._total_findings,
                grounding_cache_hits=self._grounding_cache_hits,
                grounding_cache_misses=self._grounding_cache_misses,
                diff_pairs_evaluated=self._diff_pairs_evaluated,
                diff_pairs_by_mode=dict(self._diff_pairs_by_mode),
                diff_norms_promoted=self._diff_norms_promoted,
                component_activity=measure_component_activity(self._component_events),
                timing=measure_campaign_timing(self._phase_events),
            )

    # ------------------------------------------------------------------
    # Token tracking
    # ------------------------------------------------------------------

    def record_tokens(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int = 0,
        *,
        phase: str = "default",
    ) -> None:
        with self._lock:
            usage = TokenUsage(
                input_tokens,
                cached_input_tokens,
                output_tokens,
                1,
            )
            self._tokens.add(usage)
            phase_usage = self._tokens_by_phase.setdefault(phase, TokenUsage())
            phase_usage.add(usage)

    def set_model_id(self, model_id: str) -> None:
        """Record the model used by the semantic compiler.

        The value is presentation metadata; it never participates in verdicts.
        """

        with self._lock:
            self._model_id = model_id

    def record_grounding_cache_hit(self, axis: str) -> None:
        with self._lock:
            self._grounding_cache_hits += 1

    def record_grounding_cache_miss(self, axis: str) -> None:
        with self._lock:
            self._grounding_cache_misses += 1

    # ------------------------------------------------------------------
    # Generator performance
    # ------------------------------------------------------------------

    def record_generator_outcome(
        self,
        action_id: str,
        strategy: str,
        verdict: VerdictStatus,
    ) -> None:
        with self._lock:
            key = (action_id, strategy)
            stats = self._generator_stats.setdefault(
                key, {"pass": 0, "fail": 0, "unscoreable": 0, "error": 0}
            )
            verdict_key = verdict.value if hasattr(verdict, "value") else str(verdict)
            if verdict_key not in stats:
                verdict_key = "unscoreable"
            stats[verdict_key] += 1
            self._total_checks += 1

    def record_finding(self) -> None:
        with self._lock:
            self._total_findings += 1

    # ------------------------------------------------------------------
    # Differential discovery
    # ------------------------------------------------------------------

    def record_diff_pair(self, mode: str = "factors") -> None:
        """Count one executed control/treatment pair, by discovery mode."""

        with self._lock:
            self._diff_pairs_evaluated += 1
            self._diff_pairs_by_mode[mode] = self._diff_pairs_by_mode.get(mode, 0) + 1

    def record_diff_norm_promoted(self, count: int = 1) -> None:
        """Count norms promoted from measured behavior variance."""

        if count < 0:
            raise ValueError("count must not be negative")
        with self._lock:
            self._diff_norms_promoted += count

    def record_phase(self, event: PhaseChanged) -> None:
        """Record one campaign phase transition for timing reports."""

        with self._lock:
            self._phase_events.append(event)

    def record_component_event(self, event: ComponentLifecycleEvent) -> None:
        """Record one component lifecycle event for activity reports."""

        with self._lock:
            self._component_events.append(event)

    # ------------------------------------------------------------------
    # Live activity tracking
    # ------------------------------------------------------------------

    def set_activity(self, description: str) -> None:
        """Update what the campaign is doing right now."""
        with self._lock:
            self._current_activity = description

    def model_request_started(self, description: str = "") -> None:
        with self._lock:
            self._model_requests_active += 1
            if description:
                self._current_activity = description

    def model_request_finished(self) -> None:

        with self._lock:
            self._model_requests_active = max(0, self._model_requests_active - 1)
            self._model_requests_completed += 1
            if self._model_requests_active == 0:
                self._current_activity = ""
