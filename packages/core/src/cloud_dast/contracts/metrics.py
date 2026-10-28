"""Immutable runtime metric snapshots and activity projections."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType
from typing import Protocol

from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentKind,
    ComponentLifecycleEvent,
    ComponentOutput,
    ComponentSkipped,
    DomainEvent,
    DownstreamDecision,
    PhaseChanged,
    measure_event_time_bounds,
)

DEFAULT_PROMOTION_CONVERSION_ZERO_CONSULTATIONS = 3


@dataclass(frozen=True, slots=True)
class CampaignTimingSnapshot:
    """Immutable campaign wall-time and per-phase elapsed read model."""

    wall_time: timedelta = timedelta()
    phase_elapsed: Mapping[str, timedelta] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "phase_elapsed",
            MappingProxyType(dict(self.phase_elapsed)),
        )


def measure_campaign_timing(
    events: Iterable[DomainEvent],
) -> CampaignTimingSnapshot:
    """Aggregate campaign wall time and phase elapsed from event timestamps."""

    unique_events = {event.event_id: event for event in events}.values()
    bounds = measure_event_time_bounds(unique_events)
    if bounds is None:
        return CampaignTimingSnapshot()
    started_at, latest_at = bounds

    phase_events = sorted(
        (event for event in unique_events if isinstance(event, PhaseChanged)),
        key=lambda event: event.occurred_at,
    )
    finished_indices = [
        index for index, event in enumerate(phase_events) if event.phase == "finished"
    ]
    if finished_indices:
        terminal_index = min(finished_indices)
        phase_events = phase_events[: terminal_index + 1]
        ended_at = phase_events[terminal_index].occurred_at
    else:
        ended_at = latest_at

    phase_elapsed: dict[str, timedelta] = {}
    for index, event in enumerate(phase_events):
        if event.phase == "finished":
            phase_end = event.occurred_at
        elif index + 1 < len(phase_events):
            phase_end = phase_events[index + 1].occurred_at
        else:
            phase_end = ended_at
        elapsed = max(timedelta(), phase_end - event.occurred_at)
        phase_elapsed[event.phase] = (
            phase_elapsed.get(event.phase, timedelta()) + elapsed
        )

    return CampaignTimingSnapshot(
        wall_time=ended_at - started_at,
        phase_elapsed=phase_elapsed,
    )


@dataclass(frozen=True, slots=True)
class TokenUsageSnapshot:
    """Immutable LLM token usage for presentation and reports."""

    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    request_count: int = 0

    def __post_init__(self) -> None:
        values = (
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.request_count,
        )
        if any(value < 0 for value in values):
            raise ValueError("token usage must not be negative")
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens must not exceed input tokens")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def uncached_input_tokens(self) -> int:
        return max(0, self.input_tokens - self.cached_input_tokens)

    @property
    def cache_hit_rate(self) -> float:
        if self.input_tokens == 0:
            return 0.0
        return self.cached_input_tokens / self.input_tokens


@dataclass(frozen=True, slots=True)
class ActivityCorrelation:
    """One component invocation joined to the existing execution chain."""

    invocation_id: str
    check_id: str | None
    observation_id: str | None
    path_id: str | None

    @property
    def is_complete(self) -> bool:
        return all(
            (
                self.check_id,
                self.observation_id,
                self.path_id,
            )
        )


@dataclass(frozen=True, slots=True)
class ActivationChainReport:
    """Activation result for one correlated component invocation chain."""

    invocation_id: str
    failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActivityReport:
    """Immutable component lifecycle read model for one campaign."""

    component: str
    kind: ComponentKind = "producer"
    invocations: int = 0
    skipped: int = 0
    skip_reasons: Mapping[str, int] = field(default_factory=dict)
    input_digests: frozenset[str] = frozenset()
    input_completeness: Mapping[str, int] = field(default_factory=dict)
    fallback_modes: Mapping[str, int] = field(default_factory=dict)
    inputs_empty: int = 0
    inputs_non_empty: int = 0
    candidates_produced: int = 0
    candidates_survived_prefilter: int = 0
    candidates_survived_guardrail: int = 0
    proposals: int = 0
    parked: int = 0
    promoted: int = 0
    promoted_facts: int = 0
    scored: int = 0
    witnesses: int = 0
    output_counts: Mapping[str, int] = field(default_factory=dict)
    downstream_consumed: int = 0
    downstream_rejected: int = 0
    downstream_by: Mapping[str, int] = field(default_factory=dict)
    downstream_outcomes: Mapping[str, int] = field(default_factory=dict)
    correlations: tuple[ActivityCorrelation, ...] = ()
    activation_chains: tuple[ActivationChainReport, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "skip_reasons",
            "input_completeness",
            "fallback_modes",
            "output_counts",
            "downstream_by",
            "downstream_outcomes",
        ):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))

    @property
    def activation_failures(self) -> tuple[str, ...]:
        """Return every unmet positive-control condition for an ON component.

        Activation is kind-parametric.  A producer must push non-empty
        input through candidates, filters, scoring, and downstream
        consumption.  A gate must receive non-empty input and render at
        least one admission decision; rejection is a successful gate
        output, not inactivity.
        """

        if self.activation_chains:
            if any(not chain.failures for chain in self.activation_chains):
                return ()
            # Report the most complete chain, rather than unioning unrelated
            # deficits from several invocations into a fictitious proof.
            return min(
                (chain.failures for chain in self.activation_chains),
                key=lambda failures: (len(failures), failures),
            )
        return _activation_failures(
            kind=self.kind,
            invocations=self.invocations,
            inputs_non_empty=self.inputs_non_empty,
            candidates_produced=self.candidates_produced,
            candidates_survived_prefilter=self.candidates_survived_prefilter,
            candidates_survived_guardrail=self.candidates_survived_guardrail,
            scored=self.scored,
            downstream_consumed=self.downstream_consumed,
            decisions=self.downstream_consumed + self.downstream_rejected,
        )

    @property
    def activation_proven(self) -> bool:
        return not self.activation_failures

    @property
    def promotion_conversion(self) -> float:
        """Return promoted proposals divided by non-empty proposals."""

        if self.proposals == 0:
            return 0.0
        return self.promoted / self.proposals

    def summary(self) -> dict[str, object]:
        """Return the stable component-activity summary shape."""

        return {
            "kind": self.kind,
            "invocations": self.invocations,
            "skipped": self.skipped,
            "skip_reasons": dict(self.skip_reasons),
            "unique_inputs": len(self.input_digests),
            "input_completeness": dict(self.input_completeness),
            "fallback_modes": dict(self.fallback_modes),
            "inputs_empty": self.inputs_empty,
            "inputs_non_empty": self.inputs_non_empty,
            "candidates_produced": self.candidates_produced,
            "candidates_survived_prefilter": self.candidates_survived_prefilter,
            "candidates_survived_guardrail": self.candidates_survived_guardrail,
            "proposals": self.proposals,
            "parked": self.parked,
            "promoted": self.promoted,
            "promoted_facts": self.promoted_facts,
            "promotion_conversion": self.promotion_conversion,
            "scored": self.scored,
            "witnesses": self.witnesses,
            "output_counts": dict(self.output_counts),
            "downstream": {
                "consumed": self.downstream_consumed,
                "rejected": self.downstream_rejected,
                "by": dict(self.downstream_by),
                "outcomes": dict(self.downstream_outcomes),
            },
            "activation": {
                "proven": self.activation_proven,
                "failures": list(self.activation_failures),
            },
            "correlations": {
                "invocations": len(self.correlations),
                "checks": len(
                    {correlation.check_id for correlation in self.correlations}
                ),
                "observations": len(
                    {correlation.observation_id for correlation in self.correlations}
                ),
                "paths": len(
                    {correlation.path_id for correlation in self.correlations}
                ),
                "complete": sum(
                    correlation.is_complete for correlation in self.correlations
                ),
            },
        }


@dataclass(slots=True)
class _ActivityAccumulator:
    """Mutable builder used only while projecting an event stream."""

    component: str
    kind: ComponentKind = "producer"
    invocations: int = 0
    skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    input_digests: set[str] = field(default_factory=set)
    input_completeness: dict[str, int] = field(default_factory=dict)
    fallback_modes: dict[str, int] = field(default_factory=dict)
    inputs_empty: int = 0
    inputs_non_empty: int = 0
    candidates_produced: int = 0
    candidates_survived_prefilter: int = 0
    candidates_survived_guardrail: int = 0
    proposals: int = 0
    parked_from_outputs: int = 0
    parked_from_decisions: int = 0
    promoted_from_outputs: int = 0
    promoted_from_decisions: int = 0
    promoted_facts: int = 0
    scored: int = 0
    witnesses: int = 0
    output_counts: dict[str, int] = field(default_factory=dict)
    downstream_consumed: int = 0
    downstream_rejected: int = 0
    downstream_by: dict[str, int] = field(default_factory=dict)
    downstream_outcomes: dict[str, int] = field(default_factory=dict)
    correlations: set[ActivityCorrelation] = field(default_factory=set)
    activation_chains: dict[str, "_ActivationChainAccumulator"] = field(
        default_factory=dict
    )

    def chain_for(
        self, event: ComponentLifecycleEvent
    ) -> "_ActivationChainAccumulator":
        """Return the chain keyed by the strongest available correlation.

        ``invocation_id`` is the normal key.  The correlation fallback keeps
        older telemetry useful while still preventing two explicitly named
        invocations from being joined by component-level totals.  Check,
        observation, and path identifiers are the last scoped fallback for
        event producers that predate invocation IDs.
        """

        key = event.invocation_id or event.correlation_id
        if not key:
            for field_name in ("check_id", "observation_id", "path_id"):
                scoped_id = getattr(event, field_name, None)
                if scoped_id:
                    key = f"{field_name}:{scoped_id}"
                    break
        key = key or "legacy"
        return self.activation_chains.setdefault(
            key,
            _ActivationChainAccumulator(invocation_id=key),
        )

    def record_input(self, event: ComponentInvoked | ComponentSkipped) -> None:
        if event.input_digest:
            self.input_digests.add(event.input_digest)
        for name, count in event.input_completeness.items():
            self.input_completeness[name] = max(
                self.input_completeness.get(name, 0),
                count,
            )
        for mode in event.fallback_modes:
            self.fallback_modes[mode] = self.fallback_modes.get(mode, 0) + 1

    def report(self) -> ActivityReport:
        promoted = (
            self.promoted_from_outputs
            if self.promoted_from_outputs
            else self.promoted_from_decisions
        )
        activation_chains = [
            ActivationChainReport(
                invocation_id=chain.invocation_id,
                failures=chain.failures(kind=self.kind),
            )
            for chain in self.activation_chains.values()
        ]
        # Pre-correlation telemetry had no invocation IDs.  Keep its legacy
        # aggregate usable, but do not use it to join explicitly correlated
        # output/decision events from different invocation IDs.
        legacy = self.activation_chains.get("legacy")
        if legacy is not None and legacy.invoked == 0 and self.invocations:
            legacy.invoked = self.invocations
            legacy.input_non_empty = self.inputs_non_empty
            activation_chains = [
                ActivationChainReport(
                    invocation_id=chain.invocation_id,
                    failures=chain.failures(kind=self.kind),
                )
                for chain in self.activation_chains.values()
            ]
        activation_chains.sort(key=lambda chain: chain.invocation_id)
        return ActivityReport(
            component=self.component,
            kind=self.kind,
            invocations=self.invocations,
            skipped=self.skipped,
            skip_reasons=dict(self.skip_reasons),
            input_digests=frozenset(self.input_digests),
            input_completeness=dict(self.input_completeness),
            fallback_modes=dict(self.fallback_modes),
            inputs_empty=self.inputs_empty,
            inputs_non_empty=self.inputs_non_empty,
            candidates_produced=self.candidates_produced,
            candidates_survived_prefilter=self.candidates_survived_prefilter,
            candidates_survived_guardrail=self.candidates_survived_guardrail,
            proposals=self.proposals,
            parked=(
                self.parked_from_outputs
                if self.parked_from_outputs
                else self.parked_from_decisions
            ),
            promoted=promoted,
            promoted_facts=self.promoted_facts,
            scored=self.scored,
            witnesses=self.witnesses,
            output_counts=dict(self.output_counts),
            downstream_consumed=self.downstream_consumed,
            downstream_rejected=self.downstream_rejected,
            downstream_by=dict(self.downstream_by),
            downstream_outcomes=dict(self.downstream_outcomes),
            correlations=tuple(
                sorted(
                    self.correlations,
                    key=lambda correlation: (
                        correlation.invocation_id,
                        correlation.check_id or "",
                        correlation.observation_id or "",
                        correlation.path_id or "",
                    ),
                )
            ),
            activation_chains=tuple(activation_chains),
        )


@dataclass(slots=True)
class _ActivationChainAccumulator:
    """Mutable counters for exactly one correlated invocation chain."""

    invocation_id: str
    invoked: int = 0
    input_non_empty: int = 0
    candidates_produced: int = 0
    candidates_survived_prefilter: int = 0
    candidates_survived_guardrail: int = 0
    scored: int = 0
    downstream_consumed: int = 0
    decisions: int = 0

    def record_invocation(self, event: ComponentInvoked) -> None:
        self.invoked += 1
        if any(count > 0 for count in event.input_completeness.values()):
            self.input_non_empty += 1

    def record_output(self, event: ComponentOutput) -> None:
        self.candidates_produced += event.summary.get("candidates_produced", 0)
        self.candidates_survived_prefilter += event.summary.get(
            "candidates_survived_prefilter", 0
        )
        self.candidates_survived_guardrail += event.summary.get(
            "candidates_survived_guardrail", 0
        )
        self.scored += event.summary.get("scored", 0)

    def record_decision(self, event: DownstreamDecision) -> None:
        self.decisions += 1
        self.downstream_consumed += event.consumed

    def failures(self, *, kind: ComponentKind) -> tuple[str, ...]:
        return _activation_failures(
            kind=kind,
            invocations=self.invoked,
            inputs_non_empty=self.input_non_empty,
            candidates_produced=self.candidates_produced,
            candidates_survived_prefilter=self.candidates_survived_prefilter,
            candidates_survived_guardrail=self.candidates_survived_guardrail,
            scored=self.scored,
            downstream_consumed=self.downstream_consumed,
            decisions=self.decisions,
        )


def _activation_failures(
    *,
    kind: ComponentKind,
    invocations: int,
    inputs_non_empty: int,
    candidates_produced: int,
    candidates_survived_prefilter: int,
    candidates_survived_guardrail: int,
    scored: int,
    downstream_consumed: int,
    decisions: int,
) -> tuple[str, ...]:
    failures: list[str] = []
    if invocations < 1:
        failures.append("invocations=0")
    if inputs_non_empty < 1:
        failures.append("input_non_empty=0")
    if kind == "gate":
        if decisions < 1:
            failures.append("decisions=0")
        return tuple(failures)
    if candidates_produced < 1:
        failures.append("candidates_produced=0")
    if candidates_survived_prefilter < 1:
        failures.append("candidates_survived_prefilter=0")
    if candidates_survived_guardrail < 1:
        failures.append("candidates_survived_guardrail=0")
    if scored < 1:
        failures.append("scored=0")
    if downstream_consumed < 1:
        failures.append("downstream_consumed=0")
    return tuple(failures)


def _promoted_count(activity: _ActivityAccumulator) -> int:
    return (
        activity.promoted_from_outputs
        if activity.promoted_from_outputs
        else activity.promoted_from_decisions
    )


def _parked_count(activity: _ActivityAccumulator) -> int:
    return (
        activity.parked_from_outputs
        if activity.parked_from_outputs
        else activity.parked_from_decisions
    )


def measure_component_activity(
    events: Iterable[DomainEvent],
    *,
    zero_conversion_threshold: int = (DEFAULT_PROMOTION_CONVERSION_ZERO_CONSULTATIONS),
) -> Mapping[str, ActivityReport]:
    """Project component lifecycle events into immutable activity reports."""

    if zero_conversion_threshold <= 0:
        raise ValueError("zero_conversion_threshold must be positive")
    unique_events = {
        event.semantic_key: event
        for event in events
        if isinstance(event, ComponentLifecycleEvent)
    }.values()
    activities: dict[str, _ActivityAccumulator] = {}

    for event in unique_events:
        activity = activities.setdefault(
            event.component,
            _ActivityAccumulator(component=event.component, kind=event.kind),
        )
        if activity.kind != event.kind:
            raise ValueError(
                "component telemetry declares conflicting kinds: "
                f"{event.component} is both {activity.kind} and {event.kind}"
            )
        activity.correlations.add(
            ActivityCorrelation(
                invocation_id=event.invocation_id or event.event_id,
                check_id=event.check_id,
                observation_id=event.observation_id,
                path_id=event.path_id,
            )
        )
        chain = activity.chain_for(event)

        if isinstance(event, ComponentInvoked):
            activity.invocations += 1
            activity.record_input(event)
            if any(count > 0 for count in event.input_completeness.values()):
                activity.inputs_non_empty += 1
            else:
                activity.inputs_empty += 1
            chain.record_invocation(event)
        elif isinstance(event, ComponentSkipped):
            activity.skipped += 1
            activity.skip_reasons[event.reason] = (
                activity.skip_reasons.get(event.reason, 0) + 1
            )
            activity.record_input(event)
        elif isinstance(event, ComponentOutput):
            for name, count in event.summary.items():
                activity.output_counts[name] = (
                    activity.output_counts.get(name, 0) + count
                )
            activity.candidates_produced += event.summary.get("candidates_produced", 0)
            activity.candidates_survived_prefilter += event.summary.get(
                "candidates_survived_prefilter",
                0,
            )
            activity.candidates_survived_guardrail += event.summary.get(
                "candidates_survived_guardrail",
                0,
            )
            activity.proposals += event.summary.get("proposals", 0)
            activity.parked_from_outputs += event.summary.get("parked", 0)
            activity.promoted_from_outputs += event.summary.get("promoted", 0)
            activity.promoted_facts += event.summary.get("promoted_facts", 0)
            activity.scored += event.summary.get("scored", 0)
            activity.witnesses += event.summary.get("witnesses", 0)
            chain.record_output(event)
        elif isinstance(event, DownstreamDecision):
            if event.consumed:
                activity.downstream_consumed += 1
            else:
                activity.downstream_rejected += 1
            activity.downstream_by[event.by] = (
                activity.downstream_by.get(event.by, 0) + 1
            )
            activity.downstream_outcomes[event.outcome] = (
                activity.downstream_outcomes.get(event.outcome, 0) + 1
            )
            if event.outcome == "promoted":
                activity.promoted_from_decisions += 1
            elif event.outcome == "parked":
                activity.parked_from_decisions += 1
            chain.record_decision(event)

    zero_conversion_skips = tuple(
        ComponentSkipped(
            component=component,
            kind=activity.kind,
            reason="promotion_conversion_zero",
            input_completeness={
                "proposals": activity.proposals,
                "parked": _parked_count(activity),
                "promoted": _promoted_count(activity),
            },
        )
        for component, activity in activities.items()
        if component.startswith("consultation:")
        and activity.proposals >= zero_conversion_threshold
        and _promoted_count(activity) == 0
    )
    for event in zero_conversion_skips:
        activity = activities[event.component]
        activity.skipped += 1
        activity.skip_reasons[event.reason] = (
            activity.skip_reasons.get(event.reason, 0) + 1
        )
        activity.record_input(event)

    return {
        component: activities[component].report() for component in sorted(activities)
    }


@dataclass(frozen=True, slots=True)
class CampaignMetricsSnapshot:
    """Immutable campaign metrics read model.

    Runtime counters remain in the workflow layer.  Presentation code consumes
    this snapshot and can therefore never mutate or observe partially updated
    runtime state.
    """

    intent_states: Mapping[str, str] = field(default_factory=dict)
    intent_labels: Mapping[str, str] = field(default_factory=dict)
    tokens: TokenUsageSnapshot = field(default_factory=TokenUsageSnapshot)
    tokens_by_phase: Mapping[str, TokenUsageSnapshot] = field(default_factory=dict)
    timing: CampaignTimingSnapshot = field(default_factory=CampaignTimingSnapshot)
    model_id: str = ""
    generator_stats: Mapping[tuple[str, str], Mapping[str, int]] = field(
        default_factory=dict
    )
    current_activity: str = ""
    model_requests_active: int = 0
    model_requests_completed: int = 0
    total_checks: int = 0
    total_findings: int = 0
    grounding_cache_hits: int = 0
    grounding_cache_misses: int = 0
    diff_pairs_evaluated: int = 0
    diff_pairs_by_mode: Mapping[str, int] = field(default_factory=dict)
    diff_norms_promoted: int = 0
    component_activity: Mapping[str, ActivityReport] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "intent_states",
            MappingProxyType(dict(self.intent_states)),
        )
        object.__setattr__(
            self,
            "intent_labels",
            MappingProxyType(dict(self.intent_labels)),
        )
        object.__setattr__(
            self,
            "tokens_by_phase",
            MappingProxyType(dict(self.tokens_by_phase)),
        )
        object.__setattr__(
            self,
            "timing",
            CampaignTimingSnapshot(
                wall_time=self.timing.wall_time,
                phase_elapsed=self.timing.phase_elapsed,
            ),
        )
        object.__setattr__(
            self,
            "generator_stats",
            MappingProxyType(
                {
                    key: MappingProxyType(dict(outcomes))
                    for key, outcomes in self.generator_stats.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "diff_pairs_by_mode",
            MappingProxyType(dict(self.diff_pairs_by_mode)),
        )
        object.__setattr__(
            self,
            "component_activity",
            MappingProxyType(dict(self.component_activity)),
        )

    def summary(self) -> dict[str, object]:
        """Return the stable dashboard summary shape."""

        states = Counter(self.intent_states.values())
        letters = self._letter_counts()
        return {
            "intents": {
                "total": len(self.intent_states),
                "pending": states.get("pending", 0),
                "ready": states.get("ready", 0),
                "executing": states.get("executing", 0),
                "verified": states.get("verified", 0),
                "unscoreable": states.get("unscoreable", 0),
                "blocked": states.get("blocked", 0),
            },
            "letters": {
                letter: {
                    "total": sum(letter_states.values()),
                    "verified": letter_states.get("verified", 0),
                    "blocked": letter_states.get("blocked", 0),
                }
                for letter, letter_states in letters.items()
            },
            "tokens": {
                "input": self.tokens.input_tokens,
                "cached_input": self.tokens.cached_input_tokens,
                "uncached_input": self.tokens.uncached_input_tokens,
                "output": self.tokens.output_tokens,
                "total": self.tokens.total_tokens,
                "cache_hit_rate": self.tokens.cache_hit_rate,
                "requests": self.tokens.request_count,
                "by_phase": {
                    phase: {
                        "input": usage.input_tokens,
                        "cached_input": usage.cached_input_tokens,
                        "output": usage.output_tokens,
                        "total": usage.total_tokens,
                    }
                    for phase, usage in self.tokens_by_phase.items()
                },
            },
            "timing": {
                "wall_time": self.timing.wall_time.total_seconds(),
                "phase_elapsed": {
                    phase: elapsed.total_seconds()
                    for phase, elapsed in self.timing.phase_elapsed.items()
                },
            },
            "model": self.model_id,
            "checks": self.total_checks,
            "findings": self.total_findings,
            "differential": {
                "pairs_evaluated": self.diff_pairs_evaluated,
                "pairs_by_mode": dict(self.diff_pairs_by_mode),
                "norms_promoted": self.diff_norms_promoted,
            },
            "component_activity": {
                component: activity.summary()
                for component, activity in self.component_activity.items()
            },
            "activity": self.current_activity,
            "model_active": self.model_requests_active,
            "model_completed": self.model_requests_completed,
        }

    def _letter_counts(self) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {}
        for intent_id, state in self.intent_states.items():
            letter = self.intent_labels.get(intent_id, "unknown")
            letter_states = result.setdefault(letter, {})
            letter_states[state] = letter_states.get(state, 0) + 1
        return result


class CampaignMetricsView(Protocol):
    """Presentation-facing source of immutable campaign metric snapshots."""

    def snapshot(self) -> CampaignMetricsSnapshot: ...


__all__ = [
    "ActivationChainReport",
    "ActivityCorrelation",
    "ActivityReport",
    "CampaignTimingSnapshot",
    "CampaignMetricsSnapshot",
    "CampaignMetricsView",
    "TokenUsageSnapshot",
    "measure_campaign_timing",
    "measure_component_activity",
]
