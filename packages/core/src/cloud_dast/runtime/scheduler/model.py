"""State and identity values owned by coverage scheduling."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_dast.runtime.prioritization import ColdScore

PathOutcome = str


@dataclass(frozen=True, order=True, slots=True)
class CoverageKey:
    """One executable action/effect/primitive coverage cell."""

    action_id: str
    effect: str
    witness: str
    primitive: str
    effect_name: str


@dataclass(slots=True)
class State:
    """Mutable selection state for one campaign execution."""

    completed: set[str] = field(default_factory=set)
    blocked: set[str] = field(default_factory=set)
    superseded: set[str] = field(default_factory=set)
    in_flight: set[str] = field(default_factory=set)
    outcomes: dict[str, PathOutcome] = field(default_factory=dict)
    terminal_reasons: dict[str, str] = field(default_factory=dict)
    evidence_signatures: dict[str, str | None] = field(default_factory=dict)
    selections: list[str] = field(default_factory=list)
    attempts: dict[str, int] = field(default_factory=dict)
    progress: dict[str, float] = field(default_factory=dict)
    covered: set[CoverageKey] = field(default_factory=set)
    canonical_attempts: dict[CoverageKey, int] = field(default_factory=dict)
    prewarmed: set[str] = field(default_factory=set)
    latency_bootstrap_paths: set[str] = field(default_factory=set)
    latency_bootstrapped_paths: set[str] = field(default_factory=set)
    latency_bootstrap_actions: set[str] = field(default_factory=set)
    effect_selections: dict[str, int] = field(default_factory=dict)
    primitive_selections: dict[str, int] = field(default_factory=dict)
    action_selections: dict[str, int] = field(default_factory=dict)
    action_primitive_selections: dict[tuple[str, str], int] = field(
        default_factory=dict
    )
    action_outcomes: set[str] = field(default_factory=set)
    actions_without_outcome: set[str] = field(default_factory=set)
    action_allowed: set[str] = field(default_factory=set)
    cold_scores: dict[str, ColdScore] = field(default_factory=dict)
    effect_reward_totals: dict[str, float] = field(default_factory=dict)
    effect_reward_counts: dict[str, int] = field(default_factory=dict)
    quarantined_features: dict[str, frozenset[str]] = field(default_factory=dict)
    quarantined_rewards: int = 0


__all__ = ["CoverageKey", "PathOutcome", "State"]
