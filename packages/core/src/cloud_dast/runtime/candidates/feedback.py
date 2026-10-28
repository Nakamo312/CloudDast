"""Deterministic candidate scoring shared by campaign and fuzzing runtime.

The score is a pure function of the norm's effect constructor, the runtime
observation, and the verdict.  No LLM judge is involved: the ladder is a
deterministic graph query in miniature, matching the algebra's rule that
verdicts stay deterministic.
"""

from __future__ import annotations

from cloud_dast.candidates import goal_key, refresh_probe_marker
from cloud_dast.contracts.candidate_metrics import request_complexity
from cloud_dast.contracts.feedback import ExecutionFeedback, ExecutionFeedbackEntry
from cloud_dast.model import (
    AccessOutcome,
    Observation,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Struct
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norms import EFFECT_PRIMITIVES

DELIVERED_PROXIMITY = 1.0 / 3.0
WITNESS_PROXIMITY = 2.0 / 3.0
VIOLATION_PROXIMITY = 1.0


__all__ = [
    "DELIVERED_PROXIMITY",
    "ExecutionFeedback",
    "ExecutionFeedbackEntry",
    "VIOLATION_PROXIMITY",
    "WITNESS_PROXIMITY",
    "goal_key",
    "goal_proximity",
    "invariant_effect",
    "refresh_probe_marker",
    "request_complexity",
    "trace_proximity",
]


def invariant_effect(invariant: InvariantProjection) -> Struct | None:
    """Return the effect constructor of an invariant's formal norm."""

    fact = invariant.norm_fact
    if fact is None:
        return None
    if fact.predicate.name != "prevents" or len(fact.args) != 2:
        return None
    effect = fact.args[1]
    return effect if isinstance(effect, Struct) else None


def goal_proximity(
    effect: Struct | None,
    observation: Observation | None,
    verdict: VerdictStatus,
) -> float:
    """Grade one trace by its progress toward the witness pattern.

    The ladder mirrors the letter formulas: the positive atoms of the
    witness pattern are established step by step — the call was delivered,
    then the witness channel carried evidence, and a FAIL verdict marks the
    complete witness.
    """

    if verdict is VerdictStatus.FAIL:
        return VIOLATION_PROXIMITY
    if effect is None or observation is None:
        return 0.0
    if not _delivered(observation):
        return 0.0
    if _witness_established(effect, observation):
        return WITNESS_PROXIMITY
    return DELIVERED_PROXIMITY


def trace_proximity(
    effect: Struct | None,
    trace: tuple[Observation, ...],
    verdict: VerdictStatus,
    *,
    step_count: int = 1,
) -> float:
    """Grade one trace cumulatively toward the chain witness.

    For a multi-step path the witness formula spans every step: earlier
    verified steps are confirmed atoms of ``phi``.  The score is
    ``(confirmed steps + current ladder) / step count`` — potential-based
    shaping that keeps the optimum at the full witness while letting the
    bandit distinguish "dead end at step one" from "one atom short at the
    end of the chain".  Single-step paths degrade exactly to
    :func:`goal_proximity`.
    """

    if step_count <= 1 or not trace:
        return goal_proximity(effect, trace[-1] if trace else None, verdict)

    confirmed_steps = 0
    earlier = trace[:-1]
    for observation in earlier:
        if _delivered(observation):
            confirmed_steps += 1
    confirmed_steps = min(confirmed_steps, step_count - 1)
    current = goal_proximity(effect, trace[-1], verdict)
    return (confirmed_steps + current) / step_count


def _delivered(observation: Observation) -> bool:
    """UNKNOWN means transport never produced a usable response."""

    return observation.observed_outcome is not AccessOutcome.UNKNOWN


def _witness_established(effect: Struct, observation: Observation) -> bool:
    primitive = EFFECT_PRIMITIVES.get(effect.name, "unknown")
    if primitive == "outcome":
        return observation.observed_outcome in {
            AccessOutcome.ALLOWED,
            AccessOutcome.DENIED,
        }
    if primitive == "response_field":
        return observation.output is not None
    if primitive == "latency_bound":
        return observation.duration_ms is not None
    if primitive == "oob_event":
        return observation.probe_marker is not None
    if primitive == "marker":
        return bool(observation.response_summary)
    if primitive == "sequence":
        return observation.trace is not None
    return False
