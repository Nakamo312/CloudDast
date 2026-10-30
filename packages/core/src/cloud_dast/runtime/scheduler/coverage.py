"""Pure coverage identities used by the scheduler."""

from __future__ import annotations

from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model.events import normalize_action
from cloud_dast.qdl.graph import canonical_json
from cloud_dast.runtime.scheduler.model import CoverageKey
from cloud_dast.verification.norms import NormView


def keys_for(path: QdlExecutionPath) -> tuple[CoverageKey, ...]:
    return tuple(step_coverage_key(step) for step in path.steps)


def path_family_id(path_id: str) -> str:
    """Return the logical path id shared by content-addressed versions."""

    return path_id.split(":pv", 1)[0]


def step_coverage_key(step: QdlExecutionStep) -> CoverageKey:
    norm = NormView.from_invariant(step.invariant)
    if norm is None:
        identifier = step.invariant.invariant_id
        return CoverageKey(
            action_id=step.method.method_id,
            effect=identifier,
            witness=identifier,
            primitive="unknown",
            effect_name="unknown",
        )
    return CoverageKey(
        action_id=step.method.method_id,
        effect=canonical_json(norm.effect),
        witness=canonical_json(norm.effect.args[1:]),
        primitive=norm.primitive,
        effect_name=norm.effect.name,
    )


def latency_actions(path: QdlExecutionPath) -> tuple[str, ...]:
    return tuple(
        step.method.method_id
        for step in path.steps
        if (norm := NormView.from_invariant(step.invariant)) is not None
        and norm.primitive == "latency_bound"
    )


def path_actions(path: QdlExecutionPath) -> tuple[str, ...]:
    return tuple(step.method.method_id for step in path.steps)


def feature_names(features: frozenset[str]) -> str:
    return ",".join(sorted(features)) if features else "-"


__all__ = [
    "feature_names",
    "keys_for",
    "latency_actions",
    "normalize_action",
    "path_actions",
    "path_family_id",
    "step_coverage_key",
]
