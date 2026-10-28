"""Public contract for a QDL plan bound to executable scenarios."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.qdl.graph import QdlGraph, Struct
from cloud_dast.verification.invariant_projection import InvariantProjection

QdlPathKind = Literal["attack", "forbidden", "invariant", "smoke"]


@dataclass(frozen=True, slots=True)
class QdlExecutionStep:
    """One QDL-derived action bound to an executable live scenario."""

    step_id: str
    goal_id: str | None
    plan: VerificationPlan
    method: MethodSpec
    scenario: ScenarioPosition
    invariant: InvariantProjection
    required_effects: tuple[Struct, ...] = ()
    evidence_graph: QdlGraph | None = None
    effect_ids: tuple[str, ...] = ()
    irreversible: bool | None = None
    witness_requirement: Any = None


@dataclass(frozen=True, slots=True)
class QdlExecutionPath:
    """A logical QDL path bound to executable methods and scenarios."""

    path_id: str
    goal_id: str
    kind: QdlPathKind
    description: str
    steps: tuple[QdlExecutionStep, ...]
    gate: str = "AND"
    recovery: bool = False
    scoreable: bool = True


@dataclass(frozen=True, slots=True)
class QdlExecutionView:
    """Public runtime projection of a QDL plan.

    Physical execution evidence and action-runtime closure are workflow
    projections. They are intentionally not fields of this QDL contract.
    """

    graph_hash: str
    paths: tuple[QdlExecutionPath, ...]
    invariants: Mapping[str, InvariantProjection]


__all__ = [
    "QdlExecutionPath",
    "QdlExecutionStep",
    "QdlExecutionView",
    "QdlPathKind",
]
