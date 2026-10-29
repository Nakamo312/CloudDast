"""Core contract binding one QDL norm to an executable scenario."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.couplings import PlanCoupling
from cloud_dast.model.checks import (
    GeneratorName,
    MethodSpec,
    PrincipalRef,
    ScenarioPosition,
)
from cloud_dast.model.evidence import JsonValue, Severity
from cloud_dast.qdl.graph import Fact as QdlFact
from cloud_dast.qdl.graph import QdlGraph, Struct


class VerificationPlan(BaseModel):
    """Bind one QDL obligation to an executable method and live scenario.

    This is a derived execution contract.  It carries grounded execution
    data, but it does not own the norm, method schema, or scenario model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str
    invariant_id: str
    method_id: str
    scenario_id: str | None = None
    prerequisites: tuple[str, ...] = ()
    resource_params: tuple[str, ...] = Field(
        default=(),
        description="grounded object-reference fields resolved from the live stand",
    )
    resource_types: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, resource type) pairs for object references",
    )
    subject_params: tuple[str, ...] = Field(
        default=(),
        description="grounded subject-reference fields resolved from the live stand",
    )
    subject_refs: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, principal id) pairs for subject references",
    )
    role_params: tuple[str, ...] = Field(
        default=(),
        description="grounded role-reference fields resolved from the live stand",
    )
    role_refs: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, principal id) pairs for role references",
    )
    sink_types: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, sink type) pairs from payload projection",
    )
    grammar_formats: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, carrier format) grammar facts",
    )
    grammar_constraints: tuple[tuple[str, str, JsonValue], ...] = Field(
        default=(),
        description="grounded field/operator/value grammar constraints",
    )
    grammar_dialects: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field name, sink dialect) grammar facts",
    )
    resource_type: str | None = None
    identity_hint: str = ""
    identity_terms: tuple[PrincipalRef, ...] | None = Field(
        default=None,
        description=(
            "QDL-grounded valid_identity(action, subject) projection as typed "
            "principal terms; None marks a plan that was never "
            "identity-grounded (fixture provisioning seeds, hand-bound plans) "
            "and an empty tuple is a grounded identity_deficit"
        ),
    )
    expected_result: str = ""
    fact_requirements: tuple[str, ...] = ()
    couplings: tuple[PlanCoupling, ...] = Field(
        default=(),
        description=(
            "fully identified field couplings: "
            "(input_field/output_field Struct, input_field/output_field Struct, operator)"
        ),
    )
    probe_fields: tuple[str, ...] = Field(
        default=(),
        description="grounded fields that accept probe markers for this plan",
    )
    seed_hints: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="grounded (field, role) hints applied to generated seeds",
    )
    generator: GeneratorName = "template"


class InvariantProjection(BaseModel):
    """Display and oracle view derived from one QDL norm.

    QDL owns the norm and its formal fact. This view only carries the
    executable identity and presentation metadata required by verification;
    it is never a second source of declarative truth.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    invariant_id: str
    norm_id: str
    statement: str
    severity: Severity
    policy: str | None = None
    norm_fact: QdlFact | None = Field(
        default=None,
        description="formal QDL prevents-fact; preferred source of executable truth",
    )


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

    def select(self, method_id: str | None) -> tuple[QdlExecutionPath, ...]:
        """Select nonempty whole paths exercising a method anywhere in their chain."""

        if method_id is None:
            return tuple(path for path in self.paths if path.steps)
        return tuple(
            path
            for path in self.paths
            if path.steps
            and any(step.method.method_id == method_id for step in path.steps)
        )


__all__ = [
    "InvariantProjection",
    "QdlExecutionPath",
    "QdlExecutionStep",
    "QdlExecutionView",
    "QdlPathKind",
    "VerificationPlan",
]
