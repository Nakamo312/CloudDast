"""Core contract binding one QDL norm to an executable scenario."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.couplings import PlanCoupling
from cloud_dast.model.checks import GeneratorName, PrincipalRef
from cloud_dast.model.evidence import JsonValue


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


__all__ = ["VerificationPlan"]
