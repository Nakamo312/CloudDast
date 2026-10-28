from __future__ import annotations

import hashlib

from cloud_dast.candidates import validate_binding
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.extensions import TestCaseGenerator
from cloud_dast.model import (
    Check,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.schemas import is_float_type, is_integer_type
from cloud_dast.verification.invariant_projection import InvariantProjection


def _default_value(field: FieldSpec) -> object:
    if field.enum_values:
        return field.enum_values[0]

    field_type = field.type.lower()
    if "bool" in field_type:
        return False
    if is_integer_type(field_type):
        return _bounded_value(0, field)
    if is_float_type(field_type):
        return _bounded_value(0.0, field)
    return ""


def _bounded_value(value: float, field: FieldSpec) -> float:
    if field.minimum is not None and value < field.minimum:
        return field.minimum
    if field.maximum is not None and value > field.maximum:
        return field.maximum
    return value


class MinimalSeedGenerator:
    """Build a minimal valid seed check for one invariant and scenario.

    The seed contains only required fields and the first branch of every
    oneof; optional fields are omitted. Values come from grounded plan
    references (resource, subject or role facts), otherwise from the field
    type.  This is a template-derived seed, not a symbolic strategy: solver
    candidates come from ``Z3SymbolicGenerator``.
    """

    def __init__(self, template_generator: TestCaseGenerator) -> None:
        self._template_generator = template_generator

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        validate_binding(plan, method, invariant, scenario)
        template = self._template_generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )[0]
        template_values = dict(template.request)
        request: list[tuple[str, object]] = []
        selected_oneofs: set[str] = set()

        for field in method.request_schema.fields:
            if field.oneof is not None:
                if field.oneof in selected_oneofs:
                    continue
                selected_oneofs.add(field.oneof)
            elif not field.required:
                continue

            value = (
                field.enum_values[0]
                if field.enum_values
                else template_values.get(field.name)
            )
            if field.repeated and isinstance(value, tuple) and len(value) == 1:
                value = value[0]
            if value is None:
                value = _default_value(field)
            if field.repeated:
                value = (value,)
            request.append((field.name, value))

        return (
            template.model_copy(
                update={
                    "request": tuple(request),
                    "identities": template.identities,
                    "generator": "template",
                    "seed_id": hashlib.sha256(plan.plan_id.encode("utf-8")).hexdigest(),
                }
            ),
        )
