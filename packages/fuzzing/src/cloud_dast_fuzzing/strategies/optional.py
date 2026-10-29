"""Generic optional-field strategies for partial request maps."""

from __future__ import annotations

from cloud_dast.candidates import validate_binding
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.contracts.request_fields import (
    Present,
    field_value,
    omit_optional_field,
)
from cloud_dast.extensions import TestCaseGenerator
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.schemas import is_float_type, is_integer_type


class OmitOptionalFieldGenerator:
    """Omit each optional contract field in one generic candidate.

    The strategy first materializes the present summand for every optional
    field, then applies the absence operator to one field at a time.  It never
    special-cases a field name: selection is driven only by ``FieldSpec``.
    """

    def __init__(self, seed_generator: TestCaseGenerator) -> None:
        self._seed_generator = seed_generator

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
        candidates: list[Check] = []
        seen: set[tuple[tuple[tuple[str, JsonValue], ...], tuple[str, ...]]] = set()

        for seed in self._seed_generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        ):
            present_request = _request_with_optional_presence(seed.request, method)
            emitted = False
            for field in method.request_schema.fields:
                if field.required or not isinstance(
                    field_value(present_request, field),
                    Present,
                ):
                    continue
                request = omit_optional_field(present_request, field)
                key = (request, seed.identities)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(seed.model_copy(update={"request": request}))
                emitted = True
            if not emitted:
                candidates.append(seed)

        return tuple(candidates)


def present_field_value(field: FieldSpec) -> JsonValue:
    """Build a name-independent present value for one optional field."""

    if field.enum_values:
        return field.enum_values[0]

    field_type = field.type.lower()
    if "bool" in field_type:
        return False
    if is_integer_type(field_type):
        return _bounded_present_value(0, field)
    if is_float_type(field_type):
        return _bounded_present_value(0.0, field)
    if field_type in {"string", "bytes", "url", "uri"}:
        return "dast-present"
    return None


def _bounded_present_value(value: int | float, field: FieldSpec) -> int | float:
    if field.minimum is not None and value < field.minimum:
        return field.minimum
    if field.maximum is not None and value > field.maximum:
        return field.maximum
    return value


def _request_with_optional_presence(
    request: tuple[tuple[str, JsonValue], ...],
    method: MethodSpec,
) -> tuple[tuple[str, JsonValue], ...]:
    values = dict(request)
    selected_oneofs = {
        field.oneof
        for field in method.request_schema.fields
        if field.oneof is not None and _is_present(values, field)
    }

    for field in method.request_schema.fields:
        if field.required:
            continue

        assignment = field_value(values, field)
        if isinstance(assignment, Present):
            _materialize_present_value(values, field)
            continue
        if field.oneof is not None and field.oneof in selected_oneofs:
            continue
        value = present_field_value(field)
        values[field.name] = (value,) if field.repeated else value
        if field.oneof is not None:
            selected_oneofs.add(field.oneof)

    return tuple(values.items())


def _is_present(values: dict[str, JsonValue], field: FieldSpec) -> bool:
    return isinstance(field_value(values, field), Present)


def _materialize_present_value(
    values: dict[str, JsonValue],
    field: FieldSpec,
) -> None:
    current = values.get(field.name)
    value = present_field_value(field)
    if field.repeated:
        if current == (None,):
            values[field.name] = (value,)
    elif current is None:
        values[field.name] = value


__all__ = ["OmitOptionalFieldGenerator"]
