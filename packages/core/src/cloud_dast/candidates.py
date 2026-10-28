from __future__ import annotations

from uuid import uuid4

from cloud_dast.binding import validate_binding
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.contracts.request_fields import Absent, with_field_value
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ResourceRef,
    ScenarioPosition,
    StandState,
)
from cloud_dast.model.schemas import is_float_type
from cloud_dast.verification.invariant_projection import InvariantProjection


class TemplateGenerator:
    __slots__ = ()

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        del feedback
        validate_binding(plan, method, invariant, scenario)

        identities = resolve_check_identities(plan, scenario)
        return (
            Check(
                invariant_id=plan.invariant_id,
                method_id=plan.method_id,
                scenario_id=scenario.scenario_id,
                request=_request(
                    method,
                    scenario,
                    plan.resource_types,
                    plan.subject_refs,
                    plan.role_refs,
                ),
                identities=identities,
            ),
        )


def goal_key(invariant: InvariantProjection) -> str:
    """Derive a transferable search key from one QDL invariant."""

    fact = invariant.norm_fact
    if fact is None or fact.predicate.name != "prevents" or len(fact.args) != 2:
        return "generic"
    effect = fact.args[1]
    return getattr(effect, "name", None) or "generic"


def refresh_probe_marker(check: Check) -> Check:
    """Give a replayed or shrunk marker candidate its own probe identity."""

    marker = check.probe_marker
    if marker is None:
        return check
    replacement = uuid4().hex
    if len(replacement) > len(marker):
        replacement = replacement[: len(marker)]
    elif len(replacement) < len(marker):
        replacement = replacement.ljust(len(marker), "0")
    request = tuple(
        (
            name,
            value.replace(marker, replacement) if isinstance(value, str) else value,
        )
        for name, value in check.request
    )
    return check.model_copy(
        update={
            "request": request,
            "probe_marker": replacement,
        }
    )


def resolve_check_identities(
    plan: VerificationPlan,
    scenario: ScenarioPosition,
) -> tuple[str, ...]:
    """Resolve the identity one generated check executes as.

    ``VerificationPlan.identity_terms`` is the binder's QDL-grounded
    ``valid_identity(action, subject)`` projection.  A term declared by the
    scenario stand is preferred — the stand types the principal and the
    position owns it — otherwise the first grounded term executes (its
    credential comes from the token store, not the stand).  ``None`` marks a
    plan that was never identity-grounded (fixture-provisioning seeds and
    hand-bound plans); those keep the historical stand-principal behaviour.
    An empty grounded projection is an ``identity_deficit`` and raises: the
    caller reports the deficit instead of guessing an identity.
    """

    if plan.identity_terms is None:
        return tuple(p.principal_id for p in scenario.stand.principals)
    stand = {p.principal_id for p in scenario.stand.principals}
    selected = next(
        (term for term in plan.identity_terms if term.principal_id in stand),
        plan.identity_terms[0] if plan.identity_terms else None,
    )
    if selected is None:
        raise ValueError(
            "identity_deficit: QDL derives no valid identity for action "
            f"{plan.method_id}"
        )
    return (selected.principal_id,)


def apply_seed_hints(
    check: Check,
    method: MethodSpec,
    hints: tuple[tuple[str, str], ...],
    *,
    scenario: ScenarioPosition | None = None,
    resource_refs: tuple[ResourceRef, ...] = (),
    resource_types: tuple[tuple[str, str], ...] = (),
) -> Check:
    """Apply grounded seed hints to a generated check.

    ``setup_skip`` drops a field (and its dotted children) — e.g. one branch
    of a mutually exclusive payload source.  ``setup_value`` fills an
    unresolved field with a deterministic fixture value; required fields
    without a hint still get type defaults.  ``object_ref`` resolves the field
    to a live stand resource, including replacing a chain-fuzz mutation.
    """

    fields = {field.name: field for field in method.request_schema.fields}
    skipped = {name for name, role in hints if role == "setup_skip"}
    valued = {name for name, role in hints if role == "setup_value"}
    object_refs = {name for name, role in hints if role == "object_ref"}
    request = check.request
    for name in skipped:
        field = fields.get(name)
        if field is None:
            request = _omit_named_field(request, name)
        else:
            request = with_field_value(request, field, Absent())

    resolved_request = dict(request)
    required_types = dict(resource_types)
    for name, value in request:
        field = fields.get(name)
        if name in object_refs and field is not None:
            # Object references are setup facts, not fuzz inputs.  A chain
            # mutation must not replace the authoritative live container.
            resolved = resolve_resource_ref(
                field,
                scenario=scenario,
                resource_refs=resource_refs,
                resource_type=required_types.get(name),
            )
            if resolved is not None:
                value = resolved
            resolved_request[name] = value
            continue
        if value is None or value == "":
            value = _seed_default(
                name,
                field,
                valued,
            )
        resolved_request[name] = value

    for field in method.request_schema.fields:
        if field.name in skipped or field.name in resolved_request:
            continue
        if field.name in object_refs:
            resolved = resolve_resource_ref(
                field,
                scenario=scenario,
                resource_refs=resource_refs,
                resource_type=required_types.get(field.name),
            )
            if resolved is not None:
                resolved_request[field.name] = resolved
        elif field.name in valued:
            value = _seed_value_for(field)
            resolved_request[field.name] = (value,) if field.repeated else value

    return check.model_copy(update={"request": tuple(resolved_request.items())})


def _omit_named_field(
    request: tuple[tuple[str, JsonValue], ...],
    name: str,
) -> tuple[tuple[str, JsonValue], ...]:
    return tuple(
        (item_name, value)
        for item_name, value in request
        if item_name != name and not item_name.startswith(f"{name}.")
    )


def _seed_default(
    name: str,
    field: FieldSpec | None,
    valued: set[str],
) -> object:
    if field is not None and field.required:
        return _seed_value_for(field)
    if name in valued:
        return _seed_value_for(field) if field is not None else f"dast-fixture-{name}"
    return None


def _seed_value_for(field: FieldSpec) -> object:
    if field.enum_values:
        return field.enum_values[0]
    if field.type.lower() in {"int32", "int64", "uint32", "uint64"}:
        return 0
    if is_float_type(field.type):
        return 0.0
    if "bool" in field.type.lower():
        return False
    return f"dast-fixture-{field.name.rsplit('.', 1)[-1]}"


def _request(
    method: MethodSpec,
    scenario: ScenarioPosition,
    resource_types: tuple[tuple[str, str], ...] = (),
    subject_refs: tuple[tuple[str, str], ...] = (),
    role_refs: tuple[tuple[str, str], ...] = (),
) -> tuple[tuple[str, JsonValue], ...]:
    request: list[tuple[str, JsonValue]] = []
    selected_oneofs: set[str] = set()
    required_types = dict(resource_types)
    subjects = dict(subject_refs)
    roles = dict(role_refs)

    for field in method.request_schema.fields:
        if field.oneof is not None:
            if field.oneof in selected_oneofs:
                continue
            selected_oneofs.add(field.oneof)

        value = _field_value(
            field,
            scenario.stand,
            required_type=required_types.get(field.name),
            subject_ref=subjects.get(field.name),
            role_ref=roles.get(field.name),
        )
        if field.repeated:
            value = (value,)
        request.append((field.name, value))

    return tuple(request)


def resolve_resource_ref(
    field: FieldSpec,
    *,
    scenario: ScenarioPosition | None,
    resource_refs: tuple[ResourceRef, ...] = (),
    resource_type: str | None = None,
) -> JsonValue | None:
    """Resolve one object-reference field to a live stand resource.

    A grounded ``refers_to`` type selects the resource by canonical identity:
    the type string must match exactly, so ``kms.secret`` never satisfies a
    reference to ``lockbox.secret``.  Explicit references (for example the
    container selected by step setup) take precedence over the whole scenario
    stand.  Without a grounded type or an unambiguous explicit reference there
    is no substitution — the missing fact is reported by the binder as a typed
    deficit.  Synthetic ``fixture:`` placeholders are never returned.
    """

    if resource_refs:
        candidates = _live_resources(resource_refs)
    elif scenario is not None:
        candidates = _live_resources(scenario.stand.resources)
    else:
        return None

    if resource_type is not None:
        matches = [
            resource
            for resource in candidates
            if resource.resource_type == resource_type
        ]
        if len(matches) == 1:
            return _fit_resource(matches[0].resource_id, field)
        return None
    if resource_refs:
        if len(candidates) == 1:
            return _fit_resource(candidates[0].resource_id, field)
        return None
    return None


def _live_resources(resources: tuple[ResourceRef, ...]) -> list[ResourceRef]:
    return [
        resource
        for resource in resources
        if resource.resource_id and not resource.resource_id.startswith("fixture:")
    ]


def _fit_resource(value: str, field: FieldSpec) -> JsonValue:
    return (value,) if field.repeated else value


def _field_value(
    field: FieldSpec,
    stand: StandState,
    *,
    required_type: str | None,
    subject_ref: str | None,
    role_ref: str | None,
) -> JsonValue:
    if subject_ref is not None:
        principal = next(
            (item for item in stand.principals if item.principal_id == subject_ref),
            None,
        )
        return principal.principal_id if principal is not None else None
    if role_ref is not None:
        roles = {
            binding.role
            for binding in stand.bindings
            if binding.principal_id == role_ref and binding.role
        }
        if len(roles) == 1:
            return next(iter(roles))
        return None

    if required_type is not None:
        matches = [
            resource
            for resource in stand.resources
            if resource.resource_type == required_type and resource.resource_id
        ]
        if len(matches) == 1:
            return matches[0].resource_id

    return None


__all__ = [
    "TemplateGenerator",
    "apply_seed_hints",
    "goal_key",
    "refresh_probe_marker",
    "resolve_check_identities",
    "resolve_resource_ref",
]
