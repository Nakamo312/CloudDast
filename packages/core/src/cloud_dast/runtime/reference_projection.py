"""Pure runtime projections for typed input and principal references."""

from __future__ import annotations

from collections.abc import Mapping

from cloud_dast.qdl import reasoning
from cloud_dast.qdl.field_roles import (
    OBJECT_REF_ROLE,
    FieldRolePolicy,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.invariant_projection import (
    EXECUTABLE_CONTEXTS,
)


def resource_type_name(value: str) -> str:
    return value.removeprefix("resource:")


def fields_with_role_by_action(
    field_roles: FieldRolePolicy,
    role: str,
) -> dict[str, tuple[str, ...]]:
    """Group executable input fields carrying one grounded role."""

    fields: dict[str, set[str]] = {}
    for (direction, action, field), roles in field_roles.roles_by_field.items():
        if direction == "input" and role in roles:
            fields.setdefault(action, set()).add(field)
    return {action: tuple(sorted(values)) for action, values in fields.items()}


def resource_params_by_action(graph: QdlGraph) -> dict[str, tuple[str, ...]]:
    """Collect grounded object-reference fields per action."""

    return fields_with_role_by_action(resolve_field_roles(graph), OBJECT_REF_ROLE)


def refers_to_targets_by_action(
    graph: QdlGraph,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Index uniquely grounded ``refers_to`` targets per action field."""

    targets: dict[str, dict[str, set[str]]] = {}
    for fact in graph.facts:
        if fact.context not in EXECUTABLE_CONTEXTS:
            continue
        if fact.predicate.name != "refers_to" or len(fact.args) != 2:
            continue
        field_term, target = fact.args
        action, field = reasoning.read_input_field(field_term)
        target_value = atom_value(target)
        if (
            action is None
            or field is None
            or not isinstance(target_value, str)
            or not target_value
        ):
            continue
        targets.setdefault(action, {}).setdefault(field, set()).add(target_value)
    return {
        action: tuple(
            (field, next(iter(values)))
            for field, values in sorted(fields.items())
            if len(values) == 1
        )
        for action, fields in targets.items()
    }


def principal_refs_by_action(
    graph: QdlGraph,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Index uniquely targeted principal references per action."""

    return principal_refs_from_targets(refers_to_targets_by_action(graph))


def principal_refs_from_targets(
    refers_to_targets: Mapping[str, tuple[tuple[str, str], ...]],
) -> dict[str, tuple[tuple[str, str], ...]]:
    return {
        action: tuple(
            (field, target.removeprefix("principal:"))
            for field, target in pairs
            if target.startswith("principal:")
        )
        for action, pairs in refers_to_targets.items()
    }


def typed_object_refs_by_action(
    graph: QdlGraph,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Materialize grounded object-reference fields and resource types."""

    refers_to = refers_to_targets_by_action(graph)
    field_roles = resolve_field_roles(graph)
    typed: dict[str, list[tuple[str, str]]] = {}
    for action, pairs in refers_to.items():
        for field, target in pairs:
            if target.startswith("principal:"):
                continue
            if OBJECT_REF_ROLE not in field_roles.roles(
                action,
                field,
                direction="input",
            ):
                continue
            typed.setdefault(action, []).append((field, resource_type_name(target)))
    return {action: tuple(pairs) for action, pairs in typed.items() if pairs}


def resource_types_by_action(
    graph: QdlGraph,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Return the canonical typed object-reference projection."""

    return typed_object_refs_by_action(graph)


__all__ = [
    "fields_with_role_by_action",
    "principal_refs_by_action",
    "principal_refs_from_targets",
    "refers_to_targets_by_action",
    "resource_params_by_action",
    "resource_type_name",
    "resource_types_by_action",
    "typed_object_refs_by_action",
]
