"""Pure typed solving for coupled request fields."""

from __future__ import annotations

import math
import operator
from collections.abc import Iterator

from cloud_dast.couplings import FieldCoupling, normalise_action
from cloud_dast.model import Check, FieldSpec, JsonValue
from cloud_dast.model.schemas import float_range, integer_range
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import QdlGraph, Struct
from cloud_dast.qdl.graph_ops import atom_value


def solve_coupled_request(
    check: Check,
    couplings: tuple[FieldCoupling, ...] | list[FieldCoupling],
    endpoints: tuple[Struct, ...],
    rows: dict[str, dict[str, dict[Struct, JsonValue]]],
    fields: dict[str, FieldSpec],
) -> Check | None:
    """Use the core solver to join finite, typed occurrence/value witnesses."""

    current = normalise_action(check.method_id)
    request = dict(check.request)
    values = _distinct_values(rows)
    actions = tuple(rows)
    body, program, domains = [], [], {}
    destinations = []
    for index, endpoint in enumerate(endpoints):
        action = normalise_action(atom_value(endpoint.args[0]))
        name = atom_value(endpoint.args[1])
        domains[index] = set()
        if action == current:
            if name not in request or name not in fields:
                return None
            destinations.append((index, name))
            if request[name] is None and not any(
                c.operator == "eq" and endpoint in (c.left, c.right) for c in couplings
            ):
                return None
        action_index = actions.index(action)
        field = fields[name] if action == current else None
        for occurrence_index, value_index in _endpoint_values(
            endpoint, rows[action], values, field
        ):
            domains[index].add(value_index)
            program.append(f"_value({index},{occurrence_index},{value_index}).")
        if not domains[index]:
            return None
        body.append(f"_value({index},O{action_index},V{index})")
    for index, coupling in enumerate(couplings):
        left, right = endpoints.index(coupling.left), endpoints.index(coupling.right)
        body.append(f"_holds({index},V{left},V{right})")
        program.extend(
            _relation_facts(index, coupling, domains[left], domains[right], values)
        )
    arguments = ",".join(f"V{i}" for i, _ in destinations)
    program.append(f"_binding({arguments}) :- {','.join(body)}.")
    try:
        solutions = ClingoEngine().solve(QdlGraph(), query_rules=program)
    except RuntimeError:
        return None
    bindings = {
        atom[len("_binding(") : -1]
        for solution in solutions
        for atom in solution.atoms
        if atom.startswith("_binding(")
    }
    if len(bindings) != 1:
        return None
    selected = tuple(int(i) for i in bindings.pop().split(","))
    request.update(
        (name, values[value])
        for (_, name), value in zip(destinations, selected, strict=True)
    )
    return check.model_copy(update={"request": tuple(request.items())})


def _distinct_values(
    rows: dict[str, dict[str, dict[Struct, JsonValue]]],
) -> list[JsonValue]:
    values: list[JsonValue] = []
    for occurrences in rows.values():
        for row in occurrences.values():
            for value in row.values():
                if value is not None and not any(
                    type(existing) is type(value) and existing == value
                    for existing in values
                ):
                    values.append(value)
    return values


def _endpoint_values(
    endpoint: Struct,
    occurrences: dict[str, dict[Struct, JsonValue]],
    values: list[JsonValue],
    field: FieldSpec | None,
) -> Iterator[tuple[int, int]]:
    for occurrence_index, row in enumerate(occurrences.values()):
        if endpoint not in row:
            continue
        candidates = (
            values if field is not None and row[endpoint] is None else [row[endpoint]]
        )
        for value in candidates:
            if value is None or (
                field is not None and not _field_accepts(field, value)
            ):
                continue
            value_index = next(
                index
                for index, existing in enumerate(values)
                if type(existing) is type(value) and existing == value
            )
            yield occurrence_index, value_index


def _relation_facts(
    index: int,
    coupling: FieldCoupling,
    left: set[int],
    right: set[int],
    values: list[JsonValue],
) -> Iterator[str]:
    for a in left:
        for b in right:
            if _coupled_values_hold(values[a], values[b], coupling.operator):
                yield f"_holds({index},{a},{b})."


def _field_accepts(field: FieldSpec, value: object) -> bool:
    if field.repeated:
        if not isinstance(value, tuple):
            return False
        scalar = field.model_copy(update={"repeated": False})
        return all(_field_accepts(scalar, item) for item in value)
    if field.enum_values:
        return isinstance(value, str) and value in field.enum_values
    bounds = integer_range(field.type)
    if bounds is not None:
        return type(value) is int and _within_bounds(field, value, bounds)
    bounds = float_range(field.type)
    if bounds is not None:
        return (
            type(value) in (int, float)
            and math.isfinite(value)
            and _within_bounds(field, value, bounds)
        )
    if field.type.lower() in {"bool", "boolean"}:
        return type(value) is bool
    if field.type.lower() in {"string", "str", "bytes"}:
        return isinstance(value, str)
    return False


def _within_bounds(
    field: FieldSpec,
    value: int | float,
    bounds: tuple[int | float, int | float],
) -> bool:
    lower = max(bounds[0], field.minimum if field.minimum is not None else bounds[0])
    upper = min(bounds[1], field.maximum if field.maximum is not None else bounds[1])
    return lower <= value <= upper


def _coupled_values_hold(left: object, right: object, relation: str) -> bool:
    compare = {
        "eq": operator.eq,
        "ne": operator.ne,
        "lt": operator.lt,
        "le": operator.le,
        "gt": operator.gt,
        "ge": operator.ge,
    }.get(relation)
    if compare is None:
        raise ValueError(f"unknown coupled operator: {relation!r}")
    if type(left) is not type(right):
        return False
    if isinstance(left, tuple):
        return len(left) == len(right) and all(
            _coupled_values_hold(a, b, relation)
            for a, b in zip(left, right, strict=True)
        )
    try:
        return compare(left, right)
    except TypeError:
        return False


__all__ = ["solve_coupled_request"]
