"""Declared QDL value constraints over canonical input and output fields."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from cloud_dast.qdl.graph import Context, QdlGraph, Struct, canonical_json
from cloud_dast.qdl.graph_ops import atom_value

COUPLED_OPERATORS: frozenset[str] = frozenset({"eq", "ne", "lt", "le", "gt", "ge"})
type PlanCoupling = tuple[Any, Any, str]


@dataclass(frozen=True, slots=True)
class FieldCoupling:
    """One value constraint between fields of two (possibly equal) actions."""

    left: Struct
    right: Struct
    operator: str

    def __post_init__(self) -> None:
        if _field_reference(self.left) is None or _field_reference(self.right) is None:
            raise ValueError(
                "coupling endpoints must be input_field/output_field terms"
            )
        if self.operator not in COUPLED_OPERATORS:
            raise ValueError(f"unknown coupled operator: {self.operator!r}")


def normalise_action(action: str) -> str:
    """Return the method identifier encoded by a QDL action identifier."""

    return action.removeprefix("action:")


def couplings_from_plan(
    couplings: Sequence[PlanCoupling],
) -> tuple[FieldCoupling, ...]:
    """Convert plan coupling terms to fully identified solver couplings."""

    return tuple(
        FieldCoupling(left=left, right=right, operator=operator)
        for left, right, operator in couplings
    )


def couplings_for_method(
    couplings: Sequence[PlanCoupling],
    method_id: str,
) -> tuple[FieldCoupling, ...]:
    """Return request-input couplings whose two sides belong to ``method_id``.

    A cross-action coupling cannot be enforced while generating one call in
    isolation; the sequence solver owns it when both calls are present.
    """

    method = normalise_action(method_id)
    return tuple(
        FieldCoupling(left=left, right=right, operator=operator)
        for left, right, operator in couplings
        if left.name == right.name == "input_field"
        and normalise_action(atom_value(left.args[0])) == method
        and normalise_action(atom_value(right.args[0])) == method
    )


def select_outputs(
    couplings: Iterable[PlanCoupling],
    method_id: str,
    downstream: set[str],
) -> set[Struct] | None:
    """Select equality outputs reusable by downstream inputs.

    None means an applicable dependency cannot be reused as an equality witness.
    Unrelated dependencies do not constrain this source action's reuse.
    """

    witnesses: set[Struct] = set()
    for left, right, operator in couplings:
        for source, destination in ((left, right), (right, left)):
            if (
                normalise_action(atom_value(source.args[0])) != method_id
                or destination.name != "input_field"
                or normalise_action(atom_value(destination.args[0])) not in downstream
            ):
                continue
            if source.name != "output_field" or operator != "eq":
                return None
            witnesses.add(source)
    return witnesses


def couplings_from_graph(graph: QdlGraph) -> tuple[FieldCoupling, ...]:
    """Extract ``coupled`` facts as typed field couplings.

    Facts must reference both sides as ``input_field``/``output_field``
    structural terms; bare atoms cannot identify a call and are skipped.
    Unknown operators raise — the operator alphabet is closed.
    """

    couplings: list[FieldCoupling] = []
    for fact in graph.facts:
        if fact.context not in {Context.CONTRACT, Context.ACCEPTED}:
            continue
        if fact.predicate.name != "coupled" or len(fact.args) != 3:
            continue
        left = _field_reference(fact.args[0])
        right = _field_reference(fact.args[1])
        operator = atom_value(fact.args[2])
        if left is None or right is None or operator is None:
            continue
        if operator not in COUPLED_OPERATORS:
            raise ValueError(f"unknown coupled operator: {operator!r}")
        couplings.append(FieldCoupling(left=left, right=right, operator=operator))
    return tuple(couplings)


def couplings_by_action(
    graph: QdlGraph,
) -> dict[str, tuple[PlanCoupling, ...]]:
    """Group same-action couplings by action identifier.

    The result feeds ``VerificationPlan.couplings``.  Each term keeps both
    action identifiers, so a same-action coupling cannot be confused with a
    cross-action one when plans are consumed later.
    """

    grouped: dict[str, list[PlanCoupling]] = {}
    for coupling in couplings_from_graph(graph):
        left_action = atom_value(coupling.left.args[0])
        right_action = atom_value(coupling.right.args[0])
        if left_action != right_action:
            continue
        grouped.setdefault(left_action, []).append(_plan_coupling(coupling))
    return {
        action: tuple(
            sorted(
                values,
                key=lambda value: (
                    canonical_json(value[0]),
                    canonical_json(value[1]),
                    value[2],
                ),
            )
        )
        for action, values in grouped.items()
    }


def all_couplings(
    graph: QdlGraph,
) -> dict[str, tuple[PlanCoupling, ...]]:
    """Group every coupling under each action it constrains.

    Unlike :func:`couplings_by_action`, cross-action couplings are kept:
    the constraint is indexed under both actions, so either plan carries it.
    Request-input constraints are solved jointly; output terms retain their
    direction for binding actual observations during execution.
    """

    grouped: dict[str, list[PlanCoupling]] = {}
    for coupling in couplings_from_graph(graph):
        left_action = atom_value(coupling.left.args[0])
        right_action = atom_value(coupling.right.args[0])
        triple = _plan_coupling(coupling)
        actions = (
            (left_action,)
            if left_action == right_action
            else (left_action, right_action)
        )
        for action in actions:
            grouped.setdefault(action, []).append(triple)
    return {
        action: tuple(
            sorted(
                values,
                key=lambda value: (
                    canonical_json(value[0]),
                    canonical_json(value[1]),
                    value[2],
                ),
            )
        )
        for action, values in grouped.items()
    }


def _plan_coupling(coupling: FieldCoupling) -> PlanCoupling:
    return coupling.left, coupling.right, coupling.operator


def _field_reference(term: object) -> Struct | None:
    if not isinstance(term, Struct) or term.name not in {"input_field", "output_field"}:
        return None
    if len(term.args) != 2:
        return None
    action = atom_value(term.args[0])
    field = atom_value(term.args[1])
    if action is None or field is None:
        return None
    return term
