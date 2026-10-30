from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cloud_dast.qdl.graph import Atom, QdlGraph, Struct
from cloud_dast.qdl.roles import semantic_role_stride

type StrideCategory = Literal["S", "T", "R", "I", "D", "E"]


@dataclass(frozen=True, slots=True)
class StrideView:
    """One STRIDE row projected from QDL for test assertions."""

    action: Atom
    field: Struct | None = None
    role: str | None = None
    effect: Struct | None = None
    categories: tuple[StrideCategory, ...] = ()


def project_stride(graph: QdlGraph) -> tuple[StrideView, ...]:
    """Project a STRIDE view from QDL facts for tests."""

    effect_categories = {
        "allowed": "S",
        "changed": "T",
        "completed": "R",
        "denied": "D",
        "duration": "D",
        "external_call": "I",
        "has": "I",
        "identity": "S",
        "reached": "E",
    }
    views: list[StrideView] = []
    for fact in graph.facts:
        if fact.predicate.name == "has":
            holder, role = fact.args
            action = _field_action(holder) if isinstance(holder, Struct) else None
            if (
                action is not None
                and isinstance(role, Atom)
                and isinstance(role.value, str)
            ):
                views.append(
                    StrideView(
                        action=action,
                        field=holder,
                        role=role.value,
                        categories=semantic_role_stride(role.value),
                    )
                )
        elif fact.predicate.name == "causes":
            action, effect = fact.args
            if isinstance(action, Atom) and isinstance(effect, Struct):
                category = effect_categories.get(effect.name)
                views.append(
                    StrideView(
                        action=action,
                        effect=effect,
                        categories=() if category is None else (category,),
                    )
                )
    return tuple(views)


def _field_action(field: Struct) -> Atom | None:
    if field.name not in {"input_field", "output_field"} or not field.args:
        return None
    action = field.args[0]
    if isinstance(action, Atom) and isinstance(action.value, str):
        return action
    return None


__all__ = ["project_stride"]
