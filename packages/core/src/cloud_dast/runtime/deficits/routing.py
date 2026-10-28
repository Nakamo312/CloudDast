"""Deficit-to-consultation routing algebra."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any, cast

from cloud_dast.consultation import (
    ConsultationBudget,
    ConsultationKind,
    ConsultationRequest,
    EvidenceContext,
    axis_for_predicate_class,
)
from cloud_dast.qdl.graph import QdlGraph, Variable
from cloud_dast.runtime.consultation.axes import LLM_AXES
from cloud_dast.runtime.deficits.model import (
    CONSULTATION_DEFICIT_KIND,
    Deficit,
    DeficitKey,
    _context_value,
)
from cloud_dast.runtime.planning import QdlSubgoal, derivable
from cloud_dast.verification.slices import build_slice

logger = logging.getLogger("cloud_dast.runtime.deficits.routing")

# Existential positions shared by deficit constructors.
_ANY_ACTION = Variable(name="AnyAction")
_ANY_EFFECT = Variable(name="AnyEffect")
_ANY_FIELD = Variable(name="AnyField")
_ANY_ROLE = Variable(name="AnyRole")
_ANY_RESOURCE = Variable(name="AnyResource")
_ANY_MS = Variable(name="AnyMilliseconds")
_ANY_NORM = Variable(name="AnyNorm")
_ANY_NODE = Variable(name="AnyNode")
_ANY_DIMENSION = Variable(name="AnyDimension")
_ANY_TARGET = Variable(name="AnyTarget")
_ANY_WITNESS = Variable(name="AnyWitness")
_ANY_FROM = Variable(name="AnyFrom")
_ANY_TYPE = Variable(name="AnyType")


def axis_for_subgoal(
    subgoal: QdlSubgoal,
    *,
    live_response: bool = False,
    classification: bool = False,
) -> str | None:
    """Select the consultation axis for one subgoal."""

    kind = axis_for_predicate_class(
        subgoal.predicate,
        EvidenceContext(
            live_response=live_response,
            effect_constructor=subgoal.effect_constructor,
            classification=classification,
        ),
    )
    return cast(str, kind) if kind is not None else None


def consultation_deficit(
    subgoal: QdlSubgoal,
    *,
    action: str = "",
    context: tuple[tuple[str, str], ...] = (),
) -> Deficit:
    """Materialize a predicate class with no consultation producer."""

    logger.info(
        "consultation_deficit class=%s action=%s subgoal=%s",
        subgoal.predicate,
        action or "-",
        subgoal.render(),
    )
    return Deficit(
        subgoal=subgoal,
        predicate_class=subgoal.predicate,
        axis=None,
        action=action,
        context=(("deficit_kind", CONSULTATION_DEFICIT_KIND), *context),
    )


def build_deficit(
    subgoal: QdlSubgoal,
    *,
    action: str,
    context: tuple[tuple[str, str], ...] = (),
    live_response: bool = False,
    classification: bool = False,
) -> Deficit:
    """Build one deficit routed through the total consultation algebra."""

    axis = axis_for_subgoal(
        subgoal,
        live_response=live_response,
        classification=classification,
    )
    if axis is None:
        return consultation_deficit(subgoal, action=action, context=context)
    return Deficit(
        subgoal=subgoal,
        predicate_class=subgoal.predicate,
        axis=axis,
        action=action,
        context=context,
    )


def unprovable_subgoal(
    subgoal: QdlSubgoal,
    graph: QdlGraph,
    *,
    action: str = "",
    context: tuple[tuple[str, str], ...] = (),
    live_response: bool = False,
    classification: bool = False,
) -> Deficit | None:
    """Return a deficit when ``subgoal`` is not derivable from ``graph``."""

    if derivable(subgoal, graph):
        return None
    return build_deficit(
        subgoal,
        action=action,
        context=context,
        live_response=live_response,
        classification=classification,
    )


def consultation_request(
    deficit: Deficit,
    *,
    graph: QdlGraph,
    budget: ConsultationBudget,
    context: Mapping[str, Any] | None = None,
) -> ConsultationRequest | None:
    """Build the typed consultation request for one model-backed deficit."""

    if deficit.axis not in LLM_AXES:
        return None
    slice_ = build_slice(graph, actions=(deficit.action,))
    request_context = dict(context) if context is not None else {}
    request_context.update(consultation_context(deficit) or {})
    return ConsultationRequest(
        kind=cast(ConsultationKind, deficit.axis),
        deficit_id=deficit.consultation_id,
        action=deficit.action,
        slice=slice_.graph,
        budget=budget,
        context=request_context,
        background=slice_.graph,
    )


def consultation_context(deficit: Deficit) -> dict[str, Any] | None:
    """Return bounded context for one consultation axis."""

    if deficit.predicate_class == "probe_carrier":
        return {
            **dict(deficit.context),
            "unprovable_subgoal": deficit.subgoal.render(),
        }
    if deficit.axis == "classification":
        allowed_values = _context_value(deficit, "allowed_values") or ""
        return {
            "unprovable_subgoal": deficit.subgoal.render(),
            "classification_term": _context_value(deficit, "classification_term"),
            "allowed_values": tuple(
                value for value in allowed_values.split(",") if value
            ),
            **dict(deficit.context),
        }
    if deficit.predicate_class in {"refers_to", "targets"}:
        return {
            "unprovable_subgoal": deficit.subgoal.render(),
            **dict(deficit.context),
        }
    return None


def deduplicate(deficits: Iterable[Deficit]) -> tuple[Deficit, ...]:
    """Deduplicate deficits by canonical identity in stable order."""

    seen: set[DeficitKey] = set()
    unique: list[Deficit] = []
    for deficit in deficits:
        if deficit.work_item_key in seen:
            continue
        seen.add(deficit.work_item_key)
        unique.append(deficit)
    return tuple(
        sorted(
            unique,
            key=lambda item: (
                item.predicate_class,
                item.action,
                item.subgoal.render(),
            ),
        )
    )


__all__ = [
    "axis_for_subgoal",
    "build_deficit",
    "consultation_context",
    "consultation_deficit",
    "consultation_request",
    "deduplicate",
    "unprovable_subgoal",
]
