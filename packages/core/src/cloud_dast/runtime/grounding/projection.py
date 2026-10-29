"""Pure graph projections used by runtime grounding.

This module contains deterministic transformations over QDL graphs and
observations.  It deliberately has no model dispatch, repository writes,
queue mutation, task lifecycle, or campaign state.  ``grounding.py`` owns
orchestration and imports these functions as its projection seam.
"""

from __future__ import annotations

import math

from cloud_dast.model import Observation
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    input_field,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.differential.report import DiffReport


def revision_source_id(source_id: str, graph: QdlGraph) -> str:
    """Address one immutable proposal or promotion revision explicitly."""

    return f"{source_id}:{graph.content_hash}"


def timing_thresholds(
    action_id: str,
    report: DiffReport,
) -> dict[str, int] | None:
    """Return the control-leg robust bound for a measured timing variance."""

    evidence = report.timing_evidence
    if (
        evidence is None
        or evidence.control_samples < 3
        or evidence.control_median_ms is None
        or evidence.control_mad_ms is None
    ):
        return None
    median = evidence.control_median_ms
    mad = evidence.control_mad_ms
    spread = max(3.0 * mad, 0.1 * median, 1.0)
    return {action_id: max(1, math.ceil(median + spread))}


def action_key(action: str) -> str:
    """Normalize both action spellings to the plain method id."""

    return action.removeprefix("action:")


def source_action_ids(source: QdlGraph) -> frozenset[str]:
    """Return normalized action ids declared by executable source facts."""

    actions: set[str] = set()
    for fact in source.facts:
        if fact.context not in {Context.CONTRACT, Context.ACCEPTED}:
            continue
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        if atom_value(fact.args[1]) != "Action":
            continue
        action = atom_value(fact.args[0])
        if isinstance(action, str):
            actions.add(action if action.startswith("action:") else f"action:{action}")
    return frozenset(actions)


def classification_keys(graph: QdlGraph) -> frozenset[str]:
    """Return argument keys of classifications already trusted by the source."""

    return frozenset(
        canonical_json(fact.args)
        for fact in graph.facts
        if fact.predicate.name == "has" and len(fact.args) == 2
    )


def classification_action_id(holder: object) -> str | None:
    """Return the action bound to a classification holder, if any."""

    if not isinstance(holder, Struct) or not holder.args:
        return None
    action_id = atom_value(holder.args[0])
    return action_id if isinstance(action_id, str) else None


def _input_field(action: object, field_name: str):
    return input_field(action, _atom(field_name))


def _runtime_fact(predicate: str, args: tuple[object, ...]):
    return Fact(
        context=Context.RUNTIME,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _unique_graph(facts: list[Fact]) -> QdlGraph:
    unique = {canonical_json(fact): fact for fact in facts}
    return QdlGraph(facts=tuple(unique[key] for key in sorted(unique)))


def request_canary(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text or None


def treatment_contains_canary(
    treatment: Observation,
    report: DiffReport,
    canary: str,
) -> bool:
    changed_paths = (
        set(report.value_differs)
        | set(report.fields_only_control)
        | set(report.fields_only_treatment)
    )
    values = [
        str(value) for path, value in treatment.response_tree if path in changed_paths
    ]
    if treatment.output is not None:
        values.extend(
            str(value)
            for name, value in treatment.output.fields
            if name in changed_paths
        )
    if treatment.error_reason:
        values.append(treatment.error_reason)
    return any(canary in value for value in values)


def _atom(value: str) -> Atom:
    return Atom(value=value)


__all__ = [
    "action_key",
    "classification_action_id",
    "classification_keys",
    "revision_source_id",
    "request_canary",
    "source_action_ids",
    "timing_thresholds",
    "treatment_contains_canary",
]
