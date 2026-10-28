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
    Term,
    canonical_json,
    input_field,
)
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.verification.differential.report import DiffReport

_SUPERSESSION_PREDICATES = frozenset({"causes", "has"})
_CAUSES_SUPERSESSION_EFFECTS = frozenset({"reached", "duration"})
_HAS_SUPERSESSION_ROLE_FAMILIES = (frozenset({"setup_value", "setup_skip"}),)


def revision_source_id(source_id: str, graph: QdlGraph) -> str:
    """Address one immutable proposal or promotion revision explicitly."""

    return f"{source_id}:{graph.content_hash}"


def _supersession_node(fact: Fact) -> Term:
    """Return the node compared by the supersession lifecycle."""

    if fact.predicate.name == "has":
        return Struct(name="replacement", args=fact.args)
    return fact.args[-1]


def _supersession_is_meaningful(old_fact: Fact, new_fact: Fact) -> bool:
    """Restrict inferred replacement to exclusive value families."""

    if old_fact.predicate.name == "causes":
        return all(
            isinstance(fact.args[1], Struct)
            and fact.args[1].name in _CAUSES_SUPERSESSION_EFFECTS
            for fact in (old_fact, new_fact)
        )
    if old_fact.predicate.name == "has":
        old_role = atom_value(old_fact.args[1])
        new_role = atom_value(new_fact.args[1])
        if old_role is None or new_role is None:
            return False
        return any(
            {old_role, new_role} <= family for family in _HAS_SUPERSESSION_ROLE_FAMILIES
        )
    return False


def _accepted_fact_groups(graph: QdlGraph) -> dict[tuple[str, ...], list[Fact]]:
    """Group accepted facts by predicate and subject terms."""

    groups: dict[tuple[str, ...], list[Fact]] = {}
    for fact in graph.facts:
        if (
            fact.context is not Context.ACCEPTED
            or fact.predicate.name not in _SUPERSESSION_PREDICATES
            or len(fact.args) < 2
        ):
            continue
        key = (
            fact.predicate.name,
            *(canonical_json(argument) for argument in fact.args[:-1]),
        )
        groups.setdefault(key, []).append(fact)
    return groups


def _current_replacement_facts(
    graph: QdlGraph,
) -> dict[tuple[str, ...], Fact]:
    """Find unambiguous current values for supersession-capable predicates."""

    groups = _accepted_fact_groups(graph)
    current: dict[tuple[str, ...], Fact] = {}
    for key, facts in groups.items():
        nodes = {canonical_json(_supersession_node(fact)): fact for fact in facts}
        superseded = {
            canonical_json(fact.args[1])
            for fact in graph.facts
            if fact.context is Context.ACCEPTED
            and fact.predicate.name == "supersedes"
            and len(fact.args) == 2
            and canonical_json(fact.args[0]) in nodes
            and canonical_json(fact.args[1]) in nodes
        }
        current_facts = [
            fact for node_key, fact in nodes.items() if node_key not in superseded
        ]
        if len(current_facts) == 1:
            current[key] = current_facts[0]
    return current


def _supersession_node_declarations(
    node: Term,
    graphs: tuple[QdlGraph, ...],
) -> tuple[Fact, ...]:
    """Make a supersession node self-contained in the accepted context."""

    declarations: dict[str, Fact] = {}
    for graph in graphs:
        for fact in graph.facts:
            if (
                fact.context is not Context.ACCEPTED
                or fact.predicate.name != "is"
                or not fact.args
            ):
                continue
            declarations.setdefault(canonical_json(fact.args[0]), fact)

    result: list[Fact] = []
    seen: set[str] = set()

    def visit(term: Term) -> None:
        key = canonical_json(term)
        if key in seen:
            return
        seen.add(key)
        declaration = declarations.get(key)
        if declaration is None:
            declaration = Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(term, Atom(value="Node")),
            )
        else:
            declaration = declaration.model_copy(update={"context": Context.ACCEPTED})
        result.append(declaration)
        if isinstance(term, Struct):
            for argument in term.args:
                visit(argument)

    visit(node)
    return tuple(result)


def append_supersession(
    graph: QdlGraph,
    previous: QdlGraph | None,
) -> QdlGraph:
    """Append tombstones for unambiguous logical value replacements."""

    if previous is None:
        return graph
    new_groups = _accepted_fact_groups(graph)
    previous_groups = _accepted_fact_groups(previous)
    previous_current = _current_replacement_facts(previous)
    current = _current_replacement_facts(graph)
    additions: list[Fact] = []
    seen_edges: set[tuple[str, str]] = set()

    def add_edge(new_node: Term, old_node: Term) -> None:
        edge = (canonical_json(new_node), canonical_json(old_node))
        if edge in seen_edges:
            return
        seen_edges.add(edge)
        additions.append(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("supersedes"),
                args=(new_node, old_node),
            )
        )
        additions.extend(_supersession_node_declarations(new_node, (graph, previous)))
        additions.extend(_supersession_node_declarations(old_node, (graph, previous)))

    for key, new_facts in new_groups.items():
        node_keys = {
            canonical_json(_supersession_node(fact))
            for fact in (*new_facts, *previous_groups.get(key, ()))
        }
        for fact in previous.facts:
            if (
                fact.context is not Context.ACCEPTED
                or fact.predicate.name != "supersedes"
                or len(fact.args) != 2
            ):
                continue
            new_key = canonical_json(fact.args[0])
            old_key = canonical_json(fact.args[1])
            if new_key in node_keys and old_key in node_keys:
                add_edge(fact.args[0], fact.args[1])

    for key, new_fact in current.items():
        old_fact = previous_current.get(key)
        if old_fact is None:
            continue
        new_node = _supersession_node(new_fact)
        old_node = _supersession_node(old_fact)
        if canonical_json(new_node) == canonical_json(old_node):
            continue
        if not _supersession_is_meaningful(old_fact, new_fact):
            continue
        add_edge(new_node, old_node)

    if not additions:
        return graph
    unique_additions = {canonical_json(fact): fact for fact in additions}
    return merge_graphs(
        graph,
        QdlGraph(
            facts=tuple(unique_additions[key] for key in sorted(unique_additions))
        ),
    )


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
    "append_supersession",
    "classification_action_id",
    "classification_keys",
    "revision_source_id",
    "request_canary",
    "source_action_ids",
    "timing_thresholds",
    "treatment_contains_canary",
]
