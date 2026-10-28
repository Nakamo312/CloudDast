"""Project executable QDL graphs into bounded runtime grammar facts."""

from __future__ import annotations

from cloud_dast.contracts.grammar import (
    GrammarConstraint,
    GrammarFacts,
    GrammarFieldRule,
)
from cloud_dast.couplings import (
    COUPLED_OPERATORS,
    normalise_action,
)
from cloud_dast.model import JsonValue
from cloud_dast.qdl import reasoning
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import Atom, QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import (
    filter_executable_graph,
)


def facts_from_graph(graph: QdlGraph, action_id: str) -> GrammarFacts:
    """Project contract/accepted grammar facts for one action."""

    source = filter_executable_graph(graph)
    actions = {action_id, f"action:{normalise_action(action_id)}"}
    formats: dict[str, set[str]] = {}
    constraints: dict[str, list[GrammarConstraint]] = {}
    sink_types: dict[str, set[str]] = {}
    dialects: dict[str, set[str]] = {}

    declared_sink_types = reasoning.index_sinks(source)
    declared_dialects = _sink_dialects(source)
    for source_term, target_term in ClingoEngine().reaches_plus_pairs(source):
        field = _field_reference(source_term, actions)
        sink = atom_value(target_term)
        if field is None or sink is None:
            continue
        types = declared_sink_types.get(sink, set())
        if not types:
            continue
        sink_types.setdefault(field, set()).update(types)
        dialects.setdefault(field, set()).update(declared_dialects.get(sink, set()))

    for fact in source.facts:
        if fact.predicate.name == "format" and len(fact.args) == 2:
            field = _field_reference(fact.args[0], actions)
            format_name = atom_value(fact.args[1])
            if field is not None and format_name is not None:
                formats.setdefault(field, set()).add(format_name)
        elif fact.predicate.name == "constraint" and len(fact.args) == 3:
            field = _field_reference(fact.args[0], actions)
            operator = atom_value(fact.args[1])
            value = _scalar(fact.args[2])
            if field is not None and operator is not None and value is not None:
                if operator not in COUPLED_OPERATORS:
                    raise ValueError(f"unknown constraint operator: {operator!r}")
                constraints.setdefault(field, []).append(
                    GrammarConstraint(field=field, operator=operator, value=value)
                )

    return GrammarFacts(
        fields=tuple(
            GrammarFieldRule(
                field=field,
                formats=tuple(sorted(formats.get(field, ()))),
                constraints=tuple(constraints.get(field, ())),
                sink_types=tuple(sorted(sink_types.get(field, ()))),
                dialects=tuple(sorted(dialects.get(field, ()))),
            )
            for field in sorted(
                formats.keys()
                | constraints.keys()
                | sink_types.keys()
                | dialects.keys()
            )
        )
    )


def _sink_dialects(graph: QdlGraph) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for fact in graph.facts:
        if fact.predicate.name != "dialect" or len(fact.args) != 2:
            continue
        sink = atom_value(fact.args[0])
        dialect = atom_value(fact.args[1])
        if sink is not None and dialect is not None:
            result.setdefault(sink, set()).add(dialect)
    return result


def _field_reference(term: object, actions: set[str]) -> str | None:
    action, field = reasoning.read_input_field(term)
    return field if action in actions else None


def _scalar(term: object) -> JsonValue | None:
    if isinstance(term, Atom) and isinstance(term.value, (str, int, float, bool)):
        return term.value
    return None


__all__ = ["facts_from_graph"]
