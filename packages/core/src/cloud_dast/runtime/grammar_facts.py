"""Project executable QDL graphs into bounded runtime grammar facts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from cloud_dast.contracts.grammar import (
    GrammarConstraint,
    GrammarFacts,
    GrammarFieldRule,
)
from cloud_dast.couplings import COUPLED_OPERATORS, normalise_action
from cloud_dast.model import JsonValue
from cloud_dast.qdl import reasoning
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import Atom, Fact, QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import filter_executable_graph


def compile(graph: QdlGraph, action_ids: Iterable[str]) -> dict[str, GrammarFacts]:
    """Index executable grammar once, then validate in requested action order."""
    requested = sorted(set(action_ids))
    if not requested:
        return {}
    source = filter_executable_graph(graph)
    sinks = reasoning.index_sinks(source)
    dialects = _sink_dialects(source)
    aliases: dict[str, list[str]] = defaultdict(list)
    for action in requested:
        for alias in {action, f"action:{normalise_action(action)}"}:
            aliases[alias].append(action)
    facts: dict[str, list[Fact]] = defaultdict(list)
    for fact in source.facts:
        if fact.args:
            action, _ = reasoning.read_input_field(fact.args[0])
            if action is not None:
                for requested_action in aliases.get(action, ()):
                    facts[requested_action].append(fact)
    reaches: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for source_term, target_term in ClingoEngine().reaches_plus_pairs(source):
        action, field = reasoning.read_input_field(source_term)
        sink = atom_value(target_term)
        if action is not None and field is not None and sink is not None:
            for requested_action in aliases.get(action, ()):
                reaches[requested_action].append((field, sink))
    return {
        action: _project(facts[action], reaches[action], sinks, dialects)
        for action in requested
    }


def _project(
    facts: Iterable[Fact],
    reaches: Iterable[tuple[str, str]],
    declared_sink_types: dict[str, set[str]],
    declared_dialects: dict[str, set[str]],
) -> GrammarFacts:
    formats: dict[str, set[str]] = defaultdict(set)
    constraints: dict[str, list[GrammarConstraint]] = defaultdict(list)
    sink_types: dict[str, set[str]] = defaultdict(set)
    dialects: dict[str, set[str]] = defaultdict(set)
    for field, sink in reaches:
        if types := declared_sink_types.get(sink):
            sink_types[field].update(types)
            dialects[field].update(declared_dialects.get(sink, ()))
    for fact in facts:
        _, field = reasoning.read_input_field(fact.args[0])
        if field is None:
            continue
        if fact.predicate.name == "format" and len(fact.args) == 2:
            if (format_name := atom_value(fact.args[1])) is not None:
                formats[field].add(format_name)
        elif fact.predicate.name == "constraint" and len(fact.args) == 3:
            operator = atom_value(fact.args[1])
            value = _scalar(fact.args[2])
            if operator is not None and value is not None:
                if operator not in COUPLED_OPERATORS:
                    raise ValueError(f"unknown constraint operator: {operator!r}")
                constraints[field].append(GrammarConstraint(field, operator, value))
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


def _scalar(term: object) -> JsonValue | None:
    if isinstance(term, Atom) and isinstance(term.value, (str, int, float, bool)):
        return term.value
    return None


__all__ = ["compile"]
