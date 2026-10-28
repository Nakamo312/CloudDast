"""Pure operations over canonical QDL graphs."""

from __future__ import annotations

from collections.abc import Iterable

from cloud_dast.qdl.graph import Atom, Fact, QdlGraph, Rule, canonical_json


def atom_value(term: object) -> str | None:
    """Return the string value of an atom, if ``term`` is one."""

    if isinstance(term, Atom) and isinstance(term.value, str):
        return term.value
    return None


def merge_facts(graph: QdlGraph, facts: Iterable[Fact]) -> QdlGraph:
    """Merge facts into a graph without duplicating canonical content."""

    existing = {canonical_json(fact) for fact in graph.facts}
    additions = tuple(fact for fact in facts if canonical_json(fact) not in existing)
    if not additions:
        return graph
    return QdlGraph(facts=(*graph.facts, *additions), rules=graph.rules)


def merge_graphs(*graphs: QdlGraph) -> QdlGraph:
    """Merge graphs by canonical fact and rule content."""

    facts: list[Fact] = []
    rules: list[Rule] = []
    seen_facts: set[str] = set()
    seen_rules: set[str] = set()
    for graph in graphs:
        for fact in graph.facts:
            key = canonical_json(fact)
            if key not in seen_facts:
                seen_facts.add(key)
                facts.append(fact)
        for rule in graph.rules:
            key = canonical_json(rule)
            if key not in seen_rules:
                seen_rules.add(key)
                rules.append(rule)
    return QdlGraph(facts=tuple(facts), rules=tuple(rules))


__all__ = ["atom_value", "merge_facts", "merge_graphs"]
