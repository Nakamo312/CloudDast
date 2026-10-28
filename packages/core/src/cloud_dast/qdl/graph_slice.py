"""Deterministic QDL slices for bounded model requests."""

from __future__ import annotations

from cloud_dast.qdl.graph import Atom, Fact, QdlGraph, Rule, Struct, canonical_json
from cloud_dast.qdl.graph_ops import atom_value


def slice_graph_by_actions(
    graph: QdlGraph,
    *,
    max_actions: int | None = 12,
) -> QdlGraph:
    """Return a self-contained slice centered on a bounded set of actions."""

    if max_actions is not None and max_actions <= 0:
        raise ValueError("max_actions must be positive or None")

    actions = sorted(
        (
            fact.args[0]
            for fact in graph.facts
            if fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
        ),
        key=lambda term: canonical_json(term),
    )
    selected = actions if max_actions is None else actions[:max_actions]
    selected_keys = {canonical_json(term) for term in selected}
    if not selected_keys:
        return QdlGraph()

    related_facts = tuple(
        fact for fact in graph.facts if _contains_any(fact.args, selected_keys)
    )
    related_rules = tuple(
        rule
        for rule in graph.rules
        if _contains_any((*rule.body, *rule.head), selected_keys)
    )
    declarations = _declarations_for(graph, related_facts, related_rules)
    facts = _unique((*related_facts, *declarations))
    return QdlGraph(facts=facts, rules=related_rules)


def _declarations_for(
    graph: QdlGraph,
    facts: tuple[Fact, ...],
    rules: tuple[Rule, ...],
) -> tuple[Fact, ...]:
    references = {key for fact in facts for key in _term_keys(fact.args)} | {
        key
        for rule in rules
        for literal in (*rule.body, *rule.head)
        for key in _term_keys(literal.args)
    }
    return tuple(
        fact
        for fact in graph.facts
        if fact.predicate.name == "is"
        and fact.args
        and canonical_json(fact.args[0]) in references
    )


def _contains_any(terms: tuple[object, ...], keys: set[str]) -> bool:
    return any(key in keys for term in terms for key in _term_keys(term))


def _term_keys(term: object) -> set[str]:
    if isinstance(term, Fact):
        return _term_keys(term.args)
    if isinstance(term, Rule):
        return {
            key
            for literal in (*term.body, *term.head)
            for key in _term_keys(literal.args)
        }
    if isinstance(term, Atom):
        return {canonical_json(term)}
    if isinstance(term, Struct):
        return {canonical_json(term)} | {
            key for argument in term.args for key in _term_keys(argument)
        }
    if isinstance(term, tuple):
        return {key for argument in term for key in _term_keys(argument)}
    return set()


def _unique(facts: tuple[Fact, ...]) -> tuple[Fact, ...]:
    return tuple({canonical_json(fact): fact for fact in facts}.values())


__all__ = ["slice_graph_by_actions"]
