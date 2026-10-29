"""Pure operations over canonical QDL graphs."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

import clingo

from cloud_dast.qdl.asp import decode_term
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Term,
    canonical_json,
)


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


_SUPERSESSION_PREDICATES = frozenset({"causes", "has"})

_CAUSES_SUPERSESSION_EFFECTS = frozenset({"reached", "duration"})

_HAS_SUPERSESSION_ROLE_FAMILIES = (frozenset({"setup_value", "setup_skip"}),)


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


_CURRENT_INPUTS = frozenset(
    {
        "supersedes",
        "current_has",
        "current_effect",
        "superseded_has",
        "superseded_effect",
    }
)


def _solve_current(
    graph: QdlGraph,
    engine: ClingoEngine | None,
) -> Iterator[tuple[str, Context, tuple[Term, ...]]]:
    """Evaluate current and retired rows against the same untouched input."""

    solutions = (engine if engine is not None else ClingoEngine()).solve(
        graph, closures=("current_has", "current_reached")
    )
    for solution in solutions:
        for atom in solution.atoms:
            if not atom.startswith(
                ("current_effect(", "current_has(", "superseded_effect(")
            ):
                continue
            symbol = clingo.parse_term(atom)
            if len(symbol.arguments) != 3:
                continue
            context, *args = map(decode_term, symbol.arguments)
            yield symbol.name, Context(context.value), tuple(args)


def current_facts(
    graph: QdlGraph,
    *,
    engine: ClingoEngine | None = None,
) -> tuple[Fact, ...]:
    """Read current causal/role rows without rewriting the source or its rules.

    Noncausal literals retain their historical meaning. With no rules,
    tombstones or explicit current relations, the projection is the input.
    Callers must not feed this read projection into inference or storage.
    """

    if (
        engine is None
        and not graph.rules
        and not any(fact.predicate.name in _CURRENT_INPUTS for fact in graph.facts)
    ):
        return graph.facts
    predicates = {"current_effect": "causes", "current_has": "has"}
    facts = [
        fact for fact in graph.facts if fact.predicate.name not in predicates.values()
    ]
    facts.extend(
        Fact(
            context=context, predicate=Predicate.from_name(predicates[name]), args=args
        )
        for name, context, args in _solve_current(graph, engine)
        if name in predicates
    )
    unique = {canonical_json(fact): fact for fact in facts}
    return tuple(unique.values())


def superseded_effects(
    graph: QdlGraph,
    *,
    engine: ClingoEngine | None = None,
) -> frozenset[tuple[Context, str]]:
    """Read confirmed retired providers, not merely missing current providers."""

    if (
        engine is None
        and not graph.rules
        and not any(fact.predicate.name in _CURRENT_INPUTS for fact in graph.facts)
    ):
        return frozenset()
    return frozenset(
        (context, canonical_json(args[1]))
        for name, context, args in _solve_current(graph, engine)
        if name == "superseded_effect"
    )


__all__ = [
    "atom_value",
    "append_supersession",
    "current_facts",
    "superseded_effects",
    "merge_facts",
    "merge_graphs",
]
