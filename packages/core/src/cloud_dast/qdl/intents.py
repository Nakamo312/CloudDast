"""QDL intent declarations and proposal-context projections."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    PredicateSchema,
    QdlGraph,
    TermKind,
)
from cloud_dast.qdl.graph_ops import atom_value

INTENT_TYPE = "Intent"
FACT_TYPE = "Fact"


def _reference(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
        reference=True,
    )


INTENT_PREREQUISITE = Predicate.from_schema(
    PredicateSchema(
        name="intent_prerequisite",
        arguments=(_reference("intent"), _reference("prerequisite")),
    )
)
INTENT_EFFECT = Predicate.from_schema(
    PredicateSchema(
        name="intent_effect",
        arguments=(_reference("intent"), _reference("effect")),
    )
)
INTENT_ASSUMPTION = Predicate.from_schema(
    PredicateSchema(
        name="intent_assumption",
        arguments=(_reference("intent"), _reference("assumption")),
    )
)

_INTENT_EDGE_PREDICATES = frozenset(
    {INTENT_PREREQUISITE.name, INTENT_EFFECT.name, INTENT_ASSUMPTION.name}
)
_INTENT_PREDICATES = {
    INTENT_PREREQUISITE.name: INTENT_PREREQUISITE,
    INTENT_EFFECT.name: INTENT_EFFECT,
    INTENT_ASSUMPTION.name: INTENT_ASSUMPTION,
}


def intent_graph(
    intent_id: str,
    *,
    prerequisites: Iterable[str] = (),
    effects: Iterable[str] = (),
    assumptions: Iterable[str] = (),
) -> QdlGraph:
    """Build one closed proposal-context graph for a planned intent."""

    prerequisite_ids = tuple(prerequisites)
    effect_ids = tuple(effects)
    assumption_ids = tuple(assumptions)
    for name, values in (
        ("prerequisites", prerequisite_ids),
        ("effects", effect_ids),
        ("assumptions", assumption_ids),
    ):
        if any(not value for value in values):
            raise ValueError(f"intent {name} must contain non-empty identifiers")
        if len(values) != len(set(values)):
            raise ValueError(f"intent {name} must not contain duplicates")
    overlap = set(prerequisite_ids).intersection(effect_ids)
    if overlap:
        names = ", ".join(sorted(overlap))
        raise ValueError(f"intent cannot require and produce the same fact: {names}")
    assumed_and_required = set(prerequisite_ids).intersection(assumption_ids)
    if assumed_and_required:
        names = ", ".join(sorted(assumed_and_required))
        raise ValueError(f"intent cannot require and assume the same fact: {names}")

    facts: list[Fact] = [_proposal_fact("is", (_atom(intent_id), _atom(INTENT_TYPE)))]
    for atom_id in sorted({*prerequisite_ids, *effect_ids, *assumption_ids}):
        facts.append(_proposal_fact("is", (_atom(atom_id), _atom(FACT_TYPE))))
    for prerequisite in sorted(prerequisite_ids):
        facts.append(
            _proposal_fact(
                INTENT_PREREQUISITE.name, (_atom(intent_id), _atom(prerequisite))
            )
        )
    for effect in sorted(effect_ids):
        facts.append(
            _proposal_fact(INTENT_EFFECT.name, (_atom(intent_id), _atom(effect)))
        )
    for assumption in sorted(assumption_ids):
        facts.append(
            _proposal_fact(
                INTENT_ASSUMPTION.name, (_atom(intent_id), _atom(assumption))
            )
        )
    return QdlGraph(facts=tuple(facts))


@dataclass(frozen=True, slots=True)
class PlannedIntent:
    """Derived, read-only projection of one QDL intent graph."""

    intent_id: str
    prerequisites: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    description: str = ""


def intent_ids(graph: QdlGraph) -> tuple[str, ...]:
    """Return identifiers of intents declared in ``graph``."""

    return tuple(
        sorted(
            atom_value(fact.args[0])
            for fact in graph.facts
            if _declares_type(fact, Context.PROPOSAL, INTENT_TYPE)
        )
    )


def planned_intent(graph: QdlGraph, intent_id: str) -> PlannedIntent:
    """Project one declared intent from the QDL graph."""

    for view in planned_intents(graph):
        if view.intent_id == intent_id:
            return view
    raise KeyError(intent_id)


def planned_intents(graph: QdlGraph) -> tuple[PlannedIntent, ...]:
    """Project every declared intent from the QDL graph."""

    edges: dict[str, dict[str, list[str]]] = {
        intent_id: {name: [] for name in _INTENT_EDGE_PREDICATES}
        for intent_id in intent_ids(graph)
    }
    for fact in graph.facts:
        if fact.context is not Context.PROPOSAL:
            continue
        if fact.predicate.name not in _INTENT_EDGE_PREDICATES:
            continue
        subject = atom_value(fact.args[0])
        target = atom_value(fact.args[1])
        if subject in edges and target is not None:
            edges[subject][fact.predicate.name].append(target)
    return tuple(
        PlannedIntent(
            intent_id=intent_id,
            prerequisites=tuple(sorted(values[INTENT_PREREQUISITE.name])),
            assumptions=tuple(sorted(values[INTENT_ASSUMPTION.name])),
            effects=tuple(sorted(values[INTENT_EFFECT.name])),
        )
        for intent_id, values in edges.items()
    )


def intent_subgraph(graph: QdlGraph, intent_id: str) -> QdlGraph:
    """Return the closed QDL subgraph describing one intent."""

    facts: list[Fact] = []
    referenced: set[str] = set()
    for fact in graph.facts:
        if fact.context is not Context.PROPOSAL:
            continue
        subject = atom_value(fact.args[0]) if fact.args else None
        if fact.predicate.name in _INTENT_EDGE_PREDICATES and subject == intent_id:
            facts.append(fact)
            target = atom_value(fact.args[1])
            if target is not None:
                referenced.add(target)
        elif (
            _declares_type(fact, Context.PROPOSAL, INTENT_TYPE) and subject == intent_id
        ):
            facts.append(fact)
    for fact in graph.facts:
        if _declares_type(fact, Context.PROPOSAL, FACT_TYPE):
            if atom_value(fact.args[0]) in referenced:
                facts.append(fact)
    return QdlGraph(facts=tuple(facts))


def _proposal_fact(predicate_name: str, args: tuple[object, ...]) -> Fact:
    predicate = _INTENT_PREDICATES.get(predicate_name)
    if predicate is None:
        predicate = Predicate.from_name(predicate_name)
    return Fact(
        context=Context.PROPOSAL,
        predicate=predicate,
        args=args,  # type: ignore[arg-type]
    )


def _atom(value: str) -> Atom:
    return Atom(value=value)


def _declares_type(fact: Fact, context: Context, type_name: str) -> bool:
    if fact.context is not context or fact.predicate.name != "is":
        return False
    return len(fact.args) == 2 and atom_value(fact.args[1]) == type_name


__all__ = [
    "FACT_TYPE",
    "INTENT_ASSUMPTION",
    "INTENT_EFFECT",
    "INTENT_PREREQUISITE",
    "INTENT_TYPE",
    "PlannedIntent",
    "intent_graph",
    "intent_ids",
    "intent_subgraph",
    "planned_intent",
    "planned_intents",
]
