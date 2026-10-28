"""QDL projections from canonical graphs to planning views."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Protocol

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    error,
    latency,
    status,
    trace,
)
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticNormCompiler,
)

logger = logging.getLogger(__name__)


class ThreatFactCompiler(Protocol):
    """Compiler for optional derived threat facts."""

    def compile_cached(self, graph: QdlGraph) -> Iterable[Fact]: ...


def with_attacker(graph: QdlGraph, principal_id: str) -> QdlGraph:
    """Add the campaign hypothesis that a principal is the attacker."""

    principal = Atom(value=f"principal:{principal_id}")
    return merge_graphs(
        graph,
        QdlGraph(
            facts=(
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(principal, Atom(value="Subject")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("attacker"),
                    args=(principal,),
                ),
            )
        ),
    )


def with_derived_threats(
    graph: QdlGraph,
    threat_compiler: ThreatFactCompiler | None = None,
) -> QdlGraph:
    """Compile deterministic and cached threat facts for the planner."""

    try:
        facts: tuple[Fact, ...] = ()
        if threat_compiler is not None:
            facts = (*facts, *threat_compiler.compile_cached(graph))
        facts = (*facts, *SemanticNormCompiler().compile(graph))
        unique_facts = {canonical_json(fact): fact for fact in facts}
        facts = tuple(unique_facts[key] for key in sorted(unique_facts))
        if not facts:
            return graph
        return merge_graphs(graph, QdlGraph(facts=facts))
    except Exception as error:  # noqa: BLE001 - compilation is best-effort
        logger.warning(
            "threat_intent_compilation_failed reason=%.200s",
            error,
        )
        return graph


def campaign_view(
    graph: QdlGraph,
    principal_id: str,
    service: str,
    threat_compiler: ThreatFactCompiler | None = None,
) -> QdlGraph:
    """Build the planner-facing graph for one live campaign.

    The order is part of the application contract: campaign hypothesis,
    universal witnesses, availability premise, derived threats, then the
    trusted planner projection. Workflow supplies campaign identity and
    sequencing inputs but does not own these QDL rules.
    """

    graph = with_attacker(graph, principal_id)
    graph = ground_universal_exposes(graph)
    graph = ground_availability_norms(graph, service)
    graph = with_derived_threats(graph, threat_compiler)
    return planner_view(graph)


def ground_universal_exposes(graph: QdlGraph) -> QdlGraph:
    """Ground the witness channels every declared action exposes."""

    seen: set[str] = set()
    actions: list[object] = []
    for fact in graph.facts:
        if (
            fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
        ):
            key = canonical_json(fact.args[0])
            if key not in seen:
                seen.add(key)
                actions.append(fact.args[0])
    if not actions:
        return graph

    facts: list[Fact] = []
    for action in actions:
        facts.append(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            )
        )
        for witness in (status(action), error(action), latency(action), trace(action)):
            facts.extend(
                (
                    Fact(
                        context=Context.ACCEPTED,
                        predicate=Predicate.from_name("is"),
                        args=(witness, Atom(value="Witness")),
                    ),
                    Fact(
                        context=Context.ACCEPTED,
                        predicate=Predicate.from_name("exposes"),
                        args=(action, witness),
                    ),
                )
            )
    return merge_graphs(graph, QdlGraph(facts=tuple(facts)))


def ground_availability_norms(graph: QdlGraph, service: str) -> QdlGraph:
    """Ground the service availability premise for every declared subject."""

    principals = [
        fact.args[0]
        for fact in graph.facts
        if (
            fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Subject"
            and atom_value(fact.args[0]) is not None
        )
    ]
    if not principals:
        return graph

    resource = Atom(value=f"resource:service:{service}")
    facts: list[Fact] = [
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(resource, Atom(value="Resource")),
        )
    ]
    seen: set[str] = set()
    for principal in principals:
        key = canonical_json(principal)
        if key in seen:
            continue
        seen.add(key)
        facts.extend(
            (
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(principal, Atom(value="Subject")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("required"),
                    args=(principal, resource),
                ),
            )
        )
    return merge_graphs(graph, QdlGraph(facts=tuple(facts)))


def planner_view(graph: QdlGraph) -> QdlGraph:
    """Return the trusted graph surface consumed by the QDL planner."""

    contract_declarations = {
        canonical_json(fact.args)
        for fact in graph.facts
        if fact.context is Context.CONTRACT and fact.predicate.name == "is"
    }
    facts: list[Fact] = []
    changed = False
    for fact in graph.facts:
        if fact.context is Context.RUNTIME and fact.predicate.name == "evidence":
            changed = True
            continue
        if (
            fact.context in {Context.ACCEPTED, Context.PROPOSAL}
            and fact.predicate.name == "is"
            and canonical_json(fact.args) in contract_declarations
        ):
            changed = True
            continue
        facts.append(fact)
    if not changed:
        return graph
    return QdlGraph(facts=tuple(facts), rules=graph.rules)


__all__ = [
    "ThreatFactCompiler",
    "campaign_view",
    "ground_availability_norms",
    "ground_universal_exposes",
    "planner_view",
    "with_attacker",
    "with_derived_threats",
]
