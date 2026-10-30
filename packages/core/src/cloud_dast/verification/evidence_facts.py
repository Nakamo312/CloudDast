"""Canonical QDL facts used to represent runtime evidence."""

from __future__ import annotations

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    source,
)
from cloud_dast.qdl.graph_ops import atom_value

VERIFIED_FACT_TYPE = "VerifiedFact"
OBSERVATION_TYPE = "Observation"


def runtime_fact(predicate: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.RUNTIME,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def verified_fact(fact_id: str) -> Fact:
    """Build the runtime declaration of one verified fact."""

    return runtime_fact("is", (Atom(value=fact_id), Atom(value=VERIFIED_FACT_TYPE)))


def observation_source_fact(observation_id: str) -> Fact:
    """Link an observation to its durable provenance."""

    return runtime_fact(
        "evidence",
        (
            Atom(value=observation_id),
            source(Atom(value="observation"), Atom(value=observation_id)),
        ),
    )


def evidence_fact(observation_id: str, field_name: str) -> Fact:
    """Build runtime evidence that a response field was observed."""

    return runtime_fact(
        "evidence",
        (
            Atom(value=observation_id),
            source(Atom(value="response_field"), Atom(value=field_name)),
        ),
    )


def verified_fact_id(fact: Fact) -> str | None:
    """Extract the identifier from one verified-fact declaration."""

    if (
        fact.context is Context.RUNTIME
        and fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == VERIFIED_FACT_TYPE
    ):
        return atom_value(fact.args[0])
    return None


def verified_fact_ids(graph: QdlGraph) -> frozenset[str]:
    """Return identifiers of all runtime verified facts in ``graph``."""

    return frozenset(
        fact_id
        for fact in graph.facts
        if (fact_id := verified_fact_id(fact)) is not None
    )


def has_observation(graph: QdlGraph, observation_id: str) -> bool:
    """Recognize existing canonical metadata without synthesizing a new timestamp."""

    observation = Atom(value=observation_id)
    return any(
        fact.context == Context.RUNTIME
        and fact.predicate.name in {"evidence", "is"}
        and fact.args[0] == observation
        and (
            fact.predicate.name == "evidence"
            or fact.args[1] == Atom(value=OBSERVATION_TYPE)
        )
        for fact in graph.facts
    )


_DATAFLOW_CONTEXTS = (Context.CONTRACT, Context.ACCEPTED)
_DATAFLOW_SINK_TYPES = frozenset({"interpreter", "filesystem", "external_net"})


def supports_dataflows(graph: QdlGraph, action: str) -> bool:
    """Check declared action-bound context for a dataflow consultation.

    An explicit reach, a scoped sink, or an action/sink norm supplies context.
    This does not prove a sink was reached or establish a security verdict.
    """

    aliases = {action, f"action:{action}"}
    if action.startswith("action:"):
        aliases.add(action.removeprefix("action:"))
    prefixes = tuple(f"sink:{alias}:" for alias in aliases)
    sinks = {
        atom_value(fact.args[0])
        for fact in graph.facts_for("is", contexts=_DATAFLOW_CONTEXTS)
        if len(fact.args) == 2 and atom_value(fact.args[1]) in _DATAFLOW_SINK_TYPES
    }
    if any(sink is not None and sink.startswith(prefixes) for sink in sinks):
        return True
    if any(
        _read_action(fact.args[0]) in aliases
        for fact in graph.facts_for("reaches", contexts=_DATAFLOW_CONTEXTS)
        if len(fact.args) == 2
    ):
        return True
    return any(
        _targets_sink(fact.args[1], aliases, sinks)
        for fact in graph.facts_for("prevents", contexts=_DATAFLOW_CONTEXTS)
        if len(fact.args) == 2
    )


def _targets_sink(effect: object, actions: set[str], sinks: set[str | None]) -> bool:
    """Match the strict action/sink join supplied by one declared norm."""

    return (
        isinstance(effect, Struct)
        and effect.name in {"reached", "external_call"}
        and len(effect.args) == 2
        and atom_value(effect.args[0]) in actions
        and atom_value(effect.args[1]) in sinks
    )


def _read_action(term: object) -> str | None:
    """Read an action or the action component of an input-field source."""

    if isinstance(term, Struct):
        if term.name == "input_field" and term.args:
            return atom_value(term.args[0])
        return None
    return atom_value(term)


__all__ = [
    "OBSERVATION_TYPE",
    "VERIFIED_FACT_TYPE",
    "evidence_fact",
    "has_observation",
    "supports_dataflows",
    "observation_source_fact",
    "runtime_fact",
    "verified_fact",
    "verified_fact_id",
    "verified_fact_ids",
]
