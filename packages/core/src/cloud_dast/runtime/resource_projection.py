"""Pure QDL projections for executable resources and states."""

from __future__ import annotations

from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.graph import Atom, QdlGraph, Term
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.reasoning import derive_requirements, term_unifies
from cloud_dast.runtime.reference_projection import (
    resource_type_name,
)
from cloud_dast.verification.invariant_projection import (
    EXECUTABLE_CONTEXTS,
)


def target_resources(graph: QdlGraph, method_id: str) -> frozenset[str]:
    """Return executable QDL resources targeted by one action."""

    aliases = {method_id, f"action:{method_id}"}
    resources: set[str] = set()
    for fact in graph.facts_for("targets", contexts=EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        resource = atom_value(fact.args[1])
        if action in aliases and isinstance(resource, str):
            resources.add(resource)
    return frozenset(resources)


def target_resource_type(graph: QdlGraph, method_id: str) -> str | None:
    """Resolve a unique executable target resource type, if one exists."""

    resources = target_resources(graph, method_id)
    if len(resources) != 1:
        return None
    return resource_type_name(next(iter(resources)))


def services(graph: QdlGraph) -> frozenset[str]:
    """Return executable service identifiers declared by QDL."""

    values: set[str] = set()
    for fact in graph.facts_for("is", contexts=EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        service = atom_value(fact.args[0])
        if atom_value(fact.args[1]) == "Service" and isinstance(service, str):
            values.add(service.removeprefix("service:"))
    return frozenset(values)


def service_for_resource_type(graph: QdlGraph, resource_type: str) -> str | None:
    """Resolve a unique QDL service owning one resource type."""

    parts = {
        (atom_value(fact.args[0]), atom_value(fact.args[1]))
        for fact in graph.facts_for("part", contexts=EXECUTABLE_CONTEXTS)
        if len(fact.args) == 2
    }
    matches = {
        service
        for service in services(graph)
        if (f"resource:{resource_type}", f"service:{service}") in parts
    }
    return next(iter(matches)) if len(matches) == 1 else None


def required_states(
    graph: QdlGraph,
    method_id: str,
    resource_type: str,
    *,
    requirement_rows: tuple[tuple[Term, ...], ...] | None = None,
) -> tuple[str, ...]:
    """Project explicit QDL state requirements for an action and resource."""

    states = {
        atom_value(fact.args[0])
        for fact in graph.facts_for("is", contexts=EXECUTABLE_CONTEXTS)
        if len(fact.args) == 2 and atom_value(fact.args[1]) == "State"
    }
    if requirement_rows is None:
        requirement_rows = derive_requirements(graph, contexts=EXECUTABLE_CONTEXTS)
    required = {
        state
        for state in states
        if state is not None
        and any(
            len(args) == 2
            and term_unifies(Atom(value=method_id), args[0])
            and term_unifies(Atom(value=state), args[1])
            for args in requirement_rows
        )
    }
    for fact in graph.facts_for("precondition", contexts=EXECUTABLE_CONTEXTS):
        if (
            len(fact.args) == 3
            and atom_value(fact.args[0]) in action_aliases(method_id)
            and resource_type_name(atom_value(fact.args[1]) or "") == resource_type
        ):
            state = atom_value(fact.args[2])
            if state is not None:
                required.add(state)
    return tuple(sorted(required))


__all__ = [
    "required_states",
    "service_for_resource_type",
    "services",
    "target_resource_type",
    "target_resources",
]
