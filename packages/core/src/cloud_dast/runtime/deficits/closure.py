"""Pure graph projections for deficit closure and stale-state detection."""

from __future__ import annotations

from cloud_dast.model import Observation
from cloud_dast.qdl.field_roles import resolve_field_roles
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import EXPOSURE_WITNESS_NAMES
from cloud_dast.runtime.consultation.axes import LLM_AXES
from cloud_dast.runtime.deficits.model import (
    RESPONSE_SEMANTICS_AXIS,
    Deficit,
    _context_value,
)
from cloud_dast.runtime.planning import QdlSubgoal, derivable

_VARIANCE_FIELD_CLOSURE_PREDICATES = frozenset(
    {"causes", "exposes", "has", "prevents", "reaches", "requires"}
)
_VARIANCE_EFFECT_CLOSURE_PREDICATES = frozenset({"causes", "prevents", "reaches"})
_SIGNAL_GROUNDING_PREDICATE = "signal_grounds"
_SINK_INTERPRETATION_PREDICATE = "sink_interprets"
_TRANSPORT_SENTINEL_ROOTS = frozenset({"__truncated__", "__response__", "__unknown__"})

__all__ = [
    "action_aliases",
    "deficit_is_stale",
    "declared_actions",
    "effect_action",
    "effect_field",
    "grounded_output_paths",
    "grounding_result_closes_deficit",
    "has_exposed_output",
    "interpreted_signal_kinds",
    "is_transport_sentinel",
    "observation_action",
]


def grounding_result_closes_deficit(
    deficit: Deficit,
    graph: QdlGraph | None,
    *,
    observation: Observation | None = None,
) -> bool:
    """Return whether a promoted graph proves the deficit's subgoal.

    A non-empty grounding result is only transport evidence. Closure is
    algebraic: the promoted graph must derive the deficit's QDL subgoal.
    Grouped response/variance requirements close only when every measured
    field is grounded. The optional observation is retained in the contract
    for callers that carry it, but closure itself is graph-based.
    """

    del observation
    if graph is None or not graph.facts:
        return False
    if deficit.axis not in LLM_AXES:
        return False
    graph = _apply_supersedes(graph)

    if deficit.axis == "classification":
        # An existential role/type is constrained by the catalog's pre-image.
        # A generic declaration such as is(Sink, Sink) cannot discharge the
        # missing security classification merely by binding AnyType.
        allowed = (_context_value(deficit, "allowed_values") or "").split(",")
        return any(
            value
            and derivable(
                QdlSubgoal(
                    deficit.subgoal.predicate,
                    (*deficit.subgoal.args[:-1], Atom(value=value)),
                ),
                graph,
                contexts=(Context.CONTRACT, Context.ACCEPTED),
            )
            for value in allowed
        )

    if deficit.predicate_class == "exposes" and deficit.axis == RESPONSE_SEMANTICS_AXIS:
        signal = _context_value(deficit, "signal")
        if signal is not None:
            return signal in interpreted_signal_kinds(graph, deficit.action)
        output_paths = frozenset((_context_value(deficit, "fields") or "").split(","))
        if not output_paths:
            return False
        aliases = action_aliases(deficit.action)
        grounded_paths = grounded_output_paths(graph)
        return all(
            any((alias, output_path) in grounded_paths for alias in aliases)
            for output_path in output_paths
        )
    if deficit.predicate_class == "prevents":
        signal = _context_value(deficit, "signal")
        if signal is not None:
            return signal in interpreted_signal_kinds(graph, deficit.action)
        return _variance_result_closes(deficit, graph)
    return derivable(deficit.subgoal, graph)


def deficit_is_stale(
    deficit: Deficit,
    result: QdlGraph,
    *,
    active_path_ids: frozenset[str] | None,
) -> bool:
    """Return whether a deficit refers to a removed or replaced path."""

    if active_path_ids is not None:
        path_id = _context_value(deficit, "path_id")
        if path_id is not None and path_id not in active_path_ids:
            return True
    effect = _context_value(deficit, "effect")
    if not effect:
        return False
    return any(
        fact.predicate.name == "supersedes"
        and len(fact.args) >= 2
        and canonical_json(fact.args[1]) == effect
        for fact in result.facts
    )


def _apply_supersedes(graph: QdlGraph) -> QdlGraph:
    """Return the context-current view of persisted supersession facts."""

    superseded: set[tuple[object, str]] = {
        (fact.context, canonical_json(fact.args[1]))
        for fact in graph.facts
        if fact.predicate.name == "supersedes" and len(fact.args) == 2
    }
    if not superseded:
        return graph

    facts: list[Fact] = []
    for fact in graph.facts:
        node = (
            Struct(name="replacement", args=fact.args)
            if fact.predicate.name == "has" and fact.args
            else fact.args[-1]
            if fact.args
            else None
        )
        if (
            fact.predicate.name != "supersedes"
            and node is not None
            and (fact.context, canonical_json(node)) in superseded
        ):
            continue
        facts.append(fact)
    return QdlGraph(facts=tuple(facts), rules=graph.rules)


def _variance_result_closes(deficit: Deficit, graph: QdlGraph) -> bool:
    """Require a semantic fact tied to the measured variance."""

    aliases = action_aliases(deficit.action)
    field_names = _context_value(deficit, "variance_fields") or ""
    fields = frozenset(field_names.split(",")) if field_names else frozenset()
    if fields:
        return any(
            fact.predicate.name in _VARIANCE_FIELD_CLOSURE_PREDICATES
            and any(_term_mentions_field(arg, fields) for arg in fact.args)
            for fact in graph.facts
        )
    return any(
        fact.predicate.name in _VARIANCE_EFFECT_CLOSURE_PREDICATES
        and any(_term_mentions_action(arg, aliases) for arg in fact.args)
        for fact in graph.facts
    )


def interpreted_signal_kinds(
    graph: QdlGraph | None,
    action: str,
) -> frozenset[str]:
    """Return signal kinds with effect, sink, and action-bound norm mappings."""

    if graph is None:
        return frozenset()
    aliases = action_aliases(action)
    effects_by_kind: dict[str, set[str]] = {}
    for fact in graph.facts:
        if fact.predicate.name != _SIGNAL_GROUNDING_PREDICATE or len(fact.args) != 2:
            continue
        kind = atom_value(fact.args[0])
        if kind is None:
            continue
        effects_by_kind.setdefault(kind, set()).add(canonical_json(fact.args[1]))

    interpreted_sinks = {
        atom_value(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == _SINK_INTERPRETATION_PREDICATE
        and len(fact.args) >= 1
        and atom_value(fact.args[0]) is not None
    }
    caused_effects = {
        canonical_json(fact.args[1])
        for fact in graph.facts
        if fact.predicate.name == "causes"
        and len(fact.args) == 2
        and atom_value(fact.args[0]) in aliases
    }
    norm_effects = {
        canonical_json(fact.args[1])
        for fact in graph.facts
        if fact.predicate.name == "prevents"
        and len(fact.args) == 2
        and isinstance(fact.args[1], Struct)
    }
    return frozenset(
        kind
        for kind, effects in effects_by_kind.items()
        if kind in interpreted_sinks and effects & norm_effects & caused_effects
    )


def _term_mentions_action(term: object, aliases: set[str]) -> bool:
    value = atom_value(term)
    if value is not None:
        return value in aliases
    if isinstance(term, Struct):
        return any(_term_mentions_action(arg, aliases) for arg in term.args)
    return False


def _term_mentions_field(term: object, fields: frozenset[str]) -> bool:
    value = atom_value(term)
    if value is not None:
        return value in fields
    if isinstance(term, Struct):
        return any(_term_mentions_field(arg, fields) for arg in term.args)
    return False


def declared_actions(graph: QdlGraph) -> set[str]:
    """Return aliases of every action declared by the graph."""

    actions: set[str] = set()
    for fact in graph.facts:
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        if atom_value(fact.args[1]) != "Action":
            continue
        action = atom_value(fact.args[0])
        if action is not None:
            actions.update(action_aliases(action))
    return actions


def grounded_output_paths(graph: QdlGraph) -> set[tuple[str, str]]:
    """Return ``(action, output_path)`` pairs grounded by QDL facts."""

    paths = {
        (action, output_path)
        for direction, action, output_path in resolve_field_roles(graph).roles_by_field
        if direction == "output"
    }
    for fact in graph.facts:
        if fact.predicate.name != "exposes" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        witness = fact.args[1]
        if action is None or not isinstance(witness, Struct):
            continue
        if witness.name not in EXPOSURE_WITNESS_NAMES or len(witness.args) != 2:
            continue
        output_path = atom_value(witness.args[1])
        if output_path is not None:
            paths.update((alias, output_path) for alias in action_aliases(action))
    return paths


def is_transport_sentinel(path: str) -> bool:
    """Return whether a response-tree path is a transport marker."""

    return path.split(".", 1)[0] in _TRANSPORT_SENTINEL_ROOTS


def observation_action(observation: Observation) -> str | None:
    """Return the method that produced one observation."""

    steps = observation.trace.steps if observation.trace is not None else ()
    return next(
        (
            step.method_id
            for step in reversed(steps)
            if step.observation_id == observation.observation_id
        ),
        steps[-1].method_id if steps else None,
    )


def effect_action(effect: Struct) -> str | None:
    """Return the action atom of a QDL invariant effect."""

    return atom_value(effect.args[0]) if effect.args else None


def effect_field(effect: Struct) -> str | None:
    """Return the response-field name carried by a possession effect."""

    if effect.name != "has" or len(effect.args) != 2:
        return None
    value = effect.args[1]
    if not isinstance(value, Struct):
        return None
    if value.name not in EXPOSURE_WITNESS_NAMES or len(value.args) != 2:
        return None
    return atom_value(value.args[1])


def action_aliases(action: str) -> set[str]:
    """Return both raw and action-prefixed spellings of an action id."""

    aliases = {action}
    if action.startswith("action:"):
        aliases.add(action.removeprefix("action:"))
    else:
        aliases.add(f"action:{action}")
    return aliases


def has_exposed_output(
    action: str,
    field: str | None,
    *,
    exposed_actions: set[str],
    exposed_fields: set[tuple[str, str]],
) -> bool:
    """Return whether the action exposes the required response field."""

    aliases = action_aliases(action)
    if field is None:
        return bool(aliases & exposed_actions)
    return any((alias, field) in exposed_fields for alias in aliases)
