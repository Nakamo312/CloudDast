"""Contract-coverage and typed-reference deficit projections."""

from __future__ import annotations

from cloud_dast.api import ScenarioBinding
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    canonical_json,
    input_field,
)
from cloud_dast.qdl.graph import field as field_term
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import EXPOSURE_WITNESS_NAMES
from cloud_dast.runtime.deficits.closure import (
    action_aliases,
    effect_action,
    effect_field,
    has_exposed_output,
)
from cloud_dast.runtime.deficits.closure import (
    declared_actions as declared_graph_actions,
)
from cloud_dast.runtime.deficits.model import Deficit
from cloud_dast.runtime.deficits.routing import (
    _ANY_FIELD,
    _ANY_NODE,
    _ANY_RESOURCE,
    _ANY_ROLE,
    _ANY_TARGET,
    _ANY_WITNESS,
    build_deficit,
    deduplicate,
    unprovable_subgoal,
)
from cloud_dast.runtime.planning import QdlSubgoal
from cloud_dast.verification.action_runtime import (
    declared_actions as declared_method_actions,
)


def reference_deficits(binding: ScenarioBinding) -> tuple[Deficit, ...]:
    """Return missing typed input references from ordinary QDL step plans."""

    graph = binding.graph.select_contexts(
        frozenset({Context.CONTRACT, Context.ACCEPTED})
    )
    deficits: list[Deficit] = []
    for path in binding.execution.paths:
        for step in path.steps:
            typed = dict(step.plan.resource_types)
            schema = {field.name: field for field in step.method.request_schema.fields}
            for field in step.plan.resource_params:
                if field in typed or (field in schema and not schema[field].required):
                    continue
                action = step.method.method_id
                deficit = unprovable_subgoal(
                    QdlSubgoal(
                        predicate="refers_to",
                        args=(
                            input_field(Atom(value=action), Atom(value=field)),
                            _ANY_TARGET,
                        ),
                    ),
                    graph,
                    action=action,
                    context=(("field", field), ("reason", "missing_refers_to")),
                )
                if deficit is not None:
                    deficits.append(deficit)
    return deduplicate(deficits)


def gaps(
    binding: ScenarioBinding,
    *,
    include_declared_actions: bool = True,
) -> tuple[Deficit, ...]:
    """Return stable, deduplicated contract-coverage gaps."""

    grounded_input_actions = _actions_with_input_roles(binding.graph)
    exposed_actions, exposed_fields = _exposed_output_fields(binding.graph)
    path_actions = _path_actions(binding)
    declared_actions = (
        _declared_method_actions(binding.graph) if include_declared_actions else ()
    )

    deficits = _input_role_gaps(path_actions, declared_actions, grounded_input_actions)
    deficits.extend(_path_gaps(path_actions, declared_actions))
    deficits.extend(
        _exposure_gaps(
            binding,
            exposed_actions=exposed_actions,
            exposed_fields=exposed_fields,
        )
    )
    return deduplicate((*deficits, *reference_deficits(binding)))


def _input_role_gaps(
    path_actions: tuple[str, ...],
    declared_actions: tuple[str, ...],
    grounded_actions: set[str],
) -> list[Deficit]:
    deficits: list[Deficit] = []
    for action in dict.fromkeys((*path_actions, *declared_actions)):
        if action_aliases(action) & grounded_actions:
            continue
        deficits.append(
            build_deficit(
                QdlSubgoal(
                    predicate="has",
                    args=(input_field(Atom(value=action), _ANY_FIELD), _ANY_ROLE),
                ),
                action=action,
                context=(("coverage", "input_roles"),),
            )
        )
    return deficits


def _path_gaps(
    path_actions: tuple[str, ...], declared_actions: tuple[str, ...]
) -> list[Deficit]:
    path_aliases: set[str] = set()
    for action in path_actions:
        path_aliases.update(action_aliases(action))
    deficits: list[Deficit] = []
    for action in declared_actions:
        if action_aliases(action) & path_aliases:
            continue
        deficits.append(
            build_deficit(
                QdlSubgoal(
                    predicate="reaches",
                    args=(Atom(value=action), _ANY_NODE),
                ),
                action=action,
                context=(("coverage", "executable_path"),),
            )
        )
    return deficits


def _exposure_gaps(
    binding: ScenarioBinding,
    *,
    exposed_actions: set[str],
    exposed_fields: set[tuple[str, str]],
) -> list[Deficit]:
    deficits: list[Deficit] = []
    for invariant in binding.plan.invariants:
        if invariant.primitive != "response_field":
            continue
        field = effect_field(invariant.effect)
        actions = _actions_exposing_witness(binding.graph, invariant.effect)
        fallback_action = effect_action(invariant.effect)
        if (
            not actions
            and fallback_action is not None
            and action_aliases(fallback_action) & declared_graph_actions(binding.graph)
        ):
            actions = (fallback_action,)
        for action in actions:
            if has_exposed_output(
                action,
                field,
                exposed_actions=exposed_actions,
                exposed_fields=exposed_fields,
            ):
                continue
            context = (("field", field),) if field is not None else ()
            deficits.append(
                build_deficit(
                    QdlSubgoal(
                        predicate="exposes",
                        args=(
                            Atom(value=action),
                            (
                                field_term(_ANY_RESOURCE, Atom(value=field))
                                if field is not None
                                else _ANY_WITNESS
                            ),
                        ),
                    ),
                    action=action,
                    context=context,
                )
            )
    return deficits


def _path_actions(binding: ScenarioBinding) -> tuple[str, ...]:
    """Return method identifiers used by execution paths in discovery order."""

    actions: list[str] = []
    seen: set[str] = set()
    for path in binding.execution.paths:
        for step in path.steps:
            action = step.method.method_id
            if action in seen:
                continue
            seen.add(action)
            actions.append(action)
    return tuple(actions)


def _declared_method_actions(graph: QdlGraph) -> tuple[str, ...]:
    """Return contract-declared actions in method-identifier form."""

    return tuple(
        dict.fromkeys(
            action.removeprefix("action:") for action in declared_method_actions(graph)
        )
    )


def _actions_with_input_roles(graph: QdlGraph) -> set[str]:
    """Return actions with at least one grounded input-field role."""

    actions: set[str] = set()
    for fact in graph.facts:
        if fact.predicate.name != "has" or len(fact.args) != 2:
            continue
        holder = fact.args[0]
        if not isinstance(holder, Struct) or holder.name != "input_field":
            continue
        if len(holder.args) != 2:
            continue
        action = atom_value(holder.args[0])
        if action is not None:
            actions.add(action)
    return actions


def _exposed_output_fields(
    graph: QdlGraph,
) -> tuple[set[str], set[tuple[str, str]]]:
    """Index exposed response fields by action and (action, field)."""

    actions: set[str] = set()
    fields: set[tuple[str, str]] = set()
    for fact in graph.facts:
        if fact.predicate.name != "exposes" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        witness = fact.args[1]
        if action is None or not isinstance(witness, Struct):
            continue
        if witness.name not in EXPOSURE_WITNESS_NAMES or len(witness.args) != 2:
            continue
        field = atom_value(witness.args[1])
        if field is None:
            continue
        actions.add(action)
        fields.add((action, field))
    return actions, fields


def _actions_exposing_witness(graph: QdlGraph, effect: Struct) -> tuple[str, ...]:
    """Return graph actions that expose the witness named by an effect."""

    if len(effect.args) != 2 or not isinstance(effect.args[1], Struct):
        return ()
    witness = canonical_json(effect.args[1])
    actions: list[str] = []
    for fact in graph.facts:
        if fact.predicate.name != "exposes" or len(fact.args) != 2:
            continue
        if canonical_json(fact.args[1]) != witness:
            continue
        action = atom_value(fact.args[0])
        if action is not None:
            actions.append(action)
    return tuple(actions)


__all__ = ["gaps", "reference_deficits"]
