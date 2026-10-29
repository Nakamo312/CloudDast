"""Pure metadata projections over QDL execution paths."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable, Mapping

from cloud_dast.contracts.grammar import GrammarFacts
from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.couplings import all_couplings
from cloud_dast.model import MethodSpec
from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.field_roles import (
    OBJECT_REF_ROLE,
    ROLE_REF_ROLE,
    SUBJECT_REF_ROLE,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    Term,
    Variable,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.reasoning import QdlSubgoal, derive_requirements
from cloud_dast.runtime import grammar_facts
from cloud_dast.runtime.identity_projection import (
    apply_identity_terms,
    derive_identities,
)
from cloud_dast.runtime.payload_hints import compile_payload_hints, sink_types_by_action
from cloud_dast.runtime.planning import declared_action_ids
from cloud_dast.runtime.reference_projection import (
    fields_with_role_by_action,
    principal_refs_from_targets,
    refers_to_targets_by_action,
    typed_object_refs,
)
from cloud_dast.verification.invariant_projection import (
    EXECUTABLE_CONTEXTS as _EXECUTABLE_CONTEXTS,
)
from cloud_dast.verification.norms import ORACLE_EFFECT_PRIMITIVES


def decorate(
    paths: list[QdlExecutionPath],
    graph: QdlGraph,
    methods_by_action: Mapping[str, MethodSpec],
    *,
    probe_fields: Mapping[str, tuple[str, ...]],
) -> list[QdlExecutionPath]:
    """Compile one graph snapshot and attach executable metadata in one pass."""

    paths = apply_identity_terms(paths, derive_identities(graph))
    irreversible = irreversible_actions(graph)
    plan_inputs = _plan_inputs(graph, methods_by_action, probe_fields)
    actions = declared_action_ids(graph, Context.CONTRACT) | declared_action_ids(
        graph, Context.ACCEPTED
    )
    applied = [
        dataclasses.replace(
            path,
            steps=tuple(
                dataclasses.replace(
                    step,
                    plan=step.plan.model_copy(update=plan_inputs(step)),
                    irreversible=irreversible.get(step.method.method_id),
                    witness_requirement=_probe_requirement(
                        step, path.scoreable, actions
                    ),
                )
                for step in path.steps
            ),
        )
        for path in paths
    ]
    return version_executable_inputs(applied)


def _plan_inputs(
    graph: QdlGraph,
    methods: Mapping[str, MethodSpec],
    probe_fields: Mapping[str, tuple[str, ...]],
) -> Callable[[QdlExecutionStep], dict[str, object]]:
    hints = compile_payload_hints(graph)
    roles = resolve_field_roles(graph)
    targets = refers_to_targets_by_action(graph)
    types = typed_object_refs(targets, roles)
    principals = principal_refs_from_targets(targets)
    couplings = all_couplings(graph)
    # Sink attribution intentionally uses facts only; grammar also uses rules.
    sinks = sink_types_by_action(graph, hints)
    grammar = grammar_facts.compile(
        graph, sorted({m.method_id for m in methods.values()})
    )
    resources = fields_with_role_by_action(roles, OBJECT_REF_ROLE)
    subjects = fields_with_role_by_action(roles, SUBJECT_REF_ROLE)
    role_fields = fields_with_role_by_action(roles, ROLE_REF_ROLE)

    def inputs(step: QdlExecutionStep) -> dict[str, object]:
        action = step.method.method_id
        alias = f"action:{action}"
        updates: dict[str, object] = {
            "probe_fields": method_probe_fields(step.method, probe_fields)
        }
        for name, values in (("couplings", couplings), ("sink_types", sinks)):
            selected = values.get(action) or values.get(alias)
            if selected:
                updates[name] = selected
        updates.update(_grammar_inputs(grammar.get(action) or grammar.get(alias)))
        updates.update(_resource_inputs(step, resources, types))
        updates.update(_reference_inputs(step, subjects, role_fields, principals))
        return updates

    return inputs


def _resource_inputs(
    step: QdlExecutionStep,
    params: Mapping[str, tuple[str, ...]],
    types: Mapping[str, tuple[tuple[str, str], ...]],
) -> dict[str, object]:
    method_fields = {field.name for field in step.method.request_schema.fields}
    selected = action_params(step, params, method_fields)
    if not selected:
        return {}
    typed = types.get(step.method.method_id) or types.get(
        f"action:{step.method.method_id}", ()
    )
    return {
        "resource_params": selected,
        "resource_types": tuple(
            (field, kind) for field, kind in typed if field in selected
        ),
    }


def _reference_inputs(
    step: QdlExecutionStep,
    subjects: Mapping[str, tuple[str, ...]],
    roles: Mapping[str, tuple[str, ...]],
    principals: Mapping[str, tuple[tuple[str, str], ...]],
) -> dict[str, object]:
    method_fields = {field.name for field in step.method.request_schema.fields}
    subject_params = action_params(step, subjects, method_fields)
    role_params = action_params(step, roles, method_fields)
    if not (subject_params or role_params):
        return {}
    refs = principals.get(step.method.method_id) or principals.get(
        f"action:{step.method.method_id}", ()
    )
    return {
        "subject_params": subject_params,
        "subject_refs": tuple(pair for pair in refs if pair[0] in subject_params),
        "role_params": role_params,
        "role_refs": tuple(pair for pair in refs if pair[0] in role_params),
    }


def _grammar_inputs(facts: GrammarFacts | None) -> dict[str, object]:
    if facts is None or not facts.fields:
        return {}
    return {
        "grammar_formats": tuple(
            (rule.field, name) for rule in facts.fields for name in rule.formats
        ),
        "grammar_constraints": tuple(
            (item.field, item.operator, item.value)
            for rule in facts.fields
            for item in rule.constraints
        ),
        "grammar_dialects": tuple(
            (rule.field, dialect) for rule in facts.fields for dialect in rule.dialects
        ),
    }


def _probe_requirement(
    step: QdlExecutionStep,
    scoreable: bool,
    actions: set[str],
) -> QdlSubgoal | None:
    if not scoreable or not needs_probe_carrier(step):
        return None
    action = step.method.method_id.removeprefix("action:")
    if f"action:{action}" in actions:
        action = f"action:{action}"
    return QdlSubgoal("probe_carrier", (Atom(value=action), Variable(name="AnyField")))


def action_params(
    step: QdlExecutionStep,
    params: Mapping[str, tuple[str, ...]],
    method_fields: set[str],
) -> tuple[str, ...]:
    fields = params.get(step.method.method_id) or params.get(
        f"action:{step.method.method_id}", ()
    )
    return tuple(name for name in fields or () if name in method_fields)


def irreversible_actions(graph: QdlGraph) -> dict[str, bool]:
    """Project explicit mutating effects onto action aliases."""

    created_resources: dict[str, set[str]] = {}
    mutated_resources: dict[str, set[str]] = {}
    control_actions = {
        alias
        for fact in graph.facts_for("transition", contexts=_EXECUTABLE_CONTEXTS)
        if len(fact.args) == 3 and fact.args[1] != fact.args[2]
        for alias in action_aliases(atom_value(fact.args[0]) or "")
    }
    for fact in graph.facts:
        if fact.context not in _EXECUTABLE_CONTEXTS:
            continue
        if fact.predicate.name != "causes" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        effect = fact.args[1]
        if action is None or not isinstance(effect, Struct):
            continue
        if effect.name == "transition" and len(effect.args) == 2:
            if effect.args[0] != effect.args[1]:
                control_actions.update(action_aliases(action))
        resource = effect_resource(effect)
        if resource is None:
            continue
        for alias in action_aliases(action):
            if effect.name == "create":
                created_resources.setdefault(alias, set()).add(resource)
            else:
                mutated_resources.setdefault(alias, set()).add(resource)
    effects = {
        alias: bool(
            mutated_resources.get(alias, set()) - created_resources.get(alias, set())
        )
        for alias in created_resources.keys() | mutated_resources.keys()
    }
    effects.update(dict.fromkeys(control_actions, True))
    return effects


def removing_actions(graph: QdlGraph) -> dict[str, bool]:
    """Project whether an action explicitly removes its resource."""

    removals: dict[str, bool] = {}
    for fact in graph.facts:
        if fact.context not in _EXECUTABLE_CONTEXTS:
            continue
        if fact.predicate.name != "causes" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        effect = fact.args[1]
        if action is None or not isinstance(effect, Struct):
            continue
        if effect.name not in {"create", "changed", "remove"}:
            continue
        for alias in action_aliases(action):
            removals[alias] = removals.get(alias, False) or effect.name == "remove"
    return removals


def effect_resource(effect: Struct) -> str | None:
    if effect.name not in {"create", "changed", "remove"} or not effect.args:
        return None
    return atom_value(effect.args[0])


def needs_probe_carrier(step: QdlExecutionStep) -> bool:
    fact = step.invariant.norm_fact
    if fact is None or fact.context is not Context.ACCEPTED or len(fact.args) != 2:
        return False
    effect = fact.args[1]
    return isinstance(effect, Struct) and ORACLE_EFFECT_PRIMITIVES.get(effect.name) in {
        "marker",
        "oob_event",
    }


def method_probe_fields(
    method: MethodSpec,
    probe_fields: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    action = method.method_id.removeprefix("action:")
    fields = probe_fields.get(f"action:{action}") or probe_fields.get(action, ())
    declared = {field.name for field in method.request_schema.fields}
    return tuple(field for field in fields if field in declared)


def version_executable_inputs(paths: list[QdlExecutionPath]) -> list[QdlExecutionPath]:
    """Version paths, materializing requirements once per shared graph snapshot."""

    requirements: dict[int, tuple[tuple[Term, ...], ...]] = {}

    def identity(step: QdlExecutionStep) -> dict[str, object]:
        graph = step.evidence_graph
        if graph is None:
            rows = ()
        else:
            key = id(graph)
            if key not in requirements:
                requirements[key] = derive_requirements(
                    graph, contexts={Context.CONTRACT, Context.ACCEPTED}
                )
            rows = requirements[key]
        return {
            "action": step.method.method_id.removeprefix("action:"),
            "effect": step_effect(step),
            "invariant": step.invariant.invariant_id,
            "norm": step.invariant.norm_id,
            "scenario": step.scenario.scenario_id,
            "inputs": _step_inputs(step, rows),
        }

    return [
        dataclasses.replace(
            path, path_id=_path_id(path, [identity(s) for s in path.steps])
        )
        for path in paths
    ]


def _path_id(path: QdlExecutionPath, steps: list[dict[str, object]]) -> str:
    payload = json.dumps(
        {"path_id": path.path_id, "kind": path.kind, "steps": steps},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{path.path_id}:pv{digest}"


def step_effect(step: QdlExecutionStep) -> str:
    if step.required_effects:
        return canonical_json(step.required_effects)
    fact = step.invariant.norm_fact
    if fact is not None and len(fact.args) == 2 and isinstance(fact.args[1], Struct):
        return canonical_json(fact.args[1])
    return canonical_json(step.effect_ids) if step.effect_ids else ""


def _step_inputs(
    step: QdlExecutionStep,
    requirements: tuple[tuple[Term, ...], ...],
) -> dict[str, object]:
    # Evidence changes readiness, not the instruction. Version only the
    # trusted declaration slice that contributes to this action. Runtime
    # observations and unrelated contract facts must not change the
    # executable identity; action-specific contract/accepted requirements
    # still invalidate the bound path through the filtered list below.
    return {
        "method_contract": step.method.model_dump(mode="json"),
        "required_effects": [
            canonical_json(effect) for effect in step.required_effects
        ],
        "requirements": [
            canonical_json(term)
            for action, term in requirements
            if (identifier := atom_value(action)) is not None
            and action_aliases(identifier) & action_aliases(step.method.method_id)
        ],
        "couplings": [
            [left.model_dump(mode="json"), right.model_dump(mode="json"), operator]
            for left, right, operator in step.plan.couplings
        ],
        "identities": (
            None
            if step.plan.identity_terms is None
            else [term.principal_id for term in step.plan.identity_terms]
        ),
        "irreversible": step.irreversible,
        "probe_fields": list(step.plan.probe_fields),
        "resource_params": list(step.plan.resource_params),
        "resource_types": [list(item) for item in step.plan.resource_types],
        "subject_params": list(step.plan.subject_params),
        "subject_refs": [list(item) for item in step.plan.subject_refs],
        "role_params": list(step.plan.role_params),
        "role_refs": [list(item) for item in step.plan.role_refs],
        "sink_types": [list(item) for item in step.plan.sink_types],
        "grammar_formats": [list(item) for item in step.plan.grammar_formats],
        "grammar_constraints": [list(item) for item in step.plan.grammar_constraints],
        "grammar_dialects": [list(item) for item in step.plan.grammar_dialects],
        "seed_hints": [list(hint) for hint in step.plan.seed_hints],
    }


__all__ = [
    "decorate",
    "irreversible_actions",
    "removing_actions",
    "method_probe_fields",
    "needs_probe_carrier",
    "step_effect",
    "version_executable_inputs",
]
