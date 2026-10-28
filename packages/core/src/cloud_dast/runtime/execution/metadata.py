"""Pure metadata projections over QDL execution paths."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping

from cloud_dast.contracts.grammar import GrammarFacts
from cloud_dast.couplings import PlanCoupling
from cloud_dast.model import MethodSpec
from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    Variable,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
)
from cloud_dast.runtime.planning import (
    QdlSubgoal,
    declared_action_ids,
    derive_requirements,
)
from cloud_dast.verification.invariant_projection import (
    EXECUTABLE_CONTEXTS as _EXECUTABLE_CONTEXTS,
)
from cloud_dast.verification.norms import ORACLE_EFFECT_PRIMITIVES


def apply_resource_params(
    paths: list[QdlExecutionPath],
    resource_params: Mapping[str, tuple[str, ...]],
    resource_types: Mapping[str, tuple[tuple[str, str], ...]] | None = None,
) -> list[QdlExecutionPath]:
    """Attach grounded object-reference fields and their types to plans."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            fields = resource_params.get(step.method.method_id) or resource_params.get(
                f"action:{step.method.method_id}"
            )
            method_fields = {field.name for field in step.method.request_schema.fields}
            selected = tuple(name for name in fields or () if name in method_fields)
            if not selected:
                steps.append(step)
                continue
            typed = (resource_types or {}).get(step.method.method_id) or (
                resource_types or {}
            ).get(f"action:{step.method.method_id}", ())
            selected_types = tuple(
                (field, type_name)
                for field, type_name in typed or ()
                if field in selected
            )
            plan = step.plan.model_copy(
                update={
                    "resource_params": selected,
                    "resource_types": selected_types,
                }
            )
            steps.append(dataclasses.replace(step, plan=plan))
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


def apply_subject_role_params(
    paths: list[QdlExecutionPath],
    subject_params: Mapping[str, tuple[str, ...]],
    role_params: Mapping[str, tuple[str, ...]],
    principal_refs: Mapping[str, tuple[tuple[str, str], ...]],
) -> list[QdlExecutionPath]:
    """Attach grounded subject and role reference projections to plans."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            method_fields = {field.name for field in step.method.request_schema.fields}
            subjects = action_params(step, subject_params, method_fields)
            roles = action_params(step, role_params, method_fields)
            refs = principal_refs.get(step.method.method_id) or principal_refs.get(
                f"action:{step.method.method_id}", ()
            )
            subject_fields = set(subjects)
            role_fields = set(roles)
            subject_refs = tuple(
                (field, principal)
                for field, principal in refs
                if field in subject_fields
            )
            role_refs = tuple(
                (field, principal) for field, principal in refs if field in role_fields
            )
            if not (subjects or roles):
                steps.append(step)
                continue
            plan = step.plan.model_copy(
                update={
                    "subject_params": subjects,
                    "subject_refs": subject_refs,
                    "role_params": roles,
                    "role_refs": role_refs,
                }
            )
            steps.append(dataclasses.replace(step, plan=plan))
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


def action_params(
    step: QdlExecutionStep,
    params: Mapping[str, tuple[str, ...]],
    method_fields: set[str],
) -> tuple[str, ...]:
    fields = params.get(step.method.method_id) or params.get(
        f"action:{step.method.method_id}", ()
    )
    return tuple(name for name in fields or () if name in method_fields)


def apply_irreversibility(
    paths: list[QdlExecutionPath],
    irreversible_actions: Mapping[str, bool],
) -> list[QdlExecutionPath]:
    """Attach the explicit causal-effect projection to every step."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps = tuple(
            dataclasses.replace(
                step,
                irreversible=irreversible_actions.get(step.method.method_id),
            )
            for step in path.steps
        )
        applied.append(dataclasses.replace(path, steps=steps))
    return applied


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


def apply_probe_fields(
    paths: list[QdlExecutionPath],
    probe_fields: Mapping[str, tuple[str, ...]],
    graph: QdlGraph,
) -> list[QdlExecutionPath]:
    """Attach grounded probe fields and carrier subgoals to each step."""

    actions = declared_action_ids(graph, Context.CONTRACT) | declared_action_ids(
        graph, Context.ACCEPTED
    )
    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            fields = method_probe_fields(step.method, probe_fields)
            requirement = None
            if path.scoreable and needs_probe_carrier(step):
                action = step.method.method_id.removeprefix("action:")
                if f"action:{action}" in actions:
                    action = f"action:{action}"
                requirement = QdlSubgoal(
                    "probe_carrier",
                    (Atom(value=action), Variable(name="AnyField")),
                )
            plan = step.plan.model_copy(update={"probe_fields": fields})
            steps.append(
                dataclasses.replace(step, plan=plan, witness_requirement=requirement)
            )
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


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


def apply_sink_types(
    paths: list[QdlExecutionPath],
    sink_types: Mapping[str, tuple[tuple[str, str], ...]],
) -> list[QdlExecutionPath]:
    """Attach compiled sink classes to each step's executable plan."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            fields = sink_types.get(step.method.method_id) or sink_types.get(
                f"action:{step.method.method_id}", ()
            )
            if not fields:
                steps.append(step)
                continue
            plan = step.plan.model_copy(update={"sink_types": fields})
            steps.append(dataclasses.replace(step, plan=plan))
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


def apply_grammar_facts(
    paths: list[QdlExecutionPath],
    facts_by_action: Mapping[str, GrammarFacts],
) -> list[QdlExecutionPath]:
    """Attach executable grammar facts to each step's plan."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            facts = facts_by_action.get(step.method.method_id) or facts_by_action.get(
                f"action:{step.method.method_id}"
            )
            if facts is None or not facts.fields:
                steps.append(step)
                continue
            plan = step.plan.model_copy(
                update={
                    "grammar_formats": tuple(
                        (rule.field, format_name)
                        for rule in facts.fields
                        for format_name in rule.formats
                    ),
                    "grammar_constraints": tuple(
                        (constraint.field, constraint.operator, constraint.value)
                        for rule in facts.fields
                        for constraint in rule.constraints
                    ),
                    "grammar_dialects": tuple(
                        (rule.field, dialect)
                        for rule in facts.fields
                        for dialect in rule.dialects
                    ),
                }
            )
            steps.append(dataclasses.replace(step, plan=plan))
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


def version_executable_inputs(paths: list[QdlExecutionPath]) -> list[QdlExecutionPath]:
    """Version every path by its canonical executable identity."""

    return [
        dataclasses.replace(path, path_id=executable_versioned_path_id(path))
        for path in paths
    ]


def executable_versioned_path_id(path: QdlExecutionPath) -> str:
    """Return the full-hash identity of one bound executable path."""

    payload = json.dumps(
        {
            "path_id": path.path_id,
            "kind": path.kind,
            "steps": [step_identity(step) for step in path.steps],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{path.path_id}:pv{digest}"


def step_identity(step: QdlExecutionStep) -> dict[str, object]:
    """Return the canonical action/effect/norm/scenario identity of a step."""

    return {
        "action": step.method.method_id.removeprefix("action:"),
        "effect": step_effect(step),
        "invariant": step.invariant.invariant_id,
        "norm": step.invariant.norm_id,
        "scenario": step.scenario.scenario_id,
        "inputs": step_executable_inputs(step),
    }


def step_effect(step: QdlExecutionStep) -> str:
    if step.required_effects:
        return canonical_json(step.required_effects)
    fact = step.invariant.norm_fact
    if fact is not None and len(fact.args) == 2 and isinstance(fact.args[1], Struct):
        return canonical_json(fact.args[1])
    return canonical_json(step.effect_ids) if step.effect_ids else ""


def step_executable_inputs(step: QdlExecutionStep) -> dict[str, object]:
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
            for action, term in (
                derive_requirements(
                    step.evidence_graph,
                    contexts={Context.CONTRACT, Context.ACCEPTED},
                )
                if step.evidence_graph is not None
                else ()
            )
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


def apply_plan_couplings(
    paths: list[QdlExecutionPath],
    couplings: Mapping[str, tuple[PlanCoupling, ...]],
) -> list[QdlExecutionPath]:
    """Attach value couplings to each step's verification plan."""

    if not couplings:
        return paths
    applied: list[QdlExecutionPath] = []
    for path in paths:
        steps: list[QdlExecutionStep] = []
        for step in path.steps:
            method_couplings = couplings.get(step.method.method_id) or couplings.get(
                f"action:{step.method.method_id}"
            )
            if not method_couplings:
                steps.append(step)
                continue
            plan = step.plan.model_copy(update={"couplings": method_couplings})
            steps.append(dataclasses.replace(step, plan=plan))
        applied.append(dataclasses.replace(path, steps=tuple(steps)))
    return applied


__all__ = [
    "action_params",
    "apply_grammar_facts",
    "apply_irreversibility",
    "apply_plan_couplings",
    "apply_probe_fields",
    "apply_resource_params",
    "apply_sink_types",
    "apply_subject_role_params",
    "effect_resource",
    "executable_versioned_path_id",
    "irreversible_actions",
    "removing_actions",
    "method_probe_fields",
    "needs_probe_carrier",
    "step_effect",
    "step_executable_inputs",
    "step_identity",
    "version_executable_inputs",
]
