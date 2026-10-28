"""Build the runtime-owned executable view from a QDL plan."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from types import MappingProxyType

from cloud_dast.couplings import all_couplings
from cloud_dast.model import MethodSpec, ScenarioPosition
from cloud_dast.qdl.field_roles import (
    OBJECT_REF_ROLE,
    ROLE_REF_ROLE,
    SUBJECT_REF_ROLE,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import (
    QdlGraph,
    Struct,
)
from cloud_dast.qdl.reasoning import compile_probe_fields
from cloud_dast.runtime.execution import metadata
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionView,
)
from cloud_dast.runtime.execution.projection import (
    bind_execution_paths,
    record_binding_deficit,
    retained_invariants,
)
from cloud_dast.runtime.grammar_facts import (
    facts_from_graph,
)
from cloud_dast.runtime.identity_projection import (
    apply_identity_terms,
    derive_identities,
)
from cloud_dast.runtime.payload_hints import compile_payload_hints, sink_types_by_action
from cloud_dast.runtime.planning import (
    QdlForbiddenPath,
    QdlPlan,
)
from cloud_dast.runtime.reference_projection import (
    fields_with_role_by_action,
    principal_refs_from_targets,
    refers_to_targets_by_action,
    resource_types_by_action,
)
from cloud_dast.verification.action_runtime import BindingDeficit
from cloud_dast.verification.invariant_projection import (
    build_invariant_index,
)


def action_lookups(
    methods: tuple[MethodSpec, ...],
    scenarios_by_method: Mapping[str, ScenarioPosition],
) -> tuple[dict[str, MethodSpec], dict[str, ScenarioPosition]]:
    """Index methods and scenarios by plain and action-qualified identifiers."""

    methods_by_action: dict[str, MethodSpec] = {}
    scenarios_by_action: dict[str, ScenarioPosition] = {}
    for method in methods:
        methods_by_action[method.method_id] = method
        methods_by_action[f"action:{method.method_id}"] = method
        scenario = scenarios_by_method.get(method.method_id)
        if scenario is not None:
            scenarios_by_action[method.method_id] = scenario
            scenarios_by_action[f"action:{method.method_id}"] = scenario
    return methods_by_action, scenarios_by_action


def method_for_action(
    action: str,
    methods: Mapping[str, MethodSpec],
) -> MethodSpec | None:
    for candidate in (action, action.removeprefix("action:")):
        method = methods.get(candidate)
        if method is not None:
            return method
    return None


def ordered_plan_actions(plan: QdlPlan) -> tuple[str, ...]:
    actions: list[str] = []
    seen: set[str] = set()
    for path in plan.bound_paths:
        path_actions = (
            path.path.actions if isinstance(path, QdlForbiddenPath) else path.actions
        )
        for action in path_actions:
            if action not in seen:
                seen.add(action)
                actions.append(action)
    return tuple(actions)


def build(
    plan: QdlPlan,
    graph: QdlGraph,
    *,
    methods: tuple[MethodSpec, ...],
    scenarios_by_method: Mapping[str, ScenarioPosition],
    exposes_by_witness: Mapping[tuple[str, str], list[str]] | None = None,
    actions_by_effect: Mapping[Struct, tuple[str, ...]] | None = None,
    binding_deficits: list[BindingDeficit] | None = None,
) -> QdlExecutionView:
    """Project a planned QDL graph into one executable application view."""

    methods_by_action, scenarios_by_action = action_lookups(
        methods,
        scenarios_by_method,
    )
    probe_fields = MappingProxyType(compile_probe_fields(graph))
    record_probe_schema_deficits(probe_fields, methods_by_action, binding_deficits)
    index = build_invariant_index(
        plan,
        graph,
        exposes_by_witness=exposes_by_witness,
        actions_by_effect=actions_by_effect,
    )
    paths = bind_execution_paths(
        plan,
        graph,
        index,
        probe_fields=probe_fields,
        methods_by_action=methods_by_action,
        scenarios_by_action=scenarios_by_action,
        binding_deficits=binding_deficits,
    )
    paths = [
        dataclasses.replace(
            path,
            steps=tuple(
                dataclasses.replace(step, evidence_graph=graph) for step in path.steps
            ),
        )
        for path in paths
    ]
    invariants = retained_invariants(index, paths)
    paths = decorate(
        paths,
        graph,
        methods_by_action,
        probe_fields=probe_fields,
    )
    return QdlExecutionView(
        graph_hash=plan.graph_hash,
        paths=tuple(sorted(paths, key=lambda item: item.path_id)),
        invariants=invariants,
    )


def decorate(
    paths: list[QdlExecutionPath],
    graph: QdlGraph,
    methods_by_action: Mapping[str, MethodSpec],
    *,
    probe_fields: Mapping[str, tuple[str, ...]],
) -> list[QdlExecutionPath]:
    """Attach all deterministic QDL-derived execution metadata."""

    paths = apply_identity_terms(paths, derive_identities(graph))
    paths = metadata.apply_irreversibility(
        paths,
        metadata.irreversible_actions(graph),
    )
    payload_hints = compile_payload_hints(graph)
    field_roles = resolve_field_roles(graph)
    refers_to_targets = refers_to_targets_by_action(graph)
    resource_types = resource_types_by_action(graph)
    principal_refs = principal_refs_from_targets(refers_to_targets)
    paths = metadata.apply_plan_couplings(paths, all_couplings(graph))
    paths = metadata.apply_probe_fields(paths, probe_fields, graph)
    paths = metadata.apply_sink_types(paths, sink_types_by_action(graph, payload_hints))
    paths = metadata.apply_grammar_facts(
        paths,
        {
            action: facts_from_graph(graph, action)
            for action in sorted(
                {method.method_id for method in methods_by_action.values()}
            )
        },
    )
    paths = metadata.apply_resource_params(
        paths,
        fields_with_role_by_action(field_roles, OBJECT_REF_ROLE),
        resource_types,
    )
    paths = metadata.apply_subject_role_params(
        paths,
        fields_with_role_by_action(field_roles, SUBJECT_REF_ROLE),
        fields_with_role_by_action(field_roles, ROLE_REF_ROLE),
        principal_refs,
    )
    return metadata.version_executable_inputs(paths)


def missing_reference_deficits(
    execution: QdlExecutionView,
) -> tuple[BindingDeficit, ...]:
    """Report role-carrying fields whose grounded target is missing."""

    deficits: list[BindingDeficit] = []
    for path in execution.paths:
        for step in path.steps:
            plan = step.plan
            for params, refs in (
                (plan.subject_params, plan.subject_refs),
                (plan.role_params, plan.role_refs),
            ):
                targets = {field for field, _ in refs}
                deficits.extend(
                    BindingDeficit(
                        action=step.method.method_id,
                        reason="missing_refers_to",
                        context=(("field", field),),
                    )
                    for field in params
                    if field not in targets
                )
    return tuple(deficits)


def record_probe_schema_deficits(
    probe_fields: Mapping[str, tuple[str, ...]],
    methods_by_action: Mapping[str, MethodSpec],
    deficits: list[BindingDeficit] | None,
) -> None:
    """Record graph probe carriers that cannot bind to a method schema."""

    if deficits is None:
        return
    for action, fields in probe_fields.items():
        method = methods_by_action.get(action)
        if (
            method is None
            or not fields
            or metadata.method_probe_fields(method, probe_fields)
        ):
            continue
        record_binding_deficit(
            deficits,
            action=action,
            reason="probe_schema_mismatch",
            kind="incomplete_binding",
            context=(
                ("graph_fields", json.dumps(fields)),
                (
                    "method_fields",
                    json.dumps(
                        sorted(field.name for field in method.request_schema.fields)
                    ),
                ),
            ),
        )


__all__ = [
    "action_lookups",
    "build",
    "decorate",
    "method_for_action",
    "missing_reference_deficits",
    "ordered_plan_actions",
    "record_probe_schema_deficits",
]
