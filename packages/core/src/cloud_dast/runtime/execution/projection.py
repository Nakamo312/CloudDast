"""Assemble bound executable paths from a planned QDL view."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from functools import partial

from cloud_dast.contracts.assessment import BindingDeficit
from cloud_dast.contracts.plan import InvariantProjection, QdlExecutionPath
from cloud_dast.model import MethodSpec, ScenarioPosition, Severity
from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.graph import Context, QdlGraph
from cloud_dast.qdl.reasoning import QdlPlan
from cloud_dast.runtime.execution.binding import (
    bind_attack_path,
    bind_forbidden_path,
    build_step,
    invariant_path,
    path_key,
    transition_targets,
)
from cloud_dast.runtime.execution.metadata import (
    method_probe_fields,
    needs_probe_carrier,
)
from cloud_dast.runtime.planning import declared_action_ids
from cloud_dast.verification.invariant_projection import InvariantIndex


def bind_execution_paths(
    plan: QdlPlan,
    graph: QdlGraph,
    index: InvariantIndex,
    *,
    probe_fields: Mapping[str, tuple[str, ...]],
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    binding_deficits: list[BindingDeficit] | None = None,
) -> list[QdlExecutionPath]:
    """Bind attack, forbidden, invariant and smoke paths in stable order."""

    paths: list[QdlExecutionPath] = []
    path_keys: set[tuple[tuple[str, str, str], ...]] = set()
    bind_attack_paths(
        plan,
        index,
        paths,
        path_keys,
        methods_by_action=methods_by_action,
        scenarios_by_action=scenarios_by_action,
        binding_deficits=binding_deficits,
    )
    bind_forbidden_paths(
        plan,
        graph,
        index,
        paths,
        path_keys,
        methods_by_action=methods_by_action,
        scenarios_by_action=scenarios_by_action,
        binding_deficits=binding_deficits,
    )
    bind_invariant_paths(
        index,
        paths,
        path_keys,
        methods_by_action=methods_by_action,
        scenarios_by_action=scenarios_by_action,
        binding_deficits=binding_deficits,
    )
    # A dependency prefix is not a security goal. Keep it available for an
    # uncovered contract action, rather than execute it again beside its
    # consuming paths (which could repeat an otherwise unnecessary mutation).
    ordinary_paths = tuple(
        path
        for path in paths
        if path.kind == "attack" and path.steps[-1].invariant.norm_fact is None
    )
    paths = [path for path in paths if path not in ordinary_paths]
    path_keys = {path_key(path) for path in paths}
    bind_contract_smoke_paths(
        graph,
        paths,
        path_keys,
        probe_fields=probe_fields,
        methods_by_action=methods_by_action,
        scenarios_by_action=scenarios_by_action,
        binding_deficits=binding_deficits,
        dependencies=ordinary_paths,
    )
    return paths


def bind_attack_paths(
    plan: QdlPlan,
    index: InvariantIndex,
    paths: list[QdlExecutionPath],
    path_keys: set[tuple[tuple[str, str, str], ...]],
    *,
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    binding_deficits: list[BindingDeficit] | None = None,
) -> None:
    for attack in plan.attack_paths:
        bound = bind_attack_path(
            attack,
            invariants=index.invariants,
            invariants_by_action=index.by_action,
            invariants_by_effect=index.by_effect,
            methods_by_action=methods_by_action,
            scenarios_by_action=scenarios_by_action,
            record_deficit=partial(record_binding_deficit, binding_deficits),
        )
        if bound is None:
            continue
        key = path_key(bound)
        if key not in path_keys:
            path_keys.add(key)
            paths.append(bound)


def bind_forbidden_paths(
    plan: QdlPlan,
    graph: QdlGraph,
    index: InvariantIndex,
    paths: list[QdlExecutionPath],
    path_keys: set[tuple[tuple[str, str, str], ...]],
    *,
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    binding_deficits: list[BindingDeficit] | None = None,
) -> None:
    transitions = transition_targets(graph)
    for forbidden in plan.forbidden_paths:
        bound = bind_forbidden_path(
            forbidden,
            transitions=transitions,
            methods_by_action=methods_by_action,
            scenarios_by_action=scenarios_by_action,
            record_deficit=partial(record_binding_deficit, binding_deficits),
        )
        if bound is None:
            continue
        key = path_key(bound)
        if key in path_keys:
            continue
        path_keys.add(key)
        paths.append(bound)
        for item in bound.steps:
            index.invariants[item.plan.invariant_id] = item.invariant


def record_binding_deficit(
    deficits: list[BindingDeficit] | None,
    *,
    action: str,
    reason: str,
    kind: str,
    context: tuple[tuple[str, str], ...] = (),
) -> None:
    if deficits is None:
        return
    matching = [
        deficit
        for deficit in deficits
        if action_aliases(deficit.action) & action_aliases(action)
    ]
    if reason in {"contract_method_missing", "contract_scenario_missing"} and any(
        deficit.reason not in {"contract_method_missing", "contract_scenario_missing"}
        for deficit in matching
    ):
        return
    if any(
        deficit.reason == reason and deficit.context == context for deficit in matching
    ):
        return
    deficits.append(
        BindingDeficit(
            action=action,
            reason=reason,
            context=context,
            kind=kind,  # type: ignore[arg-type]
        )
    )


def bind_invariant_paths(
    index: InvariantIndex,
    paths: list[QdlExecutionPath],
    path_keys: set[tuple[tuple[str, str, str], ...]],
    *,
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    binding_deficits: list[BindingDeficit] | None = None,
) -> None:
    for action, invariant_ids in index.by_action.items():
        method = methods_by_action.get(action)
        scenario = scenarios_by_action.get(action)
        if method is None or scenario is None:
            record_binding_deficit(
                binding_deficits,
                action=action,
                reason=(
                    "contract_method_missing"
                    if method is None
                    else "contract_scenario_missing"
                ),
                kind=("method_missing" if method is None else "scenario_missing"),
                context=(
                    ("coverage", "invariant_path"),
                    ("invariant", invariant_ids[0] if invariant_ids else ""),
                ),
            )
            continue
        for invariant_id in invariant_ids:
            bound = invariant_path(
                index.invariants[invariant_id],
                method=method,
                scenario=scenario,
            )
            key = path_key(bound)
            if key not in path_keys:
                path_keys.add(key)
                paths.append(bound)


def bind_contract_smoke_paths(
    graph: QdlGraph,
    paths: list[QdlExecutionPath],
    path_keys: set[tuple[tuple[str, str, str], ...]],
    *,
    probe_fields: Mapping[str, tuple[str, ...]],
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    binding_deficits: list[BindingDeficit] | None = None,
    dependencies: tuple[QdlExecutionPath, ...] = (),
) -> None:
    bound_actions = {
        alias
        for path in paths
        if all(
            not path.scoreable
            or not needs_probe_carrier(step)
            or method_probe_fields(step.method, probe_fields)
            for step in path.steps
        )
        for step in path.steps
        for alias in action_aliases(step.method.method_id)
    }
    for action in sorted(declared_action_ids(graph, Context.CONTRACT)):
        if action_aliases(action) & bound_actions:
            continue
        method = methods_by_action.get(action)
        scenario = scenarios_by_action.get(action)
        if method is None or scenario is None:
            record_binding_deficit(
                binding_deficits,
                action=action,
                reason=(
                    "contract_method_missing"
                    if method is None
                    else "contract_scenario_missing"
                ),
                kind=("method_missing" if method is None else "scenario_missing"),
                context=(("coverage", "contract_action"),),
            )
            continue
        candidates = tuple(
            path
            for path in dependencies
            if action in action_aliases(path.steps[-1].method.method_id)
        )
        if candidates:
            dependency = min(
                candidates, key=lambda path: (len(path.steps), path.path_id)
            )
            goal = f"goal:contract-smoke:{action}"
            bound = dataclasses.replace(
                dependency,
                goal_id=goal,
                kind="smoke",
                scoreable=False,
                steps=tuple(
                    dataclasses.replace(step, goal_id=goal) for step in dependency.steps
                ),
            )
        else:
            bound = contract_smoke_path(action, method=method, scenario=scenario)
        key = path_key(bound)
        if key not in path_keys:
            path_keys.add(key)
            paths.append(bound)
            bound_actions.update(
                alias
                for step in bound.steps
                for alias in action_aliases(step.method.method_id)
            )


def contract_smoke_path(
    action: str,
    *,
    method: MethodSpec,
    scenario: ScenarioPosition,
) -> QdlExecutionPath:
    payload = json.dumps(
        {"action": action, "context": Context.CONTRACT.value, "kind": "smoke"},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    path_id = f"qdl-smoke-{digest}"
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:contract-smoke:{action}",
        kind="smoke",
        description=f"Execute declared contract action {action!r} as a non-scoring smoke check.",
        steps=(
            build_step(
                step_id=f"step:{path_id}:0",
                goal_id=f"goal:contract-smoke:{action}",
                invariant=contract_smoke_invariant(action),
                method=method,
                scenario=scenario,
            ),
        ),
        recovery=True,
        scoreable=False,
    )


def contract_smoke_invariant(action: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=f"invariant:contract-smoke:{action}",
        norm_id=f"norm:contract-smoke:{action}",
        statement=(
            f"Declared contract action {action!r} must reach the transport layer. "
            "The smoke path intentionally has no scoring oracle."
        ),
        severity=Severity.LOW,
    )


def retained_invariants(
    index: InvariantIndex,
    paths: tuple[QdlExecutionPath, ...] | list[QdlExecutionPath],
) -> dict[str, InvariantProjection]:
    retained = {step.plan.invariant_id for path in paths for step in path.steps}
    return {
        invariant_id: invariant
        for invariant_id, invariant in index.invariants.items()
        if invariant_id in index.planned_ids or invariant_id in retained
    }


__all__ = [
    "bind_attack_paths",
    "bind_contract_smoke_paths",
    "bind_execution_paths",
    "bind_forbidden_paths",
    "bind_invariant_paths",
    "contract_smoke_invariant",
    "contract_smoke_path",
    "record_binding_deficit",
    "retained_invariants",
]
