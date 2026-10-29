"""Derive executable state and resource-state paths from QDL."""

from __future__ import annotations

import json

from cloud_dast.qdl.graph import Context, QdlGraph
from cloud_dast.qdl.reasoning import (
    QdlForbiddenPath,
    QdlResourceStatePath,
    QdlStatePath,
)
from cloud_dast.qdl.state_machine import (
    ResourceStatePath,
    StateMachineEngine,
    StatePath,
)
from cloud_dast.runtime.planning.symbols import _path_id


def find_state_paths(
    graph: QdlGraph,
    contexts: tuple[Context, ...],
    engine: StateMachineEngine,
) -> tuple[tuple[QdlStatePath, ...], tuple[QdlForbiddenPath, ...]]:
    """Derive every bounded state-machine witness for the contexts.

    A reachable state can have multiple bounded action routes.  The planner
    materializes all of them instead of silently keeping only the shortest
    witness; each distinct route gets a content-addressed path identity.
    """

    state_paths: dict[tuple[Context, str, str, tuple[str, ...]], QdlStatePath] = {}
    forbidden_paths: list[QdlForbiddenPath] = []

    for context in contexts:
        if not _has_state_machine_facts(graph, context):
            continue

        solution = engine.solve(graph, context=context)
        for state in solution.reachable_states:
            for path in engine.find_paths(
                graph,
                state,
                context=context,
            ):
                _add_state_path(state_paths, path, context)

        for violation in solution.violations:
            for state_path in engine.find_paths(
                graph,
                violation.state,
                context=context,
            ):
                path = _add_state_path(state_paths, state_path, context)
                forbidden_paths.append(
                    QdlForbiddenPath(
                        path_id=_path_id(
                            "forbidden",
                            context,
                            (
                                path.initial_state,
                                path.final_state,
                                *path.actions,
                            ),
                            extra=violation.norm,
                        ),
                        norm=violation.norm,
                        path=path,
                    )
                )

    ordered_states = tuple(
        sorted(
            state_paths.values(),
            key=lambda path: (
                path.context.value,
                path.initial_state,
                path.final_state,
                path.actions,
            ),
        )
    )
    ordered_forbidden = tuple(
        sorted(
            forbidden_paths,
            key=lambda path: (
                path.path.context.value,
                path.norm,
                path.path.final_state,
                path.path.actions,
            ),
        )
    )
    return ordered_states, ordered_forbidden


def find_resource_state_paths(
    graph: QdlGraph,
    contexts: tuple[Context, ...],
    engine: StateMachineEngine,
) -> tuple[QdlResourceStatePath, ...]:
    """Derive every bounded per-resource state witness for the contexts."""

    paths: dict[
        tuple[Context, str, str, str, tuple[str, ...], tuple[str, ...]],
        QdlResourceStatePath,
    ] = {}
    for context in contexts:
        if not _has_resource_state_machine_facts(graph, context):
            continue
        solution = engine.solve_resources(graph, context=context)
        for path in solution.paths:
            _add_resource_state_path(paths, path, context)

    return tuple(
        sorted(
            paths.values(),
            key=lambda path: (
                path.context.value,
                path.resource,
                path.initial_state,
                path.final_state,
                path.actions,
            ),
        )
    )


def _add_resource_state_path(
    paths: dict[
        tuple[Context, str, str, str, tuple[str, ...], tuple[str, ...]],
        QdlResourceStatePath,
    ],
    path: ResourceStatePath,
    context: Context,
) -> QdlResourceStatePath:
    key = (
        context,
        path.resource,
        path.initial_state,
        path.final_state,
        path.actions,
        path.states,
    )
    existing = paths.get(key)
    if existing is not None:
        return existing

    view = QdlResourceStatePath(
        path_id=_path_id(
            "resource-state",
            context,
            (
                path.resource,
                path.initial_state,
                path.final_state,
                *path.actions,
            ),
            extra=json.dumps(path.states, ensure_ascii=False, separators=(",", ":")),
        ),
        context=context,
        resource=path.resource,
        initial_state=path.initial_state,
        final_state=path.final_state,
        actions=path.actions,
        states=path.states,
    )
    paths[key] = view
    return view


def _has_resource_state_machine_facts(graph: QdlGraph, context: Context) -> bool:
    return any(
        fact.context is context and fact.predicate.name in {"state", "precondition"}
        for fact in graph.facts
    )


def _has_state_machine_facts(graph: QdlGraph, context: Context) -> bool:
    return any(
        fact.context is context
        and fact.predicate.name in {"initial", "transition", "forbidden"}
        for fact in graph.facts
    )


def _add_state_path(
    paths: dict[tuple[Context, str, str, tuple[str, ...]], QdlStatePath],
    path: StatePath,
    context: Context,
) -> QdlStatePath:
    key = (context, path.initial_state, path.final_state, path.actions)
    existing = paths.get(key)
    if existing is not None:
        return existing

    view = QdlStatePath(
        path_id=_path_id(
            "state",
            context,
            (path.initial_state, path.final_state, *path.actions),
        ),
        context=context,
        initial_state=path.initial_state,
        final_state=path.final_state,
        actions=path.actions,
    )
    paths[key] = view
    return view
