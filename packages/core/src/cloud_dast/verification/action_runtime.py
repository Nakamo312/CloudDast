"""Action runtime evidence and binding deficits.

This module owns the executable action projection.  It is deliberately kept
separate from the QDL term coverage algebra: a declared action, its bound
paths, and transport evidence are not coverage cells.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from cloud_dast.contracts.assessment import (
    ActionRuntimeEntry,
    ActionRuntimeLedger,
    BindingDeficit,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DomainEvent,
    canonical_action_id,
)
from cloud_dast.qdl.graph import Context, QdlGraph, term_label


def declared_actions(
    graph: QdlGraph,
    *,
    context: Context = Context.CONTRACT,
) -> tuple[str, ...]:
    """Return action identifiers declared by one QDL context."""

    return tuple(
        sorted(
            term_label(fact.args[0])
            for fact in graph.facts_for("is", contexts={context})
            if len(fact.args) == 2 and term_label(fact.args[1]) == "Action"
        )
    )


def build_action_runtime_ledger(
    graph: QdlGraph,
    *,
    paths: Iterable[object] = (),
    planned_paths: Iterable[object] = (),
    events: Iterable[DomainEvent] = (),
    binding_deficits: Iterable[BindingDeficit] = (),
    finalize: bool = False,
) -> ActionRuntimeLedger:
    """Build runtime evidence for every action declared by the contract."""

    if not isinstance(graph, QdlGraph):
        raise TypeError("action runtime source must be a QdlGraph")

    declared = tuple(
        sorted(
            canonical_action_id(action)
            for action in declared_actions(graph, context=Context.CONTRACT)
        )
    )
    bound_paths: dict[str, set[str]] = defaultdict(set)
    logical_paths: dict[str, set[str]] = defaultdict(set)
    recovery_paths: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        path_id = getattr(path, "path_id", None)
        if not isinstance(path_id, str):
            continue
        is_recovery = bool(getattr(path, "recovery", False)) or (
            getattr(path, "kind", None) == "smoke"
        )
        for action in _step_actions(path):
            bound_paths[action].add(path_id)
            if is_recovery:
                recovery_paths[action].add(path_id)

    for path in planned_paths:
        path_id = getattr(path, "path_id", None)
        if not isinstance(path_id, str):
            continue
        for action in _path_action_ids(path):
            logical_paths[action].add(path_id)

    completed: dict[str, set[str]] = defaultdict(set)
    updated: dict[str, set[str]] = defaultdict(set)
    method_ids: dict[str, str] = {}
    for event in events:
        if isinstance(event, CheckCompleted):
            method_id = event.method_id or getattr(event.check, "method_id", None)
            if not isinstance(method_id, str):
                continue
            action = canonical_action_id(method_id)
            method_ids[action] = method_id
            completed[action].add(event.observation.observation_id)
        elif isinstance(event, CoverageUpdated):
            action = canonical_action_id(event.method_id)
            method_ids[action] = event.method_id
            updated[action].add(event.check_id)

    deficits_by_action: dict[str, list[BindingDeficit]] = defaultdict(list)
    for deficit in binding_deficits:
        deficits_by_action[canonical_action_id(deficit.action)].append(deficit)

    entries = [
        ActionRuntimeEntry(
            action_id=action,
            method_id=method_ids.get(action, action.removeprefix("action:")),
            planned_path_ids=tuple(sorted(logical_paths.get(action, set()))),
            bound_path_ids=tuple(sorted(bound_paths.get(action, set()))),
            recovery_path_ids=tuple(sorted(recovery_paths.get(action, set()))),
            request_execution_ids=tuple(sorted(completed.get(action, set()))),
            coverage_update_ids=tuple(sorted(updated.get(action, set()))),
            terminal_deficit=min(
                deficits_by_action.get(action, ()),
                key=lambda deficit: (deficit.deficit_kind, deficit.reason),
                default=None,
            ),
        )
        for action in declared
    ]
    ledger = ActionRuntimeLedger(entries=tuple(entries))
    return ledger.finalize() if finalize else ledger


def _path_action_ids(path: object) -> tuple[str, ...]:
    """Extract action ids from a planned or bound path projection."""

    actions = getattr(path, "actions", ())
    if not actions:
        nested = getattr(path, "path", None)
        actions = getattr(nested, "actions", ())
    if actions:
        return tuple(
            canonical_action_id(action) for action in actions if isinstance(action, str)
        )
    return _step_actions(path)


def _step_actions(path: object) -> tuple[str, ...]:
    """Read bound step methods without consulting logical action attributes."""

    result: list[str] = []
    for step in getattr(path, "steps", ()):
        method_id = getattr(getattr(step, "method", None), "method_id", None)
        if isinstance(method_id, str):
            result.append(canonical_action_id(method_id))
    return tuple(result)
