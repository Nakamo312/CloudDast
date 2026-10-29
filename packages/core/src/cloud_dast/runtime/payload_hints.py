"""Deterministic runtime payload-hint compilation from grounded semantics.

The model never emits engine payload hints directly. It grounds the primary
semantics — which fields reach supported sinks, which are privileged — and
this compiler projects them onto fuzzer configuration. Keeping the
projection deterministic keeps probe hints auditable and idempotent.
"""

from __future__ import annotations

from collections.abc import Mapping

from cloud_dast.qdl import reasoning
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import (
    filter_executable_graph,
)
from cloud_dast.verification.invariant_projection import EXECUTABLE_CONTEXTS


def compile_payload_hints(graph: QdlGraph) -> dict[str, tuple[str, ...]]:
    """Compile probe-marker fields per action from semantic facts."""

    source = filter_executable_graph(graph)
    sink_types = reasoning.index_sinks(source)
    fields: dict[str, set[str]] = {}

    for source_term, target_term in ClingoEngine().reaches_plus_pairs(source):
        reasoning.collect_reach_hint(source_term, target_term, sink_types, fields)

    for fact in source.facts:
        if fact.predicate.name == "has" and len(fact.args) == 2:
            reasoning.collect_role_hint(fact.args[0], fact.args[1], fields)

    return {action: tuple(sorted(values)) for action, values in fields.items()}


def sink_types_by_action(
    graph: QdlGraph,
    payload_fields: Mapping[str, tuple[str, ...]],
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Project sink classes behind already-selected payload-hint fields."""

    source = QdlGraph(
        facts=tuple(fact for fact in graph.facts if fact.context in EXECUTABLE_CONTEXTS)
    )
    sink_types = reasoning.index_sinks(source)

    result: dict[str, set[tuple[str, str]]] = {}
    for source_term, target_term in ClingoEngine().reaches_plus_pairs(source):
        action, field = reasoning.read_input_field(source_term)
        if (
            action is None
            or field is None
            or field not in payload_fields.get(action, ())
        ):
            continue
        sink = atom_value(target_term)
        if sink is None:
            continue
        for sink_type in sorted(sink_types.get(sink, ())):
            result.setdefault(action, set()).add((field, sink_type))
    return {action: tuple(sorted(values)) for action, values in result.items()}


__all__ = [
    "compile_payload_hints",
    "sink_types_by_action",
]
