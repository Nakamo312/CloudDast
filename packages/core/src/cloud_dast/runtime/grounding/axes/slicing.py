"""Deterministic model-facing slices for axis grounding."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from cloud_dast.model.events import normalize_action, normalize_principal
from cloud_dast.qdl.graph import Context, Fact, QdlGraph, canonical_json
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.runtime.consultation.axes import NORMS_AXIS
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import (
    SLICE_VERSION,
    BoundedSlice,
    SliceBudget,
    build_slice,
)

_GROUNDING_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})

__all__ = ["build_axis_slice", "policy_permission_graph"]


def build_axis_slice(
    axis: str,
    graph: QdlGraph,
    action_ids: tuple[str, ...],
    *,
    evidence: EvidenceView | None,
    budget: SliceBudget,
) -> BoundedSlice:
    """Build one axis slice, reserving policy context for norms."""

    slice_ = build_slice(
        graph,
        actions=action_ids,
        evidence=evidence,
        budget=budget,
    )
    if axis != NORMS_AXIS:
        return slice_

    policy_graph = policy_permission_graph(graph, action_ids)
    policy_keys = {
        canonical_json(fact)
        for fact in policy_graph.facts
        if fact.predicate.name == "may"
    }
    slice_keys = {canonical_json(fact) for fact in slice_.graph.facts}
    if not policy_keys or policy_keys <= slice_keys:
        return slice_

    policy_budget = SliceBudget(
        max_tokens=max(1, budget.max_tokens // 2),
        max_depth=budget.max_depth,
        bytes_per_token=budget.bytes_per_token,
    )
    policy_slice = build_slice(
        policy_graph,
        actions=action_ids,
        budget=policy_budget,
    )
    remaining = max(1, budget.max_tokens - policy_slice.token_estimate)
    action_slice = build_slice(
        graph,
        actions=action_ids,
        evidence=evidence,
        budget=SliceBudget(
            max_tokens=remaining,
            max_depth=budget.max_depth,
            bytes_per_token=budget.bytes_per_token,
        ),
    )
    merged = merge_graphs(action_slice.graph, policy_slice.graph)
    return BoundedSlice(
        graph=merged,
        evidence=evidence,
        actions=action_slice.actions,
        depth=max(action_slice.depth, policy_slice.depth),
        token_estimate=action_slice.token_estimate + policy_slice.token_estimate,
        truncated=action_slice.truncated or policy_slice.truncated,
        slice_hash=model_slice_hash(merged, evidence, action_slice.actions),
    )


def policy_permission_graph(
    graph: QdlGraph,
    action_ids: tuple[str, ...],
) -> QdlGraph:
    """Select campaign-attacker permissions for the requested actions."""

    requested_actions = {
        normalized
        for action_id in action_ids
        if (normalized := normalize_action(action_id)) is not None
    }
    attackers = campaign_attacker_values(graph)
    if not requested_actions or not attackers:
        return QdlGraph()

    declarations = graph.declarations_for(_GROUNDING_CONTEXTS)
    facts: list[Fact] = []
    seen: set[str] = set()

    def add(fact: Fact) -> None:
        key = canonical_json(fact)
        if key in seen:
            return
        seen.add(key)
        facts.append(fact)

    for fact in graph.facts_for("may", contexts=_GROUNDING_CONTEXTS):
        if (
            len(fact.args) != 3
            or normalize_principal(atom_value(fact.args[0])) not in attackers
            or normalize_action(atom_value(fact.args[1])) not in requested_actions
        ):
            continue
        add(fact)
        for term in fact.args:
            declaration = declarations.get(canonical_json(term))
            if declaration is not None:
                add(declaration)
    return QdlGraph(facts=tuple(facts))


def campaign_attacker_values(graph: QdlGraph) -> frozenset[str]:
    """Resolve the campaign attacker without hardcoding service actions."""

    explicit = {
        normalized
        for fact in graph.facts
        if fact.context in _GROUNDING_CONTEXTS
        and fact.predicate.name == "attacker"
        and len(fact.args) == 1
        and (normalized := normalize_principal(atom_value(fact.args[0]))) is not None
    }
    if explicit:
        return frozenset(explicit)

    may_principals = {
        normalized
        for fact in graph.facts
        if fact.context in _GROUNDING_CONTEXTS
        and fact.predicate.name == "may"
        and len(fact.args) == 3
        and (normalized := normalize_principal(atom_value(fact.args[0]))) is not None
    }
    return frozenset(
        principal for principal in may_principals if principal == "attacker"
    )


def model_slice_hash(
    graph: QdlGraph,
    evidence: EvidenceView | None,
    actions: Sequence[str],
) -> str:
    """Hash the exact model-facing content of an augmented slice."""

    payload = {
        "slice_version": SLICE_VERSION,
        "actions": list(actions),
        "graph": graph.model_dump(mode="json"),
        "evidence": evidence.digest if evidence is not None else None,
    }
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()
