"""Pure verification projections from QDL norms and effects."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.model.evidence import Severity
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    canonical_json,
    transition,
)
from cloud_dast.qdl.graph import Fact as QdlFact
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.reasoning import QdlInvariant, QdlPlan
from cloud_dast.qdl.semantic_norm_compiler import (
    derive_causal_effects,
)
from cloud_dast.verification.norms import Primitive

EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})

_INVARIANT_SEVERITY: Mapping[Primitive, Severity] = {
    "outcome": Severity.HIGH,
    "sequence": Severity.CRITICAL,
    "response_field": Severity.MEDIUM,
    "latency_bound": Severity.LOW,
    "marker": Severity.HIGH,
    "differential": Severity.HIGH,
    "oob_event": Severity.HIGH,
    "unknown": Severity.MEDIUM,
}


class InvariantProjection(BaseModel):
    """Display and oracle view derived from one QDL norm.

    QDL owns the norm and its formal fact. This view only carries the
    executable identity and presentation metadata required by verification;
    it is never a second source of declarative truth.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    invariant_id: str
    norm_id: str
    statement: str
    severity: Severity
    policy: str | None = None
    norm_fact: QdlFact | None = Field(
        default=None,
        description="formal QDL prevents-fact; preferred source of executable truth",
    )


@dataclass(frozen=True, slots=True)
class InvariantIndex:
    """Canonical QDL invariant lookup tables for path binding."""

    invariants: dict[str, InvariantProjection]
    by_action: dict[str, list[str]]
    by_effect: dict[str, list[str]]
    planned_ids: frozenset[str]


def build_invariant_index(
    plan: QdlPlan,
    graph: QdlGraph,
    *,
    exposes_by_witness: Mapping[tuple[str, str], list[str]] | None = None,
    actions_by_effect: Mapping[Struct, tuple[str, ...]] | None = None,
) -> InvariantIndex:
    """Deduplicate planned invariants and index them by action and effect."""

    invariants: dict[str, InvariantProjection] = {}
    invariants_by_action: dict[str, list[str]] = {}
    witnesses = (
        exposes_by_witness
        if exposes_by_witness is not None
        else index_exposed_witnesses(graph)
    )
    effect_actions = (
        actions_by_effect
        if actions_by_effect is not None
        else index_actions_by_effect(graph)
    )
    seen_norm_keys: set[tuple[str, str, str]] = set()
    for qdl_invariant in plan.invariants:
        projection = project_invariant(qdl_invariant)
        actions = tuple(
            dict.fromkeys(
                invariant_actions(
                    qdl_invariant,
                    witnesses,
                    actions_by_effect=effect_actions,
                )
            )
        )
        if not actions:
            _remember_global(
                projection,
                qdl_invariant.effect,
                invariants,
                seen_norm_keys,
            )
            continue
        if all(
            norm_key(action, qdl_invariant.effect) in seen_norm_keys
            for action in actions
        ):
            continue
        if projection.invariant_id not in invariants:
            invariants[projection.invariant_id] = projection
        for action in actions:
            _remember_action(
                projection,
                action,
                qdl_invariant.effect,
                invariants_by_action,
                seen_norm_keys,
            )
    return InvariantIndex(
        invariants=invariants,
        by_action=invariants_by_action,
        by_effect=invariants_by_effect(invariants),
        planned_ids=frozenset(invariants),
    )


def invariants_by_effect(
    invariants: Mapping[str, InvariantProjection],
) -> dict[str, list[str]]:
    """Index prevents-norms by their canonical prevented effect."""

    by_effect: dict[str, list[str]] = {}
    for invariant in invariants.values():
        fact = invariant.norm_fact
        if (
            fact is None
            or fact.predicate.name != "prevents"
            or len(fact.args) != 2
            or not isinstance(fact.args[1], Struct)
        ):
            continue
        by_effect.setdefault(canonical_json(fact.args[1]), []).append(
            invariant.invariant_id
        )
    return by_effect


def index_exposed_witnesses(graph: QdlGraph) -> dict[tuple[str, str], list[str]]:
    """Index ``exposes(action, field(resource, name))`` facts by witness."""

    result: dict[tuple[str, str], list[str]] = {}
    for fact in graph.facts:
        if fact.predicate.name != "exposes" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        witness = fact.args[1]
        if not isinstance(witness, Struct) or witness.name != "field":
            continue
        if len(witness.args) != 2:
            continue
        resource = atom_value(witness.args[0])
        name = atom_value(witness.args[1])
        if action and resource and name:
            result.setdefault((resource, name), []).append(action)
    return result


def invariant_actions(
    invariant: QdlInvariant,
    exposes_by_witness: Mapping[tuple[str, str], list[str]],
    *,
    actions_by_effect: Mapping[Struct, tuple[str, ...]],
) -> tuple[str, ...]:
    """Return every action an invariant must be verified against."""

    if invariant.effect.name == "has":
        return _exposed_actions(invariant.effect, exposes_by_witness)
    if invariant.effect.name in {"changed", "transition"}:
        return actions_by_effect.get(invariant.effect, ())
    action = effect_action(invariant.effect)
    if action is not None:
        return (action,)
    return _exposed_actions(invariant.effect, exposes_by_witness)


def index_actions_by_effect(graph: QdlGraph) -> dict[Struct, tuple[str, ...]]:
    """Index current causal effects and explicit state-machine transitions."""

    actions: dict[Struct, set[str]] = defaultdict(set)
    for action, effect in derive_causal_effects(graph):
        action_id = atom_value(action)
        if action_id is not None:
            actions[effect].add(action_id)
    for fact in graph.facts_for("transition", contexts=EXECUTABLE_CONTEXTS):
        action, from_state, to_state = fact.args
        effect = transition(from_state, to_state)
        action_id = atom_value(action)
        if action_id is not None:
            actions[effect].add(action_id)
    return {effect: tuple(sorted(ids)) for effect, ids in actions.items()}


def project_invariant(item: QdlInvariant) -> InvariantProjection:
    effect_key = canonical_json(item.effect)
    digest = hashlib.sha256(effect_key.encode("utf-8")).hexdigest()[:12]
    return InvariantProjection(
        invariant_id=f"invariant:qdl:{item.norm}:{digest}",
        norm_id=norm_id(item.norm),
        statement=f"QDL norm {item.norm!r} prevents {effect_key}.",
        severity=_INVARIANT_SEVERITY[item.primitive],
        policy=f"not {effect_key}",
        norm_fact=item.fact,
    )


def effect_action(effect: Struct) -> str | None:
    if not effect.args:
        return None
    term = effect.args[0]
    if isinstance(term, Atom) and isinstance(term.value, str):
        return term.value
    return None


def norm_id(norm: str) -> str:
    return f"norm:{norm.removeprefix('norm:')}"


def norm_key(action: str, effect: Struct) -> tuple[str, str, str]:
    """Return the canonical action/effect/witness identity of a bound norm."""

    return (
        action.removeprefix("action:"),
        canonical_json(effect),
        canonical_json(effect.args[1:]),
    )


def _exposed_actions(
    effect: Struct,
    exposes_by_witness: Mapping[tuple[str, str], list[str]],
) -> tuple[str, ...]:
    if effect.name != "has" or len(effect.args) != 2:
        return ()
    value = effect.args[1]
    if not isinstance(value, Struct) or value.name != "field":
        return ()
    if len(value.args) != 2:
        return ()
    witness = (atom_value(value.args[0]), atom_value(value.args[1]))
    if witness[0] is None or witness[1] is None:
        return ()
    return tuple(exposes_by_witness.get(witness, ()))


def _remember_global(
    projection: InvariantProjection,
    effect: Struct,
    invariants: dict[str, InvariantProjection],
    seen_norm_keys: set[tuple[str, str, str]],
) -> None:
    key = norm_key("", effect)
    if key in seen_norm_keys:
        return
    seen_norm_keys.add(key)
    invariants.setdefault(projection.invariant_id, projection)


def _remember_action(
    projection: InvariantProjection,
    action: str,
    effect: Struct,
    invariants_by_action: dict[str, list[str]],
    seen_norm_keys: set[tuple[str, str, str]],
) -> None:
    key = norm_key(action, effect)
    if key in seen_norm_keys:
        return
    seen_norm_keys.add(key)
    invariants_by_action.setdefault(action, []).append(projection.invariant_id)


__all__ = [
    "EXECUTABLE_CONTEXTS",
    "InvariantIndex",
    "build_invariant_index",
    "effect_action",
    "index_actions_by_effect",
    "index_exposed_witnesses",
    "invariant_actions",
    "invariants_by_effect",
    "norm_id",
    "norm_key",
    "project_invariant",
]
