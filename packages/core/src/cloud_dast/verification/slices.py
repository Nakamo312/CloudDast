"""Bounded, deterministic QDL slices for model requests.

A slice is the only graph shape an LLM call may see: a depth-bounded
neighbourhood of seed actions, the runtime evidence projected next to it,
and a token budget that caps the rendered payload.  A slice is a transport
projection, never a second source of truth: facts keep their original
contexts, and the model still answers only with proposals.

S31 adds the deterministic sibling-action slice: the effect neighbourhood
of one action computed purely from QDL relations (shared ``causes``,
``requires``, ``targets``, or resource type), so "which sibling actions
could unblock this step" is answered from the graph instead of replaying
the model's own natural-language questions.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from cloud_dast.qdl.graph import (
    Atom,
    Fact,
    QdlGraph,
    Rule,
    Struct,
    canonical_json,
    collect_references,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.evidence import EvidenceView

SLICE_VERSION = 1
DEFAULT_BYTES_PER_TOKEN = 4
SIBLING_SLICE_VERSION = 1
DEFAULT_MAX_SIBLINGS = 12
_EMPTY_SLICE_GRAPH = QdlGraph()
# The deterministic relations that make one action a sibling of another.
# ``resource_type`` is derived from ``targets`` plus ``is``-declarations and
# is intentionally not a predicate name.
SIBLING_RELATION_PREDICATES: tuple[str, ...] = ("causes", "requires", "targets")
SIBLING_RELATION_NAMES: tuple[str, ...] = (
    *SIBLING_RELATION_PREDICATES,
    "resource_type",
)


@dataclass(frozen=True, slots=True)
class SliceBudget:
    """Upper bounds for one model-facing graph slice.

    ``max_tokens`` bounds the rendered graph plus the attached runtime
    evidence together.  ``max_depth`` bounds expansion over declared
    entities: hop 1 selects facts that mention a seed action anywhere in
    their terms, and every later hop may traverse only terms the source
    graph declares with an ``is`` fact.  The default keeps the established
    one-hop action-slice semantics; deeper budgets are opt-in.
    """

    max_tokens: int = 8192
    max_depth: int = 1
    bytes_per_token: int = DEFAULT_BYTES_PER_TOKEN

    def __post_init__(self) -> None:
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if self.max_depth <= 0:
            raise ValueError("max_depth must be positive")
        if self.bytes_per_token <= 0:
            raise ValueError("bytes_per_token must be positive")


DEFAULT_SLICE_BUDGET = SliceBudget()


@dataclass(frozen=True, slots=True)
class BoundedSlice:
    """One bounded QDL neighbourhood with its runtime evidence projection."""

    graph: QdlGraph
    evidence: EvidenceView | None = None
    actions: tuple[str, ...] = ()
    depth: int = 0
    token_estimate: int = 0
    truncated: bool = False
    slice_hash: str = ""

    def context(self) -> dict[str, Any]:
        """Render the model-facing context for this slice."""

        payload: dict[str, Any] = {"graph": self.graph.model_dump(mode="json")}
        if self.evidence is not None:
            payload["evidence"] = self.evidence.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class SiblingAction:
    """One QDL-justified sibling of a seed action.

    ``relations`` names the deterministic QDL relations shared with the
    seed: ``causes`` (the same effect term), ``requires`` (the same
    permission term), ``targets`` (the same target term), or
    ``resource_type`` (targets of the same declared resource type).
    ``shared_terms`` carries the canonical JSON of those shared terms, so
    every membership claim is checkable against the slice graph without
    trusting any model output.
    """

    action: str
    relations: tuple[str, ...]
    shared_terms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SiblingActionSlice:
    """The deterministic effect neighbourhood of one action.

    The slice answers "which sibling actions could unblock this step" from
    QDL relations alone, never from natural-language model uncertainties.
    Participants are the seed and siblings with at least one shared
    ``causes`` / ``requires`` / ``targets`` / resource-type term. The graph
    also carries declarations required to validate those terms; these do
    not expand the participant domain recorded by ``siblings``.
    """

    action: str
    siblings: tuple[SiblingAction, ...] = ()
    graph: QdlGraph = _EMPTY_SLICE_GRAPH
    truncated: bool = False
    slice_hash: str = ""


def build_sibling_action_slice(
    graph: QdlGraph,
    *,
    action: str,
    max_siblings: int | None = DEFAULT_MAX_SIBLINGS,
) -> SiblingActionSlice:
    """Build the deterministic sibling-action slice for one action.

    For a seed action ``A`` the slice contains exactly the declared actions
    ``B`` that share at least one QDL relation with ``A``:

    - ``causes(A, E)`` and ``causes(B, E)`` for one effect term ``E``;
    - ``requires(A, P)`` and ``requires(B, P)`` for one permission ``P``;
    - ``targets(A, T)`` and ``targets(B, T)`` for one target term ``T``;
    - target terms whose declared resource types intersect
      (``is(T, Type)`` with ``is(Type, ResourceType)``), even when the
      target terms themselves differ.

    Like every other slice this is a transport projection, not a second
    source of truth: original facts keep their contexts, declarations are
    added for terms the justification facts reference. A referenced action
    declaration supports those facts without becoming a sibling. No model
    is involved at any point.
    """

    if max_siblings is not None and max_siblings <= 0:
        raise ValueError("max_siblings must be positive or None")

    seed_atoms = _resolve_action_atoms(graph, (action,))
    if not seed_atoms:
        return SiblingActionSlice(
            action="",
            graph=QdlGraph(),
            slice_hash=_sibling_slice_hash("", (), QdlGraph()),
        )
    seed_keys = {canonical_json(atom) for atom in seed_atoms}
    declarations = graph.declarations_for()
    declared_actions = _declared_action_index(graph)
    relation_terms = _action_relation_terms(graph, declared_actions)
    term_types, typing_facts = _resource_type_index(graph)
    action_types = _action_resource_types(relation_terms["targets"], term_types)
    seed_relation_terms = {
        predicate: _union_sets(
            relation_terms[predicate].get(key, frozenset()) for key in seed_keys
        )
        for predicate in SIBLING_RELATION_PREDICATES
    }
    seed_types = _union_sets(action_types.get(key, frozenset()) for key in seed_keys)

    justified: list[tuple[str, SiblingAction, dict[str, set[str]]]] = []
    for key in sorted(declared_actions, key=declared_actions.__getitem__):
        if key in seed_keys:
            continue
        shared: dict[str, set[str]] = {}
        for predicate in SIBLING_RELATION_PREDICATES:
            overlap = seed_relation_terms[predicate] & relation_terms[predicate].get(
                key, frozenset()
            )
            if overlap:
                shared[predicate] = overlap
        # A shared target term already proves the direct relation, and so
        # do the types it derives: ``resource_type`` matters only when the
        # target terms themselves differ.
        shared_target_types = _union_sets(
            term_types.get(term, frozenset())
            for term in shared.get("targets", frozenset())
        )
        type_overlap = (seed_types & action_types.get(key, set())) - shared_target_types
        if type_overlap:
            shared["resource_type"] = type_overlap
        if not shared:
            continue
        justified.append(
            (
                key,
                SiblingAction(
                    action=declared_actions[key],
                    relations=tuple(sorted(shared)),
                    shared_terms=tuple(sorted(_union_sets(shared.values()))),
                ),
                shared,
            )
        )

    truncated = max_siblings is not None and len(justified) > max_siblings
    if truncated:
        justified = justified[:max_siblings]
    sibling_keys = {key for key, _, _ in justified}
    participant_keys = seed_keys | sibling_keys
    direct_shared_terms = _union_sets(
        shared.get(predicate, frozenset())
        for _, _, shared in justified
        for predicate in SIBLING_RELATION_PREDICATES
    )
    resource_type_terms = _union_sets(
        shared.get("resource_type", frozenset()) for _, _, shared in justified
    )

    kept_facts: dict[str, Fact] = {}
    for key in participant_keys:
        declaration = declarations.get(key)
        if declaration is not None:
            kept_facts[canonical_json(declaration)] = declaration
    for fact in graph.facts:
        if (
            fact.predicate.name not in SIBLING_RELATION_PREDICATES
            or len(fact.args) < 2
            or not isinstance(fact.args[0], Atom)
        ):
            continue
        action_key = canonical_json(fact.args[0])
        if action_key not in participant_keys:
            continue
        term_key = canonical_json(fact.args[1])
        if term_key in direct_shared_terms:
            kept_facts[canonical_json(fact)] = fact
            continue
        derived_types = term_types.get(term_key, frozenset()) & resource_type_terms
        if fact.predicate.name == "targets" and derived_types:
            kept_facts[canonical_json(fact)] = fact
            for type_key in sorted(derived_types):
                if type_key == term_key:
                    continue
                typing_fact = typing_facts.get((term_key, type_key))
                if typing_fact is not None:
                    kept_facts[canonical_json(typing_fact)] = typing_fact

    _add_referenced_declarations(
        kept_facts,
        declarations,
    )
    slice_graph = QdlGraph(facts=tuple(kept_facts.values()))
    siblings = tuple(sibling for _, sibling, _ in justified)
    resolved_action = seed_atoms[0].value
    return SiblingActionSlice(
        action=resolved_action,
        siblings=siblings,
        graph=slice_graph,
        truncated=truncated,
        slice_hash=_sibling_slice_hash(resolved_action, siblings, slice_graph),
    )


def build_slice(
    graph: QdlGraph,
    *,
    actions: Sequence[str] = (),
    evidence: EvidenceView | None = None,
    budget: SliceBudget = DEFAULT_SLICE_BUDGET,
) -> BoundedSlice:
    """Build a deterministic, self-contained slice around seed actions.

    Expansion runs breadth-first over declared entities for at most
    ``budget.max_depth`` hops.  The result is then assembled central facts
    first and trimmed until the graph and the attached evidence fit
    ``budget.max_tokens``.  Runtime evidence is never rewritten or dropped
    here: it is the already bounded ``EvidenceView`` projection of captured
    events, and the graph shrinks to the tokens that remain after it.
    """

    declarations = graph.declarations_for()
    seed_atoms = _resolve_action_atoms(graph, actions)
    if seed_atoms:
        seed_keys = {canonical_json(atom) for atom in seed_atoms}
    elif not _declares_actions(graph):
        # Action-less graphs, such as one transported norm, still need a
        # bounded neighbourhood: seed from every declared entity.
        seed_keys = set(declarations)
    else:
        seed_keys = set()

    selected, depths = _expand(graph, seed_keys, declarations, budget.max_depth)
    rules = _related_rules(graph, seed_keys, selected)
    # Reserve the exact rendered evidence and JSON envelope, including any
    # expansion caused by model-facing redaction. Evidence remains local and
    # intact; an evidence-only overflow is an explicit budget deficit.
    empty_context = BoundedSlice(graph=_EMPTY_SLICE_GRAPH, evidence=evidence).context()
    context_tokens = estimate_tokens(
        empty_context, bytes_per_token=budget.bytes_per_token
    )
    if context_tokens > budget.max_tokens:
        raise ValueError("rendered slice evidence exceeds token budget")
    overhead_tokens = context_tokens - estimate_tokens(
        _EMPTY_SLICE_GRAPH, bytes_per_token=budget.bytes_per_token
    )
    # Reserve one extra token for independent rounding of the envelope.
    available = max(0, budget.max_tokens - overhead_tokens - 1)
    kept_facts, kept_rules, kept_depths, truncated = _assemble(
        selected,
        depths,
        rules,
        declarations,
        available_tokens=available,
        bytes_per_token=budget.bytes_per_token,
    )
    slice_graph = QdlGraph(
        facts=tuple(kept_facts.values()),
        rules=tuple(kept_rules.values()),
    )
    resolved_actions = tuple(
        atom.value for atom in seed_atoms if isinstance(atom.value, str)
    )
    token_estimate = estimate_tokens(
        BoundedSlice(graph=slice_graph, evidence=evidence).context(),
        bytes_per_token=budget.bytes_per_token,
    )
    return BoundedSlice(
        graph=slice_graph,
        evidence=evidence,
        actions=resolved_actions,
        depth=max(kept_depths.values(), default=0),
        token_estimate=token_estimate,
        truncated=truncated,
        slice_hash=_slice_hash(slice_graph, evidence, resolved_actions),
    )


def estimate_tokens(
    value: object,
    *,
    bytes_per_token: int = DEFAULT_BYTES_PER_TOKEN,
) -> int:
    """Estimate tokens from canonical JSON bytes, deterministically."""

    if bytes_per_token <= 0:
        raise ValueError("bytes_per_token must be positive")
    return math.ceil(len(_canonical_text(value).encode("utf-8")) / bytes_per_token)


def _expand(
    graph: QdlGraph,
    seed_keys: set[str],
    declarations: Mapping[str, Fact],
    max_depth: int,
) -> tuple[dict[str, Fact], dict[str, int]]:
    """Select facts breadth-first from seed terms over declared entities."""

    selected: dict[str, Fact] = {}
    depths: dict[str, int] = {}
    frontier = set(seed_keys)
    for depth in range(1, max_depth + 1):
        additions: list[tuple[str, Fact]] = []
        next_terms: set[str] = set()
        for fact in graph.facts:
            key = canonical_json(fact)
            if key in selected:
                continue
            fact_terms = _term_keys(fact.args)
            if fact_terms & frontier:
                additions.append((key, fact))
                next_terms |= fact_terms
        if not additions:
            break
        for key, fact in additions:
            selected[key] = fact
            depths[key] = depth
        frontier = {key for key in next_terms if key in declarations}
    return selected, depths


def _related_rules(
    graph: QdlGraph,
    seed_keys: set[str],
    selected: Mapping[str, Fact],
) -> tuple[Rule, ...]:
    """Return rules that reference any term already present in the slice."""

    universe = set(seed_keys)
    for fact in selected.values():
        universe |= _term_keys(fact.args)
    return tuple(rule for rule in graph.rules if _rule_keys(rule) & universe)


def _assemble(
    selected: Mapping[str, Fact],
    depths: Mapping[str, int],
    rules: Sequence[Rule],
    declarations: Mapping[str, Fact],
    *,
    available_tokens: int,
    bytes_per_token: int,
) -> tuple[dict[str, Fact], dict[str, Rule], dict[str, int], bool]:
    """Keep central facts first while the graph fits the token budget."""

    kept: dict[str, Fact] = {}
    kept_rules: dict[str, Rule] = {}
    kept_depths: dict[str, int] = {}
    truncated = False

    ordered = sorted(
        selected.items(),
        key=lambda item: (depths.get(item[0], 0), item[0]),
    )
    for key, fact in ordered:
        additions = _missing_declarations(
            _term_keys(fact.args),
            kept,
            declarations,
        )
        candidate = [
            *kept.values(),
            fact,
            *additions,
        ]
        if _graph_tokens(candidate, (), bytes_per_token) > available_tokens:
            truncated = True
            continue
        kept[key] = fact
        kept_depths[key] = depths.get(key, 0)
        for declaration in additions:
            declaration_key = canonical_json(declaration)
            kept[declaration_key] = declaration
            kept_depths[declaration_key] = depths.get(key, 0)

    for rule in sorted(rules, key=canonical_json):
        literal_keys = _rule_keys(rule)
        additions = _missing_declarations(literal_keys, kept, declarations)
        candidate_facts = [*kept.values(), *additions]
        candidate_rules = [*kept_rules.values(), rule]
        if _graph_tokens(candidate_facts, candidate_rules, bytes_per_token) > (
            available_tokens
        ):
            truncated = True
            continue
        kept_rules[canonical_json(rule)] = rule
        for declaration in additions:
            declaration_key = canonical_json(declaration)
            kept[declaration_key] = declaration
            kept_depths[declaration_key] = 0

    return kept, kept_rules, kept_depths, truncated


def _missing_declarations(
    keys: Iterable[str],
    kept: Mapping[str, Fact],
    declarations: Mapping[str, Fact],
) -> list[Fact]:
    """Return source declarations for referenced terms not kept yet."""

    additions: list[Fact] = []
    addition_keys = {canonical_json(fact) for fact in additions}
    for key in sorted(keys):
        declaration = declarations.get(key)
        if declaration is None:
            continue
        fact_key = canonical_json(declaration)
        if fact_key in kept or fact_key in addition_keys:
            continue
        additions.append(declaration)
        addition_keys.add(fact_key)
    return additions


def _declares_actions(graph: QdlGraph) -> bool:
    return any(
        fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == "Action"
        for fact in graph.facts
    )


def _declared_action_index(graph: QdlGraph) -> dict[str, str]:
    """Map canonical action atoms to their declared action ids."""

    result: dict[str, str] = {}
    for fact in graph.facts:
        if (
            fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
            and isinstance(fact.args[0], Atom)
        ):
            value = atom_value(fact.args[0])
            if isinstance(value, str):
                result.setdefault(canonical_json(fact.args[0]), value)
    return result


def _action_relation_terms(
    graph: QdlGraph,
    declared_actions: Mapping[str, str],
) -> dict[str, dict[str, set[str]]]:
    """Index ``causes``/``requires``/``targets`` terms per declared action."""

    result: dict[str, dict[str, set[str]]] = {
        predicate: {} for predicate in SIBLING_RELATION_PREDICATES
    }
    for fact in graph.facts:
        predicate = fact.predicate.name
        if (
            predicate not in result
            or len(fact.args) < 2
            or not isinstance(fact.args[0], Atom)
        ):
            continue
        action_key = canonical_json(fact.args[0])
        if action_key not in declared_actions:
            continue
        result[predicate].setdefault(action_key, set()).add(
            canonical_json(fact.args[1])
        )
    return result


def _resource_type_index(
    graph: QdlGraph,
) -> tuple[dict[str, set[str]], dict[tuple[str, str], Fact]]:
    """Return resource types per term and the ``is`` facts deriving them.

    A term declared ``is(Type, ResourceType)`` is its own resource type; a
    term with ``is(T, Type)`` where ``Type`` is a declared resource type is
    an instance of that type.  Everything else — plain ``Resource`` or
    ``ResourceType`` class declarations — carries no sibling information.
    """

    resource_type_keys = {
        canonical_json(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == "ResourceType"
    }
    term_types: dict[str, set[str]] = {key: {key} for key in resource_type_keys}
    typing_facts: dict[tuple[str, str], Fact] = {}
    for fact in graph.facts:
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        term_key = canonical_json(fact.args[0])
        type_key = canonical_json(fact.args[1])
        if term_key in resource_type_keys or type_key not in resource_type_keys:
            continue
        term_types.setdefault(term_key, set()).add(type_key)
        typing_facts[(term_key, type_key)] = fact
    return term_types, typing_facts


def _action_resource_types(
    targets_by_action: Mapping[str, set[str]],
    term_types: Mapping[str, set[str]],
) -> dict[str, set[str]]:
    """Union the declared resource types of every action's target terms."""

    result: dict[str, set[str]] = {}
    for action_key, target_terms in targets_by_action.items():
        types: set[str] = set()
        for term_key in target_terms:
            types.update(term_types.get(term_key, ()))
        result[action_key] = types
    return result


def _union_sets(sets: Iterable[set[str] | frozenset[str]]) -> set[str]:
    """Union an iterable of sets without failing on an empty iterable."""

    return set().union(*sets)


def _add_referenced_declarations(
    kept_facts: dict[str, Fact],
    declarations: Mapping[str, Fact],
) -> None:
    """Add declarations for referenced terms until the slice is closed.

    The core schemas distinguish an action reference from a data literal
    with the same spelling. Supporting declarations do not grant membership
    in the explicit seed/sibling consultation and promotion domain.
    """

    pending = list(kept_facts.values())
    while pending:
        fact = pending.pop()
        references = set().union(
            *(
                collect_references(term, schema)
                for term, schema in zip(
                    fact.args, fact.predicate.definition.arguments, strict=True
                )
            )
        )
        for key in _term_keys(fact.args):
            declaration = declarations.get(key)
            if declaration is None:
                continue
            declaration_key = canonical_json(declaration)
            if declaration_key in kept_facts:
                continue
            if _is_action_declaration(declaration) and key not in references:
                continue
            kept_facts[declaration_key] = declaration
            pending.append(declaration)


def _is_action_declaration(fact: Fact) -> bool:
    return (
        fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == "Action"
    )


def _resolve_action_atoms(
    graph: QdlGraph,
    action_ids: Sequence[str],
) -> tuple[Atom, ...]:
    """Resolve requested action ids to the graph's Action atoms."""

    declared: list[tuple[str, Atom]] = []
    for fact in graph.facts:
        if (
            fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
            and isinstance(fact.args[0], Atom)
        ):
            value = atom_value(fact.args[0])
            if isinstance(value, str):
                declared.append((value, fact.args[0]))
    if not action_ids:
        selected = {canonical_json(atom): atom for _, atom in declared}
        return tuple(selected[key] for key in sorted(selected))

    requested: set[str] = set()
    for action_id in action_ids:
        requested.add(action_id)
        if action_id.startswith("action:"):
            requested.add(action_id.removeprefix("action:"))
        else:
            requested.add(f"action:{action_id}")
    selected = {
        canonical_json(atom): atom for value, atom in declared if value in requested
    }
    return tuple(selected[key] for key in sorted(selected))


def _term_keys(term: object) -> set[str]:
    """Return every canonical term key inside a fact argument tree."""

    if isinstance(term, Fact):
        return _term_keys(term.args)
    if isinstance(term, Rule):
        return _rule_keys(term)
    if isinstance(term, Atom):
        return {canonical_json(term)}
    if isinstance(term, Struct):
        return {canonical_json(term)} | {
            key for argument in term.args for key in _term_keys(argument)
        }
    if isinstance(term, tuple):
        return {key for argument in term for key in _term_keys(argument)}
    return set()


def _rule_keys(rule: Rule) -> set[str]:
    return {
        key for literal in (*rule.body, *rule.head) for key in _term_keys(literal.args)
    }


def _graph_tokens(
    facts: Sequence[Fact],
    rules: Sequence[Rule],
    bytes_per_token: int,
) -> int:
    return estimate_tokens(
        {
            "facts": [fact.model_dump(mode="json") for fact in facts],
            "rules": [rule.model_dump(mode="json") for rule in rules],
        },
        bytes_per_token=bytes_per_token,
    )


def _slice_hash(
    graph: QdlGraph,
    evidence: EvidenceView | None,
    actions: Sequence[str],
) -> str:
    """Hash the exact model-facing slice content."""

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


def _sibling_slice_hash(
    action: str,
    siblings: Sequence[SiblingAction],
    graph: QdlGraph,
) -> str:
    """Hash the exact sibling-slice content and justifications."""

    payload = {
        "sibling_slice_version": SIBLING_SLICE_VERSION,
        "action": action,
        "siblings": [
            {
                "action": sibling.action,
                "relations": list(sibling.relations),
                "shared_terms": list(sibling.shared_terms),
            }
            for sibling in siblings
        ],
        "graph": graph.model_dump(mode="json"),
    }
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _canonical_text(value: object) -> str:
    if isinstance(value, BaseModel):
        return canonical_json(value)
    if isinstance(value, tuple | list) and all(
        isinstance(item, BaseModel) for item in value
    ):
        return canonical_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


__all__ = [
    "BoundedSlice",
    "DEFAULT_SLICE_BUDGET",
    "DEFAULT_MAX_SIBLINGS",
    "SIBLING_RELATION_NAMES",
    "SIBLING_RELATION_PREDICATES",
    "SiblingAction",
    "SiblingActionSlice",
    "SliceBudget",
    "build_sibling_action_slice",
    "build_slice",
    "estimate_tokens",
]
