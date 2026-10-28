"""Pure proposal filtering for one grounding axis.

The functions here enforce the QDL boundary of a grounding result: axis
predicate ownership, semantic-role closure, alternatives grammar, and live
response grounding.  They do not dispatch model calls or mutate campaign
state; ``axis_grounding.py`` owns that lifecycle and uses this module as a
deterministic projection seam.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Iterator, Mapping
from dataclasses import replace

from cloud_dast.consultation import (
    CONSULTATION_PREDICATES,
    ownership_effect_is_proposable,
)
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Fact,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import filter_semantic_roles
from cloud_dast.qdl.validation import ValidationIssue, filter_declaration_closure
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import (
    EvidenceView,
    evidence_response_fields,
)

_RESPONSE_SEMANTICS_PREDICATES = frozenset({"is", "exposes", "has"})
_AXIS_PREDICATES: dict[str, frozenset[str]] = {
    kind: predicates
    for kind, predicates in CONSULTATION_PREDICATES.items()
    if kind != "seed_enrichment"
}
_AXIS_PREDICATES["norms"] = frozenset({"is", "prevents"})
_ALTERNATIVE_EFFECT_CONSTRUCTORS = frozenset(CAUSAL_EFFECT_CONSTRUCTORS)
logger = logging.getLogger("cloud_dast.runtime.grounding.parallel")


def _bounded_log_value(value: object, *, limit: int = 512) -> str:
    text = str(value)
    return text if len(text) <= limit else f"{text[:limit]}…"


def _filter_axis_predicates(
    axis: str,
    graph: QdlGraph,
    *,
    has_evidence: bool,
) -> tuple[QdlGraph | None, tuple[ValidationIssue, ...]]:
    """Keep only the predicates owned by one grounding axis."""

    allowed = _AXIS_PREDICATES[axis]
    facts: list[Fact] = []
    dropped_facts: list[Fact] = []
    dropped_by_predicate: dict[str, int] = {}
    for fact in graph.facts:
        if fact.predicate.name in allowed and _axis_fact_is_allowed(
            axis, fact, has_evidence=has_evidence
        ):
            facts.append(fact)
            continue
        predicate = fact.predicate.name
        dropped_by_predicate[predicate] = dropped_by_predicate.get(predicate, 0) + 1
        dropped_facts.append(fact)
    if dropped_facts:
        predicates = ",".join(
            f"{predicate}={count}"
            for predicate, count in sorted(dropped_by_predicate.items())
        )
        logger.warning(
            "axis_grounding_predicate_rejected axis=%s predicates=%s dropped=%d",
            axis,
            _bounded_log_value(predicates),
            len(dropped_facts),
        )
    issues = tuple(
        ValidationIssue(
            code="predicate",
            message=f"predicate is outside the {axis} grounding axis",
            path=f"facts[{canonical_json(fact)}]",
        )
        for fact in dropped_facts
    )
    result = filter_declaration_closure(facts, graph.rules, issues=issues)
    return result.graph, result.issues


def _axis_fact_is_allowed(
    axis: str,
    fact: Fact,
    *,
    has_evidence: bool,
) -> bool:
    """Apply the predicate-shape boundary owned by one axis."""

    if fact.predicate.name != "causes":
        return True
    effect = fact.args[1] if len(fact.args) == 2 else None
    effect_name = effect.name if isinstance(effect, Struct) else None
    return ownership_effect_is_proposable(
        axis,
        effect_name,
        has_evidence=has_evidence,
    )


def _filter_alternatives_grammar(
    result: AxisResult,
    source: QdlGraph,
) -> AxisResult:
    """Close alternatives grammar over fields and effect constructors."""

    if result.graph is None:
        return result
    declared_fields = _declared_input_fields(source)
    kept: list[Fact] = []
    issues: list[ValidationIssue] = []
    for fact in result.graph.facts:
        violation = _alternatives_fact_violation(fact, declared_fields)
        if violation is None:
            kept.append(fact)
            continue
        issues.append(
            ValidationIssue(
                code="alternatives_grammar",
                message=violation,
                path=f"facts[{canonical_json(fact)}]",
            )
        )
    if issues:
        logger.warning(
            "alternatives_grammar_rejected facts=%d declared_fields=%d",
            len(issues),
            len(declared_fields),
        )
    closure = filter_declaration_closure(kept, issues=issues)
    graph = closure.graph
    if (
        issues
        and graph is not None
        and not any(
            fact.predicate.name in {"causes", "requires", "has"} for fact in graph.facts
        )
    ):
        graph = None
    issue_count = result.issue_count + len(closure.issues)
    return replace(
        result,
        graph=graph,
        issue_count=issue_count,
        issues=(*result.issues, *closure.issues),
    )


def _alternatives_fact_violation(
    fact: Fact,
    declared_fields: frozenset[str],
) -> str | None:
    """Return the grammar violation of one alternatives proposal fact."""

    predicate = fact.predicate.name
    if predicate in {"causes", "requires"}:
        effect = fact.args[1] if len(fact.args) == 2 else None
        if not (
            isinstance(effect, Struct)
            and effect.name in _ALTERNATIVE_EFFECT_CONSTRUCTORS
        ):
            return "effect constructor is outside the closed alternatives alphabet"
    for term in fact.args:
        for field_term in _input_field_terms(term):
            if canonical_json(field_term) not in declared_fields:
                return "input field is not declared by the source graph"
    return None


def _declared_input_fields(source: QdlGraph) -> frozenset[str]:
    """Collect every input field the source graph declares."""

    fields: set[str] = set()
    for fact in source.facts:
        for term in fact.args:
            for field_term in _input_field_terms(term):
                fields.add(canonical_json(field_term))
    return frozenset(fields)


def _input_field_terms(term: object) -> Iterator[Struct]:
    """Yield every ``input_field`` struct nested in one term."""

    if not isinstance(term, Struct):
        return
    if term.name == "input_field":
        yield term
    for argument in term.args:
        yield from _input_field_terms(argument)


def _filter_grounding_graph(
    axis: str,
    graph: QdlGraph,
    *,
    has_evidence: bool,
) -> tuple[QdlGraph | None, tuple[ValidationIssue, ...]]:
    """Apply semantic-role and per-axis predicate boundaries."""

    graph, role_violations = filter_semantic_roles(graph)
    issues = tuple(
        ValidationIssue(
            code="semantic_role",
            message=f"role {violation.role} is outside the semantic alphabet",
            path="facts",
        )
        for violation in role_violations
    )
    if role_violations:
        roles = ",".join(
            f"{violation.role}:{violation.reason}" for violation in role_violations
        )
        logger.warning(
            "axis_grounding_role_rejected axis=%s roles=%s dropped=%d",
            axis,
            _bounded_log_value(roles),
            len(role_violations),
        )
    if graph is None:
        return None, issues
    graph, predicate_issues = _filter_axis_predicates(
        axis,
        graph,
        has_evidence=has_evidence,
    )
    return graph, (*issues, *predicate_issues)


def _response_semantics_graph(
    graph: QdlGraph,
    action_slice: QdlGraph,
    action_ids: tuple[str, ...],
    evidence: EvidenceView | None,
) -> tuple[QdlGraph | None, tuple[ValidationIssue, ...]]:
    """Narrow a validated proposal to response-shape semantic facts."""

    filtered, issues = _filter_response_semantics_facts(
        graph,
        action_slice,
        action_ids,
        evidence,
    )
    if filtered is None:
        return None, issues
    response_facts = tuple(
        fact for fact in filtered.facts if _is_response_semantics_fact(fact)
    )
    issues = (
        *issues,
        *(
            ValidationIssue(
                code="response_predicate",
                message="fact is outside the response-semantics axis",
                path=f"facts[{canonical_json(fact)}]",
            )
            for fact in filtered.facts
            if not _is_response_semantics_fact(fact)
        ),
    )
    result = filter_declaration_closure(response_facts, issues=issues)
    return result.graph, result.issues


def _filter_response_semantics_facts(
    graph: QdlGraph,
    action_slice: QdlGraph,
    action_ids: tuple[str, ...],
    evidence: EvidenceView | None,
) -> tuple[QdlGraph | None, tuple[ValidationIssue, ...]]:
    """Ground response-shaped model facts in actions, owners, and evidence."""

    allowed_actions = _allowed_actions(action_slice, action_ids)
    target_resources = _resources_by_action(action_slice)
    evidence_fields = evidence_response_fields(evidence)
    kept_facts = tuple(
        fact
        for fact in graph.facts
        if not _requires_response_grounding(fact)
        or _response_fact_is_grounded(
            fact,
            allowed_actions,
            target_resources,
            evidence_fields,
        )
    )
    kept_keys = {canonical_json(fact) for fact in kept_facts}
    issues = tuple(
        ValidationIssue(
            code="response_grounding",
            message="response fact is not action-, owner-, or evidence-bound",
            path=f"facts[{canonical_json(fact)}]",
        )
        for fact in graph.facts
        if canonical_json(fact) not in kept_keys
    )
    result = filter_declaration_closure(kept_facts, issues=issues)
    return result.graph, result.issues


def _requires_response_grounding(fact: Fact) -> bool:
    if fact.predicate.name == "exposes":
        return True
    if fact.predicate.name == "has" and fact.args:
        holder = fact.args[0]
        return isinstance(holder, Struct) and holder.name == "output_field"
    if fact.predicate.name == "is" and len(fact.args) == 2:
        entity = fact.args[0]
        return isinstance(entity, Struct) and entity.name in {"output_field", "field"}
    return False


def _response_fact_is_grounded(
    fact: Fact,
    allowed_actions: set[str],
    target_resources: Mapping[str, set[str | None]],
    evidence_fields: set[str],
) -> bool:
    """Require response facts to be action-, owner-, and evidence-bound."""

    if fact.predicate.name == "has" and len(fact.args) == 2:
        return _field_is_bound(
            fact.args[0], "output_field", allowed_actions, evidence_fields
        )
    if fact.predicate.name == "exposes" and len(fact.args) == 2:
        action = atom_value(fact.args[0])
        return (
            action in allowed_actions
            and action in target_resources
            and _field_is_bound(
                fact.args[1], "field", target_resources[action], evidence_fields
            )
        )
    if fact.predicate.name == "is" and fact.args:
        entity = fact.args[0]
        if isinstance(entity, Struct) and entity.name in {"output_field", "field"}:
            owners = (
                allowed_actions
                if entity.name == "output_field"
                else {
                    resource
                    for resources in target_resources.values()
                    for resource in resources
                }
            )
            return _field_is_bound(entity, entity.name, owners, evidence_fields)
    return True


def _field_is_bound(
    entity: object,
    kind: str,
    owners: Collection[str | None],
    evidence_fields: set[str],
) -> bool:
    """Check a field's shape, owner, and observed name as one binding."""

    return (
        isinstance(entity, Struct)
        and entity.name == kind
        and len(entity.args) == 2
        and atom_value(entity.args[0]) in owners
        and atom_value(entity.args[1]) in evidence_fields
    )


def _allowed_actions(action_slice: QdlGraph, action_ids: tuple[str, ...]) -> set[str]:
    requested: set[str] = set()
    for action_id in action_ids:
        requested.add(action_id)
        if action_id.startswith("action:"):
            requested.add(action_id.removeprefix("action:"))
        else:
            requested.add(f"action:{action_id}")
    if requested:
        return requested
    return set(_actions(action_slice))


def _resources_by_action(graph: QdlGraph) -> dict[str | None, set[str | None]]:
    result: dict[str | None, set[str | None]] = {}
    for fact in graph.facts:
        if fact.predicate.name != "targets" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        resource = atom_value(fact.args[1])
        if action is not None:
            result.setdefault(action, set()).add(resource)
    return result


def _is_response_semantics_fact(fact: Fact) -> bool:
    if fact.predicate.name not in _RESPONSE_SEMANTICS_PREDICATES:
        return False
    if fact.predicate.name != "has":
        return True
    holder = fact.args[0] if fact.args else None
    return (
        isinstance(holder, Struct)
        and holder.name == "output_field"
        and len(holder.args) == 2
    )


def _actions(graph: QdlGraph) -> tuple[str, ...]:
    return tuple(
        sorted(
            atom_value(fact.args[0])
            for fact in graph.facts
            if fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
            and atom_value(fact.args[0]) is not None
        )
    )


def _action_atoms(graph: QdlGraph, action_ids: tuple[str, ...]) -> list:
    """Return graph Action atoms for the requested action ids."""

    return [
        fact.args[0]
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == "Action"
        and atom_value(fact.args[0]) in action_ids
    ]


__all__ = [
    "_action_atoms",
    "_actions",
    "_filter_alternatives_grammar",
    "_filter_grounding_graph",
    "_filter_response_semantics_facts",
    "_response_semantics_graph",
]
