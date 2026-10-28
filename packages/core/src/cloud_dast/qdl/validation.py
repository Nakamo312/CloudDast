"""Neutral validation results and declaration closure for QDL graphs.

This module knows only the canonical QDL graph.  It deliberately does not
know how a model emits, repairs, or salvages proposals.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import ValidationError

from cloud_dast.qdl.graph import (
    STRUCT_SCHEMAS,
    ArgumentSchema,
    Atom,
    Fact,
    QdlGraph,
    Rule,
    Struct,
    Term,
    Variable,
    canonical_json,
)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One machine-readable QDL validation failure."""

    code: str
    message: str
    path: str = ""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Result of validating a QDL graph or graph fragment."""

    graph: QdlGraph | None
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return self.graph is not None and not self.issues


def filter_declaration_closure(
    facts: Sequence[Fact],
    rules: Sequence[Rule] = (),
    *,
    issues: Sequence[ValidationIssue] = (),
) -> ValidationResult:
    """Return the declaration-closed subset of a QDL graph fragment."""

    kept_facts = list(facts)
    kept_rules = list(rules)
    collected_issues = list(issues)

    while True:
        declarations = _collect_fact_declarations(kept_facts)
        unclosed_facts = [
            fact
            for fact in kept_facts
            if _literal_has_missing_reference(fact, declarations)
        ]
        unclosed_rules = [
            rule
            for rule in kept_rules
            if any(
                _literal_has_missing_reference(literal, declarations)
                for literal in (*rule.body, *rule.head)
            )
        ]
        if not unclosed_facts and not unclosed_rules:
            break

        unclosed_fact_keys = {canonical_json(fact) for fact in unclosed_facts}
        unclosed_rule_keys = {canonical_json(rule) for rule in unclosed_rules}
        kept_facts = [
            fact
            for fact in kept_facts
            if canonical_json(fact) not in unclosed_fact_keys
        ]
        kept_rules = [
            rule
            for rule in kept_rules
            if canonical_json(rule) not in unclosed_rule_keys
        ]
        collected_issues.extend(
            ValidationIssue(
                code="closure",
                message="declaration closure rejected fact",
                path=f"facts[{canonical_json(fact)}]",
            )
            for fact in unclosed_facts
        )
        collected_issues.extend(
            ValidationIssue(
                code="closure",
                message="declaration closure rejected rule",
                path=f"rules[{canonical_json(rule)}]",
            )
            for rule in unclosed_rules
        )

    if not kept_facts and not kept_rules:
        return ValidationResult(None, tuple(collected_issues))
    try:
        graph = QdlGraph(facts=tuple(kept_facts), rules=tuple(kept_rules))
    except ValidationError as error:
        return ValidationResult(
            None,
            (*collected_issues, *_graph_validation_issues(error)),
        )
    except ValueError as error:
        return ValidationResult(
            None,
            (*collected_issues, ValidationIssue(code="graph", message=str(error))),
        )
    return ValidationResult(graph, tuple(collected_issues))


_STRUCT_ARGUMENTS_BY_NAME = {
    schema.name: schema.all_arguments for schema in STRUCT_SCHEMAS
}


def _collect_fact_declarations(facts: Sequence[Fact]) -> set[str]:
    declarations: set[str] = set()
    for fact in facts:
        if fact.predicate.name != "is" or not fact.args:
            continue
        entity = fact.args[0]
        if not isinstance(entity, Variable):
            declarations.add(canonical_json(entity))
    return declarations


def _literal_has_missing_reference(
    literal: Fact,
    declarations: set[str],
) -> bool:
    return any(
        reference not in declarations
        for term, argument in zip(
            literal.args,
            literal.predicate.definition.arguments,
            strict=True,
        )
        for reference in _collect_term_references(term, argument)
    )


def _collect_term_references(
    term: Term | object,
    argument: ArgumentSchema,
) -> set[str]:
    if isinstance(term, Variable):
        return set()
    if isinstance(term, Atom):
        return {canonical_json(term)} if argument.reference else set()
    if not isinstance(term, Struct):
        return set()

    references = {canonical_json(term)} if argument.reference else set()
    struct_arguments = _STRUCT_ARGUMENTS_BY_NAME.get(term.name, ())
    for child, child_argument in zip(
        term.args,
        struct_arguments[: len(term.args)],
        strict=True,
    ):
        references.update(_collect_term_references(child, child_argument))
    return references


def _graph_validation_issues(error: ValidationError) -> tuple[ValidationIssue, ...]:
    return tuple(
        ValidationIssue(
            code="graph",
            message=message,
            path=".".join(str(part) for part in location),
        )
        for message, location in _pydantic_errors(error)
    )


def _pydantic_errors(
    error: ValidationError,
) -> tuple[tuple[str, tuple[object, ...]], ...]:
    return tuple(
        (error_message["msg"], tuple(error_message["loc"]))
        for error_message in error.errors()
    )


__all__ = [
    "ValidationIssue",
    "ValidationResult",
    "filter_declaration_closure",
]
