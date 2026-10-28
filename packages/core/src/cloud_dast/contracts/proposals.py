"""Bounded proposal wire models and admission of model-generated QDL artefacts.

This module is an application-facing proposal boundary. The QDL package
provides only neutral graph validation; model wire formats and salvage policy
do not belong to the language kernel.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
)

from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.qdl.graph import (
    STRUCT_SCHEMAS,
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Term,
    Variable,
    canonical_json,
)
from cloud_dast.qdl.parser import parse_fact, parse_term
from cloud_dast.qdl.validation import (
    ValidationIssue,
    ValidationResult,
)

MAX_MODEL_FACTS = 256
MAX_MODEL_RULES = 128
MAX_MODEL_UNCERTAINTIES = 32
MAX_MODEL_STRING_LENGTH = 8192


class FormalFact(BaseModel):
    """A predicate application as emitted by a model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    context: Context
    predicate: str = Field(min_length=1, max_length=256)
    args: tuple[Term, ...] = Field(default_factory=tuple)

    @field_validator("args")
    @classmethod
    def bound_term_strings(cls, value: tuple[Term, ...]) -> tuple[Term, ...]:
        if not all(_term_strings_are_bounded(term) for term in value):
            raise ValueError("model string exceeds the output cap")
        return value


class FormalRule(BaseModel):
    """A Datalog rule as emitted by a model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    body: tuple[FormalFact, ...] = Field(default_factory=tuple)
    head: tuple[FormalFact, ...] = Field(default_factory=tuple)


class FormalUncertainty(BaseModel):
    """A self-reported gap in one model response.

    The model can ask for data it lacks (for example, a live response
    example before committing to a field role).  Uncertainties never
    become facts: they are hints for the next reactive grounding context.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Field(default="", max_length=256)
    question: str = Field(max_length=4096)


class FormalModelOutput(BaseModel):
    """A constrained LLM response containing only formal QDL artefacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    context: Context = Context.PROPOSAL
    facts: tuple[FormalFact, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_FACTS,
    )
    rules: tuple[FormalRule, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_RULES,
    )
    uncertainties: tuple[FormalUncertainty, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_UNCERTAINTIES,
    )


class FormalModelWireOutput(BaseModel):
    """Wire schema aligned with the textual fact prompts.

    Axis prompts ask for facts such as ``has(input_field(A, F), role)``.  A
    wire schema with string facts removes the provider-side conflict between
    that instruction and a structured ``predicate/args`` object; the existing
    validator parses the textual facts into the formal model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    context: Literal["proposal"] = "proposal"
    facts: tuple[
        Annotated[str, StringConstraints(max_length=MAX_MODEL_STRING_LENGTH)], ...
    ] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_FACTS,
    )
    rules: tuple[
        Annotated[str, StringConstraints(max_length=MAX_MODEL_STRING_LENGTH)], ...
    ] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_RULES,
    )
    uncertainties: tuple[FormalUncertainty, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_UNCERTAINTIES,
    )


def _term_strings_are_bounded(term: Term) -> bool:
    if isinstance(term, Atom):
        return not isinstance(term.value, str) or (
            len(term.value) <= MAX_MODEL_STRING_LENGTH
        )
    if isinstance(term, Variable):
        return len(term.name) <= MAX_MODEL_STRING_LENGTH
    if isinstance(term, Struct):
        return len(term.name) <= MAX_MODEL_STRING_LENGTH and all(
            _term_strings_are_bounded(argument) for argument in term.args
        )
    return True


_EXTENSION_PREDICATES = {
    schema.name: Predicate.from_schema(schema) for schema in EXTENSION_PREDICATE_SCHEMAS
}

_STRUCT_ARGUMENTS_BY_NAME = {
    schema.name: schema.all_arguments for schema in STRUCT_SCHEMAS
}


def _predicate(name: str) -> Predicate:
    if name in {
        "is",
        "part",
        "has",
        "may",
        "requires",
        "causes",
        "prevents",
        "evidence",
        "targets",
        "coupled",
        "binding",
        "attacker",
        "grants",
        "applies_to",
        "transition",
        "initial",
        "forbidden",
        "reaches",
        "exposes",
        "accepts",
        "binds",
        "required",
    }:
        return Predicate.from_name(name)
    return _EXTENSION_PREDICATES[name]


class FormalModelOutputValidator:
    """Validate an LLM response as a self-contained proposal graph."""

    def validate(self, payload: Mapping[str, Any]) -> ValidationResult:
        try:
            output = FormalModelOutput.model_validate(payload)
        except ValidationError as error:
            issues = tuple(
                ValidationIssue(
                    code="schema",
                    message=error_message,
                    path=".".join(str(part) for part in location),
                )
                for error_message, location in _pydantic_errors(error)
            )
            return ValidationResult(None, issues)

        context_issues = _context_issues(output)
        if context_issues:
            return ValidationResult(None, context_issues)

        if not output.facts and not output.rules:
            return ValidationResult(
                None,
                (
                    ValidationIssue(
                        code="empty",
                        message="model proposal has no facts or rules",
                    ),
                ),
            )

        try:
            facts = tuple(
                Fact(
                    context=item.context,
                    predicate=_predicate(item.predicate),
                    args=item.args,
                )
                for item in output.facts
            )
            rules = tuple(
                Rule(
                    body=tuple(
                        Fact(
                            context=literal.context,
                            predicate=_predicate(literal.predicate),
                            args=literal.args,
                        )
                        for literal in rule.body
                    ),
                    head=tuple(
                        Fact(
                            context=literal.context,
                            predicate=_predicate(literal.predicate),
                            args=literal.args,
                        )
                        for literal in rule.head
                    ),
                )
                for rule in output.rules
            )
            graph = QdlGraph(facts=facts, rules=rules)
        except ValidationError as error:
            issues = tuple(
                ValidationIssue(
                    code="graph",
                    message=error_message,
                    path=".".join(str(part) for part in location),
                )
                for error_message, location in _pydantic_errors(error)
            )
            return ValidationResult(None, issues)
        except (ValueError, KeyError) as error:
            return ValidationResult(
                None,
                (ValidationIssue(code="graph", message=str(error)),),
            )

        return ValidationResult(graph)

    def salvage(
        self,
        payload: Mapping[str, Any],
        *,
        background: QdlGraph | None = None,
    ) -> ValidationResult:
        """Return the largest valid subset of a partially invalid proposal.

        Facts are validated first; each rule is then added only if the graph
        with all previously kept artifacts stays valid.  One bad rule must
        not discard dozens of good facts — proposals are fuel for the
        algebra-driven campaign loop.
        """

        overflow = _model_output_overflow(payload)
        if overflow:
            return ValidationResult(None, overflow)

        normalized = _normalize_payload(payload)
        facts = normalized["facts"]
        rules = normalized["rules"]
        if not facts and not rules:
            return ValidationResult(
                None,
                (
                    ValidationIssue(
                        code="empty",
                        message="model proposal has no facts or rules",
                    ),
                ),
            )

        # A proposal may reference entities declared by the source graph
        # (e.g. an action) without re-declaring them: resolve proposal
        # references against the background slice, not in isolation.
        supporting = [
            {
                "context": "proposal",
                "predicate": fact.predicate.name,
                "args": [term.model_dump(mode="json") for term in fact.args],
            }
            for fact in (background.facts if background is not None else ())
            if fact.predicate.name == "is"
        ]
        # One entity may be declared in several provenance contexts
        # (contract, accepted, runtime).  Re-labelling those declarations as
        # proposal context collapses them into duplicate facts, which would
        # reject the whole proposal — so supporting declarations are
        # deduplicated by their proposal-context identity.
        supporting = list({_supporting_key(item): item for item in supporting}.values())

        # Salvage facts, not just rules: one undeclared witness must not
        # discard the valid norm and field roles in the same model response.
        # Declarations go first so a model-declared sink/marker can support a
        # later reference; invalid facts are dropped individually.
        unique_facts: dict[tuple[Any, Any, str], Mapping[str, Any]] = {}
        for fact in facts:
            unique_facts.setdefault(_supporting_key(fact), fact)
        remaining_facts = list(unique_facts.values())
        kept_facts: list[Mapping[str, Any]] = []
        kept_keys: set[Any] = set()
        fact_issues: list[ValidationIssue] = []
        while remaining_facts:
            deferred: list[Mapping[str, Any]] = []
            progressed = False
            for fact in remaining_facts:
                fact_key = _supporting_key(fact)
                candidate_supporting = [
                    item
                    for item in supporting
                    if _supporting_key(item) != fact_key
                    and _supporting_key(item) not in kept_keys
                ]
                candidate = [*candidate_supporting, *kept_facts, fact]
                result = self.validate({**normalized, "facts": candidate, "rules": []})
                if result.valid:
                    kept_facts.append(fact)
                    kept_keys.add(fact_key)
                    supporting = [
                        item
                        for item in supporting
                        if _supporting_key(item) not in kept_keys
                    ]
                    progressed = True
                else:
                    deferred.append(fact)
            remaining_facts = deferred
            if not progressed:
                break
        for fact in remaining_facts:
            fact_key = _supporting_key(fact)
            candidate_supporting = [
                item
                for item in supporting
                if _supporting_key(item) != fact_key
                and _supporting_key(item) not in kept_keys
            ]
            result = self.validate(
                {
                    **normalized,
                    "facts": [*candidate_supporting, *kept_facts, fact],
                    "rules": [],
                }
            )
            fact_issues.extend(
                ValidationIssue(
                    code=result_issue.code,
                    message=result_issue.message,
                    path=f"facts.{result_issue.path}",
                )
                for result_issue in result.issues
            )
        if facts and not kept_facts:
            return ValidationResult(
                None,
                (
                    ValidationIssue(
                        code="salvage",
                        message="no valid model fact subset in proposal",
                    ),
                    *fact_issues,
                ),
            )
        facts = [*supporting, *kept_facts]
        base = self.validate({**normalized, "facts": facts, "rules": []})
        if not base.valid or base.graph is None or not base.graph.facts:
            return ValidationResult(
                None,
                (
                    ValidationIssue(
                        code="salvage",
                        message="no valid fact subset in proposal",
                    ),
                    *fact_issues,
                ),
            )

        kept: list[Mapping[str, Any]] = []
        dropped: list[ValidationIssue] = list(fact_issues)
        for index, rule in enumerate(rules):
            result = self.validate(
                {**normalized, "facts": facts, "rules": [*kept, rule]}
            )
            if result.valid:
                kept.append(rule)
            else:
                dropped.extend(
                    ValidationIssue(
                        code=result_issue.code,
                        message=result_issue.message,
                        path=f"rules[{index}].{result_issue.path}",
                    )
                    for result_issue in result.issues
                )

        final = self.validate({**normalized, "facts": facts, "rules": kept})
        if not final.valid or final.graph is None:
            return ValidationResult(None, tuple(dropped))
        return ValidationResult(final.graph, tuple(dropped))


def _normalize_facts(raw: Any) -> list[Mapping[str, Any]]:
    """Convert model-emitted facts into schema objects.

    Models routinely return facts as canonical strings such as
    ``has(input_field(action:m, f), object_ref)`` even when asked for the
    structured schema, or embed the JSON Schema description of ``predicate``
    instead of its name, or omit the proposal context.  All three forms are
    unambiguous, so the validator salvages them deterministically instead of
    discarding the whole response.
    """

    if not isinstance(raw, list):
        return []
    result: list[Mapping[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            parsed = parse_fact(item, max_length=MAX_MODEL_STRING_LENGTH)
            if parsed is not None:
                result.append(parsed)
        elif isinstance(item, Mapping):
            normalized = _normalize_fact_object(item)
            if normalized is not None:
                result.append(normalized)
    return result


def _model_output_overflow(payload: Mapping[str, Any]) -> tuple[ValidationIssue, ...]:
    """Reject count/string overflow before normalization or salvage."""

    issues: list[ValidationIssue] = []
    facts = _sequence_count(payload.get("facts"))
    norms = _sequence_count(payload.get("norms"))
    rules = _sequence_count(payload.get("rules"))
    uncertainties = _sequence_count(payload.get("uncertainties"))

    if (
        (facts is not None and facts > MAX_MODEL_FACTS)
        or (norms is not None and norms > MAX_MODEL_FACTS)
        or (facts is not None and norms is not None and facts + norms > MAX_MODEL_FACTS)
    ):
        issues.append(
            ValidationIssue(
                code="limit",
                message=f"model facts exceed the cap of {MAX_MODEL_FACTS}",
                path="facts",
            )
        )
    if rules is not None and rules > MAX_MODEL_RULES:
        issues.append(
            ValidationIssue(
                code="limit",
                message=f"model rules exceed the cap of {MAX_MODEL_RULES}",
                path="rules",
            )
        )
    if uncertainties is not None and uncertainties > MAX_MODEL_UNCERTAINTIES:
        issues.append(
            ValidationIssue(
                code="limit",
                message=(
                    f"model uncertainties exceed the cap of {MAX_MODEL_UNCERTAINTIES}"
                ),
                path="uncertainties",
            )
        )

    for key in ("facts", "rules"):
        raw = payload.get(key)
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            continue
        for index, item in enumerate(raw):
            if not _raw_strings_are_bounded(item):
                issues.append(
                    ValidationIssue(
                        code="limit",
                        message=(
                            "model string exceeds the cap of "
                            f"{MAX_MODEL_STRING_LENGTH} characters"
                        ),
                        path=f"{key}[{index}]",
                    )
                )
                break

    for key in ("norms", "uncertainties"):
        raw = payload.get(key)
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            continue
        for index, item in enumerate(raw):
            if not _raw_strings_are_bounded(item):
                issues.append(
                    ValidationIssue(
                        code="limit",
                        message=(
                            "model string exceeds the cap of "
                            f"{MAX_MODEL_STRING_LENGTH} characters"
                        ),
                        path=f"{key}[{index}]",
                    )
                )
                break
            if not isinstance(item, Mapping):
                continue
            if any(issue.path.startswith(f"{key}[{index}]") for issue in issues):
                break

    return tuple(issues)


def _sequence_count(raw: Any) -> int | None:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return None
    return len(raw)


def _raw_strings_are_bounded(value: object) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if len(item) > MAX_MODEL_STRING_LENGTH:
                return False
        elif isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            pending.extend(item)
    return True


def _normalize_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build a schema-clean payload from any of the observed model forms.

    Models emit several shapes: textual facts, schema-copied predicates,
    flat string arguments, and a dedicated ``norms`` array with
    ``{id, prevents: "effect(action)"}`` entries.  All are unambiguous and
    salvaged here; unknown top-level keys are dropped so ``extra="forbid"``
    does not discard an otherwise valid response.
    """

    facts = _normalize_facts(payload.get("facts"))
    facts.extend(_normalize_norms(payload.get("norms")))
    rules = _normalize_rules(payload.get("rules"))
    return {
        "context": payload.get("context", "proposal"),
        "facts": facts,
        "rules": rules,
    }


def _normalize_norms(raw: Any) -> list[Mapping[str, Any]]:
    """Convert ``{id, prevents: "effect(action)"}`` entries into facts."""

    if not isinstance(raw, list):
        return []
    facts: list[Mapping[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        norm_id = item.get("id") or item.get("norm_id")
        effect = item.get("prevents") or item.get("effect")
        if not isinstance(norm_id, str) or not norm_id.strip():
            continue
        facts.append(
            {
                "context": "proposal",
                "predicate": "is",
                "args": [_atom_term(norm_id), _atom_term("Norm")],
            }
        )
        effect_term = _normalize_term(effect)
        if effect_term is not None:
            facts.append(
                {
                    "context": "proposal",
                    "predicate": "prevents",
                    "args": [_atom_term(norm_id), effect_term],
                }
            )
    return facts


def _normalize_rules(raw: Any) -> list[Mapping[str, Any]]:
    """Normalize rule literals the same way as facts."""

    if not isinstance(raw, list):
        return []
    rules: list[Mapping[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        body = _normalize_facts(item.get("body"))
        head = _normalize_facts(item.get("head"))
        if body and head:
            rules.append({"body": body, "head": head})
    return rules


def _args_key(args: Any) -> str:
    import json

    return json.dumps(args, ensure_ascii=False, sort_keys=True)


def _supporting_key(item: Mapping[str, Any]) -> tuple[Any, Any, str]:
    """Return the proposal-context identity of one supporting declaration."""

    return (item.get("context"), item.get("predicate"), _args_key(item.get("args")))


def _atom_term(value: str) -> dict[str, Any]:
    return {"kind": "atom", "literal_type": "string", "value": value}


def _normalize_fact_object(item: Mapping[str, Any]) -> dict[str, Any] | None:
    """Normalize one object-shaped fact.

    Models that see the full JSON Schema sometimes copy the schema of the
    ``predicate`` field into the value (``{"name": ..., "arguments": ...}``)
    instead of emitting the predicate name, and often omit the context.
    """

    predicate = item.get("predicate")
    if isinstance(predicate, Mapping):
        predicate = predicate.get("name")
    if not isinstance(predicate, str) or not predicate.strip():
        return None
    args = item.get("args")
    if not isinstance(args, list) or not args:
        recovered = _recover_args_from_predicate(predicate)
        if recovered is not None:
            predicate, args = recovered
    if not isinstance(args, list):
        return None
    normalized_args = [_normalize_term(argument) for argument in args]
    if any(argument is None for argument in normalized_args):
        return None
    return {
        # A missing context defaults to the proposal context; a non-proposal
        # context is preserved so validation rejects it — a model must never
        # silently promote its own output to accepted facts.
        "context": item.get("context", "proposal"),
        "predicate": predicate.strip(),
        "args": normalized_args,
    }


def _recover_args_from_predicate(value: str) -> tuple[str, list[Any]] | None:
    """Recover facts emitted with arguments embedded in ``predicate``.

    Structured-output providers occasionally accept a malformed object where
    ``predicate`` contains ``is,'args':[{...}]`` while the real ``args`` field
    is empty.  The model produced the complete fact, but placed its arguments
    in the wrong JSON field; recover it instead of reducing the proposal to
    background declarations.
    """

    text = value.strip()
    if not text:
        return None

    if "(" in text and text.endswith(")"):
        parsed = parse_fact(text, max_length=MAX_MODEL_STRING_LENGTH)
        if parsed is not None:
            return str(parsed["predicate"]), list(parsed["args"])

    for marker in ("'args':", '"args":'):
        marker_at = text.find(marker)
        if marker_at < 0:
            continue
        name, separator, _ = text.partition(",")
        if not separator or not _is_predicate_name(name):
            continue
        args = _balanced_list_after(text, marker_at + len(marker))
        if args is None:
            continue
        try:
            parsed_args = ast.literal_eval(args)
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed_args, list):
            return name, parsed_args
    return None


def _is_predicate_name(value: str) -> bool:
    return bool(value) and all(char.isalnum() or char == "_" for char in value)


def _balanced_list_after(text: str, start: int) -> str | None:
    """Return the first balanced ``[...]`` fragment starting at ``start``."""

    index = start
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "[":
        return None

    depth = 0
    quote: str | None = None
    escaped = False
    for position in range(index, len(text)):
        char = text[position]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[index : position + 1]
    return None


def _normalize_term(value: Any) -> dict[str, Any] | None:
    """Normalize one argument: keep dicts, convert scalars and DSL strings."""

    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        return parse_term(value, max_length=MAX_MODEL_STRING_LENGTH)
    if isinstance(value, bool):
        return {"kind": "atom", "literal_type": "boolean", "value": value}
    if isinstance(value, int):
        return {"kind": "atom", "literal_type": "integer", "value": value}
    return None


def _context_issues(output: FormalModelOutput) -> tuple[ValidationIssue, ...]:
    issues: list[ValidationIssue] = []
    if output.context is not Context.PROPOSAL:
        issues.append(
            ValidationIssue(
                code="context",
                message="model output context must be proposal",
                path="context",
            )
        )
    for index, fact in enumerate(output.facts):
        if fact.context is not Context.PROPOSAL:
            issues.append(
                ValidationIssue(
                    code="context",
                    message="model fact context must be proposal",
                    path=f"facts[{index}].context",
                )
            )
    for index, rule in enumerate(output.rules):
        for literal in (*rule.body, *rule.head):
            if literal.context is not Context.PROPOSAL:
                issues.append(
                    ValidationIssue(
                        code="context",
                        message="model rule literal context must be proposal",
                        path=f"rules[{index}]",
                    )
                )
                break
    return tuple(issues)


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
    term: object,
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
    "FormalFact",
    "FormalModelOutput",
    "FormalModelOutputValidator",
    "FormalModelWireOutput",
    "FormalRule",
    "FormalUncertainty",
    "MAX_MODEL_FACTS",
    "MAX_MODEL_RULES",
    "MAX_MODEL_STRING_LENGTH",
    "MAX_MODEL_UNCERTAINTIES",
    "ValidationIssue",
    "ValidationResult",
]
