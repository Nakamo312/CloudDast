"""Model-backed proposal of formal QDL threat-model artefacts."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from cloud_dast.contracts.proposals import (
    FormalFact,
    FormalModelOutput,
    FormalModelOutputValidator,
    FormalRule,
)
from cloud_dast.ports import (
    ModelClient,
    ModelRequest,
    ModelResponse,
)
from cloud_dast.proposals import FormalThreatModelResult
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.roles import (
    format_semantic_roles,
    semantic_role_violation,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticRoleViolation,
    filter_semantic_roles,
)
from cloud_dast.qdl.validation import ValidationIssue, ValidationResult
from cloud_dast.verification.slices import (
    DEFAULT_SLICE_BUDGET,
    BoundedSlice,
    SliceBudget,
    build_slice,
)

logger = logging.getLogger(__name__)


def _select_actions(graph: QdlGraph, max_actions: int | None) -> tuple[str, ...]:
    """Return the deterministically first action ids for one model call."""

    actions = tuple(
        sorted(
            value
            for value in (
                atom_value(fact.args[0])
                for fact in graph.facts
                if fact.predicate.name == "is"
                and len(fact.args) == 2
                and atom_value(fact.args[1]) == "Action"
            )
            if isinstance(value, str)
        )
    )
    return actions if max_actions is None else actions[:max_actions]


@dataclass(frozen=True, slots=True)
class _ArtifactSelection:
    """Artefacts preserved from an invalid response and artefacts to repair."""

    valid_facts: tuple[FormalFact, ...] = ()
    invalid_facts: tuple[FormalFact, ...] = ()
    valid_rules: tuple[FormalRule, ...] = ()
    invalid_rules: tuple[FormalRule, ...] = ()


@dataclass(frozen=True, slots=True)
class _DecodedResponse:
    """A model payload plus a transport-level decoding failure, if any."""

    payload: Mapping[str, Any]
    issue: ValidationIssue | None = None


class FormalThreatModeler:
    """Ask a constrained model for a formal proposal over a QDL graph.

    The model never produces verified facts.  Its output is validated as a
    self-contained ``proposal`` graph and returned unchanged in that context;
    promotion to ``accepted`` is an explicit later decision outside this
    service.
    """

    __slots__ = ("_budget", "_client", "_max_actions", "_validator")

    def __init__(
        self,
        client: ModelClient,
        *,
        validator: FormalModelOutputValidator | None = None,
        max_actions: int | None = 12,
        budget: SliceBudget = DEFAULT_SLICE_BUDGET,
    ) -> None:
        if max_actions is not None and max_actions <= 0:
            raise ValueError("max_actions must be positive or None")
        self._client = client
        self._validator = validator or FormalModelOutputValidator()
        self._max_actions = max_actions
        self._budget = budget

    def propose(self, graph: QdlGraph) -> FormalThreatModelResult:
        """Propose formal threat facts and rules for one QDL graph."""

        slice_ = build_slice(
            graph,
            actions=_select_actions(graph, self._max_actions),
            budget=self._budget,
        )
        response = self._client.complete(
            self._request(slice_),
            response_type=FormalModelOutput,
        )
        decoded = _decode_response(response)
        initial = self._validate_decoded(decoded, slice_.graph)
        if initial.valid:
            return FormalThreatModelResult(proposal=initial.graph)

        output = _model_output(decoded.payload)
        selection = (
            _select_artifacts(output, self._validator)
            if output is not None
            else _ArtifactSelection()
        )
        repair_response = self._client.complete(
            self._repair_request(slice_, selection, initial.issues),
            response_type=FormalModelOutput,
        )
        repair_decoded = _decode_response(repair_response)
        repair = self._validate_repair(
            repair_decoded,
            selection,
            slice_.graph,
        )

        if repair.valid:
            return FormalThreatModelResult(
                proposal=repair.graph,
                initial_issues=initial.issues,
                attempts=2,
            )

        # One bad rule must not discard the whole proposal: keep the valid
        # fact subset and the rules that survive individual validation.
        salvaged = self._reject_semantic_roles(self._validator.salvage(decoded.payload))
        if salvaged.graph is not None:
            return FormalThreatModelResult(
                proposal=salvaged.graph,
                issues=salvaged.issues,
                initial_issues=initial.issues,
                repair_issues=repair.issues,
                attempts=2,
            )

        return FormalThreatModelResult(
            proposal=None,
            issues=repair.issues,
            initial_issues=initial.issues,
            repair_issues=repair.issues,
            attempts=2,
        )

    @staticmethod
    def _request(slice_: BoundedSlice) -> ModelRequest:
        return ModelRequest(
            task="formal_threat_modeling",
            instruction=(
                "You are a constrained QDL compiler. Inspect the supplied QDL "
                "graph and propose semantic roles, threats, norms, and causal "
                "effects. A semantic role alone is not enough: every testable "
                "security hypothesis must also contain prevents(Norm, Effect). "
                "Prefer action-bound effects such as allowed(Action), "
                "denied(Action), external_call(Action, Marker), "
                "reached(Action, Sink), or duration(Action, Milliseconds). "
                "The Effect constructor in prevents must be exactly one of: "
                "allowed, denied, completed, duration, external_call, identity, "
                "or reached. Never use a constructor named prevented. "
                "If you use reached(Action, Sink), declare the Sink with an "
                "is fact unless it is already present in the graph. "
                "Facts must be ground: variables are allowed only inside rule "
                "literals, never in facts. "
                "Use only Action identifiers supplied in the graph. Represent "
                "semantic roles with has(input_field(Action, Field), Role) or "
                "has(output_field(Action, Field), Role), and causal effects "
                "with causes(Subject, Effect). Role atoms come from the "
                "closed semantic-role alphabet — use exactly these and never "
                "invent new role names: "
                + format_semantic_roles()
                + ". Sink, flow, and action kinds are not roles; declare "
                "them with is facts. "
                "ALSO ground dataflow and exposure: (1) if an input "
                "field flows into a sink that interprets it (SQL engine, "
                "template engine, XML parser, command shell, browser DOM), "
                "emit reaches(input_field(Action, Field), SinkId) and "
                "is(SinkId, interpreter); (2) if a response field exposes "
                "sensitive data, emit exposes(Action, field(ResourceId, "
                "Field)) where ResourceId is the identifier of the resource "
                'that owns the field (for example "resource:user") and '
                "Field is the field name; (3) if an action makes an "
                "outbound call to a user-influenced URL, emit reaches("
                "input_field(Action, Field), MarkerId), causes(Action, "
                "external_call(Action, MarkerId)), and is(MarkerId, "
                "external_net). "
                "Declare every ResourceId, SinkId, and MarkerId with an "
                "is fact. "
                "Return only a JSON object "
                "matching FormalModelOutput. The output context and "
                "every fact or rule literal context must be proposal. Use known "
                "QDL predicates and typed constructors only. Declare every "
                "referenced identifier with an is fact. Do not return prose, "
                "explanations, findings, accepted/runtime/report facts, STRIDE "
                "categories, or IDs outside the supplied graph except new "
                "proposal threats and norms."
            ),
            context=slice_.context(),
        )

    @staticmethod
    def _repair_request(
        slice_: BoundedSlice,
        selection: _ArtifactSelection,
        issues: tuple[ValidationIssue, ...],
    ) -> ModelRequest:
        return ModelRequest(
            task="formal_threat_modeling_repair",
            instruction=(
                "The previous formal proposal failed validation. Repair only "
                "invalid_artifacts. Return only replacement facts and rules in "
                "proposal context. You may add is declarations required by a "
                "replacement unless that declaration is already present in "
                "valid_artifacts. Do not return or alter valid_artifacts. Use known "
                "QDL predicates and typed constructors only. The Effect constructor "
                "in prevents must be exactly one of: allowed, denied, completed, "
                "duration, external_call, identity, or reached; never prevented. "
                "Declare every referenced Sink with an is fact. "
                "Facts must be ground; variables are allowed only in rules. "
                "Return no prose or explanations."
            ),
            context={
                **slice_.context(),
                "valid_artifacts": {
                    "facts": [
                        fact.model_dump(mode="json") for fact in selection.valid_facts
                    ],
                    "rules": [
                        rule.model_dump(mode="json") for rule in selection.valid_rules
                    ],
                },
                "invalid_artifacts": {
                    "facts": [
                        fact.model_dump(mode="json") for fact in selection.invalid_facts
                    ],
                    "rules": [
                        rule.model_dump(mode="json") for rule in selection.invalid_rules
                    ],
                },
                "issues": [
                    {
                        "code": issue.code,
                        "message": issue.message,
                        "path": issue.path,
                    }
                    for issue in issues
                ],
            },
        )

    def _validate_decoded(
        self,
        decoded: _DecodedResponse,
        source: QdlGraph,
    ) -> ValidationResult:
        result = self._validator.validate(
            _with_source_declarations(decoded.payload, source)
        )
        result = self._reject_semantic_roles(result)
        if decoded.issue is not None:
            return ValidationResult(None, (*result.issues, decoded.issue))
        return self._require_testable_norm(result)

    def _validate_repair(
        self,
        repair: _DecodedResponse,
        selection: _ArtifactSelection,
        source: QdlGraph,
    ) -> ValidationResult:
        replacement = _model_output(repair.payload)
        if replacement is None:
            result = self._validator.validate(repair.payload)
            issue = repair.issue
            issues = result.issues if issue is None else (*result.issues, issue)
            return ValidationResult(None, issues)

        merged = {
            "context": Context.PROPOSAL.value,
            "facts": [
                *(fact.model_dump(mode="json") for fact in selection.valid_facts),
                *(fact.model_dump(mode="json") for fact in replacement.facts),
            ],
            "rules": [
                *(rule.model_dump(mode="json") for rule in selection.valid_rules),
                *(rule.model_dump(mode="json") for rule in replacement.rules),
            ],
        }
        result = self._validator.validate(_with_source_declarations(merged, source))
        result = self._reject_semantic_roles(result)
        result = self._require_testable_norm(result)
        if repair.issue is not None:
            return ValidationResult(None, (*result.issues, repair.issue))
        return result

    @staticmethod
    def _require_testable_norm(result: ValidationResult) -> ValidationResult:
        if not result.valid or result.graph is None:
            return result
        if any(fact.predicate.name == "prevents" for fact in result.graph.facts):
            return result
        return ValidationResult(
            None,
            (
                ValidationIssue(
                    code="norms",
                    message="formal proposal requires at least one prevents fact",
                ),
            ),
        )

    @staticmethod
    def _reject_semantic_roles(
        result: ValidationResult,
    ) -> ValidationResult:
        if result.graph is None:
            return result
        graph, violations = filter_semantic_roles(result.graph)
        if not violations:
            return result
        issues = (*result.issues, *_semantic_role_issues(violations))
        if graph is None:
            return ValidationResult(None, issues)
        return ValidationResult(graph, issues)


def _decode_response(response: ModelResponse) -> _DecodedResponse:
    structured = response.structured
    if isinstance(structured, FormalModelOutput):
        return _DecodedResponse(structured.model_dump(mode="json"))
    if isinstance(structured, Mapping):
        return _DecodedResponse(structured)
    return _DecodedResponse(
        {},
        ValidationIssue(
            code="payload",
            message="model structured response must be a JSON object",
        ),
    )


def _model_output(payload: Mapping[str, Any]) -> FormalModelOutput | None:
    try:
        return FormalModelOutput.model_validate(payload)
    except ValidationError:
        logger.warning("formal_model_output_rejected reason=invalid_schema")
        return None


def _with_source_declarations(
    payload: Mapping[str, Any],
    source: QdlGraph,
) -> dict[str, Any]:
    """Add deterministic source declarations used by a model proposal."""

    try:
        output = FormalModelOutput.model_validate(payload)
    except ValidationError:
        return dict(payload)

    references = {key for fact in output.facts for key in _term_keys(fact.args)} | {
        key
        for rule in output.rules
        for literal in (*rule.body, *rule.head)
        for key in _term_keys(literal.args)
    }
    declarations = tuple(
        FormalFact(
            context=Context.PROPOSAL,
            predicate=fact.predicate.name,
            args=fact.args,
        )
        for fact in source.facts
        if fact.predicate.name == "is"
        and fact.args
        and canonical_json(fact.args[0]) in references
    )
    facts = _unique_facts((*output.facts, *declarations))
    return output.model_copy(update={"facts": facts}).model_dump(mode="json")


def _term_keys(term: object) -> set[str]:
    if isinstance(term, Atom):
        return {canonical_json(term)}
    if isinstance(term, Struct):
        return {canonical_json(term)} | {
            key for argument in term.args for key in _term_keys(argument)
        }
    if isinstance(term, tuple):
        return {key for argument in term for key in _term_keys(argument)}
    return set()


def _select_artifacts(
    output: FormalModelOutput,
    validator: FormalModelOutputValidator,
) -> _ArtifactSelection:
    if output.context is not Context.PROPOSAL:
        return _ArtifactSelection(
            invalid_facts=output.facts,
            invalid_rules=output.rules,
        )

    declarations = _unique_facts(
        fact
        for fact in output.facts
        if fact.predicate == "is" and fact.context is Context.PROPOSAL
    )
    valid_facts: list[FormalFact] = []
    invalid_facts: list[FormalFact] = []
    seen_facts: set[str] = set()

    for fact in output.facts:
        key = canonical_json(fact)
        duplicate = key in seen_facts
        seen_facts.add(key)
        if (
            fact.context is Context.PROPOSAL
            and not duplicate
            and _fact_is_valid(fact, declarations, validator)
        ):
            valid_facts.append(fact)
        else:
            invalid_facts.append(fact)

    valid_rules: list[FormalRule] = []
    invalid_rules: list[FormalRule] = []
    seen_rules: set[str] = set()
    for rule in output.rules:
        key = canonical_json(rule)
        duplicate = key in seen_rules
        seen_rules.add(key)
        if (
            _rule_context_is_proposal(rule)
            and not duplicate
            and _rule_is_valid(rule, declarations, validator)
        ):
            valid_rules.append(rule)
        else:
            invalid_rules.append(rule)

    return _ArtifactSelection(
        valid_facts=tuple(valid_facts),
        invalid_facts=tuple(invalid_facts),
        valid_rules=tuple(valid_rules),
        invalid_rules=tuple(invalid_rules),
    )


def _fact_is_valid(
    fact: FormalFact,
    declarations: tuple[FormalFact, ...],
    validator: FormalModelOutputValidator,
) -> bool:
    if semantic_role_violation(fact.predicate, fact.args) is not None:
        return False
    payload = _artifact_payload(_unique_facts((*declarations, fact)), ())
    return not validator.validate(payload).issues


def _rule_is_valid(
    rule: FormalRule,
    declarations: tuple[FormalFact, ...],
    validator: FormalModelOutputValidator,
) -> bool:
    if any(
        semantic_role_violation(literal.predicate, literal.args) is not None
        for literal in (*rule.body, *rule.head)
    ):
        return False
    payload = _artifact_payload(declarations, (rule,))
    return not validator.validate(payload).issues


def _unique_facts(
    facts: Iterable[FormalFact],
) -> tuple[FormalFact, ...]:
    return tuple({canonical_json(fact): fact for fact in facts}.values())


def _rule_context_is_proposal(rule: FormalRule) -> bool:
    return all(
        literal.context is Context.PROPOSAL for literal in (*rule.body, *rule.head)
    )


def _artifact_payload(
    facts: tuple[FormalFact, ...],
    rules: tuple[FormalRule, ...],
) -> dict[str, Any]:
    return {
        "context": Context.PROPOSAL.value,
        "facts": [fact.model_dump(mode="json") for fact in facts],
        "rules": [rule.model_dump(mode="json") for rule in rules],
    }


def _semantic_role_issues(
    violations: tuple[SemanticRoleViolation, ...],
) -> tuple[ValidationIssue, ...]:
    return tuple(
        ValidationIssue(
            code="semantic_role",
            message=(
                f"engine role is not accepted from LLM: {violation.role}"
                if violation.reason == "engine"
                else f"unknown semantic role: {violation.role}"
            ),
        )
        for violation in violations
    )


__all__ = [
    "FormalThreatModeler",
    "FormalThreatModelResult",
]
