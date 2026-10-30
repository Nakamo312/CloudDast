"""Declaration-closure safety for proposal filtering and promotion."""

from __future__ import annotations

import json

from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.ports import ModelResponse
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    canonical_json,
    changed,
    field,
    has,
    input_field,
    output_field,
)
from cloud_dast.qdl.validation import filter_declaration_closure
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.verification.promotion import (
    promote_proposal,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher


class RecordingResponseClient:
    """Return one deterministic formal model response."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def complete(self, request, response_type=None) -> ModelResponse:
        del request, response_type
        return ModelResponse(
            structured=self._payload,
            content=json.dumps(self._payload),
            model_id="test-model",
            input_tokens=1,
            output_tokens=1,
        )


def _fact(
    predicate: str,
    args: tuple[object, ...],
    *,
    context: Context = Context.PROPOSAL,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def test_response_semantics_drops_dangling_field_but_keeps_consultation() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:order")
    label = field(resource, Atom(value="label"))
    output_holder = output_field(action, Atom(value="visible"))
    input_holder = input_field(action, Atom(value="query"))
    source = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                context=Context.CONTRACT,
            ),
            _fact(
                "is",
                (resource, Atom(value="Resource")),
                context=Context.CONTRACT,
            ),
            _fact("targets", (action, resource), context=Context.CONTRACT),
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:get", "Action")',
            'is(output_field("action:get", "visible"), "Field")',
            'has(output_field("action:get", "visible"), "sensitive")',
            'is(input_field("action:get", "query"), "InputField")',
            'has(input_field("action:get", "query"), "object_ref")',
            'is(field("resource:order", "label"), "Witness")',
            'has(field("resource:order", "label"), "sensitive")',
        ],
        "rules": [],
    }
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("visible", "value"),),
    )
    service = Followup(
        consultation=ConsultationDispatcher(
            grounding_client := RecordingResponseClient(payload)
        ),
        grounding_dispatcher=Dispatcher(grounding_client),
        batch_size=1,
        max_workers=1,
    )

    result = service.ground_reactive(
        "response_semantics",
        ("action:get",),
        source,
        observation=observation,
    )

    assert result.graph is not None
    assert any(
        fact.predicate.name == "has"
        and canonical_json(fact.args[0]) == canonical_json(output_holder)
        for fact in result.graph.facts
    )
    assert any(
        fact.predicate.name == "is"
        and canonical_json(fact.args[0]) == canonical_json(input_holder)
        for fact in result.graph.facts
    )
    assert not any(
        fact.predicate.name == "has"
        and canonical_json(fact.args[0]) == canonical_json(label)
        for fact in result.graph.facts
    )
    assert not any(
        fact.predicate.name == "is"
        and canonical_json(fact.args[0]) == canonical_json(label)
        for fact in result.graph.facts
    )
    assert any(
        issue.code == "response_grounding" and canonical_json(label) in issue.path
        for issue in result.issues
    )
    assert any(
        issue.code == "closure" and canonical_json(label) in issue.path
        for issue in result.issues
    )
    assert any(
        issue.code == "response_predicate"
        and canonical_json(input_holder) in issue.path
        for issue in result.issues
    )
    assert result.issue_count == len(result.issues)


def test_declaration_closure_drops_a_fact_dependent_on_a_dropped_declaration() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:order")
    label = field(resource, Atom(value="label"))
    action_declaration = _fact("is", (action, Atom(value="Action")))
    label_role = _fact("has", (label, Atom(value="sensitive")))

    result = filter_declaration_closure((action_declaration, label_role))

    assert result.graph is not None
    assert [canonical_json(fact) for fact in result.graph.facts] == [
        canonical_json(action_declaration)
    ]
    assert any(
        issue.code == "closure" and canonical_json(label_role) in issue.path
        for issue in result.issues
    )


def test_declaration_closure_collects_graph_validation_errors() -> None:
    action = Atom(value="action:get")
    declaration = _fact("is", (action, Atom(value="Action")))

    result = filter_declaration_closure((declaration, declaration))

    assert result.graph is None
    assert any(
        issue.code == "graph" and "duplicate fact" in issue.message
        for issue in result.issues
    )


def test_promotion_response_filter_keeps_unrelated_semantics() -> None:
    action = Atom(value="action:get")
    principal = Atom(value="principal:attacker")
    resource = Atom(value="resource:order")
    label = field(resource, Atom(value="label"))
    source = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (principal, Atom(value="Principal"))),
            _fact("is", (label, Atom(value="Witness"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("causes", (action, has(principal, label))),
            _fact("causes", (action, changed(resource, Atom(value="role")))),
        )
    )

    result = promote_proposal(ProposalPromotionRequest(source, proposal))

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and canonical_json(fact.args[1])
        == canonical_json(changed(resource, Atom(value="role")))
        for fact in result.graph.facts
    )
    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and canonical_json(fact.args[1]) == canonical_json(has(principal, label))
        for fact in result.graph.facts
    )
    assert any(
        issue.code == "response_grounding" and canonical_json(label) in issue.path
        for issue in result.issues
    )
    assert any(
        issue.code == "closure" and canonical_json(label) in issue.path
        for issue in result.issues
    )


def test_promotion_reports_rejected_norm_as_a_typed_issue() -> None:
    action = Atom(value="action:get")
    unknown_action = Atom(value="action:unknown")
    norm = Atom(value="norm:invalid")
    source = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (unknown_action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, allowed(unknown_action))),
        )
    )

    result = promote_proposal(ProposalPromotionRequest(source, proposal))

    assert result.rejected_norms == ("norm:invalid",)
    assert any(
        issue.code == "norm" and issue.path == "norms[norm:invalid]"
        for issue in result.issues
    )


def test_promotion_reports_parked_classification_as_a_typed_issue() -> None:
    action = Atom(value="action:get")
    holder = input_field(action, Atom(value="token"))
    source = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (holder, Atom(value="InputField"))),
            _fact("has", (holder, Atom(value="sensitive"))),
        )
    )

    result = promote_proposal(ProposalPromotionRequest(source, proposal))

    assert result.parked_classifications is not None
    assert any(
        issue.code == "classification_parked" and canonical_json(holder) in issue.path
        for issue in result.issues
    )
