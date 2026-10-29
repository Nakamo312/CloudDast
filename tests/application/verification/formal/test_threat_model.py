from __future__ import annotations

import json

from cloud_dast.contracts.proposals import FormalModelOutput
from cloud_dast.ports import ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
)
from cloud_dast.verification.slices import SliceBudget
from cloud_dast_llm.threat_model import FormalThreatModeler
from tests.support.threat_model import project_stride


class FakeModelClient:
    def __init__(self, *responses: ModelResponse) -> None:
        self.responses = responses
        self.requests: list[tuple[object, object]] = []

    def complete(
        self,
        request,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append((request, response_type))
        if len(self.requests) > len(self.responses):
            raise AssertionError("model client was called more times than expected")
        return self.responses[len(self.requests) - 1]


def atom(value: str) -> dict[str, object]:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def variable(name: str) -> dict[str, object]:
    return {"kind": "variable", "name": name}


def struct(name: str, *args: dict[str, object]) -> dict[str, object]:
    return {"kind": "struct", "name": name, "args": list(args)}


def fact(
    predicate: str,
    args: tuple[dict[str, object], ...],
    *,
    context: Context = Context.PROPOSAL,
) -> dict[str, object]:
    return {
        "context": context.value,
        "predicate": predicate,
        "args": list(args),
    }


def rule(
    body: tuple[dict[str, object], ...],
    head: tuple[dict[str, object], ...],
) -> dict[str, object]:
    return {"body": list(body), "head": list(head)}


def output(
    facts: tuple[dict[str, object], ...] = (),
    rules: tuple[dict[str, object], ...] = (),
    *,
    context: Context = Context.PROPOSAL,
) -> dict[str, object]:
    return {
        "context": context.value,
        "facts": list(facts),
        "rules": list(rules),
    }


def response(payload: dict[str, object]) -> ModelResponse:
    return ModelResponse(structured=payload, model_id="fake-model")


def source_graph() -> QdlGraph:
    action = Atom(value="action:update_user")
    resource = Atom(value="resource:user")
    permission = Atom(value="permission:user.update")
    return QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="ResourceType")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(permission, Atom(value="Permission")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(action, permission),
            ),
        )
    )


def multi_action_graph() -> QdlGraph:
    facts = []
    for index in range(3):
        action = Atom(value=f"action:get-{index}")
        permission = Atom(value=f"permission:get-{index}")
        facts.extend(
            (
                Fact(
                    context=Context.CONTRACT,
                    predicate=Predicate.from_name("is"),
                    args=(action, Atom(value="Action")),
                ),
                Fact(
                    context=Context.CONTRACT,
                    predicate=Predicate.from_name("is"),
                    args=(permission, Atom(value="Permission")),
                ),
                Fact(
                    context=Context.CONTRACT,
                    predicate=Predicate.from_name("requires"),
                    args=(action, permission),
                ),
            )
        )
    return QdlGraph(facts=tuple(facts))


def test_formal_threat_modeler_requests_bounded_action_slice() -> None:
    action = atom("action:get-0")
    norm = atom("norm:no-get")
    payload = output(
        (
            fact("is", (action, atom("Action"))),
            fact("is", (norm, atom("Norm"))),
            fact("prevents", (norm, struct("allowed", action))),
        )
    )
    client = FakeModelClient(response(payload))
    modeler = FormalThreatModeler(client, max_actions=2)

    modeler.propose(multi_action_graph())

    request = client.requests[0][0]
    graph = QdlGraph.model_validate(request.context["graph"])
    actions = {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "is" and fact.args[1].value == "Action"
    }
    assert actions == {"action:get-0", "action:get-1"}


def test_modeler_request_slice_is_token_bounded() -> None:
    payload = output(
        (
            fact("is", (atom("action:get-0"), atom("Action"))),
            fact("is", (atom("norm:no-get"), atom("Norm"))),
            fact(
                "prevents",
                (atom("norm:no-get"), struct("allowed", atom("action:get-0"))),
            ),
        )
    )
    default_client = FakeModelClient(response(payload))
    bounded_client = FakeModelClient(response(payload))
    default_modeler = FormalThreatModeler(default_client, max_actions=2)
    default_modeler.propose(multi_action_graph())
    bounded_modeler = FormalThreatModeler(
        bounded_client,
        max_actions=2,
        budget=SliceBudget(max_tokens=300),
    )

    bounded_modeler.propose(multi_action_graph())

    default_graph = QdlGraph.model_validate(
        default_client.requests[0][0].context["graph"]
    )
    bounded_graph = QdlGraph.model_validate(
        bounded_client.requests[0][0].context["graph"]
    )
    assert len(bounded_graph.facts) < len(default_graph.facts)


def test_modeler_request_slice_is_deterministic() -> None:
    payload = output(
        (
            fact("is", (atom("action:get-0"), atom("Action"))),
            fact("is", (atom("norm:no-get"), atom("Norm"))),
            fact(
                "prevents",
                (atom("norm:no-get"), struct("allowed", atom("action:get-0"))),
            ),
        )
    )
    clients = [FakeModelClient(response(payload)) for _ in range(2)]

    for client in clients:
        FormalThreatModeler(client, max_actions=2).propose(multi_action_graph())

    assert (
        clients[0].requests[0][0].context["graph"]
        == clients[1].requests[0][0].context["graph"]
    )


def stride_graph() -> QdlGraph:
    action = Atom(value="action:update_user")
    field = Struct(
        name="input_field",
        args=(action, Atom(value="role")),
    )
    return QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="resource:user"), Atom(value="ResourceType")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(field, Atom(value="Field")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(field, Atom(value="privileged")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("causes"),
                args=(
                    action,
                    Struct(
                        name="changed",
                        args=(Atom(value="resource:user"), Atom(value="role")),
                    ),
                ),
            ),
        )
    )


def proposal_payload() -> dict[str, object]:
    return output(
        facts=(
            fact("is", (atom("action:update_user"), atom("Action"))),
            fact("is", (atom("threat:t1"), atom("Threat"))),
            fact("is", (atom("norm:no_mass_assignment"), atom("Norm"))),
            fact("is", (atom("resource:user"), atom("ResourceType"))),
            fact(
                "is",
                (
                    struct(
                        "input_field",
                        atom("action:update_user"),
                        atom("role"),
                    ),
                    atom("Field"),
                ),
            ),
            fact(
                "has",
                (
                    struct(
                        "input_field",
                        atom("action:update_user"),
                        atom("role"),
                    ),
                    atom("privileged"),
                ),
            ),
            fact(
                "causes",
                (
                    atom("threat:t1"),
                    struct("changed", atom("resource:user"), atom("role")),
                ),
            ),
            fact(
                "prevents",
                (
                    atom("norm:no_mass_assignment"),
                    struct("changed", atom("resource:user"), atom("role")),
                ),
            ),
        ),
        rules=(
            rule(
                body=(
                    fact("is", (variable("Threat"), variable("ThreatType"))),
                    fact("is", (variable("Resource"), variable("ResourceType"))),
                    fact("is", (variable("Field"), variable("FieldType"))),
                    fact("is", (variable("Norm"), variable("NormType"))),
                    fact(
                        "prevents",
                        (
                            variable("Norm"),
                            struct(
                                "changed",
                                variable("Resource"),
                                variable("Field"),
                            ),
                        ),
                    ),
                ),
                head=(
                    fact(
                        "causes",
                        (
                            variable("Threat"),
                            struct(
                                "changed",
                                variable("Resource"),
                                variable("Field"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def test_modeler_accepts_valid_proposal_without_repair() -> None:
    client = FakeModelClient(response(proposal_payload()))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid, result.issues
    assert result.attempts == 1
    assert not result.initial_issues
    assert result.proposal is not None
    assert all(item.context is Context.PROPOSAL for item in result.proposal.facts)
    assert all(
        literal.context is Context.PROPOSAL
        for item in result.proposal.rules
        for literal in (*item.body, *item.head)
    )

    request, response_type = client.requests[0]
    assert request.task == "formal_threat_modeling"
    assert response_type is FormalModelOutput
    assert "proposal" in request.instruction
    assert "Do not return prose" in request.instruction
    assert request.context["graph"]["facts"]
    assert response_type.model_json_schema()


def test_modeler_request_asks_for_semantic_roles_and_causal_effects() -> None:
    client = FakeModelClient(response(proposal_payload()))

    FormalThreatModeler(client).propose(source_graph())

    request = client.requests[0][0]
    assert "semantic roles" in request.instruction
    assert "causal effects" in request.instruction
    assert "has(input_field(Action, Field), Role)" in request.instruction
    assert "causes(Subject, Effect)" in request.instruction
    assert "exposes(Action, field(ResourceId, Field))" in request.instruction
    assert "exposes(Action, output_field(Action," not in request.instruction
    assert "Do not return prose" in request.instruction
    assert "STRIDE categories" in request.instruction


def test_modeler_accepts_semantic_role_and_causal_effect_proposal() -> None:
    client = FakeModelClient(response(proposal_payload()))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid, result.issues
    assert result.proposal is not None
    predicates = {item.predicate.name for item in result.proposal.facts}
    assert {"has", "causes", "prevents"} <= predicates


def test_stride_view_projects_semantic_roles_and_causal_effects() -> None:
    views = project_stride(stride_graph())

    assert len(views) == 2
    assert [(view.role, view.categories) for view in views if view.role] == [
        ("privileged", ("T",))
    ]
    assert [(view.effect.name, view.categories) for view in views if view.effect] == [
        ("changed", ("T",))
    ]


def test_modeler_rejects_free_text_after_one_repair() -> None:
    client = FakeModelClient(
        ModelResponse(content="This looks like mass assignment.", model_id="fake"),
        ModelResponse(content="Still just prose.", model_id="fake"),
    )

    result = FormalThreatModeler(client).propose(source_graph())

    assert not result.valid
    assert result.proposal is None
    assert result.attempts == 2
    assert any(issue.code == "payload" for issue in result.initial_issues)
    assert any(issue.code == "payload" for issue in result.issues)


def test_modeler_repairs_semantic_only_proposal_with_prevent_norm() -> None:
    semantic_only = output(facts=(fact("is", (atom("threat:t1"), atom("Threat"))),))
    action = atom("action:update_user")
    norm = atom("norm:no-update")
    repaired = output(
        facts=(
            fact("is", (action, atom("Action"))),
            fact("is", (norm, atom("Norm"))),
            fact("prevents", (norm, struct("denied", action))),
        )
    )
    client = FakeModelClient(response(semantic_only), response(repaired))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid, result.issues
    assert result.attempts == 2
    assert any(issue.code == "norms" for issue in result.initial_issues)


def test_modeler_adds_source_declarations_deterministically() -> None:
    action = atom("action:update_user")
    norm = atom("norm:no-update")
    payload = output(
        facts=(
            fact("is", (norm, atom("Norm"))),
            fact("prevents", (norm, struct("denied", action))),
        )
    )
    client = FakeModelClient(response(payload))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid, result.issues
    assert result.proposal is not None
    assert any(
        fact.predicate.name == "is"
        and fact.args[0].value == "action:update_user"
        and fact.context is Context.PROPOSAL
        for fact in result.proposal.facts
    )


def test_modeler_repairs_only_invalid_artifacts() -> None:
    invalid_fact = fact("narrates", (atom("threat:t1"),))
    initial = output(
        facts=(
            fact("is", (atom("threat:t1"), atom("Threat"))),
            fact("is", (atom("resource:user"), atom("ResourceType"))),
            fact("is", (atom("norm:no-change"), atom("Norm"))),
            fact(
                "prevents",
                (
                    atom("norm:no-change"),
                    struct("changed", atom("resource:user"), atom("role")),
                ),
            ),
            invalid_fact,
        )
    )
    repair = output(
        facts=(
            fact(
                "causes",
                (
                    atom("threat:t1"),
                    struct("changed", atom("resource:user"), atom("role")),
                ),
            ),
        )
    )
    client = FakeModelClient(response(initial), response(repair))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid, result.issues
    assert result.repaired
    assert result.attempts == 2
    assert any(issue.code == "graph" for issue in result.initial_issues)
    assert not result.repair_issues
    assert result.proposal is not None
    assert {"is", "causes", "prevents"}.issubset(
        {item.predicate.name for item in result.proposal.facts}
    )
    assert not any(item.predicate.name == "narrates" for item in result.proposal.facts)

    repair_request = client.requests[1][0]
    valid_artifacts = json.dumps(repair_request.context["valid_artifacts"])
    invalid_artifacts = json.dumps(repair_request.context["invalid_artifacts"])
    assert "threat:t1" in valid_artifacts
    assert "narrates" in invalid_artifacts
    assert "narrates" not in valid_artifacts
    assert repair_request.task == "formal_threat_modeling_repair"


def test_modeler_rejects_unknown_predicate_after_repair() -> None:
    payload = output(
        facts=(
            fact("is", (atom("threat:t1"), atom("Threat"))),
            fact("narrates", (atom("threat:t1"),)),
        )
    )
    repair = output(facts=(fact("narrates", (atom("threat:t1"),)),))
    client = FakeModelClient(response(payload), response(repair))

    result = FormalThreatModeler(client).propose(source_graph())

    assert not result.valid
    assert result.attempts == 2
    assert any(
        issue.code == "graph" and "narrates" in issue.message for issue in result.issues
    )


def test_modeler_rejects_unknown_reference_after_repair() -> None:
    payload = output(
        facts=(
            fact("is", (atom("threat:t1"), atom("Threat"))),
            fact(
                "causes",
                (
                    atom("threat:t1"),
                    struct("changed", atom("resource:missing"), atom("role")),
                ),
            ),
        )
    )
    repair = output(
        facts=(
            fact(
                "causes",
                (
                    atom("threat:t1"),
                    struct("changed", atom("resource:missing"), atom("role")),
                ),
            ),
        )
    )
    client = FakeModelClient(response(payload), response(repair))

    result = FormalThreatModeler(client).propose(source_graph())

    assert not result.valid
    assert result.attempts == 2
    assert any(
        issue.code == "graph" and "unknown reference" in issue.message
        for issue in result.issues
    )


def test_modeler_rejects_cross_context_promotion_after_repair() -> None:
    payload = output(
        rules=(
            rule(
                body=(fact("is", (variable("Entity"), variable("Type"))),),
                head=(
                    fact(
                        "is",
                        (variable("Entity"), variable("Type")),
                        context=Context.ACCEPTED,
                    ),
                ),
            ),
        )
    )
    client = FakeModelClient(response(payload), response(payload))

    result = FormalThreatModeler(client).propose(source_graph())

    assert not result.valid
    assert result.proposal is None
    assert result.attempts == 2
    assert any(issue.code == "context" for issue in result.issues)


def test_valid_result_never_contains_accepted_context() -> None:
    client = FakeModelClient(response(proposal_payload()))

    result = FormalThreatModeler(client).propose(source_graph())

    assert result.valid
    assert result.proposal is not None
    assert all(item.context is Context.PROPOSAL for item in result.proposal.facts)
    assert all(
        literal.context is Context.PROPOSAL
        for item in result.proposal.rules
        for literal in (*item.body, *item.head)
    )
