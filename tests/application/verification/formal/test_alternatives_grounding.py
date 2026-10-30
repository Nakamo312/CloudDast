"""MazeRunner branch grounding: alternatives for one blocked step."""

from __future__ import annotations

import json

from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import commit_branch, make_grounding

ACTION = "action:grpc:nsfy.shop.v1.OrderService.PayOrder"
SIBLING = "action:grpc:nsfy.shop.v1.OrderService.CreateOrder"


class FakeModelClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest, *, response_type=None) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            structured=self.payload,
            content=json.dumps(self.payload),
            model_id="fake-model",
        )


def _source_graph() -> QdlGraph:
    action = Atom(value=ACTION)
    sibling = Atom(value=SIBLING)
    resource = Atom(value="resource:order")
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
                args=(sibling, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(action, resource),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(sibling, resource),
            ),
        )
    )


def _alternative_payload() -> dict:
    action = {"kind": "atom", "value": ACTION, "literal_type": "string"}
    other = {
        "kind": "atom",
        "value": "action:grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "literal_type": "string",
    }
    effect = {
        "kind": "struct",
        "name": "changed",
        "args": [
            {"kind": "atom", "value": "resource:order", "literal_type": "string"},
            {"kind": "atom", "value": "state", "literal_type": "string"},
        ],
    }
    resource = {
        "kind": "atom",
        "value": "resource:order",
        "literal_type": "string",
    }
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    other,
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    resource,
                    {"kind": "atom", "value": "Resource", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    effect,
                    {"kind": "atom", "value": "Effect", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "causes",
                "args": [action, effect],
            },
        ],
        "rules": [],
    }


def _ownership_payload() -> dict:
    """An alternatives response that tries to mint a create ownership fact."""

    action = {"kind": "atom", "value": ACTION, "literal_type": "string"}
    resource = {
        "kind": "atom",
        "value": "resource:order",
        "literal_type": "string",
    }
    effect = {
        "kind": "struct",
        "name": "create",
        "args": [resource],
    }
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    action,
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    resource,
                    {"kind": "atom", "value": "ResourceType", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    effect,
                    {"kind": "atom", "value": "Effect", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "causes",
                "args": [action, effect],
            },
        ],
        "rules": [],
    }


def _observation() -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="payment method rejected",
        transport_status=HttpStatus(code=403),
    )


def test_alternatives_prompt_carries_only_evidence_view() -> None:
    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    observation = _observation()

    result = service.ground_alternatives(
        _source_graph(),
        ACTION.removeprefix("action:"),
        observation=observation,
        effect_hint='{"name":"allowed"}',
        blocked_reason="QDL effect chain was not verified",
    )

    assert result.graph is not None and result.graph.facts
    assert result.observation_ids == (observation.observation_id,)
    request = client.requests[0]
    assert request.task == "formal_grounding_alternatives"
    assert "ALTERNATIVE" in request.instruction
    context = request.context
    assert context["blocked_step"]["action"] == ACTION.removeprefix("action:")
    assert context["blocked_step"]["blocked_reason"] == (
        "QDL effect chain was not verified"
    )
    assert context["sibling_actions"] == [
        {
            "action": SIBLING,
            "relations": ["targets"],
            "shared_terms": [
                '{"kind":"atom","literal_type":"string","value":"resource:order"}'
            ],
        }
    ]
    assert "live_observation" not in context
    assert context["evidence"]["response_summary"] == "payment method rejected"
    assert "payment method rejected" in json.dumps(context)


def test_alternatives_prompt_declares_closed_role_alphabet() -> None:
    """The alternatives prompt must not let the model invent roles."""
    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    service.ground_alternatives(_source_graph(), ACTION.removeprefix("action:"))

    instruction = client.requests[0].instruction
    assert "object_ref, sensitive, credential" in instruction
    assert (
        "privileged, attacker_controlled, unbounded, verbose, deprecated" in instruction
    )
    assert "never invent new names" in instruction
    assert 'is(Action, "Action")' in instruction
    assert 'is(Effect, "Effect")' in instruction
    assert (
        'causes("action:existing", changed("resource:thing", "state"))' in instruction
    )
    assert "Never emit ownership" in instruction
    assert "causes(Action, create(ResourceType))" in instruction
    assert "causes(Action, remove(ResourceId))" in instruction


def test_alternatives_without_observation_omits_live_block() -> None:
    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_alternatives(
        _source_graph(), ACTION.removeprefix("action:")
    )

    assert result.graph is not None
    assert "live_observation" not in client.requests[0].context


def test_alternatives_prompt_never_replays_prior_uncertainties() -> None:
    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    service.ground_alternatives(_source_graph(), ACTION.removeprefix("action:"))

    assert "prior_uncertainties" not in client.requests[0].context


def test_alternatives_without_qdl_relations_returns_deficit() -> None:
    """An isolated action has no neighbourhood: deficit, never a model call."""

    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    isolated = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=ACTION), Atom(value="Action")),
            ),
        )
    )

    result = service.ground_alternatives(isolated, ACTION.removeprefix("action:"))

    assert result.graph is None
    assert [issue.code for issue in result.issues] == ["sibling_slice_deficit"]
    assert client.requests == []


def test_alternatives_result_carries_model_uncertainties() -> None:
    payload = _alternative_payload()
    payload["uncertainties"] = [
        {"field": "query", "question": "need a live response example"}
    ]
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_alternatives(
        _source_graph(), ACTION.removeprefix("action:")
    )

    assert result.graph is not None
    assert result.uncertainties == (("query", "need a live response example"),)


def test_alternatives_unknown_action_returns_empty() -> None:
    client = FakeModelClient(_alternative_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_alternatives(_source_graph(), "missing")

    assert result.graph is None
    assert client.requests == []


def test_alternatives_reject_unknown_effect_constructors() -> None:
    """Invented effect names never survive the alternatives grammar."""

    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            'is("read", "Effect")',
            f'requires("{ACTION}", "read")',
            'is(changed("resource:order", "state"), "Effect")',
            f'causes("{ACTION}", changed("resource:order", "state"))',
        ],
        "rules": [],
    }
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_alternatives(
        _source_graph(), ACTION.removeprefix("action:")
    )

    assert client.requests, "the model was called and its answer was rejected"
    assert result.graph is not None
    predicates = {fact.predicate.name for fact in result.graph.facts}
    assert "requires" not in predicates
    assert not any(
        fact.predicate.name == "is"
        and isinstance(fact.args[0], Atom)
        and fact.args[0].value == "read"
        for fact in result.graph.facts
    )
    assert any(
        fact.predicate.name == "causes"
        and getattr(fact.args[1], "name", None) == "changed"
        for fact in result.graph.facts
    )
    assert result.issue_count >= 2


def test_alternatives_reject_undeclared_fields_and_natural_language_rules() -> None:
    """The alternatives grammar admits declared fields and formal rules only."""

    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            f'is(input_field("{ACTION}", "admin_note"), "InputField")',
            f'has(input_field("{ACTION}", "admin_note"), "attacker_controlled")',
        ],
        "rules": ["an attacker may read any file by sending quot=1"],
    }
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_alternatives(
        _source_graph(), ACTION.removeprefix("action:")
    )

    assert client.requests, "the model was called and its answer was rejected"
    assert result.graph is None
    assert "alternatives_grammar" in {issue.code for issue in result.issues}
    assert result.issue_count >= 3


def test_alternatives_cannot_promote_create() -> None:
    """Alternatives never mint create ownership, even with live evidence.

    The blocked action is the order consumer's sibling, so an unevidenced
    ``causes(blocked, create(order))`` would make it a false setup provider
    for ``resource:order``.  The axis filter drops the ownership fact before
    promotion, and the promoted batch contains no create effect.
    """

    client = FakeModelClient(_ownership_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    observation = _observation()

    result = service.ground_alternatives(
        _source_graph(),
        ACTION.removeprefix("action:"),
        observation=observation,
    )

    assert result.graph is not None
    assert not any(
        fact.predicate.name == "causes"
        and len(fact.args) == 2
        and getattr(fact.args[1], "name", None) == "create"
        for fact in result.graph.facts
    )

    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    grounder_options_1 = GrounderOptions(
        consultation=ConsultationDispatcher(
            grounding_client := FakeModelClient(_ownership_payload())
        ),
        grounding_dispatcher=Dispatcher(grounding_client),
    )
    grounding = make_grounding(
        repository,
        startup=Bootstrap(options=grounder_options_1),
        reactive=Followup(options=grounder_options_1),
        promotion_policy=PromotionPolicy(enabled=True),
    )

    promoted = commit_branch(
        grounding,
        "orders",
        ACTION.removeprefix("action:"),
        observation=observation,
    )

    assert promoted is None or not any(
        fact.predicate.name == "causes"
        and len(fact.args) == 2
        and getattr(fact.args[1], "name", None) == "create"
        for fact in promoted.facts
    )


class InMemoryFormalRepository:
    def __init__(self) -> None:
        self.saved = []

    def save(
        self,
        source_id,
        graph,
        *,
        provenance,
        adapter_version,
        mapping_report,
    ):
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id):
        return next(
            (
                item["graph"]
                for item in reversed(self.saved)
                if item["source_id"] == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix):
        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


def test_branch_batch_does_not_replay_prior_uncertainties() -> None:
    payload = _alternative_payload()
    payload["uncertainties"] = [
        {"field": "query", "question": "need a live response example"}
    ]
    client = FakeModelClient(payload)
    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    grounder_options_2 = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    grounding = make_grounding(
        repository,
        startup=Bootstrap(options=grounder_options_2),
        reactive=Followup(options=grounder_options_2),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    action = ACTION.removeprefix("action:")

    first = commit_branch(grounding, "orders", action)
    commit_branch(grounding, "orders", action)

    assert first is not None and first.facts
    # Model questions are logged, never replayed: the second prompt carries
    # the QDL sibling neighbourhood instead of the model's own questions.
    assert len(client.requests) == 2
    assert "prior_uncertainties" not in client.requests[0].context
    assert "prior_uncertainties" not in client.requests[1].context
    assert client.requests[1].context["sibling_actions"]
