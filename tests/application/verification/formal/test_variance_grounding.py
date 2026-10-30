"""Differential variance grounding: formalize one measured behavior diff."""

from __future__ import annotations

import json

from cloud_dast.model import (
    AccessOutcome,
    GrpcStatus,
    Observation,
    ResponseData,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, Struct
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.verification.differential import project_diff
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher

ACTION = "action:grpc:nsfy.shop.v1.OrderService.ExportData"


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
    return QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )


def _variance_payload() -> dict:
    action = _atom(ACTION)
    norm = _atom("norm:export_other")
    effect = {"kind": "struct", "name": "allowed", "args": [action]}
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [norm, _atom("Norm")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [effect, _atom("Effect")],
            },
            {
                "context": "proposal",
                "predicate": "prevents",
                "args": [norm, effect],
            },
        ],
        "rules": [],
    }


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _control() -> Observation:
    return Observation(
        check_id="check-control",
        scenario_id="scenario-control",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="gRPC status: OK",
        transport_status=GrpcStatus(code="OK"),
        output=ResponseData(
            fields=(("email", "alice@example.com"),),
            field_names=("email", "nested.profile"),
        ),
    )


def _treatment() -> Observation:
    return Observation(
        check_id="check-treatment",
        scenario_id="scenario-treatment",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="gRPC status: PERMISSION_DENIED",
        transport_status=GrpcStatus(code="PERMISSION_DENIED"),
        output=ResponseData(
            fields=(("payment_token", "tok_123"),),
            field_names=("payment_token",),
        ),
        error_reason="export denied for attacker identity",
    )


def _report() -> DiffReport:
    return DiffReport(
        action_id=ACTION.removeprefix("action:"),
        control_observation_id="control-1",
        treatment_observation_id="treatment-1",
        outcome_differs=True,
        fields_only_treatment=("payment_token",),
        value_differs=("email",),
        error_differs=True,
    )


def test_variance_prompt_carries_only_evidence_view() -> None:
    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    report = _report()

    result = service.ground_variance(
        _source_graph(),
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=report,
    )

    assert result.axis == "variance"
    assert result.graph is not None and result.graph.facts
    assert all(fact.context is Context.PROPOSAL for fact in result.graph.facts)
    request = client.requests[0]
    assert request.task == "formal_grounding_variance"
    assert "paired_observations" not in request.context
    evidence = request.context["evidence"]
    assert evidence["control"]["response_summary"] == _control().response_summary
    assert evidence["treatment"]["response_summary"] == _treatment().response_summary
    assert "gRPC status: OK" in json.dumps(evidence)
    assert "gRPC status: PERMISSION_DENIED" in json.dumps(evidence)
    assert evidence["control"]["status"] == "grpc:OK"
    assert evidence["treatment"]["status"] == "grpc:PERMISSION_DENIED"
    assert evidence["control"]["outcome"] == "allowed"
    assert evidence["treatment"]["outcome"] == "denied"
    assert [leaf["path"] for leaf in evidence["control"]["response"]["leaves"]] == [
        "email"
    ]
    assert [leaf["path"] for leaf in evidence["treatment"]["response"]["leaves"]] == [
        "payment_token"
    ]
    assert evidence["diff"]["outcome_differs"] is True
    assert evidence["diff"]["fields_only_treatment"][0]["path"] == "payment_token"
    assert evidence["diff"]["value_differs"][0]["path"] == "email"
    assert evidence["diff"]["error_differs"] is True


def test_variance_paired_block_retains_bounded_values() -> None:
    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    service.ground_variance(
        _source_graph(),
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=_report(),
    )

    context = client.requests[0].context
    rendered = json.dumps(context, ensure_ascii=False)
    assert "paired_observations" not in context
    assert "alice@example.com" in rendered
    assert "tok_123" in rendered


def test_variance_prompt_carries_safe_diff_report_context() -> None:
    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    report = _report()

    service.ground_variance(
        _source_graph(),
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=report,
    )

    context = client.requests[0].context
    assert context["diff_report"] == {
        "action": ACTION.removeprefix("action:"),
        "control_observation_id": "control-1",
        "treatment_observation_id": "treatment-1",
        "dimensions": ["outcome", "fields", "value", "error"],
        "signature": report.signature,
    }


def test_variance_instruction_forbids_inventing_values() -> None:
    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    service.ground_variance(
        _source_graph(),
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=_report(),
    )

    instruction = client.requests[0].instruction
    assert "SHAPE-ONLY" in instruction
    assert "never invent or request them" in instruction
    assert "prevents(NormId, Effect)" in instruction
    assert "exposes(Action, field(ResourceId, Field))" in instruction
    assert "has(input_field(Action, Field), Role)" in instruction
    assert "object_ref, sensitive, credential" in instruction


def test_variance_drops_hallucinated_exposes_not_in_paired_evidence() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [_atom(ACTION), _atom("Action")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "struct",
                        "name": "field",
                        "args": [
                            _atom("resource:user"),
                            _atom("hallucinated_secret"),
                        ],
                    },
                    _atom("Witness"),
                ],
            },
            {
                "context": "proposal",
                "predicate": "exposes",
                "args": [
                    _atom(ACTION),
                    {
                        "kind": "struct",
                        "name": "field",
                        "args": [
                            _atom("resource:user"),
                            _atom("hallucinated_secret"),
                        ],
                    },
                ],
            },
        ],
        "rules": [],
    }
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_variance(
        _source_graph(),
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=_report(),
    )

    assert result.graph is not None
    assert not any(fact.predicate.name == "exposes" for fact in result.graph.facts)
    assert not any(
        fact.predicate.name == "is"
        and isinstance(fact.args[0], Struct)
        and fact.args[0].name == "field"
        and fact.args[0].args[1].value == "hallucinated_secret"
        for fact in result.graph.facts
    )


def test_variance_unknown_action_returns_empty() -> None:
    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_variance(
        _source_graph(),
        "missing",
        control=_control(),
        treatment=_treatment(),
        report=_report(),
    )

    assert result.axis == "variance"
    assert result.graph is None
    assert client.requests == []


def test_variance_slice_keeps_action_referenced_diff_facts() -> None:
    """Projected diff facts must survive the action-centric LLM slice."""

    client = FakeModelClient(_variance_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    report = _report()
    graph = merge_graphs(_source_graph(), project_diff(report))

    service.ground_variance(
        graph,
        ACTION.removeprefix("action:"),
        control=_control(),
        treatment=_treatment(),
        report=report,
    )

    slice_facts = client.requests[0].context["graph"]["facts"]
    diff_facts = [
        fact
        for fact in slice_facts
        if fact["predicate"]["name"] == "evidence"
        and fact["args"][1]["name"] == "differs"
    ]
    assert {
        (fact["args"][0]["value"], fact["args"][1]["args"][1]["value"])
        for fact in diff_facts
    } == {
        ("observation:treatment-1", "error"),
        ("observation:treatment-1", "fields"),
        ("observation:treatment-1", "outcome"),
        ("observation:treatment-1", "value"),
    }
