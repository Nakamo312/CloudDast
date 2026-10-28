"""Typed consultation requests built from execution deficits."""

from __future__ import annotations

import json

import pytest

from cloud_dast.consultation import (
    ConsultationBudget,
)
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import QdlStepEvaluated
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    Variable,
    canonical_json,
    changed,
    denied,
    differs,
    field,
    input_field,
)
from cloud_dast.runtime.deficits import (
    Deficit,
    classify_step_event,
    consultation_request,
    missing_role_deficit,
)
from cloud_dast.runtime.planning import QdlSubgoal
from cloud_dast.verification.slices import build_slice
from cloud_dast_llm.consultation import ConsultationDispatcher

_ANY_ACTION = Variable(name="AnyAction")
_ANY_EFFECT = Variable(name="AnyEffect")
_ANY_FIELD = Variable(name="AnyField")
_ANY_ROLE = Variable(name="AnyRole")
_ANY_NORM = Variable(name="AnyNorm")
_ANY_RESOURCE = Variable(name="AnyResource")
_ANY_DIMENSION = Variable(name="AnyDimension")
_ANY_TARGET = Variable(name="AnyTarget")


def _blocked_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (_ANY_ACTION, denied(Atom(value="action:get"))),
        ),
        predicate_class="causes",
        axis="alternatives",
        action="action:get",
        context=(("path_id", "p1"), ("reason", "not verified")),
    )


def _irreversibility_deficit() -> Deficit:
    effect = changed(Atom(value="resource:order"), Atom(value="total"))
    return Deficit(
        subgoal=QdlSubgoal("causes", (Atom(value="action:get"), effect)),
        predicate_class="causes",
        axis="alternatives",
        action="action:get",
        context=(
            ("path_id", "p1"),
            ("step_id", "step:p1:0"),
            ("effect", canonical_json(effect)),
        ),
    )


def _exposure_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="action:get"),
                field(_ANY_RESOURCE, Atom(value="secret")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="action:get",
        context=(("field", "secret"),),
    )


def _response_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (Atom(value="action:get"), field(_ANY_RESOURCE, _ANY_FIELD)),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="action:get",
        context=(("fields", "email"),),
    )


def _variance_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "prevents",
            (
                _ANY_NORM,
                differs(Atom(value="get"), _ANY_DIMENSION),
            ),
        ),
        predicate_class="prevents",
        axis="variance",
        action="get",
        context=(("diff", "outcome:True"),),
    )


def _fixture_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "refers_to",
            (
                input_field(Atom(value="action:get"), Atom(value="order_id")),
                _ANY_TARGET,
            ),
        ),
        predicate_class="refers_to",
        axis="fixture",
        action="action:get",
        context=(
            ("field", "order_id"),
            ("required_resource_type", ""),
            ("required_state", "existing"),
        ),
    )


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _build_graph() -> QdlGraph:
    get = Atom(value="action:get")
    other = Atom(value="action:other")
    get_field = Struct(name="input_field", args=(get, Atom(value="secret_id")))
    other_field = Struct(name="input_field", args=(other, Atom(value="other_id")))
    return QdlGraph(
        facts=(
            _fact("is", (get, Atom(value="Action"))),
            _fact("is", (other, Atom(value="Action"))),
            _fact("is", (get_field, Atom(value="InputField"))),
            _fact("is", (other_field, Atom(value="InputField"))),
            _fact(
                "has",
                (
                    get_field,
                    Atom(value="object_ref"),
                ),
                context=Context.ACCEPTED,
            ),
            _fact(
                "has",
                (
                    other_field,
                    Atom(value="sensitive"),
                ),
                context=Context.ACCEPTED,
            ),
        )
    )


def _budget() -> ConsultationBudget:
    return ConsultationBudget(max_input_tokens=2048, max_output_tokens=256)


@pytest.mark.parametrize(
    ("deficit", "expected_kind"),
    [
        (_blocked_deficit(), "alternatives"),
        (
            missing_role_deficit(
                "action:get",
                (("coverage", "input_roles"),),
            ),
            "roles",
        ),
        (_irreversibility_deficit(), "alternatives"),
        (_exposure_deficit(), "exposures"),
        (_response_deficit(), "response_semantics"),
        (_variance_deficit(), "variance"),
    ],
)
def test_consultation_request_maps_llm_deficits_to_typed_kinds(
    deficit: Deficit,
    expected_kind: str,
) -> None:
    request = consultation_request(deficit, graph=_build_graph(), budget=_budget())

    assert request is not None
    assert request.kind == expected_kind
    assert request.deficit_id == deficit.consultation_id
    assert request.action == deficit.action
    assert request.budget == _budget()
    assert request.context == {}
    assert request.depth == 0


def test_consultation_request_routes_deterministic_and_fixture_deficits() -> None:
    event = QdlStepEvaluated(
        path_id="latency",
        step_id="step:latency:0",
        verdict=VerdictStatus.UNSCOREABLE,
        phase="unscoreable",
        reason="no runtime latency baseline for method action:get",
        step_index=0,
    )
    baseline = classify_step_event(event)
    assert baseline is not None

    assert (
        consultation_request(baseline, graph=_build_graph(), budget=_budget()) is None
    )

    request = consultation_request(
        _fixture_deficit(),
        graph=_build_graph(),
        budget=_budget(),
    )

    assert request is not None
    assert request.kind == "fixture"
    assert request.context["unprovable_subgoal"] == (
        'refers_to(input_field("action:get", "order_id"), AnyTarget)'
    )
    assert request.context["required_state"] == "existing"


def test_consultation_request_slices_the_graph_to_the_deficit_action() -> None:
    deficit = missing_role_deficit(
        "action:get",
        (("coverage", "input_roles"),),
    )

    request = consultation_request(deficit, graph=_build_graph(), budget=_budget())

    assert request is not None
    assert (
        request.slice.content_hash
        == build_slice(
            _build_graph(),
            actions=("action:get",),
        ).graph.content_hash
    )
    slice_json = json.dumps(request.slice.model_dump(mode="json"))
    assert "action:get" in slice_json
    assert "action:other" not in slice_json
    assert "other_id" not in slice_json


def test_consultation_request_resolves_the_plain_method_id_alias() -> None:
    deficit = missing_role_deficit(
        "get",
        (("coverage", "input_roles"),),
    )

    request = consultation_request(deficit, graph=_build_graph(), budget=_budget())

    assert request is not None
    assert request.slice.facts
    assert "action:get" in json.dumps(request.slice.model_dump(mode="json"))


def test_consultation_request_carries_bounded_context() -> None:
    deficit = missing_role_deficit("action:get")

    request = consultation_request(
        deficit,
        graph=_build_graph(),
        budget=_budget(),
        context={"blocked_step": {"reason": "not verified"}},
    )

    assert request is not None
    assert request.context == {"blocked_step": {"reason": "not verified"}}


def test_deficit_consultation_id_is_stable_and_canonical() -> None:
    first = missing_role_deficit(
        "action:get",
        (("coverage", "input_roles"),),
    )
    second = missing_role_deficit(
        "action:get",
        (("coverage", "other"),),
    )
    different_field = _exposure_deficit()

    assert first.consultation_id == second.consultation_id
    assert first.consultation_id.startswith("has|has|")
    assert first.consultation_id != different_field.consultation_id


class OneCallModelClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests: list[ModelRequest] = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            structured=self.payload,
            content=json.dumps(self.payload),
            model_id="specialist-model",
            input_tokens=10,
            output_tokens=4,
        )


def test_deficit_request_dispatches_through_the_typed_protocol() -> None:
    deficit = missing_role_deficit(
        "action:get",
        (("coverage", "input_roles"),),
    )
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:get", "Action")',
            'is(input_field("action:get", "secret_id"), "InputField")',
            'has(input_field("action:get", "secret_id"), "object_ref")',
        ],
        "rules": [],
    }
    client = OneCallModelClient(payload)
    dispatcher = ConsultationDispatcher(client)
    request = consultation_request(deficit, graph=_build_graph(), budget=_budget())
    assert request is not None

    outcome = dispatcher.dispatch(request)

    assert outcome.status == "proposal"
    assert outcome.proposal is not None and outcome.proposal.facts
    assert outcome.provenance.deficit_id == deficit.consultation_id
    assert outcome.provenance.kind == "roles"
    assert outcome.provenance.model_version == "specialist-model"
    assert len(client.requests) == 1


def test_fixture_request_uses_the_missing_fact_alphabet() -> None:
    deficit = _fixture_deficit()
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:get", "Action")',
            'is(input_field("action:get", "order_id"), "Field")',
            'is("resource:order", "ResourceType")',
            'refers_to(input_field("action:get", "order_id"), "resource:order")',
            'targets("action:get", "resource:order")',
            'causes("action:get", create("resource:order"))',
            'causes("action:get", changed("resource:order", "state"))',
        ],
        "rules": [],
    }
    client = OneCallModelClient(payload)
    dispatcher = ConsultationDispatcher(client)
    request = consultation_request(
        deficit,
        graph=_build_graph(),
        budget=_budget(),
        context={"evidence": {"response_summary": "order 1001 created"}},
    )
    assert request is not None

    outcome = dispatcher.dispatch(request)

    assert outcome.status == "proposal"
    assert outcome.proposal is not None
    predicates = {fact.predicate.name for fact in outcome.proposal.facts}
    assert {"refers_to", "targets", "causes"} <= predicates
    effects = {
        fact.args[1].name
        for fact in outcome.proposal.facts
        if fact.predicate.name == "causes"
    }
    assert effects == {"create"}
    instruction = client.requests[0].instruction
    assert "refers_to(input_field(Action, Field), ResourceType)" in instruction
    assert "targets(Action, ResourceType)" in instruction
    assert "causes(Action, create(ResourceType))" in instruction
