from __future__ import annotations

import hashlib
import json
import logging
from unittest.mock import Mock

import pytest

from cloud_dast.contracts.proposals import FormalModelWireOutput
from cloud_dast.infrastructure.runtime import FileGroundingCache
from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, Struct
from cloud_dast.runtime.grounding.axes.filtering import _response_fact_is_grounded
from cloud_dast.runtime.grounding.axes.projection import intersect_axis_batch_proposals
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.verification.evidence import build_evidence_view
from cloud_dast.verification.slices import (
    SliceBudget,
    build_slice,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher

ACTION = "action:get"


@pytest.mark.parametrize(
    ("predicate", "kind", "owner", "bound"),
    [
        ("has", "output_field", ACTION, True),
        ("is", "output_field", ACTION, True),
        ("has", "output_field", "action:other", False),
        ("is", "output_field", "action:other", False),
        ("exposes", "field", "resource:user", True),
        ("exposes", "field", "resource:other", False),
        ("exposes", "output_field", ACTION, False),
        ("has", "field", "resource:user", False),
        ("is", "field", "resource:user", True),
        ("is", "field", "resource:other", True),
        ("is", "field", "resource:invented", False),
    ],
)
@pytest.mark.parametrize("observed", [True, False])
def test_response_fact_keeps_owner_and_evidence_bindings(
    predicate: str, kind: str, owner: str, bound: bool, observed: bool
) -> None:
    entity = Struct(name=kind, args=(Atom(value=owner), Atom(value="email")))
    args = (
        (Atom(value=ACTION), entity)
        if predicate == "exposes"
        else (entity, Atom(value="sensitive" if predicate == "has" else "Field"))
    )
    fact = Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name(predicate),
        args=args,
    )

    assert _response_fact_is_grounded(
        fact,
        {ACTION},
        {ACTION: {"resource:user"}, "action:other": {"resource:other"}},
        {"email"} if observed else set(),
    ) is (bound and observed)


@pytest.mark.parametrize("targets", [{}, {"action:other": {"resource:user"}}])
def test_response_exposure_needs_target_of_the_observed_action(targets) -> None:
    fact = Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("exposes"),
        args=(
            Atom(value=ACTION),
            Struct(
                name="field",
                args=(Atom(value="resource:user"), Atom(value="email")),
            ),
        ),
    )

    assert not _response_fact_is_grounded(fact, {ACTION}, targets, {"email"})


class OneResponseClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = 0

    def complete(self, request: ModelRequest, *, response_type=None) -> ModelResponse:
        self.calls += 1
        return ModelResponse(
            structured=self.payload,
            content=json.dumps(self.payload),
            model_id="test-model",
            input_tokens=100,
            cached_input_tokens=50,
            output_tokens=10,
        )


class RecordingResponseClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests: list[ModelRequest] = []
        self.response_types = []

    def complete(self, request: ModelRequest, *, response_type=None) -> ModelResponse:
        self.requests.append(request)
        self.response_types.append(response_type)
        return ModelResponse(
            structured=self.payload,
            content=json.dumps(self.payload),
            model_id="test-model",
        )


class MapCache:
    def __init__(self) -> None:
        self.values: dict[str, QdlGraph] = {}

    def load(self, key: str) -> QdlGraph | None:
        return self.values.get(key)

    def save(self, key: str, graph: QdlGraph) -> None:
        self.values[key] = graph


class RecordingMetrics:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.finished = 0
        self.tokens: list[tuple[int, int, int, str]] = []
        self.model_ids: list[str] = []

    def model_request_started(self, description: str = "") -> None:
        self.started.append(description)

    def model_request_finished(self) -> None:
        self.finished += 1

    def record_tokens(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int = 0,
        *,
        phase: str = "default",
    ) -> None:
        self.tokens.append((input_tokens, output_tokens, cached_input_tokens, phase))

    def set_model_id(self, model_id: str) -> None:
        self.model_ids.append(model_id)

    def record_grounding_cache_hit(self, axis: str) -> None:
        del axis

    def record_grounding_cache_miss(self, axis: str) -> None:
        del axis


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


def _two_action_graph() -> QdlGraph:
    action = Atom(value=ACTION)
    other = Atom(value="action:other")
    permission = Atom(value="permission:admin")
    resource = Atom(value="resource:user")
    owner = Atom(value="principal:admin")
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
                args=(other, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(permission, Atom(value="Permission")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(owner, Atom(value="Principal")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(action, permission),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(other, permission),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(action, resource),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("owner"),
                args=(resource, owner),
            ),
        )
    )


def _model_payload() -> dict:
    action = {"kind": "atom", "value": ACTION, "literal_type": "string"}
    field = {
        "kind": "struct",
        "name": "input_field",
        "args": [
            action,
            {
                "kind": "atom",
                "value": "secret_id",
                "literal_type": "string",
            },
        ],
    }
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [action, _atom("Action")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [field, _atom("InputField")],
            },
            {
                "context": "proposal",
                "predicate": "has",
                "args": [field, _atom("object_ref")],
            },
        ],
        "rules": [],
    }


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _exposures_model_payload() -> dict:
    """A literal exposures response using the schema-valid field witness."""

    action = {"kind": "atom", "value": ACTION, "literal_type": "string"}
    witness = {
        "kind": "struct",
        "name": "field",
        "args": [
            {"kind": "atom", "value": "resource:user", "literal_type": "string"},
            {"kind": "atom", "value": "email", "literal_type": "string"},
        ],
    }
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "atom",
                        "value": "resource:user",
                        "literal_type": "string",
                    },
                    _atom("ResourceType"),
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [witness, _atom("Witness")],
            },
            {
                "context": "proposal",
                "predicate": "exposes",
                "args": [action, witness],
            },
        ],
        "rules": [],
    }


def _semantic_model_payload() -> dict:
    """A combined valid proposal with role, dataflow, and exposure facts."""

    action = _atom(ACTION)
    input_field = {
        "kind": "struct",
        "name": "input_field",
        "args": [action, _atom("query")],
    }
    sink = _atom("sink:sql")
    witness = {
        "kind": "struct",
        "name": "field",
        "args": [_atom("resource:user"), _atom("email")],
    }
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [action, _atom("Action")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [input_field, _atom("InputField")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [sink, _atom("Sink")],
            },
            {
                "context": "proposal",
                "predicate": "reaches",
                "args": [input_field, sink],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [_atom("resource:user"), _atom("ResourceType")],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [witness, _atom("Witness")],
            },
            {
                "context": "proposal",
                "predicate": "exposes",
                "args": [action, witness],
            },
            {
                "context": "proposal",
                "predicate": "has",
                "args": [input_field, _atom("object_ref")],
            },
        ],
        "rules": [],
    }


def _axis_proposal(*roles: str) -> QdlGraph:
    action = Atom(value=ACTION)
    field_term = Struct(
        name="input_field",
        args=(action, Atom(value="token")),
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
                args=(field_term, Atom(value="InputField")),
            ),
            *(
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("has"),
                    args=(field_term, Atom(value=role)),
                )
                for role in roles
            ),
        )
    )


def test_exposures_axis_accepts_field_witness_payload() -> None:
    """The exposures axis must validate field(ResourceId, Field) witnesses.

    Regression: the prompt used to ask for output_field(Action, Field),
    which the QDL witness alphabet rejects, so the whole exposure batch
    was discarded by the validator.
    """

    client = OneResponseClient(_exposures_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    source = _source_graph()

    proposals = service.ground_batches(source)

    exposures = [proposal for axis, _, proposal in proposals if axis == "exposures"]
    assert exposures
    expose_facts = [
        fact for fact in exposures[0].facts if fact.predicate.name == "exposes"
    ]
    assert expose_facts
    witness = expose_facts[0].args[1]
    assert witness.name == "field"
    assert witness.args[0].value == "resource:user"
    assert witness.args[1].value == "email"


def test_exposures_instruction_requests_field_witness_form() -> None:
    """The exposures prompt must request the schema-valid witness form."""

    from cloud_dast_llm.axis_grounding import _AXIS_INSTRUCTIONS

    instruction = _AXIS_INSTRUCTIONS["exposures"]
    assert "exposes(Action, field(ResourceId, Field))" in instruction
    assert "output_field(Action, Field)" not in instruction
    assert "resource:user" in instruction


def test_dataflows_instruction_requests_generic_sink_types() -> None:
    """The dataflows prompt must cover every generic QDL sink type."""

    from cloud_dast_llm.axis_grounding import _AXIS_INSTRUCTIONS

    instruction = _AXIS_INSTRUCTIONS["dataflows"]
    assert "is(SinkId, interpreter)" in instruction
    assert "is(SinkId, filesystem)" in instruction
    assert "is(SinkId, business_flow)" in instruction
    assert "is(MarkerId, external_net)" in instruction


def test_grounding_cache_reuses_validated_proposals(tmp_path) -> None:
    client = OneResponseClient(_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=FileGroundingCache(tmp_path),
        cache_namespace="test:model",
    )
    source = _source_graph()

    first = service.ground(source, cache_source=source)
    first_calls = client.calls
    second = service.ground(source, cache_source=source)

    assert first.facts
    assert second == first
    assert client.calls == first_calls


def test_axis_grounding_records_metrics_through_port() -> None:
    client = OneResponseClient(_model_payload())
    metrics = RecordingMetrics()
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client, metrics=metrics),
        batch_size=1,
        max_workers=1,
        metrics=metrics,
    )

    service.ground_batches(_source_graph())

    assert len(metrics.started) == 6
    assert metrics.finished == 6
    assert metrics.tokens == [
        (100, 10, 50, f"grounding:{axis}")
        for axis in (
            "roles",
            "dataflows",
            "exposures",
            "authentication",
            "availability",
            "norms",
        )
    ]
    assert metrics.model_ids == ["test-model"] * 6


def test_grounder_requires_explicit_model_dispatch() -> None:
    client = OneResponseClient(_model_payload())

    with pytest.raises(ValueError, match="grounding_dispatcher must be injected"):
        Bootstrap(consultation=ConsultationDispatcher(client))

    assert client.calls == 0


def test_dispatch_cache_key_preserves_v3_prompt_and_schema_identity() -> None:
    client = RecordingResponseClient({})
    dispatcher = Dispatcher(client)
    dispatcher.dispatch("roles", {"actions": [ACTION]})
    request = client.requests[0]
    payload = {
        "cache_version": 3,
        "namespace": "campaign-model",
        "axis": "roles",
        "instruction": request.instruction,
        "response_schema": json.dumps(
            client.response_types[0].model_json_schema(), ensure_ascii=False
        ),
        "slice_hash": "source-slice",
    }
    expected = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    assert dispatcher.cache_key("roles", "campaign-model", "source-slice") == expected
    assert dispatcher.cache_key("roles", "another-model", "source-slice") != expected
    assert dispatcher.cache_key("roles", "campaign-model", "another-slice") != expected


def test_model_failure_finishes_usage_without_fabricating_tokens() -> None:
    client = Mock()
    client.complete.side_effect = RuntimeError("model unavailable")
    metrics = RecordingMetrics()
    dispatcher = Dispatcher(client, metrics=metrics)
    request = ModelRequest(task="formal_grounding_roles", context={"actions": [ACTION]})

    with pytest.raises(RuntimeError, match="model unavailable"):
        dispatcher.dispatch("roles", request.context)

    client.complete.assert_called_once()
    call = client.complete.call_args
    assert call.kwargs["response_type"] is FormalModelWireOutput
    assert call.args[0].task == request.task
    assert call.args[0].context == request.context
    assert metrics.started == ["grounding roles (1 actions)"]
    assert metrics.finished == 1
    assert metrics.tokens == []
    assert metrics.model_ids == []


def test_grounder_requires_explicit_consultation() -> None:
    client = OneResponseClient(_model_payload())

    with pytest.raises(ValueError, match="consultation must be injected"):
        Followup(grounding_dispatcher=Dispatcher(client))

    assert client.calls == 0


def test_grounding_cache_does_not_store_empty_model_responses() -> None:
    client = OneResponseClient({"facts": [], "rules": []})
    cache = MapCache()
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=cache,
        cache_namespace="test:model",
    )
    source = _source_graph()

    first = service.ground(source, cache_source=source)
    calls_after_first = client.calls
    second = service.ground(source, cache_source=source)

    assert first.facts == ()
    assert second.facts == ()
    assert client.calls > calls_after_first
    assert cache.values == {}


def test_invalid_model_response_log_is_bounded(caplog) -> None:
    raw_response = "x" * 2500

    class RawResponseClient:
        def complete(
            self, request: ModelRequest, *, response_type=None
        ) -> ModelResponse:
            return ModelResponse(content=raw_response)

    service = Bootstrap(
        consultation=ConsultationDispatcher(grounding_client := RawResponseClient()),
        grounding_dispatcher=Dispatcher(grounding_client),
        batch_size=1,
        max_workers=1,
    )

    with caplog.at_level(
        logging.WARNING,
        logger="cloud_dast.runtime.grounding.parallel",
    ):
        service.ground_batches(_source_graph())

    records = [
        record
        for record in caplog.records
        if record.getMessage().startswith("axis_grounding_invalid")
    ]
    assert records
    for record in records:
        assert record.getMessage().partition("raw_response=")[2] == raw_response[:2000]


def test_target_action_log_is_bounded(caplog) -> None:
    blocked_action = "a" * 2500
    action = Atom(value=blocked_action)
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )
    service = Followup(
        consultation=ConsultationDispatcher(
            grounding_client := RecordingResponseClient({"facts": [], "rules": []})
        ),
        grounding_dispatcher=Dispatcher(grounding_client),
        batch_size=1,
        max_workers=1,
    )

    with caplog.at_level(
        logging.INFO,
        logger="cloud_dast.runtime.grounding.parallel",
    ):
        service.ground_alternatives(source, blocked_action)

    records = [
        record
        for record in caplog.records
        if record.getMessage().startswith("grounding_alternatives")
    ]
    assert records
    logged_action = records[0].getMessage().partition("action=")[2].split(maxsplit=1)[0]
    assert logged_action == blocked_action[:2000]


def test_grounding_cache_key_ignores_previously_accepted_outputs(tmp_path) -> None:
    client = OneResponseClient(_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=FileGroundingCache(tmp_path),
        cache_namespace="test:model",
    )
    source = _source_graph()
    service.ground(source, cache_source=source)
    calls_before = client.calls

    action = Atom(value=ACTION)
    accepted = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("is"),
        args=(action, Atom(value="Action")),
    )
    source_with_accepted = QdlGraph(facts=(*source.facts, accepted))

    service.ground(source_with_accepted, cache_source=source)

    assert client.calls == calls_before


def test_staged_norms_see_semantic_facts_and_evidence() -> None:
    client = RecordingResponseClient(_semantic_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    evidence = build_evidence_view(
        observation=Observation(
            check_id="check",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="ok",
            response_tree=(("email", "alice@example.com"),),
        )
    )

    proposals = service.ground_batches(
        _source_graph(),
        evidence=evidence,
    )

    assert {axis for axis, _, _ in proposals} == {
        "roles",
        "dataflows",
        "exposures",
        "authentication",
        "availability",
        "norms",
    }
    norms_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_norms"
    ]
    assert len(norms_requests) == 1
    assert all(
        request.task != "formal_grounding_norms" for request in client.requests[:-1]
    )
    norms_predicates = {
        fact["predicate"]["name"]
        for fact in norms_requests[0].context["graph"]["facts"]
    }
    assert {"has", "reaches", "exposes"} <= norms_predicates
    evidence_leaf = norms_requests[0].context["evidence"]["response"]["leaves"][0]
    assert evidence_leaf["path"] == "email"
    assert evidence_leaf["value"] == "alice@example.com"


def test_norms_slice_contains_campaign_policy_facts() -> None:
    action = Atom(value="action:CreateApiKey")
    unrelated_action = Atom(value="action:Unrelated")
    attacker = Atom(value="principal:attacker")
    resource = Atom(value="resource:api-key")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(unrelated_action, Atom(value="Action")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(attacker, Atom(value="Subject")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("may"),
                args=(attacker, action, resource),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("may"),
                args=(attacker, unrelated_action, resource),
            ),
        )
    )
    client = RecordingResponseClient(_semantic_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    service.ground_batches(source)

    norms_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_norms"
    ]
    target_requests = []
    for request in norms_requests:
        graph = QdlGraph.model_validate(request.context["graph"])
        actions = {
            fact.args[0].value
            for fact in graph.facts
            if fact.predicate.name == "is" and fact.args[1].value == "Action"
        }
        if actions == {"action:CreateApiKey"}:
            target_requests.append((request, graph))
    assert target_requests
    request, graph = target_requests[0]
    may_actions = {
        fact.args[1].value for fact in graph.facts if fact.predicate.name == "may"
    }
    assert may_actions == {"action:CreateApiKey"}
    assert "Do not propose" in request.instruction
    assert "expected behavior" in request.instruction


def test_norms_slice_preserves_policy_facts_under_token_pressure() -> None:
    action = Atom(value="action:CreateApiKey")
    attacker = Atom(value="principal:attacker")
    resource = Atom(value="resource:api-key")
    facts = [
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(action, Atom(value="Action")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(attacker, Atom(value="Subject")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(resource, Atom(value="Resource")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("may"),
            args=(attacker, action, resource),
        ),
    ]
    for index in range(10):
        permission = Atom(value=f"permission:filler-{index}")
        facts.extend(
            (
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(permission, Atom(value="Permission")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("requires"),
                    args=(action, permission),
                ),
            )
        )
    source = QdlGraph(facts=tuple(facts))
    client = RecordingResponseClient(_semantic_model_payload())
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        slice_budget=SliceBudget(max_tokens=1200),
    )

    service.ground_batches(source)

    norms_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_norms"
    ]
    assert norms_requests
    graph = QdlGraph.model_validate(norms_requests[0].context["graph"])
    assert any(
        fact.predicate.name == "may"
        and fact.args[0] == attacker
        and fact.args[1] == action
        and fact.args[2] == resource
        for fact in graph.facts
    )


def test_staged_cache_keys_separate_semantic_and_norms_slices() -> None:
    client = RecordingResponseClient(_semantic_model_payload())
    cache = MapCache()
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=cache,
        cache_namespace="test:staged",
    )
    source = _source_graph()
    evidence = build_evidence_view(
        observation=Observation(
            check_id="check",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="first",
        )
    )
    service.ground_batches(source, evidence=evidence)
    baseline_calls = len(client.requests)

    action = Atom(value=ACTION)
    accepted = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("is"),
        args=(action, Atom(value="Action")),
    )
    source_with_accepted = QdlGraph(facts=(*source.facts, accepted))

    service.ground_batches(
        source_with_accepted,
        cache_source=source,
        evidence=evidence,
    )
    assert len(client.requests) == baseline_calls

    changed_evidence = build_evidence_view(
        observation=Observation(
            check_id="check",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.DENIED,
            response_summary="second",
            response_tree=(("email", "bob@example.com"),),
        )
    )
    service.ground_batches(
        source_with_accepted,
        cache_source=source,
        evidence=changed_evidence,
    )
    new_tasks = [request.task for request in client.requests[baseline_calls:]]

    assert new_tasks == ["formal_grounding_norms"]


def test_axis_grounding_sends_bounded_slice_not_full_graph() -> None:
    client = RecordingResponseClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        slice_budget=SliceBudget(max_depth=1),
    )

    service.ground_reactive("roles", (ACTION,), _two_action_graph())

    request = client.requests[0]
    graph = QdlGraph.model_validate(request.context["graph"])
    actions = {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "is" and fact.args[1].value == "Action"
    }
    assert actions == {ACTION}
    assert not any(fact.predicate.name == "owner" for fact in graph.facts)
    assert not any("action:other" in fact.model_dump_json() for fact in graph.facts)


def test_startup_and_reactive_roles_requests_share_framing() -> None:
    """Startup and reactive roles grounding must share request framing.

    Consultation instructions remain deliberately call-specific; the task,
    response schema, and bounded graph slice must not drift between paths.
    """

    client = RecordingResponseClient(_model_payload())
    options = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    startup = Bootstrap(options=options)
    reactive = Followup(options=options)
    source = _source_graph()

    startup.ground_batches(source)
    reactive.ground_reactive("roles", (ACTION,), source)

    requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_roles"
    ]
    assert len(requests) == 2
    startup, reactive = requests
    assert reactive.task == startup.task
    assert len(set(client.response_types)) == 1
    assert client.response_types[0].model_json_schema()
    assert reactive.context["graph"] == startup.context["graph"]


def test_axis_grounding_slice_is_token_bounded() -> None:
    source = _two_action_graph()
    full = build_slice(
        source,
        actions=(ACTION,),
        budget=SliceBudget(max_depth=1),
    )
    client = RecordingResponseClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        slice_budget=SliceBudget(
            max_tokens=full.token_estimate // 2,
            max_depth=1,
        ),
    )

    service.ground_reactive("roles", (ACTION,), source)

    graph = QdlGraph.model_validate(client.requests[0].context["graph"])
    assert len(graph.facts) < len(full.graph.facts)


def test_axis_grounding_slice_is_deterministic() -> None:
    source = _two_action_graph()
    requests = []
    for _ in range(2):
        client = RecordingResponseClient(_model_payload())
        service = Followup(
            consultation=ConsultationDispatcher(client),
            grounding_dispatcher=Dispatcher(client),
            batch_size=1,
            max_workers=1,
        )
        service.ground_reactive("roles", (ACTION,), source)
        requests.append(client.requests[0])

    assert requests[0].context["graph"] == requests[1].context["graph"]


def test_roles_axis_drops_requires_predicate_and_logs_issue(caplog) -> None:
    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            'is(input_field("action:get", "query"), "InputField")',
            'has(input_field("action:get", "query"), "object_ref")',
            'is("permission:admin", "Permission")',
            'requires("action:get", "permission:admin")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    with caplog.at_level(
        logging.WARNING,
        logger="cloud_dast.formal.consultation",
    ):
        result = service.ground_reactive("roles", (ACTION,), _source_graph())

    assert result.graph is not None
    predicates = {fact.predicate.name for fact in result.graph.facts}
    assert "has" in predicates
    assert "requires" not in predicates
    assert result.issue_count >= 1
    assert "consultation_predicate_rejected" in caplog.text
    assert "kind=roles" in caplog.text
    assert "predicates=requires=1" in caplog.text


def test_response_semantics_requires_explicit_exposes_fact() -> None:
    action = Atom(value=ACTION)
    resource = Atom(value="resource:user")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
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
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            f'is(output_field("{ACTION}", "email"), "Field")',
            f'has(output_field("{ACTION}", "email"), "sensitive")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("email", "bob@example.com"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
    )

    assert result.graph is not None
    facts = result.graph.facts
    # A ``has`` role alone must not fabricate ownership: without an explicit
    # ``exposes`` fact no exposure witness is created.
    assert not any(
        fact.predicate.name == "exposes"
        and atom_text(fact.args[0]) == ACTION
        and atom_text(fact.args[1].args[1]) == "email"
        for fact in facts
    )
    assert not any(
        fact.predicate.name == "is"
        and isinstance(fact.args[0], Struct)
        and fact.args[0].name == "field"
        and atom_text(fact.args[0].args[1]) == "email"
        for fact in facts
    )
    assert any(
        fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and atom_text(fact.args[0].args[1]) == "email"
        and atom_text(fact.args[1]) == "sensitive"
        for fact in facts
    )


def test_response_semantics_rejects_fields_absent_from_evidence() -> None:
    action = Atom(value=ACTION)
    resource = Atom(value="resource:user")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
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
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            f'is(output_field("{ACTION}", "not_in_response"), "Field")',
            f'has(output_field("{ACTION}", "not_in_response"), "sensitive")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("visible", "value"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
    )

    assert result.graph is not None
    assert all(
        fact.predicate.name != "exposes"
        or atom_text(fact.args[1].args[1]) != "not_in_response"
        for fact in result.graph.facts
    )
    assert all(
        fact.predicate.name != "has"
        or atom_text(fact.args[0].args[1]) != "not_in_response"
        for fact in result.graph.facts
    )


def test_response_semantics_rejects_invented_actions_and_resources() -> None:
    action = Atom(value=ACTION)
    resource = Atom(value="resource:user")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
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
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:invented", "Action")',
            'is("resource:invented", "Resource")',
            'is(field("resource:user", "email"), "Witness")',
            'exposes("action:invented", field("resource:user", "email"))',
            'has(output_field("action:wrong", "email"), "sensitive")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("email", "bob@example.com"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
    )

    assert result.graph is not None
    assert not any(fact.predicate.name == "exposes" for fact in result.graph.facts)
    assert not any(
        fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and atom_text(fact.args[0].args[0]) != ACTION
        for fact in result.graph.facts
    )


def test_response_semantics_does_not_transfer_evidence_to_related_action() -> None:
    blocked = Atom(value=ACTION)
    related = Atom(value="action:related")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(blocked, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(related, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(blocked, related),
            ),
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:related", "Action")',
            'is(output_field("action:related", "email"), "Field")',
            'has(output_field("action:related", "email"), "sensitive")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("email", "bob@example.com"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
    )

    assert result.graph is not None
    assert not any(
        fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and atom_text(fact.args[0].args[0]) == "action:related"
        for fact in result.graph.facts
    )


def test_response_semantics_does_not_guess_with_multiple_targets() -> None:
    action = Atom(value=ACTION)
    first = Atom(value="resource:first")
    second = Atom(value="resource:second")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(first, Atom(value="Resource")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(second, Atom(value="Resource")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(action, first),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(action, second),
            ),
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            f'is(output_field("{ACTION}", "email"), "Field")',
            f'has(output_field("{ACTION}", "email"), "sensitive")',
        ],
        "rules": [],
    }
    client = RecordingResponseClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("email", "bob@example.com"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
    )

    assert result.graph is not None
    assert not any(fact.predicate.name == "exposes" for fact in result.graph.facts)


def test_axis_intersection_is_comparable_only_inside_one_axis_batch() -> None:
    """S34R intersections never erase S21R's orthogonal axis ownership."""

    roles_first = _axis_proposal("object_ref", "payload")
    roles_second = _axis_proposal("object_ref", "credential")
    exposures = _axis_proposal("object_ref")

    first_order = intersect_axis_batch_proposals(
        (
            ("roles", "action:get", roles_first),
            ("roles", "action:get", roles_second),
            ("exposures", "action:get", exposures),
        )
    )
    second_order = intersect_axis_batch_proposals(
        (
            ("exposures", "action:get", exposures),
            ("roles", "action:get", roles_second),
            ("roles", "action:get", roles_first),
        )
    )

    assert first_order == (_axis_proposal("object_ref"), exposures)
    assert second_order == first_order


def atom_text(term: object) -> str | None:
    return term.value if isinstance(term, Atom) else None


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("with_metrics", [False, True])
def test_reactive_dispatch_preserves_request_and_finishes_usage(
    fails: bool, with_metrics: bool
) -> None:
    from dataclasses import replace

    from cloud_dast.consultation import (
        ConsultationBudget,
        ConsultationRequest,
        bind_consultation_telemetry,
        current_consultation_telemetry,
        rejected_outcome,
    )

    request = ConsultationRequest(
        kind="roles",
        deficit_id="deficit:roles",
        action=ACTION,
        slice=_source_graph(),
        budget=ConsultationBudget(),
        observation_ids=("observation:live",),
    )
    rejected = rejected_outcome(request, "", "no proposal")
    outcome = replace(
        rejected,
        provenance=replace(
            rejected.provenance,
            model_version="test-model",
            input_tokens=100,
            cached_input_tokens=50,
            output_tokens=10,
        ),
    )
    metrics = RecordingMetrics() if with_metrics else None
    consultation = Mock()
    grounder = Followup(
        consultation=consultation,
        grounding_dispatcher=Mock(),
        metrics=metrics,
    )
    publisher = Mock()

    def dispatch(actual, *, telemetry):
        assert actual is request
        assert telemetry is current_consultation_telemetry()
        assert telemetry.publisher is publisher
        if metrics is not None:
            assert metrics.started == [f"consultation roles ({ACTION})"]
            assert metrics.finished == 0
        if fails:
            raise RuntimeError("consultation unavailable")
        return outcome

    consultation.dispatch.side_effect = dispatch
    with bind_consultation_telemetry(publisher):
        if fails:
            with pytest.raises(RuntimeError, match="consultation unavailable"):
                grounder.dispatch_consultation(request)
        else:
            assert grounder.dispatch_consultation(request) is outcome
    consultation.dispatch.assert_called_once()
    if metrics is not None:
        assert metrics.finished == 1
        assert metrics.tokens == (
            [] if fails else [(100, 10, 50, "consultation:roles")]
        )
        assert metrics.model_ids == ([] if fails else ["test-model"])


def _startup_probe(*, fail_axis=None):
    from cloud_dast.runtime.grounding.results import AxisResult
    from cloud_dast.runtime.grounding.startup import Bootstrap

    calls = []

    class ReverseRunner:
        def run_tasks(self, tasks, *, max_workers, timeout):
            for index in reversed(range(len(tasks))):
                yield index, tasks[index]()

    def ground(axis, batch, graph, cache, evidence):
        calls.append((axis, batch, graph, cache, evidence))
        if axis == fail_axis:
            raise RuntimeError("failed semantic task")
        proposal = QdlGraph(
            facts=(
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("is"),
                    args=(Atom(value=f"action:{axis}"), Atom(value="Action")),
                ),
            )
        )
        return AxisResult(axis, proposal, 0, len(batch))

    class Probe(Bootstrap):
        def _ground_axis_batch(self, *args):
            return ground(*args)

    service = Probe(
        grounding_dispatcher=Mock(),
        batch_size=1,
        task_runner=ReverseRunner(),
        max_workers=2,
        axis_timeout=0.5,
    )
    return service, calls


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("failed_axis", [None, "exposures"])
def test_startup_stage_barrier_preserves_graph_cache_and_evidence(
    streaming, failed_axis
):
    from cloud_dast.contracts.axes import SEMANTIC_AXES
    from cloud_dast.qdl.graph_ops import merge_graphs
    from cloud_dast.runtime.grounding.axes.projection import batch_key

    service, calls = _startup_probe(fail_axis=failed_axis)
    source = _source_graph()
    cache = QdlGraph()
    evidence = object()
    operation = service.ground_stream if streaming else service.ground_batches
    proposals = list(operation(source, cache_source=cache, evidence=evidence))
    semantic = [call for call in calls if call[0] != "norms"]
    norms = [call for call in calls if call[0] == "norms"]
    assert [call[0] for call in semantic] == list(reversed(SEMANTIC_AXES))
    assert [axis for axis, _, _ in proposals] == [
        axis for axis in reversed(SEMANTIC_AXES) if axis != failed_axis
    ] + ["norms"]
    assert all(call[2] is source and call[4] is None for call in semantic)
    semantic_graphs = [graph for axis, _, graph in proposals if axis != "norms"]
    assert norms[0][2] == merge_graphs(source, *semantic_graphs)
    assert norms[0][3] == merge_graphs(cache, *semantic_graphs)
    assert norms[0][4] is evidence
    assert all(key == batch_key(axis, (ACTION,)) for axis, key, _ in proposals)


def test_closing_startup_stream_does_not_schedule_norms(caplog):
    service, calls = _startup_probe()
    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime.grounding.parallel"):
        stream = service.ground_stream(_source_graph())
        next(stream)
        stream.close()
    assert len(calls) == 1
    assert calls[0][0] != "norms"
    assert not any("completed" in record.getMessage() for record in caplog.records)


def test_closing_startup_stream_discards_pending_thread_result():
    import threading

    from cloud_dast.infrastructure.runtime.grounding_runner import (
        GroundingTaskStatus,
        ThreadedGroundingRunner,
    )
    from cloud_dast.runtime.grounding.results import AxisResult
    from cloud_dast.runtime.grounding.startup import Bootstrap

    started = threading.Event()
    release = threading.Event()
    calls = []

    class Runner(ThreadedGroundingRunner):
        def __init__(self):
            super().__init__()
            self.handles = []

        def start_task(self, task):
            handle = super().start_task(task)
            self.handles.append(handle)
            return handle

    def ground(axis, batch, graph, cache, evidence):
        calls.append(axis)
        if axis == "dataflows":
            started.set()
            assert release.wait(3), "test did not release the pending worker"
        return AxisResult(axis, graph, 0, len(batch))

    runner = Runner()

    class Probe(Bootstrap):
        def _ground_axis_batch(self, *args):
            return ground(*args)

    service = Probe(
        grounding_dispatcher=Mock(),
        batch_size=1,
        task_runner=runner,
        max_workers=2,
        axis_timeout=None,
    )
    stream = service.ground_stream(_source_graph())
    try:
        assert next(stream)[0] == "roles"
        assert started.wait(1)
        stream.close()
        assert runner.handles[1].status is GroundingTaskStatus.TIMED_OUT
        assert calls == ["roles", "dataflows"]
        release.set()
        with pytest.raises(TimeoutError, match="discarded after cancellation"):
            runner.handles[1].result(timeout=1)
    finally:
        release.set()
        stream.close()
        runner.close()


def test_startup_does_not_require_reactive_dispatch():
    client = OneResponseClient(_model_payload())
    startup = Bootstrap(
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    proposals = startup.ground_batches(_source_graph())
    assert proposals
    assert client.calls == 6


def test_reactive_does_not_require_startup_resources_or_validate_their_limits():
    client = OneResponseClient(_model_payload())
    reactive = Followup(
        consultation=ConsultationDispatcher(client),
        batch_size=0,
        max_workers=0,
        axis_timeout=0,
    )
    result = reactive.ground_reactive("roles", (ACTION,), _source_graph())
    assert result.axis == "roles"
    assert client.calls == 1


@pytest.mark.parametrize("contaminated", [False, True])
def test_cached_axis_result_keeps_integer_count_and_filter_issues(contaminated):
    from cloud_dast.qdl.graph import allowed
    from cloud_dast.runtime.grounding.axes.filtering import _filter_grounding_graph

    client = OneResponseClient(_model_payload())
    cache = MapCache()
    service = Bootstrap(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=cache,
        cache_namespace="test:model",
    )
    source = _source_graph()
    fresh = service._ground_axis_batch("roles", (ACTION,), source, source)
    assert isinstance(fresh.issue_count, int) and fresh.issue_count == 0
    calls = client.calls
    if contaminated:
        action = Atom(value=ACTION)
        effect = allowed(action)
        key, graph = next(iter(cache.values.items()))
        cache.values[key] = QdlGraph(
            facts=(
                *graph.facts,
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("is"),
                    args=(effect, Atom(value="Effect")),
                ),
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("requires"),
                    args=(action, effect),
                ),
            )
        )
    graph = next(iter(cache.values.values()))
    expected_graph, issues = _filter_grounding_graph("roles", graph, has_evidence=False)
    cached = service._ground_axis_batch("roles", (ACTION,), source, source)
    assert cached.cache_hit and cached.action_count == 1
    assert client.calls == calls
    assert cached.graph == expected_graph
    assert isinstance(cached.issue_count, int)
    assert cached.issue_count == len(issues)
    assert cached.issues == issues
    assert bool(issues) is contaminated
