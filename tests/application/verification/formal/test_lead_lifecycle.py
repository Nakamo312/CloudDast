"""S32R: lead lifecycle as belief revision."""

from __future__ import annotations

import json

from cloud_dast.consultation import (
    ConsultationBudget,
    ConsultationRequest,
    bind_consultation_telemetry,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    input_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.runtime.grounding.axis import Grounder
from cloud_dast.runtime.grounding.state import LeadLifecycle, evidence_signature
from cloud_dast.verification.promotion import (
    PromotionPolicy,
    lead_descriptor,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher

ACTION = "action:get"
DEFICIT_ID = "missing_role|action:get"


class FakeModelClient:
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
            model_id="consultation-model",
            input_tokens=120,
            cached_input_tokens=30,
            output_tokens=40,
        )


class InMemoryFormalRepository:
    def __init__(self) -> None:
        self.saved: list[dict] = []

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: dict,
        adapter_version: str,
        mapping_report: dict,
    ) -> None:
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id: str) -> QdlGraph:
        return next(
            (
                item["graph"]
                for item in reversed(self.saved)
                if item["source_id"] == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix: str) -> QdlGraph:
        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[object] = []

    def publish(self, event) -> None:
        self.events.append(event)


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.PROPOSAL,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _source_graph() -> QdlGraph:
    return QdlGraph(
        facts=(
            _fact("is", (Atom(value=ACTION), Atom(value="Action")), Context.CONTRACT),
        )
    )


def _classification_fact() -> Fact:
    action = Atom(value=ACTION)
    return _fact(
        "has",
        (input_field(action, Atom(value="secret_id")), Atom(value="sensitive")),
    )


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _sensitive_payload() -> dict:
    action = _atom(ACTION)
    field = {
        "kind": "struct",
        "name": "input_field",
        "args": [action, _atom("secret_id")],
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
                "args": [field, _atom("sensitive")],
            },
        ],
        "rules": [],
    }


def _request(**overrides) -> ConsultationRequest:
    defaults: dict = {
        "kind": "roles",
        "deficit_id": DEFICIT_ID,
        "action": ACTION,
        "slice": _source_graph(),
        "budget": ConsultationBudget(
            max_input_tokens=1024,
            max_output_tokens=512,
        ),
    }
    defaults.update(overrides)
    return ConsultationRequest(**defaults)


def _grounding(client: FakeModelClient) -> AutoGroundingService:
    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    return AutoGroundingService(
        repository,
        axis_grounding=Grounder(
            consultation=ConsultationDispatcher(client),
            grounding_dispatcher=Dispatcher(client),
        ),
        promotion_policy=PromotionPolicy(enabled=True),
    )


def test_lead_descriptor_projects_predicate_typed_roles() -> None:
    action = Atom(value=ACTION)
    holder = input_field(action, Atom(value="secret_id"))
    classification = _fact("has", (holder, Atom(value="sensitive")))
    flow = _fact("reaches", (holder, Atom(value="sink:interpreter")))

    classified = lead_descriptor(classification)
    reached = lead_descriptor(flow)

    assert classified is not None
    assert classified.action == ACTION
    assert classified.holder == canonical_json(holder)
    assert classified.role == json.dumps(
        ("has", canonical_json(Atom(value="sensitive"))),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert classified.fact_key == canonical_json(classification)
    assert classified.fact_hash == classification.content_hash
    assert reached is not None
    assert reached.action == ACTION
    assert reached.holder == classified.holder
    assert reached.role != classified.role


def test_lead_key_is_stable_and_revises_only_with_new_evidence() -> None:
    fact = _classification_fact()
    lifecycle = LeadLifecycle()

    first = lifecycle.record(fact, frozenset({"observation:first"}))
    repeat = lifecycle.record(fact, frozenset({"observation:first"}))
    vacuous = lifecycle.record(fact, frozenset())

    assert repeat is first
    assert vacuous is first
    assert first.lead_key == (
        first.action,
        first.holder,
        first.role,
        first.evidence_signature,
    )
    assert first.action == ACTION
    assert first.holder == canonical_json(fact.args[0])
    assert first.evidence_signature == evidence_signature(
        frozenset({"observation:first"})
    )
    assert first.confirmations == 1

    revised = lifecycle.record(fact, frozenset({"observation:second"}))

    assert revised is not first
    assert revised.lead_key[:3] == first.lead_key[:3]
    assert revised.evidence_signature != first.evidence_signature
    assert revised.evidence_refs == frozenset(
        {"observation:first", "observation:second"}
    )
    assert revised.confirmations == 2
    assert len(lifecycle.snapshot()) == 1


def test_lead_key_ignores_supporting_fact_shape() -> None:
    action = Atom(value=ACTION)
    classification = _classification_fact()
    lifecycle = LeadLifecycle()

    lifecycle.record_graph(
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action"))),
                _fact("is", (classification.args[0], Atom(value="Field"))),
                classification,
            )
        ),
        frozenset({"observation:first"}),
    )
    lifecycle.record_graph(
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action"))),
                _fact("is", (classification.args[0], Atom(value="InputField"))),
                classification,
            )
        ),
        frozenset({"observation:first"}),
    )

    leads = lifecycle.snapshot()

    assert len(leads) == 1
    assert leads[0].fact_key == canonical_json(classification)
    assert leads[0].evidence_signature == evidence_signature(
        frozenset({"observation:first"})
    )
    assert leads[0].confirmations == 1


def test_consultation_repeats_only_with_new_evidence() -> None:
    client = FakeModelClient(_sensitive_payload())
    grounding = _grounding(client)
    first_request = _request(observation_ids=("observation:one",))
    repeat_request = _request(observation_ids=("observation:one",))
    revised_request = _request(observation_ids=("observation:one", "observation:two"))

    first = grounding.ground_consultation("orders", first_request)
    after_first = grounding.parked_lead_states()
    repeat = grounding.ground_consultation("orders", repeat_request)
    assert grounding.parked_lead_states() == after_first
    revised = grounding.ground_consultation("orders", revised_request)

    assert first.outcome.status == "proposal"
    assert repeat.outcome.status == "unscoreable"
    assert "no new evidence" in repeat.outcome.reason
    assert revised.outcome.status == "proposal"
    assert len(client.requests) == 2

    leads = grounding.parked_lead_states()
    assert len(leads) == 1
    assert leads[0].evidence_refs == frozenset({"observation:one", "observation:two"})
    assert leads[0].confirmations == 2


def test_consultation_without_evidence_is_not_repeated() -> None:
    client = FakeModelClient(_sensitive_payload())
    grounding = _grounding(client)
    request = _request()

    first = grounding.ground_consultation("orders", request)
    repeat = grounding.ground_consultation("orders", request)

    assert first.outcome.status == "proposal"
    assert repeat.outcome.status == "unscoreable"
    assert "no new evidence" in repeat.outcome.reason
    assert len(client.requests) == 1
    leads = grounding.parked_lead_states()
    assert len(leads) == 1
    assert leads[0].evidence_signature == evidence_signature(frozenset())


def test_suppressed_consultation_publishes_skip_telemetry() -> None:
    client = FakeModelClient(_sensitive_payload())
    grounding = _grounding(client)
    publisher = RecordingPublisher()
    request = _request(observation_ids=("observation:one",))

    with bind_consultation_telemetry(publisher, deficit_id=DEFICIT_ID):
        grounding.ground_consultation("orders", request)
        grounding.ground_consultation("orders", request)

    skips = [
        event
        for event in publisher.events
        if getattr(event, "event_type", "") == "component_skipped"
    ]
    assert len(skips) == 1
    assert skips[0].component == "consultation:roles"
    assert skips[0].reason == "lead_preserved_without_new_evidence"
