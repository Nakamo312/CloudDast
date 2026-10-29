"""Typed consultation protocol: validation, budget, provenance, promotion."""

from __future__ import annotations

import json
from itertools import permutations

import pytest

from cloud_dast.consultation import (
    CONSULTATION_EVIDENCE_ROUTES,
    CONSULTATION_INSTRUCTIONS,
    CONSULTATION_PREDICATES,
    CONSULTATION_REQUIREMENT_CLASSES,
    ConsultationBudget,
    ConsultationOutcome,
    ConsultationProvenance,
    ConsultationRequest,
    EvidenceContext,
    axis_for_predicate_class,
    bind_consultation_telemetry,
    intersect_consultation_outcomes,
    intersect_grounded_proposals,
)
from cloud_dast.contracts.proposals import (
    FormalUncertainty,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    PREDICATE_SCHEMAS,
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import make_grounding

ACTION = "action:get"
DEFICIT_ID = "missing_role|action:get"


class FakeModelClient:
    def __init__(
        self,
        payload: dict,
        *,
        model_id: str = "consultation-model",
        input_tokens: int = 120,
        cached_input_tokens: int = 30,
        output_tokens: int = 40,
    ) -> None:
        self.payload = payload
        self.model_id = model_id
        self.input_tokens = input_tokens
        self.cached_input_tokens = cached_input_tokens
        self.output_tokens = output_tokens
        self.requests: list[ModelRequest] = []
        self.response_types = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        self.response_types.append(response_type)
        return ModelResponse(
            structured=self.payload,
            content=json.dumps(self.payload),
            model_id=self.model_id,
            input_tokens=self.input_tokens,
            cached_input_tokens=self.cached_input_tokens,
            output_tokens=self.output_tokens,
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
    """Minimal event publisher for telemetry-bound consultations."""

    def __init__(self) -> None:
        self.events = []

    def publish(self, event) -> None:
        self.events.append(event)


def _source_graph() -> QdlGraph:
    action = Atom(value=ACTION)
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
                args=(
                    Struct(name="input_field", args=(action, Atom(value="secret_id"))),
                    Atom(value="InputField"),
                ),
            ),
        )
    )


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _valid_roles_payload() -> dict:
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
                "args": [field, _atom("object_ref")],
            },
        ],
        "rules": [],
    }


def _invalid_payload() -> dict:
    return {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "definitely_not_a_predicate",
                "args": [_atom(ACTION)],
            }
        ],
        "rules": [],
    }


def _request(
    **overrides,
) -> ConsultationRequest:
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


def _seed_enrichment_request() -> ConsultationRequest:
    return ConsultationRequest(
        kind="seed_enrichment",
        deficit_id="payload_entropy|action:get|inv|scenario",
        action=ACTION,
        slice=_source_graph(),
        budget=ConsultationBudget(max_input_tokens=1024, max_output_tokens=512),
        context={
            "saturated_history": {
                "kind": "saturated_payload_history",
                "candidates": [],
                "witness_signals": [],
                "diff_pairs": [],
            }
        },
    )


def _valid_seed_enrichment_payload() -> dict:
    return {
        "context": "proposal",
        "productions": [],
        "slot_alternatives": [
            {
                "production_id": "sql-ansi",
                "slot_name": "terminator",
                "alternatives": ["\n"],
            }
        ],
        "uncertainties": [],
    }


def _grounded_proposal(*roles: str) -> QdlGraph:
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


def _outcome_proposal(graph: QdlGraph) -> ConsultationOutcome:
    return ConsultationOutcome(
        "proposal",
        graph,
        ConsultationProvenance(
            deficit_id=DEFICIT_ID,
            kind="roles",
            model_version="test-model",
            prompt_hash="prompt",
            graph_slice_hash="slice",
            input_tokens=1,
            cached_input_tokens=0,
            output_tokens=1,
            latency_ms=1.0,
            depth=0,
        ),
    )


def _outcome_unscoreable() -> ConsultationOutcome:
    return ConsultationOutcome(
        "unscoreable",
        None,
        ConsultationProvenance(
            deficit_id=DEFICIT_ID,
            kind="roles",
            model_version="test-model",
            prompt_hash="prompt",
            graph_slice_hash="slice",
            input_tokens=1,
            cached_input_tokens=0,
            output_tokens=1,
            latency_ms=1.0,
            depth=0,
        ),
        reason="empty model proposal",
    )


def test_dispatch_returns_schema_valid_proposal_with_full_provenance() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)
    request = _request()

    outcome = dispatcher.dispatch(request)

    assert outcome.status == "proposal"
    assert outcome.unscoreable is False
    assert outcome.proposal is not None and outcome.proposal.facts
    assert any(
        fact.predicate.name == "has" and fact.args[0].name == "input_field"
        for fact in outcome.proposal.facts
    )
    provenance = outcome.provenance
    assert provenance.model_version == "consultation-model"
    assert provenance.deficit_id == DEFICIT_ID
    assert provenance.kind == "roles"
    assert len(provenance.prompt_hash) == 64
    assert provenance.graph_slice_hash == request.slice.content_hash
    assert provenance.input_tokens == 120
    assert provenance.cached_input_tokens == 30
    assert provenance.output_tokens == 40
    assert provenance.latency_ms >= 0.0
    assert provenance.depth == 0


def test_dispatch_provenance_carries_work_item_identity() -> None:
    """S30: a coalesced call names its work item and every deficit id."""

    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)
    publisher = RecordingPublisher()
    work_item_id = "wi:missing_role:action:get:0123456789ab"
    deficit_ids = (
        "missing_role|action:get|secret_id",
        "missing_role|action:get|display_name",
    )

    with bind_consultation_telemetry(
        publisher,
        deficit_id=work_item_id,
        work_item_id=work_item_id,
        deficit_ids=deficit_ids,
    ):
        outcome = dispatcher.dispatch(_request())

    assert outcome.status == "proposal"
    assert outcome.provenance.work_item_id == work_item_id
    assert outcome.provenance.deficit_ids == deficit_ids
    assert any(
        event.invocation_id == f"consultation:{work_item_id}:0"
        for event in publisher.events
    )

    # Startup consultations without a bound work item keep the request's
    # own deficit id for traceability instead of inventing a work item.
    unbound = dispatcher.dispatch(_request())
    assert unbound.provenance.work_item_id == ""
    assert unbound.provenance.deficit_ids == (DEFICIT_ID,)


def test_dispatch_uses_the_closed_instruction_and_carries_the_budget() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    dispatcher.dispatch(_request())

    assert len(client.requests) == 1
    request = client.requests[0]
    assert request.task == "formal_grounding_roles"
    assert request.instruction == CONSULTATION_INSTRUCTIONS["roles"]
    assert request.budget is not None
    assert request.budget.max_input_tokens == 1024
    assert request.budget.max_output_tokens == 512
    assert request.context["graph"] == _request().slice.model_dump(mode="json")


def test_dataflows_instruction_requests_generic_sink_types() -> None:
    instruction = CONSULTATION_INSTRUCTIONS["dataflows"]

    assert "is(SinkId, interpreter)" in instruction
    assert "is(SinkId, filesystem)" in instruction
    assert "is(SinkId, business_flow)" in instruction
    assert "is(MarkerId, external_net)" in instruction


def test_dispatch_calls_the_model_exactly_once() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    dispatcher.dispatch(_request())

    assert len(client.requests) == 1


def test_dispatch_rejects_an_invalid_proposal() -> None:
    client = FakeModelClient(_invalid_payload())
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request())

    assert outcome.status == "unscoreable"
    assert outcome.unscoreable is True
    assert outcome.proposal is None
    assert outcome.reason == "proposal failed schema validation"
    assert outcome.issue_count > 0
    assert outcome.provenance.deficit_id == DEFICIT_ID
    assert outcome.provenance.model_version == "consultation-model"


def test_dispatch_rejects_an_unknown_kind_without_a_model_call() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)
    request = _request(kind="norms")  # type: ignore[arg-type]

    outcome = dispatcher.dispatch(request)

    assert outcome.status == "unscoreable"
    assert outcome.reason == "unknown consultation kind"
    assert outcome.proposal is None
    assert client.requests == []
    assert outcome.provenance.prompt_hash == ""
    assert outcome.provenance.graph_slice_hash == request.slice.content_hash


def test_dispatch_enforces_the_delegation_depth_budget() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    rejected = dispatcher.dispatch(_request(depth=3))

    assert rejected.status == "unscoreable"
    assert rejected.reason == "delegation depth exceeded"
    assert client.requests == []

    allowed = dispatcher.dispatch(_request(depth=2))

    assert allowed.status == "proposal"
    assert len(client.requests) == 1
    assert allowed.provenance.depth == 2

    shallower_budget = ConsultationBudget(
        max_input_tokens=1024,
        max_output_tokens=512,
        max_depth=1,
    )
    capped = dispatcher.dispatch(_request(depth=2, budget=shallower_budget))

    assert capped.status == "unscoreable"
    assert capped.reason == "delegation depth exceeded"
    assert len(client.requests) == 1


def test_dispatch_rejects_a_response_over_the_token_budget() -> None:
    from types import SimpleNamespace

    from cloud_dast.infrastructure.runtime.model import LangChainModelClient

    class Provider:
        def __init__(self):
            self.invocations = 0
            self.kwargs = {}

        def bind(self, **kwargs):
            self.kwargs.update(kwargs)
            return self

        def invoke(self, messages):
            self.invocations += 1
            return SimpleNamespace(
                content=json.dumps(_valid_roles_payload()),
                additional_kwargs={},
                usage_metadata={"input_tokens": 1024, "output_tokens": 513},
                response_metadata={},
            )

    provider = Provider()
    dispatcher = ConsultationDispatcher(LangChainModelClient(provider))
    outcome = dispatcher.dispatch(_request())

    assert outcome.status == "unscoreable"
    assert outcome.reason == "token budget exceeded"
    assert outcome.proposal is None
    assert outcome.provenance.output_tokens == 513
    assert provider.invocations == 1
    assert provider.kwargs["max_tokens"] == 512


def test_dispatch_rejects_an_invalid_budget_without_a_model_call() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="greater than 0"):
        dispatcher.dispatch(
            _request(
                budget=ConsultationBudget(max_input_tokens=0, max_output_tokens=512)
            )
        )
    assert client.requests == []


def test_dispatch_rejects_an_empty_graph_slice_without_a_model_call() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request(slice=QdlGraph()))

    assert outcome.status == "unscoreable"
    assert outcome.reason == "empty graph slice"
    assert client.requests == []


def test_dispatch_rejects_a_missing_deficit_id_without_a_model_call() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request(deficit_id=""))

    assert outcome.status == "unscoreable"
    assert outcome.reason == "missing deficit id"
    assert client.requests == []


def test_dispatch_drops_predicates_outside_the_consultation_kind() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            'is(input_field("action:get", "query"), "InputField")',
            'has(input_field("action:get", "query"), "object_ref")',
            'is("norm:out-of-scope", "Norm")',
            f'prevents("norm:out-of-scope", allowed("{ACTION}"))',
        ],
        "rules": [],
    }
    client = FakeModelClient(payload)
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request())

    assert outcome.status == "proposal"
    assert outcome.proposal is not None
    predicates = {fact.predicate.name for fact in outcome.proposal.facts}
    assert "has" in predicates
    assert "prevents" not in predicates
    assert outcome.issue_count >= 1


def test_dispatch_rejects_alternative_effects_outside_the_closed_alphabet() -> None:
    """Invented effect names are dropped before any promotion."""

    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            'is("resource:x", "Resource")',
            'is("read", "Effect")',
            f'requires("{ACTION}", "read")',
            'is(changed("resource:x", "state"), "Effect")',
            f'causes("{ACTION}", changed("resource:x", "state"))',
        ],
        "rules": [],
    }
    client = FakeModelClient(payload)
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request(kind="alternatives", action=ACTION))

    assert outcome.status == "proposal"
    assert outcome.proposal is not None
    assert not any(fact.predicate.name == "requires" for fact in outcome.proposal.facts)
    assert not any(
        fact.predicate.name == "is"
        and fact.args
        and getattr(fact.args[0], "value", None) == "read"
        for fact in outcome.proposal.facts
    )
    assert any(
        fact.predicate.name == "causes"
        and getattr(fact.args[1], "name", None) == "changed"
        for fact in outcome.proposal.facts
    )
    assert outcome.issue_count >= 2


def test_dispatch_rejects_alternative_natural_language_rules() -> None:
    """Natural-language rules are rejected with issues, never salvaged."""

    payload = {
        "context": "proposal",
        "facts": [
            f'is("{ACTION}", "Action")',
            'is("resource:x", "Resource")',
            'is(changed("resource:x", "state"), "Effect")',
            f'causes("{ACTION}", changed("resource:x", "state"))',
        ],
        "rules": ["an attacker may enumerate every resource"],
    }
    client = FakeModelClient(payload)
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request(kind="alternatives", action=ACTION))

    assert outcome.status == "proposal"
    assert outcome.issue_count >= 1
    assert outcome.proposal is not None
    assert outcome.proposal.rules == ()


def test_dispatch_rejects_an_empty_model_proposal() -> None:
    payload = {
        "context": "proposal",
        "facts": [],
        "rules": [],
    }
    client = FakeModelClient(payload)
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request())

    assert outcome.status == "unscoreable"
    assert outcome.proposal is None
    assert outcome.reason == "empty model proposal"
    assert outcome.provenance.model_version == "consultation-model"


def test_prompt_hash_is_deterministic_and_context_sensitive() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)

    first = dispatcher.dispatch(_request())
    second = dispatcher.dispatch(_request())
    changed = dispatcher.dispatch(
        _request(context={"blocked_step": {"reason": "not verified"}}),
    )

    assert first.provenance.prompt_hash == second.provenance.prompt_hash
    assert first.provenance.prompt_hash != changed.provenance.prompt_hash


def test_request_context_cannot_replace_the_graph_slice() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)
    request = _request(context={"graph": "forged-graph"})

    dispatcher.dispatch(request)

    model_request = client.requests[0]
    assert model_request.context["graph"] == request.slice.model_dump(mode="json")


def test_observation_context_flows_into_request_and_provenance() -> None:
    client = FakeModelClient(_valid_roles_payload())
    dispatcher = ConsultationDispatcher(client)
    request = _request(context={"observation_id": "observation:live"})
    paired = _request(
        context={
            "control": "observation:control",
            "treatment": "observation:treatment",
        }
    )

    outcome = dispatcher.dispatch(request)

    assert request.observation_ids == ("observation:live",)
    assert paired.observation_ids == (
        "observation:control",
        "observation:treatment",
    )
    assert outcome.observation_ids == ("observation:live",)
    assert outcome.provenance.observation_ids == ("observation:live",)


def test_dispatch_surfaces_model_uncertainties() -> None:
    payload = _valid_roles_payload()
    payload["uncertainties"] = [
        {"field": "query", "question": "need a live response example"}
    ]
    client = FakeModelClient(payload)
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch(_request())

    assert outcome.status == "proposal"
    assert outcome.uncertainties == (
        FormalUncertainty(field="query", question="need a live response example"),
    )


def test_ground_consultation_promotes_a_valid_proposal_deterministically() -> None:
    client = FakeModelClient(_valid_roles_payload())
    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    grounder_options_1 = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    grounding = make_grounding(
        repository,
        startup=Bootstrap(options=grounder_options_1),
        reactive=Followup(options=grounder_options_1),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    request = _request()

    result = grounding.consultation.run("orders", request)

    assert result.outcome.status == "proposal"
    assert result.promoted is not None and result.promoted.facts
    saved = repository.saved[-1]
    assert saved["source_id"] == (
        f"accepted-batch:orders:consultation:{DEFICIT_ID}:{saved['graph'].content_hash}"
    )
    assert saved["adapter_version"] == "consultation-v1"
    provenance = saved["provenance"]
    assert provenance["source_kind"] == "consultation"
    assert provenance["kind"] == "roles"
    assert provenance["deficit_id"] == DEFICIT_ID
    assert provenance["model_version"] == "consultation-model"
    assert provenance["prompt_hash"] == result.outcome.provenance.prompt_hash
    assert provenance["graph_slice_hash"] == result.outcome.provenance.graph_slice_hash
    assert provenance["input_tokens"] == 120
    assert provenance["output_tokens"] == 40
    assert provenance["latency_ms"] >= 0.0
    assert provenance["depth"] == 0


def test_ground_consultation_persists_observation_evidence_refs() -> None:
    client = FakeModelClient(_valid_roles_payload())
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
    request = _request(observation_ids=("observation:live",))

    result = grounding.consultation.run("orders", request)

    assert result.observation_ids == ("observation:live",)
    saved = repository.saved[-1]
    assert saved["provenance"]["evidence_refs"] == ["observation:live"]


def test_ground_consultation_rejects_an_invalid_proposal_without_promotion() -> None:
    client = FakeModelClient(_invalid_payload())
    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    grounder_options_3 = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    grounding = make_grounding(
        repository,
        startup=Bootstrap(options=grounder_options_3),
        reactive=Followup(options=grounder_options_3),
        promotion_policy=PromotionPolicy(enabled=True),
    )

    result = grounding.consultation.run("orders", _request())

    assert result.outcome.status == "unscoreable"
    assert result.outcome.reason == "proposal failed schema validation"
    assert result.promoted is None
    assert not [
        item
        for item in repository.saved
        if item["source_id"].startswith("accepted-batch:orders:consultation:")
    ]


def test_ground_consultation_without_reactive_capability_is_unscoreable() -> None:
    repository = InMemoryFormalRepository()
    grounding = make_grounding(repository)
    request = _request()

    result = grounding.consultation.run("orders", request)

    assert result.outcome.status == "unscoreable"
    assert result.outcome.reason == "reactive grounding is disabled"
    assert result.promoted is None
    assert result.outcome.provenance.deficit_id == DEFICIT_ID
    assert result.outcome.provenance.graph_slice_hash == request.slice.content_hash


def test_seed_enrichment_dispatch_returns_data_with_full_provenance() -> None:
    client = FakeModelClient(_valid_seed_enrichment_payload())
    dispatcher = ConsultationDispatcher(client)
    request = _seed_enrichment_request()

    outcome = dispatcher.dispatch_seed_enrichment(request)

    assert outcome.status == "proposal"
    assert outcome.proposal is not None
    assert outcome.proposal.slot_alternatives[0].production_id == "sql-ansi"
    assert outcome.proposal.slot_alternatives[0].alternatives == ("\n",)
    assert outcome.provenance.kind == "seed_enrichment"
    assert outcome.provenance.model_version == "consultation-model"
    assert outcome.provenance.prompt_hash
    assert outcome.provenance.graph_slice_hash == request.slice.content_hash
    assert client.requests[0].task == "payload_seed_enrichment"
    assert (
        client.requests[0].instruction == CONSULTATION_INSTRUCTIONS["seed_enrichment"]
    )
    assert "slot_alternatives" in str(client.response_types[0].model_json_schema())
    assert "saturated_history" in client.requests[0].context


def test_seed_enrichment_rejects_classification_and_strategy_channels() -> None:
    client = FakeModelClient(
        {
            "context": "proposal",
            "facts": ['has(input_field("action:get", "query"), sensitive)'],
            "strategy": "return st.just('endpoint-specific-payload')",
            "slot_alternatives": [],
        }
    )
    dispatcher = ConsultationDispatcher(client)

    outcome = dispatcher.dispatch_seed_enrichment(_seed_enrichment_request())

    assert outcome.status == "unscoreable"
    assert outcome.proposal is None
    assert outcome.reason == "payload proposal failed schema validation"


def test_predicate_class_axis_is_total_over_qdl_predicates() -> None:
    """S21R: every QDL class has an axis image or a typed absence."""

    predicate_classes = {
        *(schema.name for schema in PREDICATE_SCHEMAS),
        *(schema.name for schema in EXTENSION_PREDICATE_SCHEMAS),
        # The QDL predicate universe is open: a future extension schema
        # must route to a deficit, never raise.
        "future_extension_predicate",
    }
    evidence_contexts = (
        EvidenceContext(),
        EvidenceContext(live_response=True),
        EvidenceContext(effect_constructor="duration"),
        EvidenceContext(effect_constructor="create"),
        EvidenceContext(effect_constructor="remove"),
        EvidenceContext(live_response=True, effect_constructor="create"),
    )

    images: set[str] = set()
    for predicate_class in predicate_classes:
        for evidence in evidence_contexts:
            axis = axis_for_predicate_class(predicate_class, evidence)
            assert axis is None or axis in CONSULTATION_PREDICATES
            if axis is not None:
                images.add(axis)

    assert images <= set(CONSULTATION_PREDICATES)


def test_axis_image_is_closable_by_its_consultation() -> None:
    """Every routed class lies inside the axis's proposal alphabet.

    A route whose axis cannot author the missing predicate would be a
    false image: the consultation could never close the deficit.
    """

    for kind, classes in CONSULTATION_REQUIREMENT_CLASSES.items():
        for predicate_class in classes:
            assert predicate_class in CONSULTATION_PREDICATES[kind]

    for _channel, predicate_class, kind in CONSULTATION_EVIDENCE_ROUTES:
        assert predicate_class in CONSULTATION_PREDICATES[kind]


def test_predicate_classes_have_at_most_one_default_image() -> None:
    """The default route is a partial function, never a coin flip."""

    images: dict[str, str] = {}
    for kind, classes in CONSULTATION_REQUIREMENT_CLASSES.items():
        for predicate_class in classes:
            previous = images.setdefault(predicate_class, kind)
            assert previous == kind


@pytest.mark.parametrize(
    ("predicate_class", "evidence", "expected_axis"),
    [
        ("refers_to", EvidenceContext(), "fixture"),
        ("reaches", EvidenceContext(), "dataflows"),
        ("causes", EvidenceContext(), "alternatives"),
        ("causes", EvidenceContext(effect_constructor="duration"), "availability"),
        ("causes", EvidenceContext(effect_constructor="create"), "fixture"),
        ("causes", EvidenceContext(effect_constructor="remove"), "dataflows"),
        ("transition", EvidenceContext(), "state"),
        ("has", EvidenceContext(), "roles"),
        ("exposes", EvidenceContext(), "exposures"),
        ("exposes", EvidenceContext(live_response=True), "response_semantics"),
        ("prevents", EvidenceContext(), "variance"),
        ("may", EvidenceContext(), None),
        ("sink_interprets", EvidenceContext(), None),
    ],
)
def test_axis_routing_by_class_and_evidence_context(
    predicate_class: str,
    evidence: EvidenceContext,
    expected_axis: str | None,
) -> None:
    """f(class, evidence) is deterministic and grammar-addressed only."""

    assert axis_for_predicate_class(predicate_class, evidence) == expected_axis
    assert axis_for_predicate_class(predicate_class, evidence) == expected_axis


def test_intersection_keeps_only_canonical_common_grounded_facts() -> None:
    """Only facts present in every comparable grounded proposal survive."""

    first = _grounded_proposal("object_ref", "payload")
    second = _grounded_proposal("object_ref", "credential")
    expected = _grounded_proposal("object_ref")

    assert intersect_grounded_proposals((first, second)) == expected
    assert intersect_grounded_proposals((first,)) == first
    assert intersect_grounded_proposals((first, first)) == first


def test_intersection_returns_the_empty_graph_for_an_empty_intersection() -> None:
    """No common fact means no accepted fact; empty input is not the universe."""

    first = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=ACTION), Atom(value="Action")),
            ),
        )
    )
    second = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:other"), Atom(value="Action")),
            ),
        )
    )

    assert intersect_grounded_proposals(()) == QdlGraph()
    assert intersect_grounded_proposals((first, second)) == QdlGraph()
    assert intersect_grounded_proposals((first, QdlGraph())) == QdlGraph()
    assert (
        intersect_consultation_outcomes(
            (_outcome_proposal(first), _outcome_unscoreable())
        )
        == QdlGraph()
    )


def test_intersection_is_independent_of_proposal_order() -> None:
    """Intersection is commutative and duplicates cannot change the result."""

    proposals = (
        _grounded_proposal("object_ref", "payload"),
        _grounded_proposal("object_ref"),
        _grounded_proposal("object_ref", "credential"),
    )
    expected = _grounded_proposal("object_ref")
    results = {
        intersect_grounded_proposals(order).content_hash
        for order in permutations(proposals)
    }

    assert len(results) == 1
    assert intersect_grounded_proposals((*proposals, proposals[0])) == expected


def test_native_structured_response_is_not_reparsed_as_content():
    from types import SimpleNamespace

    from cloud_dast.infrastructure.runtime.model import LangChainModelClient

    class NativeModel:
        def bind(self, **kwargs):
            return self

        def invoke(self, messages):
            return SimpleNamespace(
                content="diagnostic text is not the structured proposal",
                additional_kwargs={"parsed": _valid_roles_payload()},
                usage_metadata={"input_tokens": 120, "output_tokens": 40},
                response_metadata={},
            )

    outcome = ConsultationDispatcher(LangChainModelClient(NativeModel())).dispatch(
        _request()
    )
    assert outcome.status == "proposal"
    assert outcome.proposal is not None


@pytest.mark.parametrize("save_fails", [False, True])
def test_consultation_returns_saved_supersession_revision(save_fails, monkeypatch):
    repository = InMemoryFormalRepository()
    grounding = make_grounding(repository)
    action = Atom(value=ACTION)
    holder = Struct(name="input_field", args=(action, Atom(value="token")))
    declaration = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("is"),
        args=(holder, Atom(value="InputField")),
    )

    def revision(role):
        return QdlGraph(
            facts=(
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(action, Atom(value="Action")),
                ),
                declaration,
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("has"),
                    args=(holder, Atom(value=role)),
                ),
            )
        )

    previous, promoted = revision("setup_value"), revision("setup_skip")
    request = _request(observation_ids=("obs:z", "obs:a"))
    outcome = _outcome_proposal(promoted)
    original_save = repository.save

    def save(*args, **kwargs):
        if save_fails:
            raise RuntimeError("repository unavailable")
        original_save(*args, **kwargs)

    monkeypatch.setattr(repository, "save", save)

    def persist():
        return grounding.consultation._save(
            "orders",
            previous,
            request,
            outcome,
            promoted,
            evidence_refs=frozenset(request.observation_ids),
        )

    if save_fails:
        with pytest.raises(RuntimeError, match="repository unavailable"):
            persist()
        assert repository.saved == []
        return
    result = persist()
    saved = repository.saved[0]
    assert any(f.predicate.name == "supersedes" for f in saved["graph"].facts)
    assert result.outcome is outcome
    assert result.promoted == saved["graph"]
    assert result.promoted is saved["graph"]
    assert (
        saved["source_id"]
        == f"accepted-batch:orders:consultation:{DEFICIT_ID}:{result.promoted.content_hash}"
    )
    assert saved["mapping_report"] == {
        "mapped": len(result.promoted.facts),
        "unmapped": 0,
    }
    assert saved["adapter_version"] == "consultation-v1"
    assert saved["provenance"] == {
        "source_kind": "consultation",
        "kind": request.kind,
        "deficit_id": DEFICIT_ID,
        "model_version": outcome.provenance.model_version,
        "prompt_hash": outcome.provenance.prompt_hash,
        "graph_slice_hash": outcome.provenance.graph_slice_hash,
        "input_tokens": 1,
        "cached_input_tokens": 0,
        "output_tokens": 1,
        "latency_ms": 1.0,
        "depth": 0,
        "evidence_refs": ["obs:a", "obs:z"],
    }
    assert len(promoted.facts) == 3
