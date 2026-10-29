from __future__ import annotations

import json
import threading

import pytest

from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
    ResponseData,
)
from cloud_dast.ports import (
    EvidenceEvent,
    GroundingBatch,
    ModelRequest,
    ModelResponse,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, Struct
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import commit_branch, make_grounding

ACTION = "action:get"


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


class RecordingCache:
    def __init__(self) -> None:
        self.loads = 0
        self.saves = 0

    def load(self, key: str) -> QdlGraph | None:
        self.loads += 1
        return None

    def save(self, key: str, graph: QdlGraph) -> None:
        self.saves += 1


class InMemoryFormalRepository:
    def __init__(self) -> None:
        self.graphs: dict[str, QdlGraph] = {}

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: dict,
        adapter_version: str,
        mapping_report: dict,
    ) -> None:
        self.graphs[source_id] = graph

    def load(self, source_id: str) -> QdlGraph:
        return self.graphs.get(source_id, QdlGraph())

    def load_merged(self, source_prefix: str) -> QdlGraph:
        merged = QdlGraph()
        for source_id, graph in self.graphs.items():
            if source_id.startswith(source_prefix):
                merged = merge_graphs(merged, graph)
        return merged


class RecordingStartupAxisGrounding:
    def __init__(self) -> None:
        self.sources: list[QdlGraph] = []
        self.cache_sources: list[QdlGraph] = []

    def ground_stream(self, source, *, cache_source=None):
        self.sources.append(source)
        self.cache_sources.append(cache_source or source)
        return
        yield  # pragma: no cover - empty stream

    def ground_batches(self, source, *, cache_source=None):
        self.sources.append(source)
        self.cache_sources.append(cache_source or source)
        return ()


class ScriptedStartupAxisGrounding:
    """Fake startup grounding that yields a fixed batch list."""

    def __init__(self, batches):
        self._batches = batches

    def ground_stream(self, source, *, cache_source=None):
        yield from self._batches

    def ground_reactive(self, axis, action_ids, graph, **kwargs):
        from cloud_dast.runtime.grounding.results import AxisResult

        return AxisResult(axis, None, 0, len(action_ids))


def _source_graph() -> QdlGraph:
    action = Atom(value=ACTION)
    sibling = Atom(value="action:put")
    resource = Atom(value="resource:thing")
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


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _model_payload() -> dict:
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


def _response_semantics_payload(
    action: str = ACTION, field_name: str = "email"
) -> dict:
    return {
        "context": "proposal",
        "facts": [
            f'is("{action}", "Action")',
            'is("resource:user", "Resource")',
            f'is(field("resource:user", "{field_name}"), "Witness")',
            f'exposes("{action}", field("resource:user", "{field_name}"))',
            f'is(output_field("{action}", "{field_name}"), "Field")',
            f'has(output_field("{action}", "{field_name}"), "sensitive")',
            'is("norm:out-of-scope", "Norm")',
            f'prevents("norm:out-of-scope", allowed("{action}"))',
        ],
        "rules": [],
    }


def _observation() -> Observation:
    return Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="blocked at the blind link",
        output=ResponseData(
            fields=(
                ("error", "insufficient permissions"),
                ("request_id", 404),
            )
        ),
    )


def test_ground_reactive_returns_graph_from_model_response() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    result = service.ground_reactive("roles", (ACTION,), _source_graph())

    assert result.axis == "roles"
    assert result.graph is not None
    assert any(
        fact.predicate.name == "has" and fact.args[0].name == "input_field"
        for fact in result.graph.facts
    )
    assert result.issue_count == 0
    assert result.action_count == 1
    assert result.cache_hit is False


def test_ground_reactive_uses_only_evidence_view_for_live_observation() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    service.ground_reactive(
        "roles",
        (ACTION,),
        _source_graph(),
        observation=_observation(),
    )

    assert len(client.requests) == 1
    request = client.requests[0]
    assert request.task == "formal_grounding_roles"
    assert "Classify every input and output field" in request.instruction
    assert ACTION in json.dumps(request.context["graph"])
    assert set(request.context) == {"graph", "evidence"}
    assert "live_observation" not in request.context
    evidence = request.context["evidence"]
    assert evidence["response_summary"]["evidence_encoding"] == "redacted"
    assert "blocked at the blind link" not in json.dumps(evidence)
    assert [leaf["path"] for leaf in evidence["response"]["leaves"]] == [
        "error",
        "request_id",
    ]
    assert all(
        leaf["value"]["evidence_encoding"] == "redacted"
        for leaf in evidence["response"]["leaves"]
    )


def test_ground_reactive_puts_structured_evidence_into_prompt() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
    check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=(("query", "attacker-canary"),),
        identities=("attacker",),
        probe_marker="marker-1",
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="blocked",
        transport_status=HttpStatus(code=403),
        error_reason="permission denied",
        probe_marker="marker-1",
        response_tree=(("nested.token", "tok-full-fidelity"),),
    )

    service.ground_reactive(
        "roles",
        (ACTION,),
        _source_graph(),
        observation=observation,
        check=check,
        oob_events=(
            EvidenceEvent(channel="oob", correlation_id="marker-1", source="10.0.0.8"),
            EvidenceEvent(channel="oob", correlation_id="other"),
        ),
    )

    evidence = client.requests[0].context["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["request"]["values"][0]["name"] == "query"
    assert evidence["request"]["values"][0]["value"]["evidence_encoding"] == "redacted"
    assert evidence["response"]["leaves"][0]["path"] == "nested.token"
    assert evidence["response"]["leaves"][0]["value"]["evidence_encoding"] == "redacted"
    assert evidence["error_reason"]["evidence_encoding"] == "redacted"
    assert "permission denied" not in json.dumps(evidence)
    assert evidence["oob"]["events"][0]["source"]["evidence_encoding"] == "redacted"
    rendered = json.dumps(evidence, ensure_ascii=False)
    assert "attacker-canary" not in rendered
    assert "tok-full-fidelity" not in rendered
    assert "10.0.0.8" not in rendered


def test_response_semantics_axis_asks_for_generic_facts_with_evidence() -> None:
    client = FakeModelClient(_response_semantics_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )
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
    check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=(("user_id", "user-1"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        transport_status=HttpStatus(code=200),
        response_tree=(("email", "user-1@example.test"),),
    )

    result = service.ground_reactive(
        "response_semantics",
        (ACTION,),
        source,
        observation=observation,
        check=check,
    )

    request = client.requests[0]
    assert request.task == "formal_grounding_response_semantics"
    assert "exposes(Action, field(ResourceId, Field))" in request.instruction
    assert "has(output_field(Action, Field), Role)" in request.instruction
    assert "Do not emit security norms, verdicts, findings" in request.instruction
    assert "prevents(" not in request.instruction
    evidence_leaf = request.context["evidence"]["response"]["leaves"][0]
    assert evidence_leaf["path"] == "email"
    assert evidence_leaf["value"]["evidence_encoding"] == "redacted"
    assert result.graph is not None
    predicates = {fact.predicate.name for fact in result.graph.facts}
    assert predicates <= {"is", "exposes", "has"}
    assert "prevents" not in predicates
    assert any(fact.predicate.name == "exposes" for fact in result.graph.facts)
    assert any(
        fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and fact.args[1].value == "sensitive"
        for fact in result.graph.facts
    )


def test_ground_reactive_without_observation_omits_live_context() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    service.ground_reactive("roles", (ACTION,), _source_graph())

    assert len(client.requests) == 1
    request = client.requests[0]
    assert "live_observation" not in request.context
    assert "Live observation from the blocked step" not in json.dumps(
        request.context, ensure_ascii=False
    )


def test_ground_reactive_invalid_response_reports_issues() -> None:
    payload = {
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
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    result = service.ground_reactive("roles", (ACTION,), _source_graph())

    assert result.axis == "roles"
    assert result.graph is None
    assert result.issue_count > 0
    assert result.action_count == 1


def test_ground_reactive_does_not_use_cache() -> None:
    client = FakeModelClient(_model_payload())
    cache = RecordingCache()
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
        cache=cache,
        cache_namespace="test:reactive",
    )
    source = _source_graph()

    first = service.ground_reactive("roles", (ACTION,), source)
    second = service.ground_reactive("roles", (ACTION,), source)

    assert len(client.requests) == 2
    assert cache.loads == 0
    assert cache.saves == 0
    assert first.cache_hit is False
    assert second.cache_hit is False
    assert first.graph is not None
    assert second.graph is not None


def test_ground_reactive_without_graph_actions_returns_empty_result() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    result = service.ground_reactive("roles", ("action:missing",), _source_graph())

    assert result.axis == "roles"
    assert result.graph is None
    assert result.issue_count == 0
    assert result.action_count == 0
    assert client.requests == []


def test_reactive_call_surfaces_model_uncertainties() -> None:
    payload = _model_payload()
    payload["uncertainties"] = [
        {"field": "query", "question": "need a live response example"}
    ]
    client = FakeModelClient(payload)
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
        output=ResponseData(fields=(("query", "summary"),)),
    )

    result = service.ground_reactive(
        "roles",
        (ACTION,),
        _source_graph(),
        observation=observation,
    )

    assert result.graph is not None and result.graph.facts
    assert result.uncertainties == (("query", "need a live response example"),)


def test_branch_uncertainties_are_never_replayed() -> None:
    client = FakeModelClient(_model_payload())
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
    question = {"field": "query", "question": "need a live response example"}

    client.payload["uncertainties"] = [question]
    commit_branch(grounding, "orders", ACTION)
    assert "prior_uncertainties" not in client.requests[0].context

    client.payload = dict(_model_payload())
    commit_branch(grounding, "orders", ACTION)
    assert "prior_uncertainties" not in client.requests[1].context
    assert client.requests[1].context["sibling_actions"]

    commit_branch(grounding, "orders", ACTION)
    assert "prior_uncertainties" not in client.requests[2].context


def test_reactive_call_resolves_plain_method_id_alias() -> None:
    """A deficit action in method-id form must slice the action: graph."""

    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )

    result = service.ground_reactive(
        "roles",
        ("get",),  # graph declares "action:get", deficit carries plain id
        _source_graph(),
    )

    assert result.graph is not None and result.graph.facts
    assert len(client.requests) == 1


def test_ground_variance_puts_full_pair_evidence_into_prompt() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    control_check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="control",
        request=(("query", "benign"),),
        identities=("attacker",),
    )
    treatment_check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="treatment",
        request=(("query", "canary"),),
        identities=("attacker",),
    )
    control = Observation(
        check_id="control",
        scenario_id="control",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("email", "alice@example.com"),),
    )
    treatment = Observation(
        check_id="treatment",
        scenario_id="treatment",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(
            ("email", "bob@example.com"),
            ("payment_token", "tok_123"),
        ),
    )
    report = DiffReport(
        action_id="get",
        control_observation_id="control",
        treatment_observation_id="treatment",
        fields_only_treatment=("payment_token",),
        value_differs=("email",),
    )

    service.ground_variance(
        _source_graph(),
        "get",
        control=control,
        treatment=treatment,
        report=report,
        control_check=control_check,
        treatment_check=treatment_check,
    )

    evidence = client.requests[0].context["evidence"]
    assert evidence["control"]["request"]["values"][0]["value"][
        "evidence_encoding"
    ] == ("redacted")
    assert (
        evidence["treatment"]["request"]["values"][0]["value"]["evidence_encoding"]
        == "redacted"
    )
    assert evidence["diff"]["value_differs"][0]["path"] == "email"
    assert (
        evidence["diff"]["value_differs"][0]["control_value"]["evidence_encoding"]
        == "redacted"
    )
    assert (
        evidence["diff"]["value_differs"][0]["treatment_value"]["evidence_encoding"]
        == "redacted"
    )
    assert evidence["diff"]["fields_only_treatment"][0]["path"] == "payment_token"
    assert (
        evidence["diff"]["fields_only_treatment"][0]["treatment_value"][
            "evidence_encoding"
        ]
        == "redacted"
    )


def test_ground_alternatives_uses_evidence_instead_of_safe_field_whitelist() -> None:
    client = FakeModelClient(_model_payload())
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
    )
    check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=(("query", "retry-canary"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="blocked",
        output=ResponseData(fields=(("safe", "sanitized"),)),
        response_tree=(("safe", "sanitized"), ("nested.reason", "full reason")),
    )

    service.ground_alternatives(
        _source_graph(),
        ACTION.removeprefix("action:"),
        observation=observation,
        check=check,
        blocked_reason="chain blocked",
    )

    evidence = client.requests[0].context["evidence"]
    assert evidence["request"]["values"][0]["name"] == "query"
    assert evidence["request"]["values"][0]["value"]["evidence_encoding"] == "redacted"
    assert [leaf["path"] for leaf in evidence["response"]["leaves"]] == [
        "safe",
        "nested.reason",
    ]
    assert evidence["response"]["safe_fields"][0]["path"] == "safe"
    assert (
        evidence["response"]["safe_fields"][0]["value"]["evidence_encoding"]
        == "redacted"
    )
    assert evidence["response"]["leaves"][1]["value"]["evidence_encoding"] == "redacted"


def test_auto_grounding_passes_check_evidence_through_branch_batch() -> None:
    client = FakeModelClient(_model_payload())
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
    check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=(("query", "wrapper-canary"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="blocked",
        response_tree=(("error", "full error"),),
    )

    commit_branch(
        grounding,
        "orders",
        ACTION.removeprefix("action:"),
        observation=observation,
        check=check,
    )

    evidence = client.requests[0].context["evidence"]
    assert evidence["request"]["values"][0]["name"] == "query"
    assert evidence["request"]["values"][0]["value"]["evidence_encoding"] == "redacted"
    assert evidence["response"]["leaves"][0]["path"] == "error"
    assert evidence["response"]["leaves"][0]["value"]["evidence_encoding"] == "redacted"


def test_startup_grounding_sees_accepted_and_diff_sources() -> None:
    repository = InMemoryFormalRepository()
    contract = _source_graph()
    accepted_batch = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="accepted-batch"), Atom(value="ResourceType")),
            ),
        )
    )
    diff = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="diff"), Atom(value="ResourceType")),
            ),
        )
    )
    for source_id, graph in (
        ("contract:orders", contract),
        ("accepted-batch:orders:roles:test", accepted_batch),
        ("diff:orders:campaign", diff),
    ):
        repository.save(
            source_id,
            graph,
            provenance={"source_kind": "test"},
            adapter_version="test-v1",
            mapping_report={"mapped": len(graph.facts), "unmapped": 0},
        )

    axis_grounding = RecordingStartupAxisGrounding()
    grounding = make_grounding(
        repository, startup=axis_grounding, reactive=axis_grounding
    )
    expected = merge_graphs(contract, accepted_batch, diff)

    handle = grounding.lifecycle.start_grounded("orders", ThreadedGroundingRunner())
    assert handle is not None
    assert handle.wait_batch(timeout=1) is None

    assert len(axis_grounding.sources) == 1
    assert all(
        source.content_hash == expected.content_hash
        for source in axis_grounding.sources
    )


def test_staged_stream_skips_axis_that_never_returns() -> None:
    """One hung axis must not block the remaining grounding batches."""

    class OmitFirstTaskRunner(ThreadedGroundingRunner):
        def __init__(self) -> None:
            super().__init__()
            self.first = True

        def run_tasks(self, tasks, *, max_workers, timeout):
            del max_workers, timeout
            for index, task in enumerate(tasks):
                if self.first and index == 0:
                    self.first = False
                    continue
                yield index, task()

    service = Bootstrap(
        consultation=ConsultationDispatcher(
            grounding_client := FakeModelClient(_model_payload())
        ),
        grounding_dispatcher=Dispatcher(grounding_client),
        batch_size=1,
        max_workers=2,
        axis_timeout=0.2,
        task_runner=OmitFirstTaskRunner(),
    )

    single_action = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=ACTION), Atom(value="Action")),
            ),
        )
    )

    proposals = list(service.ground_stream(single_action))

    axes = {axis for axis, _, _ in proposals}
    # The hung semantic axis was abandoned; every other semantic axis and
    # the norms phase still completed and yielded their proposals.
    assert "roles" not in axes
    assert {"dataflows", "exposures", "authentication", "availability"} <= axes
    assert "norms" in axes


def test_start_grounded_isolates_repository_save_failures() -> None:
    """A batch that fails to persist must not abort the remaining batches."""

    class FailingSaveRepository(InMemoryFormalRepository):
        def __init__(self) -> None:
            super().__init__()
            self.failed_saves: list[str] = []

        def save(
            self,
            source_id: str,
            graph: QdlGraph,
            *,
            provenance: dict,
            adapter_version: str,
            mapping_report: dict,
        ) -> None:
            if source_id.startswith("accepted-batch:orders:roles:"):
                self.failed_saves.append(source_id)
                raise RuntimeError("repository exploded")
            super().save(
                source_id,
                graph,
                provenance=provenance,
                adapter_version=adapter_version,
                mapping_report=mapping_report,
            )

    repository = FailingSaveRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    action = Atom(value=ACTION)
    field = Struct(name="input_field", args=(action, Atom(value="secret_id")))
    norm_graph = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="norm:test"), Atom(value="Norm")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:test"),
                    Struct(name="allowed", args=(action,)),
                ),
            ),
        )
    )
    role_graph = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(field, Atom(value="Field")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(field, Atom(value="object_ref")),
            ),
        )
    )
    grounding_component_3 = ScriptedStartupAxisGrounding(
        (("roles", "b0", role_graph), ("norms", "b1", norm_graph))
    )
    grounding = make_grounding(
        repository,
        startup=grounding_component_3,
        reactive=grounding_component_3,
        promotion_policy=PromotionPolicy(enabled=True),
    )

    handle = grounding.lifecycle.start_grounded("orders", ThreadedGroundingRunner())
    assert handle is not None
    # The good norms batch is still promoted and published after the roles
    # batch failed to persist.
    assert handle.wait_batch(timeout=5) == GroundingBatch(
        axis="norms",
        batch_key="b1",
        fact_count=len(norm_graph.facts),
    )
    assert handle.wait_batch(timeout=5) is None
    assert handle.error is None
    assert len(repository.failed_saves) == 1
    assert repository.failed_saves[0].startswith("accepted-batch:orders:roles:b0:")
    assert any(
        source_id.startswith("accepted-batch:orders:norms:b1:")
        for source_id in repository.graphs
    )


def test_start_grounded_finishes_before_slow_formal_proposal() -> None:
    """A slow formal proposal must not keep the grounding handle open.

    The finish sentinel is the campaign's grounding fixed point and covers
    the axis stream only.  Even with a formal timeout far beyond the test
    wait, the sentinel arrives while the formal task is still running.
    """

    release = threading.Event()

    class SlowFormalGrounder:
        def prepare(self, service: str):
            release.wait(timeout=30)
            return None

    repository = InMemoryFormalRepository()
    repository.save(
        "contract:orders",
        _source_graph(),
        provenance={"source_kind": "contract"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 1, "unmapped": 0},
    )
    grounding_component_4 = RecordingStartupAxisGrounding()
    grounding = make_grounding(
        repository,
        startup=grounding_component_4,
        reactive=grounding_component_4,
        formal_grounder=SlowFormalGrounder(),
        formal_timeout=30.0,
        promotion_policy=PromotionPolicy(enabled=True),
    )

    try:
        handle = grounding.lifecycle.start_grounded("orders", ThreadedGroundingRunner())
        assert handle is not None
        assert handle.wait_batch(timeout=5) is None
        assert handle.error is None
        assert handle.enrichment_status == "pending"
    finally:
        release.set()


@pytest.mark.parametrize("startup_enabled", [False, True])
@pytest.mark.parametrize("reactive_enabled", [False, True])
@pytest.mark.parametrize("skip", [False, True])
def test_service_uses_startup_and_reactive_capabilities_independently(
    startup_enabled,
    reactive_enabled,
    skip,
):
    from cloud_dast.runtime.grounding.results import AxisResult

    calls = []
    proposal = AxisResult("roles", QdlGraph(), 0, 1)

    class Startup:
        def ground_stream(self, source, *, cache_source=None):
            calls.append("startup")
            return
            yield

    class Reactive:
        def ground_reactive(self, axis, action_ids, source, **values):
            calls.append("reactive")
            return proposal

    repository = InMemoryFormalRepository()
    repository.graphs["contract:orders"] = _source_graph()
    service = make_grounding(
        repository,
        startup=Startup() if startup_enabled else None,
        reactive=Reactive() if reactive_enabled else None,
        skip_llm_grounding=skip,
    )
    runner = ThreadedGroundingRunner()
    try:
        handle = service.lifecycle.start_grounded("orders", runner)
        if startup_enabled and not skip:
            assert handle is not None
            assert handle.wait_batch(timeout=1) is None
        else:
            assert handle is None
        result = service.batches.prepare_reactive(_source_graph(), "roles", (ACTION,))
        assert service.batches.reactive_capable == (reactive_enabled and not skip)
        assert result is (proposal if reactive_enabled and not skip else None)
        assert calls == (["startup"] if startup_enabled and not skip else []) + (
            ["reactive"] if reactive_enabled and not skip else []
        )
    finally:
        runner.close()
