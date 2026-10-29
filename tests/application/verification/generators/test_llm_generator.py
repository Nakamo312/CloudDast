from __future__ import annotations

import json
import logging

import pytest

from cloud_dast.candidates import TemplateGenerator
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    Severity,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    external_call,
    input_field,
    reached,
)
from cloud_dast.verification.slices import SliceBudget
from cloud_dast_fuzzing.strategies.goal_payload import (
    OOB_URL_PLACEHOLDER,
    PROBE_MARKER_PLACEHOLDER,
)
from cloud_dast_llm.generator import LlmGenerator


class FakeModelClient:
    def __init__(self, payload: object) -> None:
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
            content="{}",
            model_id="fake-model",
            request_id=request.request_id,
        )


class FailingModelClient:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.calls += 1
        raise self.error


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="example.Get",
        service="example",
        name="Get",
        layer=EndpointLayer.PUBLIC,
        fields=(
            FieldSpec(name="resource_id", type="string", required=True),
            FieldSpec(name="value", type="string"),
            FieldSpec(name="tags", type="string", repeated=True),
        ),
    )


def _scenario() -> ScenarioPosition:
    from cloud_dast.model import ScenarioProfile, ScopeRelation, StandState

    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _binding():
    method = _method()
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="target norm",
        severity=Severity.MEDIUM,
    )
    plan = VerificationPlan(
        plan_id="plan",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id="scenario",
    )
    return method, plan, invariant, _scenario()


def _norm_invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="target norm",
        severity=Severity.MEDIUM,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:inv"), effect),
        ),
    )


def test_llm_generator_uses_model_values_and_filters_unknown_fields() -> None:
    method, plan, invariant, scenario = _binding()
    client = FakeModelClient(
        {
            "checks": [
                {
                    "request": {
                        "resource_id": "model-resource",
                        "value": "model-value",
                        "unknown": "ignored",
                    },
                    "rationale": "schema-valid alternative",
                }
            ]
        }
    )

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert len(checks) == 1
    assert checks[0].generator == "llm"
    request = dict(checks[0].request)
    assert request["resource_id"] == "model-resource"
    assert request["value"] == "model-value"
    assert "unknown" not in request
    assert client.requests[0].task == "generate_test_case"
    assert "vulnerability catalogue" in client.requests[0].instruction


def test_llm_generator_omits_runtime_placeholders_for_non_marker_norm() -> None:
    method, plan, invariant, scenario = _binding()
    client = FakeModelClient(
        {"checks": [{"request": {"value": "model-value"}, "rationale": ""}]}
    )

    LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    request = client.requests[0]
    assert PROBE_MARKER_PLACEHOLDER not in request.instruction
    assert OOB_URL_PLACEHOLDER not in request.instruction
    assert "payload_placeholders" not in request.context


def test_llm_generator_advertises_marker_placeholder_for_marker_norm() -> None:
    method, plan, _, scenario = _binding()
    invariant = _norm_invariant(
        reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))
    )
    client = FakeModelClient(
        {"checks": [{"request": {"value": "model-value"}, "rationale": ""}]}
    )

    LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    request = client.requests[0]
    assert PROBE_MARKER_PLACEHOLDER in request.instruction
    assert OOB_URL_PLACEHOLDER not in request.instruction
    assert request.context["payload_placeholders"] == {
        "probe_marker": PROBE_MARKER_PLACEHOLDER
    }


def test_llm_generator_advertises_oob_placeholder_for_oob_norm() -> None:
    method, plan, _, scenario = _binding()
    invariant = _norm_invariant(
        external_call(Atom(value=method.method_id), Atom(value="dast-oob-marker"))
    )
    client = FakeModelClient(
        {"checks": [{"request": {"value": "model-value"}, "rationale": ""}]}
    )

    LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    request = client.requests[0]
    assert OOB_URL_PLACEHOLDER in request.instruction
    assert PROBE_MARKER_PLACEHOLDER not in request.instruction
    assert request.context["payload_placeholders"] == {"oob_url": OOB_URL_PLACEHOLDER}


def test_llm_generator_does_not_expose_engine_payload_corpus() -> None:
    method, plan, _, scenario = _binding()
    invariant = _norm_invariant(
        reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))
    )
    client = FakeModelClient(
        {"checks": [{"request": {"value": "model-value"}, "rationale": ""}]}
    )

    LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    instruction = client.requests[0].instruction
    for token in ("OR 1=1", "../", "printf", "`", "%2e%2e"):
        assert token not in instruction
    assert "payload corpus" not in instruction


def test_llm_generator_fits_repeated_values() -> None:
    method, plan, invariant, scenario = _binding()
    client = FakeModelClient(
        {"checks": [{"request": {"tags": "model-tag"}, "rationale": ""}]}
    )

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert dict(checks[0].request)["tags"] == ("model-tag",)


def test_llm_generator_rejects_schema_invalid_values() -> None:
    method, plan, invariant, scenario = _binding()
    method = method.model_copy(
        update={
            "fields": (
                *method.fields,
                FieldSpec(name="total", type="int32", minimum=0, maximum=10),
                FieldSpec(name="mode", type="string", enum_values=("fast", "slow")),
                FieldSpec(name="left", type="string", oneof="choice"),
                FieldSpec(name="right", type="string", oneof="choice"),
            )
        }
    )
    client = FakeModelClient(
        {
            "checks": [
                {
                    "request": {
                        "resource_id": 42,
                        "total": 99,
                        "mode": "unknown",
                        "left": "left",
                        "right": "right",
                    },
                    "rationale": "invalid",
                },
                {
                    "request": {
                        "resource_id": "valid-resource",
                        "total": 7,
                        "mode": "fast",
                        "left": "choice",
                    },
                    "rationale": "valid",
                },
            ]
        }
    )

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert len(checks) == 1
    request = dict(checks[0].request)
    assert request["resource_id"] == "valid-resource"
    assert request["total"] == 7
    assert request["mode"] == "fast"
    assert "right" not in request


def test_llm_generator_rejects_broken_couplings_and_sends_them_to_model() -> None:
    method, plan, invariant, scenario = _binding()
    method = method.model_copy(
        update={
            "fields": (
                *method.fields,
                FieldSpec(name="from", type="int32"),
                FieldSpec(name="to", type="int32"),
            )
        }
    )
    plan = plan.model_copy(
        update={
            "couplings": (
                (
                    input_field(Atom(value="example.Get"), Atom(value="from")),
                    input_field(Atom(value="example.Get"), Atom(value="to")),
                    "lt",
                ),
            )
        },
    )
    client = FakeModelClient(
        {
            "checks": [
                {"request": {"from": 10, "to": 1}, "rationale": "violates lt"},
                {"request": {"from": 1, "to": 10}, "rationale": "satisfies lt"},
            ]
        }
    )

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert len(checks) == 1
    assert dict(checks[0].request)["from"] == 1
    assert dict(checks[0].request)["to"] == 10
    assert client.requests[0].context["plan"]["couplings"] == [["from", "to", "lt"]]


def test_llm_generator_sends_bounded_slice_instead_of_full_contract() -> None:
    method, plan, _, scenario = _binding()
    invariant = _norm_invariant(
        reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))
    )
    client = FakeModelClient(
        {"checks": [{"request": {"value": "model-value"}, "rationale": ""}]}
    )

    LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    request = client.requests[0]
    assert "method" not in request.context
    assert set(request.context["schema"]) == {"method_id", "fields"}
    assert request.context["schema"]["method_id"] == method.method_id
    assert [field["name"] for field in request.context["schema"]["fields"]] == [
        "resource_id",
        "value",
        "tags",
    ]
    graph = QdlGraph.model_validate(request.context["graph"])
    assert any(
        fact.predicate.name == "prevents" and fact.args[1].name == "reached"
        for fact in graph.facts
    )
    assert any(
        fact.predicate.name == "is"
        and fact.args[0].value == method.method_id
        and fact.args[1].value == "Action"
        for fact in graph.facts
    )
    assert "norm_fact" not in request.context["invariant"]
    assert "service" not in json.dumps(request.context["schema"])


def test_llm_generator_bounds_schema_by_slice_budget() -> None:
    method, plan, invariant, scenario = _binding()
    method = method.model_copy(
        update={
            "fields": tuple(
                FieldSpec(name=f"field_{index}", type="string") for index in range(8)
            )
        }
    )
    client = FakeModelClient({"checks": []})
    generator = LlmGenerator(
        client,
        TemplateGenerator(),
        slice_budget=SliceBudget(max_tokens=120),
    )

    generator.generate(plan, method, invariant, scenario)

    schema = client.requests[0].context["schema"]
    assert len(schema["fields"]) < len(method.fields)
    assert schema["truncated"] is True


def test_llm_generator_slice_is_deterministic() -> None:
    method, plan, _, scenario = _binding()
    invariant = _norm_invariant(
        reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))
    )
    graphs = []
    for _ in range(2):
        client = FakeModelClient({"checks": []})
        LlmGenerator(client, TemplateGenerator()).generate(
            plan, method, invariant, scenario
        )
        graphs.append(client.requests[0].context["graph"])

    assert graphs[0] == graphs[1]


def test_llm_generator_falls_back_to_seed_when_model_returns_no_checks() -> None:
    method, plan, invariant, scenario = _binding()
    client = FakeModelClient({"checks": []})

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert len(checks) == 1
    assert checks[0].generator == "template"


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("model timed out"),
        RuntimeError("model provider unavailable"),
    ],
)
def test_llm_generator_falls_back_to_seed_when_model_fails(
    error: Exception,
) -> None:
    method, plan, invariant, scenario = _binding()
    client = FailingModelClient(error)

    checks = LlmGenerator(client, TemplateGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert client.calls == 1
    assert len(checks) == 1
    assert checks[0].generator == "template"
    assert dict(checks[0].request)["resource_id"] is None


def test_llm_generator_logs_one_bounded_model_failure_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    method, plan, invariant, scenario = _binding()
    generator = LlmGenerator(
        FailingModelClient(TimeoutError("model timed out")),
        TemplateGenerator(),
    )

    with caplog.at_level(logging.WARNING, logger="cloud_dast.generators.llm"):
        generator.generate(plan, method, invariant, scenario)
        generator.generate(plan, method, invariant, scenario)

    records = [
        record
        for record in caplog.records
        if record.name == "cloud_dast.generators.llm"
        and record.levelno == logging.WARNING
    ]
    assert len(records) == 1
    assert "error_type=TimeoutError" in records[0].getMessage()
    assert "fallback=template" in records[0].getMessage()
