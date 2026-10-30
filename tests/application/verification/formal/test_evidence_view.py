from __future__ import annotations

import hashlib
import json

import pytest

from cloud_dast.model import (
    AccessOutcome,
    Check,
    ExecutionTrace,
    HttpStatus,
    Observation,
    ResponseData,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.runtime.candidates.feedback import (
    ExecutionFeedback,
    ExecutionFeedbackEntry,
)
from cloud_dast.runtime.execution.checks import run_check
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence import (
    EvidenceBudget,
    EvidenceView,
    build_evidence_view,
    build_execution_feedback_view,
    build_paired_evidence_view,
)


@pytest.mark.parametrize("cap", [1, 64, 1023])
def test_evidence_budget_requires_space_for_metadata(cap) -> None:
    with pytest.raises(ValueError, match="max_total_bytes must be at least 1024"):
        EvidenceBudget(max_total_bytes=cap)


def test_default_evidence_budget_includes_rendered_separator_overhead() -> None:
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=tuple((f"leaf.{i}", "v" * 48) for i in range(1024)),
    )

    view = build_evidence_view(observation=observation)
    rendered_bytes = len(json.dumps(view.to_dict(), ensure_ascii=False).encode("utf-8"))

    assert rendered_bytes <= EvidenceBudget().max_total_bytes


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        {
            "max_leaves": 1,
            "max_string_chars": 1024,
            "max_total_bytes": 1024,
            "dropped_leaves": 0,
            "truncated": "false",
        },
        {
            "max_leaves": 1,
            "max_string_chars": 10000,
            "max_total_bytes": 64,
            "dropped_leaves": 0,
            "truncated": False,
        },
    ],
)
def test_explicit_invalid_evidence_budget_is_not_ignored(metadata) -> None:
    with pytest.raises(ValueError, match="invalid evidence budget metadata"):
        EvidenceView(
            data={"kind": "observation", "label": "x" * 2000, "budget": metadata},
            original_digest="original",
        )


@pytest.mark.parametrize(
    ("input_value", "output_value"),
    [
        ("INPUT-CANARY", "OUTPUT-CANARY"),
        (("nested", 1, None), ("🔥", False)),
        (False, 123),
        (None, "output"),
    ],
)
def test_run_check_retains_bounded_input_output_trace_and_oob(
    input_value, output_value
) -> None:
    check = Check(
        invariant_id="inv",
        method_id="get",
        scenario_id="scenario",
        identities=("actor",),
        request=(("value", input_value),),
        probe_marker="marker",
    )

    def target(actual):
        return Observation(
            check_id=actual.check_id,
            scenario_id=actual.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="RESPONSE-CANARY",
            output=ResponseData(fields=(("value", output_value),)),
        )

    observation = run_check(check, target)
    view = build_evidence_view(
        check=check,
        observation=observation,
        oob_events=(
            EvidenceEvent(
                channel="oob",
                correlation_id="marker",
                source="internal-host",
                attributes=(("value", "OOB-CANARY"),),
            ),
        ),
    )
    data = view.to_dict()
    assert data["request"]["values"][0]["value"] == json.loads(json.dumps(input_value))
    assert data["response"]["leaves"][0]["value"] == json.loads(
        json.dumps(output_value)
    )
    assert data["trace"][0]["response"]["fields"][0]["value"] == json.loads(
        json.dumps(output_value)
    )
    assert data["response_summary"] == "RESPONSE-CANARY"
    assert data["oob"]["events"][0]["source"] == "internal-host"
    assert data["oob"]["events"][0]["attributes"]["value"] == "OOB-CANARY"
    assert data == view.data


@pytest.mark.parametrize("cap", [1024, 2048, 4096, 8192, 128 * 1024])
@pytest.mark.parametrize("character", ["🔥", "я", '"', "\\"])
def test_evidence_byte_cap_includes_unicode_and_json_escaping(cap, character) -> None:
    text = character * 1024
    observation = Observation(
        observation_id=text,
        check_id=text,
        scenario_id=text,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary=text,
    )

    view = build_evidence_view(
        observation=observation, budget=EvidenceBudget(max_total_bytes=cap)
    )

    for data in (view.data, view.to_dict()):
        assert len(json.dumps(data, ensure_ascii=False).encode("utf-8")) <= cap


def test_evidence_view_carries_full_bounded_runtime_evidence() -> None:
    check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="scenario-1",
        request=(("query", "attacker-canary"),),
        identities=("attacker",),
        probe_marker="marker-1",
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
        transport_status=HttpStatus(code=403),
        output=ResponseData(
            fields=(("safe", "sanitized"),),
            field_names=("safe", "nested.token"),
        ),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="check-1",
                    step_id="step-1",
                    method_id="get",
                    scenario_id="scenario-1",
                    status=AccessOutcome.DENIED,
                    response=ResponseData(fields=(("safe", "sanitized"),)),
                    resource_state_before=(("total", 10),),
                    resource_state_after=(("total", 20),),
                ),
            )
        ),
        duration_ms=12.5,
        probe_marker="marker-1",
        error_reason="permission denied for attacker",
        response_tree=(
            ("safe", "sanitized"),
            ("nested.token", "tok-full-fidelity"),
        ),
    )
    events = (
        EvidenceEvent(
            channel="oob",
            correlation_id="marker-1",
            source="10.0.0.8",
            attributes=(("method", "GET"), ("path", "/cb")),
        ),
        EvidenceEvent(channel="oob", correlation_id="other-marker"),
    )

    view = build_evidence_view(
        check=check,
        observation=observation,
        oob_events=events,
    )
    data = view.to_dict()

    request_value = data["request"]["values"][0]["value"]
    assert request_value == "attacker-canary"
    assert data["response"]["source"] == "response_tree"
    assert [leaf["path"] for leaf in data["response"]["leaves"]] == [
        "safe",
        "nested.token",
    ]
    assert {leaf["path"]: leaf["value"] for leaf in data["response"]["leaves"]} == {
        "safe": "sanitized",
        "nested.token": "tok-full-fidelity",
    }
    assert data["response"]["safe_fields"][0]["path"] == "safe"
    assert data["response"]["safe_fields"][0]["value"] == "sanitized"
    assert data["error_reason"] == "permission denied for attacker"
    assert view.data["error_reason"] == "permission denied for attacker"
    assert data["status"] == "http:403"
    assert data["outcome"] == "denied"
    assert data["duration_ms"] == 12.5
    assert data["trace"][0]["resource_before"][0]["value"] == 10
    assert data["trace"][0]["resource_after"][0]["value"] == 20
    assert data["trace"][0]["response"]["fields"][0]["value"] == "sanitized"
    assert data["oob"]["events"][0]["correlation_id"] == "marker-1"
    assert data["oob"]["events"][0]["attributes"]["method"] == "GET"
    assert view.data["oob"]["events"][0]["attributes"]["method"] == "GET"
    assert data["oob"]["events"][0]["observed_at"] == 0.0
    assert data["oob"]["events"][0]["attributes"]["path"] == "/cb"
    assert data["oob"]["events"][0]["source"] == "10.0.0.8"
    assert view.truncated is False
    rendered = json.dumps(data, ensure_ascii=False)
    assert "attacker-canary" in rendered
    assert "tok-full-fidelity" in rendered
    assert "/cb" in rendered
    assert "10.0.0.8" in rendered


def test_paired_evidence_view_carries_values_and_path_diffs() -> None:
    control_check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="control",
        request=(("query", "benign"),),
        identities=("attacker",),
    )
    treatment_check = Check(
        invariant_id="invariant-1",
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

    data = build_paired_evidence_view(
        control_check=control_check,
        control=control,
        treatment_check=treatment_check,
        treatment=treatment,
        report=report,
    ).to_dict()

    assert data["control"]["request"]["values"][0]["value"] == "benign"
    assert data["treatment"]["request"]["values"][0]["value"] == "canary"
    assert data["diff"]["fields_only_treatment"][0]["treatment_value"] == "tok_123"
    assert data["diff"]["value_differs"][0]["control_value"] == "alice@example.com"
    assert data["diff"]["value_differs"][0]["treatment_value"] == "bob@example.com"
    assert data["diff"]["fields_only_treatment"][0]["path"] == "payment_token"
    assert data["diff"]["value_differs"][0]["path"] == "email"


def test_execution_feedback_view_carries_outcome_response_and_trace() -> None:
    check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="scenario-1",
        request=(("resource_id", "candidate"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id=check.check_id,
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ERROR,
        response_summary="resource not found",
        transport_status=HttpStatus(code=404),
        response_tree=(("error.message", "resource not found"),),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="observation-1",
                    step_id="step-1",
                    method_id="get",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ERROR,
                    resource_state_before=(("state", "before"),),
                    resource_state_after=(("state", "after"),),
                ),
            )
        ),
    )
    feedback = ExecutionFeedback(
        entries=(
            ExecutionFeedbackEntry(
                check=check,
                observation=observation,
                verdict=VerdictStatus.UNSCOREABLE,
                grounded=False,
                proximity=1 / 3,
            ),
        )
    )

    data = build_execution_feedback_view(feedback).to_dict()
    attempt = data["attempts"][0]

    assert data["kind"] == "execution_feedback"
    assert data["attempt_count"] == 1
    assert attempt["verdict"] == "unscoreable"
    assert attempt["grounded"] is False
    assert attempt["proximity"] == pytest.approx(1 / 3)
    assert attempt["evidence"]["request"]["values"][0]["name"] == "resource_id"
    assert attempt["evidence"]["request"]["values"][0]["value"] == "candidate"
    assert attempt["evidence"]["response"]["leaves"][0]["path"] == "error.message"
    assert attempt["evidence"]["response"]["leaves"][0]["value"] == "resource not found"
    assert attempt["evidence"]["trace"][0]["resource_before"][0]["value"] == "before"
    assert attempt["evidence"]["trace"][0]["resource_after"][0]["value"] == "after"


def test_execution_feedback_budget_keeps_the_latest_attempt() -> None:
    entries = tuple(
        ExecutionFeedbackEntry(
            check=Check(
                invariant_id="invariant-1",
                method_id="get",
                scenario_id=f"scenario-{index}",
                request=(("resource_id", f"candidate-{index}"),),
                identities=("attacker",),
            ),
            observation=Observation(
                check_id=f"check-{index}",
                scenario_id=f"scenario-{index}",
                observed_outcome=AccessOutcome.ALLOWED,
                response_summary="ok",
                response_tree=((f"result.{index}", index),),
            ),
            verdict=VerdictStatus.PASS,
        )
        for index in range(2)
    )

    view = build_execution_feedback_view(
        ExecutionFeedback(entries=entries),
        budget=EvidenceBudget(max_leaves=1),
    )
    data = view.to_dict()

    assert view.truncated is True
    assert data["attempts"][0]["evidence"]["response"]["leaves"] == []
    assert (
        data["attempts"][1]["evidence"]["response"]["leaves"][0]["path"] == "result.1"
    )
    assert data["attempts"][1]["evidence"]["response"]["leaves"][0]["value"] == 1


def test_evidence_budgets_hash_and_truncate_oversized_values() -> None:
    tree = (
        ("large", "x" * 2048),
        ("binary", "a\x00b"),
        *((f"leaf.{index}", index) for index in range(1025)),
    )
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        output=ResponseData(fields=tree),
    )

    view = build_evidence_view(observation=observation)
    data = view.to_dict()
    leaves = view.data["response"]["leaves"]

    assert len(leaves) == 1024
    assert data["budget"]["truncated"] is True
    assert data["budget"]["dropped_leaves"] >= 1
    values = {leaf["path"]: leaf["value"] for leaf in leaves}
    encoded = values["large"]
    assert encoded["evidence_encoding"] == "truncated"
    assert encoded["length"] == 2048
    assert len(encoded["preview"]) < 2048
    assert len(encoded["sha256"]) == 64
    binary = values["binary"]
    assert binary["evidence_encoding"] == "binary"
    assert binary["sha256"] and "\\x00" in binary["preview"]
    model_leaves = data["response"]["leaves"]
    assert model_leaves == leaves


def test_evidence_total_budget_is_enforced() -> None:
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=tuple((f"leaf.{index}", "v" * 48) for index in range(256)),
    )
    budget = EvidenceBudget(
        max_leaves=1024,
        max_string_chars=64,
        max_total_bytes=4096,
    )

    view = build_evidence_view(observation=observation, budget=budget)
    rendered_bytes = len(json.dumps(view.to_dict(), ensure_ascii=False).encode("utf-8"))

    assert rendered_bytes <= budget.max_total_bytes
    assert view.truncated is True
    assert view.digest != view.original_digest


def test_evidence_digest_covers_the_bounded_model_view() -> None:
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("token", "secret-value"),),
    )

    view = build_evidence_view(observation=observation)
    rendered = json.dumps(
        view.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )

    assert view.digest == hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def test_evidence_json_copy_is_detached_and_digest_is_stable() -> None:
    payload = {
        "response": {"leaves": [{"path": "value", "value": {"nested": ["original"]}}]}
    }
    view = EvidenceView(data=payload, original_digest="original-identity")
    digest = view.digest
    payload["response"]["leaves"][0]["value"]["nested"].append("caller-mutated")
    rendered = view.to_dict()
    rendered["response"]["leaves"][0]["value"]["nested"].append("copy-mutated")
    assert view.to_dict()["response"]["leaves"][0]["value"]["nested"] == ["original"]
    assert view.model_dump() == view.data
    assert view.digest == digest
    assert view.original_digest == "original-identity"
    assert (
        digest
        == hashlib.sha256(
            json.dumps(
                view.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
    )


@pytest.mark.parametrize("cap", [1024, 2048, 4096])
def test_manual_budget_normalization_is_idempotent(cap) -> None:
    data = {
        "kind": "observation",
        "label": "🔥" * 5000,
        "budget": {
            "max_leaves": "1024",
            "max_string_chars": "1024",
            "max_total_bytes": str(cap),
            "dropped_leaves": 0,
            "truncated": False,
        },
    }
    view = EvidenceView(data=data, original_digest="original")
    rendered = view.to_dict()
    assert len(json.dumps(rendered, ensure_ascii=False).encode()) <= cap
    assert rendered["budget"]["max_total_bytes"] == cap
    assert view.truncated is True
    for _ in range(3):
        repeated = EvidenceView(data=rendered, original_digest=view.original_digest)
        assert repeated.to_dict() == rendered
        assert repeated.digest == view.digest
        assert repeated.truncated is True
    assert data["label"] == "🔥" * 5000


def test_original_digest_is_independent_of_projection_budget() -> None:
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="x" * 5000,
    )
    small = build_evidence_view(
        observation=observation, budget=EvidenceBudget(max_total_bytes=1024)
    )
    default = build_evidence_view(observation=observation)
    assert small.original_digest == default.original_digest
    assert small.digest != default.digest
