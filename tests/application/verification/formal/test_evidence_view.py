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
from cloud_dast.qdl.field_roles import FieldRolePolicy, resolve_field_roles
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    input_field,
    output_field,
)
from cloud_dast.runtime.candidates.feedback import (
    ExecutionFeedback,
    ExecutionFeedbackEntry,
)
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence import (
    EvidenceBudget,
    build_evidence_view,
    build_execution_feedback_view,
    build_paired_evidence_view,
)


def _field_role_fact(
    action: str,
    field_name: str,
    role: str,
    *,
    context: Context = Context.ACCEPTED,
    direction: str = "input",
) -> Fact:
    constructor = input_field if direction == "input" else output_field
    field = constructor(Atom(value=action), Atom(value=field_name))
    return Fact(
        context=context,
        predicate=Predicate.from_name("has"),
        args=(field, Atom(value=role)),
    )


def _role_graph(*facts: Fact) -> QdlGraph:
    """Declare every referenced term so the role graph stays grounded."""

    declarations: dict[str, Fact] = {}
    for fact in facts:
        field = fact.args[0]
        declaration_type = (
            "InputField" if field.name == "input_field" else "OutputField"
        )
        declarations.setdefault(
            canonical_json(field),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(field, Atom(value=declaration_type)),
            ),
        )
    action = Atom(value="action:get")
    return QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            *declarations.values(),
            *facts,
        )
    )


def _is_redacted(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("evidence_encoding") == "redacted"
        and isinstance(value.get("sha256"), str)
        and len(value["sha256"]) == 64
        and isinstance(value.get("length"), int)
    )


def test_evidence_view_carries_redacted_runtime_evidence() -> None:
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
    assert _is_redacted(request_value)
    assert data["response"]["source"] == "response_tree"
    assert [leaf["path"] for leaf in data["response"]["leaves"]] == [
        "safe",
        "nested.token",
    ]
    assert all(_is_redacted(leaf["value"]) for leaf in data["response"]["leaves"])
    assert data["response"]["safe_fields"][0]["path"] == "safe"
    assert _is_redacted(data["response"]["safe_fields"][0]["value"])
    assert _is_redacted(data["error_reason"])
    assert view.data["error_reason"] == "permission denied for attacker"
    assert data["status"] == "http:403"
    assert data["outcome"] == "denied"
    assert data["duration_ms"] == 12.5
    assert _is_redacted(data["trace"][0]["resource_before"][0]["value"])
    assert _is_redacted(data["trace"][0]["resource_after"][0]["value"])
    assert _is_redacted(data["trace"][0]["response"]["fields"][0]["value"])
    assert data["oob"]["events"][0]["correlation_id"] == "marker-1"
    assert _is_redacted(data["oob"]["events"][0]["attributes"]["method"])
    assert view.data["oob"]["events"][0]["attributes"]["method"] == "GET"
    assert data["oob"]["events"][0]["observed_at"] == 0.0
    assert _is_redacted(data["oob"]["events"][0]["attributes"]["path"])
    assert _is_redacted(data["oob"]["events"][0]["source"])
    assert view.truncated is False
    rendered = json.dumps(data, ensure_ascii=False)
    assert "attacker-canary" not in rendered
    assert "tok-full-fidelity" not in rendered
    assert "/cb" not in rendered
    assert "10.0.0.8" not in rendered


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

    assert _is_redacted(data["control"]["request"]["values"][0]["value"])
    assert _is_redacted(data["treatment"]["request"]["values"][0]["value"])
    assert _is_redacted(data["diff"]["fields_only_treatment"][0]["treatment_value"])
    assert _is_redacted(data["diff"]["value_differs"][0]["control_value"])
    assert _is_redacted(data["diff"]["value_differs"][0]["treatment_value"])
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
    assert _is_redacted(attempt["evidence"]["request"]["values"][0]["value"])
    assert attempt["evidence"]["response"]["leaves"][0]["path"] == "error.message"
    assert _is_redacted(attempt["evidence"]["response"]["leaves"][0]["value"])
    assert _is_redacted(attempt["evidence"]["trace"][0]["resource_before"][0]["value"])
    assert _is_redacted(attempt["evidence"]["trace"][0]["resource_after"][0]["value"])


def test_evidence_view_retains_fields_with_accepted_object_ref_roles() -> None:
    policy = resolve_field_roles(
        _role_graph(
            _field_role_fact("action:get", "order_id", "object_ref"),
            _field_role_fact("action:get", "session_id", "credential"),
        )
    )
    check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="scenario-1",
        request=(
            ("order_id", "order-victim"),
            ("session_id", "session-secret"),
        ),
        identities=("attacker",),
    )
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
    )

    data = build_evidence_view(
        check=check,
        observation=observation,
        field_roles=policy,
    ).to_dict()

    values = {entry["name"]: entry["value"] for entry in data["request"]["values"]}
    assert values["order_id"] == "order-victim"
    assert _is_redacted(values["session_id"])


def test_evidence_view_retains_response_leaves_by_output_role() -> None:
    policy = resolve_field_roles(
        _role_graph(
            _field_role_fact(
                "action:get",
                "order.id",
                "object_ref",
                direction="output",
            ),
        )
    )
    check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="scenario-1",
        request=(("order_id", "order-victim"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(
            ("order.id", "order-victim"),
            ("session.id", "session-secret"),
        ),
    )

    data = build_evidence_view(
        check=check,
        observation=observation,
        field_roles=policy,
    ).to_dict()

    leaves = {leaf["path"]: leaf["value"] for leaf in data["response"]["leaves"]}
    assert leaves["order.id"] == "order-victim"
    assert _is_redacted(leaves["session.id"])


def test_evidence_view_reports_missing_roles_as_deficits(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = Check(
        invariant_id="invariant-1",
        method_id="get",
        scenario_id="scenario-1",
        request=(("session_id", "session-secret"),),
        identities=("attacker",),
    )

    with caplog.at_level("WARNING", logger="cloud_dast.formal.evidence_view"):
        data = build_evidence_view(
            check=check,
            field_roles=FieldRolePolicy(),
        ).to_dict()

    assert _is_redacted(data["request"]["values"][0]["value"])
    assert "input:get:session_id" in caplog.text


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
    assert _is_redacted(
        data["attempts"][1]["evidence"]["response"]["leaves"][0]["value"]
    )


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
    assert all(_is_redacted(leaf["value"]) for leaf in model_leaves)


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


def test_evidence_digest_covers_the_redacted_model_view() -> None:
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
