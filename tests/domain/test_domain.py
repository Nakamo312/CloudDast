from __future__ import annotations

import pytest
from pydantic import ValidationError

from cloud_dast.model import (
    AccessOutcome,
    Finding,
    GrpcStatus,
    HttpStatus,
    Observation,
    Severity,
)
from cloud_dast.model.events import InvestigationIntent
from cloud_dast.model.evidence import response_tree_digest


def test_finding_defaults_to_explicit_classification_deficit() -> None:
    finding = Finding(
        observation_id="observation",
        invariant_id="invariant",
        method_id="method",
        scenario_id="scenario",
        severity=Severity.HIGH,
        title="Finding",
        description="Observed violation",
        remediation="Fix policy",
    )

    assert finding.vulnerability_class == "classification_deficit"
    assert finding.classification_deficits == ("missing_classification_facts",)


@pytest.mark.parametrize("path_id", [None, "path:manual"])
@pytest.mark.parametrize("with_norm", [False, True])
def test_finding_preserves_manual_metadata_without_policy(
    invariant, check, allowed_observation, path_id, with_norm
) -> None:
    finding = Finding(
        observation_id=allowed_observation.observation_id,
        invariant_id=invariant.invariant_id,
        method_id=check.method_id,
        scenario_id=allowed_observation.scenario_id,
        severity=invariant.severity,
        title="Cross-folder Lockbox secret access",
        description="Attacker read a foreign secret",
        remediation="Restrict folder-level role assignment",
        path_id=path_id,
        rationale="Manually reviewed evidence",
        confidence=None,
        evidence_refs=(allowed_observation.observation_id,),
        minimal_poc=check.request,
        norm_fact=invariant.norm_fact if with_norm else None,
    )

    assert finding.title == "Cross-folder Lockbox secret access"
    assert finding.description == "Attacker read a foreign secret"
    assert finding.remediation == "Restrict folder-level role assignment"
    assert finding.confidence is None
    assert finding.goal_id is finding.step_id is None
    assert finding.path_id == path_id
    assert finding.rationale == "Manually reviewed evidence"
    assert finding.evidence_refs == (allowed_observation.observation_id,)
    assert finding.minimal_poc == check.request
    assert finding.norm_fact == (invariant.norm_fact if with_norm else None)


@pytest.mark.parametrize(
    "status",
    [
        {"transport": "http", "code": 999},
        {"transport": "http", "code": 99},
        {"transport": "grpc", "code": ""},
        {"transport": "grpc", "code": "  "},
        {"transport": "smtp", "code": "250"},
    ],
)
def test_invalid_transport_status_is_rejected(check, status) -> None:
    with pytest.raises(ValidationError):
        Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary="Invalid status",
            transport_status=status,
        )


def test_transport_status_is_typed_by_transport() -> None:
    http = HttpStatus(code=403)
    grpc = GrpcStatus(code="PERMISSION_DENIED")

    assert http.token == "http:403"
    assert grpc.token == "grpc:PERMISSION_DENIED"
    assert http.is_error() and grpc.is_error()
    assert not HttpStatus(code=302).is_error()
    assert not GrpcStatus(code="ok").is_error()
    assert HttpStatus(code=404).is_not_found()
    assert GrpcStatus(code="not_found").is_not_found()
    assert HttpStatus(code=401).is_auth_failure()
    assert GrpcStatus(code="unauthenticated").is_auth_failure()
    assert HttpStatus(code=504).is_timeout()
    assert GrpcStatus(code="deadline_exceeded").is_timeout()


def test_investigation_intent_rejects_non_json_payload() -> None:
    with pytest.raises(ValidationError):
        InvestigationIntent(
            method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            payload=(("invalid", object()),),
            identity="attacker",
            reason="Investigate cross-folder access",
        )


def test_response_tree_digest_is_stable_and_leaf_sensitive() -> None:
    tree = (
        ("count", 3),
        ("items.0.name", "widget"),
        ("user.address.city", "Moscow"),
    )

    assert response_tree_digest(tuple(reversed(tree))) == response_tree_digest(tree)

    for index, (path, value) in enumerate(tree):
        changed = list(tree)
        changed[index] = (
            path,
            value + "!" if isinstance(value, str) else "different",
        )
        assert response_tree_digest(tuple(changed)) != response_tree_digest(tree)


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf")])
def test_investigation_intent_rejects_non_finite_numbers(
    invalid_value: float,
) -> None:
    with pytest.raises(ValidationError):
        InvestigationIntent(
            method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            payload=(("invalid", invalid_value),),
            identity="attacker",
            reason="Investigate cross-folder access",
        )
