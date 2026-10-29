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
    VerdictStatus,
)
from cloud_dast.model.events import InvestigationIntent
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.verification.findings import (
    finding_from_observation,
)


def test_finding_requires_failed_observation(
    invariant,
    check,
    denied_observation,
) -> None:
    with pytest.raises(ValueError, match="failed observation"):
        finding_from_observation(
            check,
            denied_observation,
            invariant,
            verdict=VerdictStatus.PASS,
            title="Invalid finding",
            description="Expected denied result",
            remediation="No remediation",
        )


def test_finding_assesses_the_explicit_norm_instead_of_the_generation_hint(
    invariant,
    check,
    allowed_observation,
) -> None:
    foreign_invariant = invariant.model_copy(
        update={"invariant_id": "another-invariant"}
    )

    finding = finding_from_observation(
        check,
        allowed_observation,
        foreign_invariant,
        verdict=VerdictStatus.FAIL,
        minimal_poc=check.request,
        title="Invalid finding",
        description="Wrong invariant",
        remediation="No remediation",
    )
    assert finding.invariant_id == foreign_invariant.invariant_id
    assert finding.observation_id == allowed_observation.observation_id
    assert finding.minimal_poc == check.request
    assert check.invariant_id == invariant.invariant_id


def test_finding_rejects_observation_from_another_check(
    invariant,
    check,
    allowed_observation,
) -> None:
    foreign_observation = allowed_observation.model_copy(
        update={"check_id": "another-check"}
    )

    with pytest.raises(ValueError, match="does not belong to the check"):
        finding_from_observation(
            check,
            foreign_observation,
            invariant,
            verdict=VerdictStatus.FAIL,
            title="Invalid finding",
            description="Wrong check",
            remediation="No remediation",
        )


def test_finding_uses_check_method_provenance(
    invariant,
    check,
    allowed_observation,
) -> None:
    finding = finding_from_observation(
        check,
        allowed_observation,
        invariant,
        verdict=VerdictStatus.FAIL,
        title="Finding",
        description="Observed violation",
        remediation="Fix policy",
    )
    assert finding.method_id == check.method_id


def test_finding_carries_invariant_norm_fact(
    invariant,
    check,
    allowed_observation,
) -> None:
    finding = finding_from_observation(
        check,
        allowed_observation,
        invariant,
        verdict=VerdictStatus.FAIL,
        title="Finding",
        description="Observed violation",
        remediation="Fix policy",
    )
    assert finding.norm_fact == invariant.norm_fact


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


def test_finding_rejects_observation_from_another_scenario(
    invariant,
    check,
    allowed_observation,
) -> None:
    foreign_observation = allowed_observation.model_copy(
        update={"scenario_id": "another-scenario"}
    )

    with pytest.raises(ValueError, match="observation scenario does not belong"):
        finding_from_observation(
            check,
            foreign_observation,
            invariant,
            verdict=VerdictStatus.FAIL,
            title="Invalid finding",
            description="Wrong scenario",
            remediation="No remediation",
        )


def test_finding_keeps_check_provenance(
    invariant,
    check,
    allowed_observation,
) -> None:
    finding = finding_from_observation(
        check,
        allowed_observation,
        invariant,
        verdict=VerdictStatus.FAIL,
        title="Cross-folder Lockbox secret access",
        description="Attacker read a foreign secret",
        remediation="Restrict folder-level role assignment",
    )

    assert finding.observation_id == allowed_observation.observation_id
    assert finding.invariant_id == invariant.invariant_id
    assert finding.method_id == check.method_id
    assert finding.scenario_id == check.scenario_id


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
