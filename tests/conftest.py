from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    Finding,
    HttpStatus,
    MethodSpec,
    Observation,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, allowed
from cloud_dast.verification.findings import (
    finding_from_observation,
)
from cloud_dast.verification.invariant_projection import InvariantProjection


@pytest.fixture(autouse=True)
def _isolated_formal_sqlite_path(tmp_path, monkeypatch):
    """Keep SQLite formal persistence inside the test's temporary directory."""

    monkeypatch.setenv(
        "CLOUD_DAST_FORMAL_SQLITE_PATH",
        str(tmp_path / "formal.sqlite3"),
    )


@pytest.fixture
def method_spec() -> MethodSpec:
    return MethodSpec(
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
        service="yandex.cloud.lockbox.v1.PayloadService",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"lockbox.payload.get"}),
        resource_types=frozenset({"lockbox.secret"}),
        fields=(FieldSpec(name="secret_id", type="string", required=True),),
    )


@pytest.fixture
def method_spec_with_ids(method_spec: MethodSpec) -> MethodSpec:
    return method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="folder_id", type="string", required=True),
                FieldSpec(name="unknown_id", type="string", required=False),
            )
        }
    )


@pytest.fixture
def scenario_position() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="cross-folder-private",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.CROSS_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="created",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service="lockbox",
                    resource_type="lockbox.secret",
                    resource_id="secret-victim",
                ),
                ResourceRef(
                    service="resources",
                    resource_type="folder",
                    resource_id="folder-victim",
                ),
            ),
            effective_permissions=frozenset(),
            permissions_known=True,
        ),
    )


@pytest.fixture
def verification_plan(
    method_spec: MethodSpec, scenario_position: ScenarioPosition
) -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan:lockbox-foreign-secret-read",
        invariant_id="lockbox-foreign-secret-read",
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
        resource_types=(("secret_id", "lockbox.secret"),),
    )


@pytest.fixture
def invariant(method_spec: MethodSpec) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="lockbox-foreign-secret-read",
        norm_id="threat:foreign-secret-read",
        statement="Attacker must not read a foreign Lockbox secret",
        severity=Severity.HIGH,
        policy="response access must be denied",
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:foreign-secret-read"),
                allowed(Atom(value=f"action:{method_spec.method_id}")),
            ),
        ),
    )


@pytest.fixture
def check(
    method_spec: MethodSpec,
    invariant: InvariantProjection,
    scenario_position: ScenarioPosition,
) -> Check:
    return Check(
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(("secret_id", "secret-victim"),),
        identities=("attacker",),
    )


@pytest.fixture
def denied_observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="Access denied",
        transport_status=HttpStatus(code=403),
    )


@pytest.fixture
def allowed_observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="Secret payload returned",
        transport_status=HttpStatus(code=200),
    )


@pytest.fixture
def finding(
    check: Check,
    allowed_observation: Observation,
    invariant: InvariantProjection,
) -> Finding:
    return finding_from_observation(
        check,
        allowed_observation,
        invariant,
        verdict=VerdictStatus.FAIL,
        title="Cross-folder Lockbox secret access",
        description="Attacker read a secret from another folder",
        remediation="Restrict folder-level role assignment",
    )
