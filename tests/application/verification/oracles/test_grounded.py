from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    GrpcStatus,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
)
from cloud_dast.verification.oracles import GroundedOutcomeOracle


@pytest.mark.parametrize(
    ("required", "effective", "grounded"),
    [
        ({"p1", "p2"}, {"p1", "p2", "extra"}, False),
        ({"p1", "p2"}, {"p1"}, True),
        ({"p1", "p2"}, {"other"}, True),
        (set(), set(), False),
    ],
)
def test_permission_evidence_decides_grounding(
    method_spec, scenario_position, allowed_observation, required, effective, grounded
) -> None:
    method = method_spec.model_copy(update={"permissions": frozenset(required)})
    scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "effective_permissions": frozenset(effective),
                    "permissions_known": True,
                }
            )
        }
    )

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        _invariant("permissions", method.method_id),
        allowed_observation,
        method,
        scenario,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is grounded
    assert verdict.deterministic


def test_grounded_oracle_fails_when_missing_permission_is_allowed(
    method_spec,
    scenario_position,
    allowed_observation,
) -> None:
    invariant = _invariant("inv", method_spec.method_id)
    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        allowed_observation,
        method_spec,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic
    assert verdict.grounded


def test_grounded_oracle_passes_when_missing_permission_is_denied(
    method_spec,
    scenario_position,
    denied_observation,
) -> None:
    invariant = _invariant("inv", method_spec.method_id)
    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        denied_observation,
        method_spec,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.deterministic
    assert verdict.grounded


def test_grounded_oracle_marks_authentication_failure_unscoreable(
    method_spec,
    scenario_position,
    denied_observation,
) -> None:
    invariant = _invariant("inv", method_spec.method_id)
    observation = denied_observation.model_copy(update={"auth_failed": True})

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        observation,
        method_spec,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic
    assert not verdict.grounded


def test_grounded_oracle_marks_grpc_unauthenticated_unscoreable(
    method_spec,
    scenario_position,
    denied_observation,
) -> None:
    invariant = _invariant("inv", method_spec.method_id)
    observation = denied_observation.model_copy(
        update={"transport_status": GrpcStatus(code="UNAUTHENTICATED")}
    )

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        observation,
        method_spec,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic
    assert not verdict.grounded


def test_grounded_oracle_requires_known_effective_permissions(
    method_spec,
    scenario_position,
    allowed_observation,
) -> None:
    invariant = _invariant("inv", method_spec.method_id)
    scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={"permissions_known": False}
            )
        }
    )

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        allowed_observation,
        method_spec,
        scenario,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic
    assert not verdict.grounded


def test_qdl_norm_without_graph_permissions_is_a_scoreable_lead(
    method_spec,
    scenario_position,
    allowed_observation,
) -> None:
    invariant = _invariant("hypothetical", method_spec.method_id)
    method = method_spec.model_copy(update={"permissions": frozenset()})

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        allowed_observation,
        method,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic
    assert not verdict.grounded
    assert "hypothetical" in verdict.rationale


def test_grounded_oracle_rejects_action_mismatch(
    method_spec,
    scenario_position,
    allowed_observation,
) -> None:
    invariant = _invariant("mismatch", "grpc:another.Service.Method")

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant,
        allowed_observation,
        method_spec,
        scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE


def _invariant(invariant_id: str, action_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"threat:{invariant_id}",
        statement="formal QDL norm",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=f"norm:{invariant_id}"), allowed(Atom(value=action_id))),
        ),
    )
