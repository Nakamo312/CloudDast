from __future__ import annotations

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    MethodSpec,
    Observation,
    ScenarioPosition,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    identity,
)
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    ACTION_MISMATCH_RATIONALE,
)
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)


def test_router_scores_actionless_identity_norm(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    observation = _observation(AccessOutcome.ALLOWED)

    verdict = _router().evaluate_policy(
        _identity_invariant(),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "grounded-outcome"
    assert verdict.deterministic is True
    assert verdict.grounded is True


def test_identity_norm_passes_when_the_bound_method_is_denied(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    observation = _observation(AccessOutcome.DENIED)

    verdict = _router().evaluate_policy(
        _identity_invariant(),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True


def test_identity_norm_without_iam_grounding_is_a_scoreable_lead(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    method = method_spec.model_copy(update={"permissions": frozenset()})
    observation = _observation(AccessOutcome.ALLOWED)

    verdict = _router().evaluate_policy(
        _identity_invariant(),
        (observation,),
        method=method,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert "hypothetical" in verdict.rationale


def test_identity_norm_conflicting_with_iam_remains_a_scoreable_lead(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "effective_permissions": frozenset(method_spec.permissions),
                }
            )
        }
    )
    observation = _observation(AccessOutcome.ALLOWED)
    norm = NormView.from_invariant(_identity_invariant())

    assert norm is not None

    verdict = GroundedOutcomeOracle().evaluate_outcome(
        _identity_invariant(),
        observation,
        method_spec,
        scenario,
        norm=norm,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert "QDL norm conflicts with IAM facts" in verdict.rationale


def test_action_bound_outcome_norm_still_requires_method_alignment(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    effect = allowed(Atom(value=f"action:{method_spec.method_id}"))
    executed_method = method_spec.model_copy(
        update={"method_id": "grpc:another.Service.Method"}
    )

    verdict = _router().evaluate_policy(
        _invariant(effect),
        (_observation(AccessOutcome.ALLOWED),),
        method=executed_method,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.rationale == ACTION_MISMATCH_RATIONALE


def test_identity_norm_does_not_bind_the_victim_principal_as_an_action() -> None:
    norm = NormView.from_invariant(_identity_invariant())

    assert norm is not None
    assert norm.action_id is None
    assert norm.primitive == "outcome"
    assert norm.expected_outcome is AccessOutcome.DENIED


def _identity_invariant() -> InvariantProjection:
    return _invariant(
        identity(
            Atom(value="principal:attacker"),
            Atom(value="principal:victim"),
        )
    )


class _UnusedDifferentialOracle:
    def evaluate_policy(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("identity norms must not dispatch to differential oracle")


def _router() -> PrimitiveOracleRouter:
    return PrimitiveOracleRouter(differential_oracle=_UnusedDifferentialOracle())


def _invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:identity-confusion",
        norm_id="norm:identity-confusion",
        statement="An attacker must not act as another principal",
        severity=Severity.CRITICAL,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:identity-confusion"), effect),
        ),
    )


def _observation(observed_outcome: AccessOutcome) -> Observation:
    return Observation(
        check_id="check:identity-confusion",
        scenario_id="scenario:identity-confusion",
        observed_outcome=observed_outcome,
        response_summary=observed_outcome.value,
    )
