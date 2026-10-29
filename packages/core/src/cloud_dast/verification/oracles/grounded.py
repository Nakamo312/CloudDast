"""Deterministic outcome comparison against graph-backed IAM facts."""

from __future__ import annotations

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    MethodSpec,
    Observation,
    OracleDeficit,
    PolicyVerdict,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    action_alignment_rationale,
)
from cloud_dast.verification.scenarios.capability import missing_capabilities


class GroundedOutcomeOracle:
    """Compare an observed API outcome with permissions from the graph.

    This is primitive P1.  A finding is possible only when both the norm and
    the oracle are grounded: method requirements come from the contract graph
    and effective permissions come from live IAM bindings.
    """

    def evaluate_outcome(
        self,
        invariant: InvariantProjection,
        observation: Observation,
        method: MethodSpec,
        scenario: ScenarioPosition,
        *,
        norm: NormView | None = None,
    ) -> PolicyVerdict:
        if norm is None:
            norm = NormView.from_invariant(invariant)
        if norm is None or norm.compiled.primitive != "outcome":
            return self._unscoreable(
                observation,
                "grounded outcome oracle supports only outcome-bearing QDL norms",
            )
        if norm.expected_outcome is None:
            return self._unscoreable(
                observation,
                "outcome QDL norm has no expected outcome",
            )
        status = observation.transport_status
        if observation.auth_failed or (status is not None and status.is_auth_failure()):
            return self._unscoreable(
                observation,
                "authentication failed before the policy decision was observable",
            )
        if observation.observed_outcome in {AccessOutcome.ERROR, AccessOutcome.UNKNOWN}:
            return self._unscoreable(
                observation,
                "transport or application error cannot be scored as a policy outcome",
            )
        mismatch = action_alignment_rationale(norm.action_id, method.method_id)
        if mismatch is not None:
            return self._unscoreable(observation, mismatch)

        expected, grounded, rationale = self._expected_outcome(norm, method, scenario)
        if expected is AccessOutcome.UNKNOWN:
            return self._unscoreable(observation, rationale)
        if observation.observed_outcome is expected and not grounded:
            negative_rationale = (
                f"{rationale}; matching outcome is not a grounded negative witness"
            )
            return self._unscoreable(
                observation,
                negative_rationale,
                deficits=(
                    OracleDeficit(
                        kind="ungrounded_expectation",
                        action_id=norm.action_id,
                        context=(("expected_outcome", expected.value),),
                        rationale=negative_rationale,
                    ),
                ),
            )
        status = (
            VerdictStatus.PASS
            if observation.observed_outcome is expected
            else VerdictStatus.FAIL
        )
        return PolicyVerdict(
            status=status,
            confidence=1.0 if grounded else 0.5,
            rationale=rationale,
            evidence_refs=(observation.observation_id,),
            model_id="grounded-outcome",
            negative_scope=(
                ("observed_policy_outcome",) if status is VerdictStatus.PASS else ()
            ),
            deterministic=True,
            grounded=grounded,
        )

    @staticmethod
    def _expected_outcome(
        norm: NormView,
        method: MethodSpec,
        scenario: ScenarioPosition,
    ) -> tuple[AccessOutcome, bool, str]:
        normative_outcome = norm.expected_outcome
        if not method.permissions:
            if normative_outcome is None:
                return (
                    AccessOutcome.UNKNOWN,
                    False,
                    "method has no graph-backed permission requirement",
                )
            return (
                normative_outcome,
                False,
                f"{_expectation_source()} expectation is hypothetical; "
                "method has no permission norm",
            )
        if not scenario.stand.permissions_known:
            if normative_outcome is None:
                return (
                    AccessOutcome.UNKNOWN,
                    False,
                    "effective permissions for the live principal are unknown",
                )
            return (
                normative_outcome,
                False,
                f"{_expectation_source()} expectation is hypothetical; "
                "effective permissions are unknown",
            )

        missing = missing_capabilities(method, scenario.stand.effective_permissions)
        grounded_expected = AccessOutcome.DENIED if missing else AccessOutcome.ALLOWED
        if normative_outcome is not None and normative_outcome != grounded_expected:
            return (
                normative_outcome,
                False,
                f"{_expectation_source()} conflicts with IAM facts; "
                "result is a lead, not a finding",
            )
        detail = (
            f"missing permissions: {', '.join(sorted(missing))}"
            if missing
            else "principal has every permission required by the method"
        )
        return (
            grounded_expected,
            True,
            f"IAM-grounded expected outcome is {grounded_expected.value}; {detail}",
        )

    @staticmethod
    def _unscoreable(
        observation: Observation,
        rationale: str,
        *,
        deficits: tuple[OracleDeficit, ...] = (),
    ) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=1.0,
            rationale=rationale,
            evidence_refs=(observation.observation_id,),
            model_id="grounded-outcome",
            deterministic=True,
            grounded=False,
            deficits=deficits,
        )


def _expectation_source() -> str:
    return "QDL norm"
