from __future__ import annotations

from cloud_dast.api import (
    LiveRequest,
)
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
    ScenarioPosition,
)
from cloud_dast.qdl.graph import Atom, input_field, output_field
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.differential.evidence import MeasurementKey
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionStep,
)
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.invariant_projection import InvariantProjection
from tests.support.guardrails import AllowAllGuardrail


class _NullRequestGenerator:
    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del plan, invariant, feedback
        return (
            Check(
                invariant_id=method.method_id,
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=tuple((field.name, None) for field in method.fields),
                identities=("attacker",),
            ),
        )


class _ForwardingTarget:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, check: Check) -> Observation:
        self.calls += 1
        output = (
            ResponseData(fields=(("secret_id", "forwarded"),))
            if check.method_id == "seed"
            else None
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="executed",
            transport_status=HttpStatus(code=200),
            output=output,
        )


def test_scenario_checker_scopes_output_forwarding_by_plan(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    invariant: InvariantProjection,
) -> None:
    coupling = (
        output_field(Atom(value="seed"), Atom(value="secret_id")),
        input_field(Atom(value=method_spec.method_id), Atom(value="secret_id")),
        "eq",
    )
    producer = method_spec.model_copy(update={"method_id": "seed", "fields": ()})
    seed_plan = _plan("plan:seed", producer, scenario_position, invariant)
    first_plan = _plan(
        "plan:first", method_spec, scenario_position, invariant
    ).model_copy(update={"couplings": (coupling,)})
    second_plan = first_plan.model_copy(update={"plan_id": "plan:second"})
    target = _ForwardingTarget()
    checker = Checker(target, _NullRequestGenerator(), AllowAllGuardrail())
    for consumer in (first_plan, second_plan):
        checker.set_coupling_context(
            (
                (seed_plan, producer, scenario_position),
                (consumer, method_spec, scenario_position),
            )
        )
        calls_before = target.calls
        # An independent path cannot reuse the previous path's producer output.
        assert (
            checker.execute_bindings(
                (_binding(consumer, method_spec, scenario_position, invariant),),
                reset=False,
            )
            == ()
        )
        assert target.calls == calls_before
        checker.execute_bindings(
            (
                _binding(seed_plan, producer, scenario_position, invariant),
                _binding(consumer, method_spec, scenario_position, invariant),
            ),
            reset=False,
        )
        assert dict(checker.checks[-1].request)["secret_id"] == "forwarded"
    assert target.calls == 4


def test_evidence_key_uses_method_scenario_resource_and_invariant(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    invariant: InvariantProjection,
) -> None:
    plan = _plan("plan:evidence", method_spec, scenario_position, invariant)
    step = QdlExecutionStep(
        step_id="step:evidence",
        goal_id="goal:evidence",
        plan=plan,
        method=method_spec,
        scenario=scenario_position,
        invariant=invariant,
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="resource-victim",
    )

    key = ProbeExecutor.build_evidence_key(step, request)

    assert key == MeasurementKey(
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
        resource_id="resource-victim",
        invariant_id=invariant.invariant_id,
    )
    other_key = ProbeExecutor.build_evidence_key(
        step,
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="another-resource",
        ),
    )
    assert other_key.resource_id == "another-resource"
    assert key != other_key


def test_budget_counts_live_checks_not_observations() -> None:
    budget = CallLimits(2)

    budget.spend(2, kind="check")

    assert budget.live_calls == 2
    assert budget.can_spend() is False


def _plan(
    plan_id: str,
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> VerificationPlan:
    return VerificationPlan(
        plan_id=plan_id,
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
    )


def _binding(
    plan: VerificationPlan,
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
):
    return plan, method, scenario, invariant, None
