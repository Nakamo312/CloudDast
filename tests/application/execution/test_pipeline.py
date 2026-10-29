from __future__ import annotations

from unittest.mock import Mock, call

import pytest

import cloud_dast.runtime.execution.scenarios as pipeline
from cloud_dast.candidates import TemplateGenerator
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.infrastructure import EventBus
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    HttpStatus,
    Observation,
)
from cloud_dast.model.events import (
    CheckCompleted,
    InvestigationActionExecuted,
    InvestigationIntent,
)
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.investigation import run_investigation_intent
from tests.support.guardrails import AllowAllGuardrail


def execute_scenario(
    methods,
    invariants,
    scenario,
    target,
    event_bus=None,
    generator=None,
    max_checks=None,
    guardrail=None,
):
    return Checker(
        target,
        generator or TemplateGenerator(),
        guardrail or AllowAllGuardrail(),
        event_bus,
    ).execute(methods, invariants, scenario, max_checks)


class RecordingTarget:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, check):
        self.calls.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary=f"Access denied for {check.invariant_id}",
            transport_status=HttpStatus(code=403),
        )


class RecordingInvestigationTarget:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, intent):
        self.calls.append(intent)
        return Observation(
            check_id="target-check",
            scenario_id="cross-folder-private",
            observed_outcome=AccessOutcome.DENIED,
            response_summary=f"Access denied for {intent.identity}",
            transport_status=HttpStatus(code=403),
        )


def allow_all(_: InvestigationIntent) -> bool:
    return True


def test_run_investigation_intent_executes_target_without_event_bus() -> None:
    intent = InvestigationIntent(
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
        payload=(("secret_id", "secret-victim"),),
        identity="attacker",
        reason="Investigate cross-folder access",
    )
    target = RecordingInvestigationTarget()

    observation = run_investigation_intent(intent, target, allow_all)

    assert target.calls == [intent]
    assert observation.check_id == intent.intent_id
    assert observation.observed_outcome is AccessOutcome.DENIED


def test_run_investigation_intent_publishes_investigation_action_executed() -> None:
    intent = InvestigationIntent(
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
        payload=(("secret_id", "secret-victim"),),
        identity="attacker",
        reason="Investigate cross-folder access",
    )
    target = RecordingInvestigationTarget()
    bus = EventBus()
    events: list[InvestigationActionExecuted] = []
    bus.subscribe(InvestigationActionExecuted, events.append)

    observation = run_investigation_intent(intent, target, allow_all, bus)

    assert target.calls == [intent]
    assert len(events) == 1
    assert events[0].intent == intent
    assert events[0].observation == observation
    assert events[0].correlation_id == intent.intent_id


def test_run_investigation_intent_denies_intent_before_execution() -> None:
    intent = InvestigationIntent(
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
        payload=(("secret_id", "secret-victim"),),
        identity="attacker",
        reason="Investigate cross-folder access",
    )
    target = RecordingInvestigationTarget()
    bus = EventBus()
    events: list[InvestigationActionExecuted] = []
    bus.subscribe(InvestigationActionExecuted, events.append)

    with pytest.raises(PermissionError, match="denied by guardrail"):
        run_investigation_intent(intent, target, lambda _: False, bus)

    assert target.calls == []
    assert events == []


def test_run_scenario_checks_compiles_and_runs_matching_pair(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    target = RecordingTarget()

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
    )

    assert isinstance(observations, tuple)
    assert len(target.calls) == 1
    check = target.calls[0]
    assert check.invariant_id == invariant.invariant_id
    assert check.method_id == method_spec.method_id
    assert check.scenario_id == scenario_position.scenario_id
    # The direct checker path carries no QDL refers_to fact, so the object
    # reference stays unresolved instead of being guessed from the field name.
    assert check.request == (("secret_id", None),)
    assert check.generator == "template"
    assert check.seed_id is None


def test_run_scenario_checks_accepts_duplicate_method_ids_as_input_entries(
    method_spec,
    method_spec_with_ids,
    scenario_position,
    invariant,
) -> None:
    target = RecordingTarget()

    observations = execute_scenario(
        (method_spec, method_spec_with_ids),
        (invariant,),
        scenario_position,
        target,
    )

    # Method identity is a semantic graph concern; the checker executes the
    # supplied bindings and does not silently discard a duplicate definition.
    assert len(observations) == 2
    assert len(target.calls) == 2


def test_run_scenario_checks_returns_empty_tuple_for_empty_inputs(
    scenario_position,
) -> None:
    target = RecordingTarget()

    assert execute_scenario((), (), scenario_position, target) == ()


def test_run_scenario_checks_skips_mismatched_layers_and_unknown_methods(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    public_method = method_spec.model_copy(
        update={
            "method_id": "grpc:public.method.Get",
            "layer": EndpointLayer.PUBLIC,
        }
    )
    public_invariant = invariant.model_copy(
        update={
            "invariant_id": "lockbox-public-read",
            "norm_id": "threat:public-read",
        }
    )
    unknown_method_invariant = invariant.model_copy(
        update={
            "invariant_id": "lockbox-unknown-read",
            "norm_id": "threat:unknown-read",
        }
    )
    target = RecordingTarget()

    observations = execute_scenario(
        (method_spec, public_method),
        (invariant, public_invariant, unknown_method_invariant),
        scenario_position,
        target,
    )

    # execute_scenario receives a Cartesian collection of methods and
    # invariants.  Endpoint-layer filtering excludes the public method, while
    # all invariants remain applicable to the private method.
    assert len(observations) == 3
    assert [check.invariant_id for check in target.calls] == [
        invariant.invariant_id,
        public_invariant.invariant_id,
        unknown_method_invariant.invariant_id,
    ]


def test_run_scenario_checks_runs_gateway_method_for_gateway_scenario(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    gateway_scenario = scenario_position.model_copy(
        update={
            "profile": scenario_position.profile.model_copy(
                update={"endpoint_layer": EndpointLayer.GATEWAY}
            )
        }
    )
    gateway_method = method_spec.model_copy(
        update={
            "method_id": "grpc:gateway.lockbox.v1.PayloadService.Get",
            "layer": EndpointLayer.GATEWAY,
        }
    )
    gateway_invariant = invariant.model_copy(
        update={"method_id": gateway_method.method_id}
    )
    target = RecordingTarget()

    observations = execute_scenario(
        (gateway_method,),
        (gateway_invariant,),
        gateway_scenario,
        target,
    )

    assert len(observations) == 1
    assert [check.method_id for check in target.calls] == [gateway_method.method_id]


def test_run_scenario_checks_returns_all_observations_and_publishes_events(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    second_invariant = invariant.model_copy(
        update={"invariant_id": "lockbox-foreign-secret-read-copy"}
    )
    target = RecordingTarget()
    bus = EventBus()
    events: list[CheckCompleted] = []
    bus.subscribe(CheckCompleted, events.append)

    observations = execute_scenario(
        (method_spec,),
        (invariant, second_invariant),
        scenario_position,
        target,
        bus,
    )

    assert len(observations) == 2
    assert [observation.check_id for observation in observations] == [
        check.check_id for check in target.calls
    ]
    assert [event.observation for event in events] == list(observations)
    assert [event.correlation_id for event in events] == [
        check.check_id for check in target.calls
    ]
    assert all(check.generator == "template" for check in target.calls)


def test_run_scenario_checks_delegates_to_generator_and_runs_each_check(
    monkeypatch,
    method_spec,
    scenario_position,
    invariant,
    check,
    denied_observation,
) -> None:
    target = Mock()
    event_bus = Mock()
    fuzzing_check = check.model_copy(
        update={"generator": "fuzzing", "seed_id": "seed-42"}
    )
    generator = Mock()
    generator.generate.return_value = (check, fuzzing_check)
    run_check = Mock(return_value=denied_observation)
    monkeypatch.setattr(pipeline, "run_check", run_check)

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
        event_bus,
        generator,
    )

    expected_plan = VerificationPlan(
        plan_id=f"plan:{invariant.invariant_id}:{method_spec.method_id}",
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
    )
    generator.generate.assert_called_once_with(
        expected_plan,
        method_spec,
        invariant,
        scenario_position,
    )
    assert run_check.call_args_list == [
        ((check, target, event_bus),),
        ((fuzzing_check, target, event_bus),),
    ]
    assert observations == (denied_observation, denied_observation)


def test_run_scenario_checks_with_zero_limit_generates_and_runs_no_checks(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    target = Mock()
    generator = Mock()

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
        generator=generator,
        max_checks=0,
    )

    assert observations == ()
    generator.generate.assert_not_called()
    target.assert_not_called()


def test_run_scenario_checks_with_limit_below_total_returns_earlier_observations(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    invariants = tuple(
        invariant.model_copy(update={"invariant_id": f"invariant-{number}"})
        for number in range(3)
    )
    target = RecordingTarget()
    generator = Mock(wraps=TemplateGenerator())

    observations = execute_scenario(
        (method_spec,),
        invariants,
        scenario_position,
        target,
        generator=generator,
        max_checks=2,
    )

    assert len(observations) == 2
    plans = tuple(
        VerificationPlan(
            plan_id=f"plan:{item.invariant_id}:{method_spec.method_id}",
            invariant_id=item.invariant_id,
            method_id=method_spec.method_id,
            scenario_id=scenario_position.scenario_id,
        )
        for item in invariants[:2]
    )
    assert generator.generate.call_args_list == [
        call(plans[0], method_spec, invariants[0], scenario_position),
        call(plans[1], method_spec, invariants[1], scenario_position),
    ]
    assert [check.invariant_id for check in target.calls] == [
        "invariant-0",
        "invariant-1",
    ]
    assert [observation.check_id for observation in observations] == [
        check.check_id for check in target.calls
    ]


def test_run_scenario_checks_with_limit_above_total_returns_all_observations(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    invariants = tuple(
        invariant.model_copy(update={"invariant_id": f"invariant-{number}"})
        for number in range(3)
    )
    target = RecordingTarget()
    generator = Mock(wraps=TemplateGenerator())

    observations = execute_scenario(
        (method_spec,),
        invariants,
        scenario_position,
        target,
        generator=generator,
        max_checks=4,
    )

    assert len(observations) == 3
    plans = tuple(
        VerificationPlan(
            plan_id=f"plan:{item.invariant_id}:{method_spec.method_id}",
            invariant_id=item.invariant_id,
            method_id=method_spec.method_id,
            scenario_id=scenario_position.scenario_id,
        )
        for item in invariants
    )
    assert generator.generate.call_args_list == [
        call(plans[0], method_spec, invariants[0], scenario_position),
        call(plans[1], method_spec, invariants[1], scenario_position),
        call(plans[2], method_spec, invariants[2], scenario_position),
    ]


def test_run_scenario_checks_with_limit_stops_inside_generator_result(
    monkeypatch,
    method_spec,
    scenario_position,
    invariant,
    check,
    denied_observation,
) -> None:
    target = Mock(return_value=denied_observation)
    generator = Mock()
    generator.generate.return_value = (check, check, check)
    run_check = Mock(return_value=denied_observation)
    monkeypatch.setattr(pipeline, "run_check", run_check)

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
        generator=generator,
        max_checks=2,
    )

    expected_plan = VerificationPlan(
        plan_id=f"plan:{invariant.invariant_id}:{method_spec.method_id}",
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
    )
    generator.generate.assert_called_once_with(
        expected_plan,
        method_spec,
        invariant,
        scenario_position,
    )
    assert run_check.call_count == 2
    assert observations == (denied_observation, denied_observation)


def test_run_scenario_checks_uses_allow_all_guardrail_by_default(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    target = RecordingTarget()

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
    )

    assert len(target.calls) == 1
    assert len(observations) == 1
    assert observations[0].check_id == target.calls[0].check_id
    assert observations[0].scenario_id == scenario_position.scenario_id


def test_run_scenario_checks_skips_checks_denied_by_guardrail(
    monkeypatch,
    method_spec,
    scenario_position,
    invariant,
    check,
) -> None:
    target = Mock()
    generator = Mock()
    generator.generate.return_value = (check,)
    guardrail = Mock()
    guardrail.allows.return_value = False
    run_check = Mock()
    monkeypatch.setattr(pipeline, "run_check", run_check)

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
        generator=generator,
        guardrail=guardrail,
    )

    guardrail.allows.assert_called_once_with(check)
    run_check.assert_not_called()
    target.assert_not_called()
    assert observations == ()


def test_run_scenario_checks_guardrail_does_not_spend_max_checks_budget(
    monkeypatch,
    method_spec,
    scenario_position,
    invariant,
    check,
    denied_observation,
) -> None:
    denied_check = check.model_copy(update={"check_id": "denied-check"})
    allowed_check = check.model_copy(update={"check_id": "allowed-check"})
    extra_check = check.model_copy(update={"check_id": "extra-check"})
    target = Mock()
    generator = Mock()
    generator.generate.return_value = (denied_check, allowed_check, extra_check)
    guardrail = Mock()
    guardrail.allows.side_effect = (False, True)
    run_check = Mock(return_value=denied_observation)
    monkeypatch.setattr(pipeline, "run_check", run_check)

    observations = execute_scenario(
        (method_spec,),
        (invariant,),
        scenario_position,
        target,
        generator=generator,
        max_checks=1,
        guardrail=guardrail,
    )

    assert run_check.call_args_list == [((allowed_check, target, None),)]
    assert observations == (denied_observation,)
