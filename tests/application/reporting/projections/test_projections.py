from __future__ import annotations

from cloud_dast.model.events import CheckCompleted, CoverageUpdated, FindingRaised
from cloud_dast_reporting import ReportService


def _class_key(scenario):
    profile = scenario.profile
    return (
        profile.scope_relation,
        profile.binding_level,
        profile.endpoint_layer,
        profile.resource_state,
        profile.identity_class,
        profile.addressing_mode,
    )


def test_project_contracts_groups_methods_by_service(
    method_spec,
) -> None:
    other_service_method = method_spec.model_copy(
        update={
            "method_id": "grpc:other.Service.Get",
            "service": "other.Service",
            "name": "Get",
        }
    )
    same_service_method = method_spec.model_copy(
        update={"method_id": "grpc:lockbox.PayloadService.List"}
    )

    contracts = ReportService().contracts(
        (method_spec, other_service_method, same_service_method)
    )

    assert contracts == {
        method_spec.service: (method_spec, same_service_method),
        other_service_method.service: (other_service_method,),
    }


def test_project_contracts_returns_empty_mapping_without_methods() -> None:
    assert ReportService().contracts(()) == {}


def test_project_evidence_returns_empty_mapping_without_events() -> None:
    assert ReportService().evidence(()) == {}


def test_project_evidence_links_findings_to_observations(
    denied_observation,
    allowed_observation,
    finding,
) -> None:
    events = (
        CheckCompleted(observation=denied_observation),
        CheckCompleted(observation=allowed_observation),
        FindingRaised(finding=finding),
    )

    evidence = ReportService().evidence(events)

    assert evidence == {
        denied_observation.observation_id: None,
        allowed_observation.observation_id: finding.finding_id,
    }


def test_project_evidence_keeps_finding_when_check_event_is_replayed(
    allowed_observation,
    finding,
) -> None:
    events = (
        FindingRaised(finding=finding),
        CheckCompleted(observation=allowed_observation),
    )

    evidence = ReportService().evidence(events)

    assert evidence == {allowed_observation.observation_id: finding.finding_id}


def test_project_evidence_uses_latest_finding_for_observation(
    allowed_observation,
    finding,
) -> None:
    latest_finding = finding.model_copy(update={"finding_id": "latest-finding"})
    events = (
        FindingRaised(finding=finding),
        FindingRaised(finding=latest_finding),
    )

    evidence = ReportService().evidence(events)

    assert evidence == {allowed_observation.observation_id: latest_finding.finding_id}


def test_project_coverage_marks_covered_and_uncovered_scenarios(
    scenario_position,
    denied_observation,
) -> None:
    uncovered = scenario_position.model_copy(
        update={"scenario_id": "uncovered-scenario"}
    )

    coverage = ReportService().coverage(
        (denied_observation,),
        (scenario_position, uncovered),
    )

    assert coverage == {
        scenario_position.scenario_id: True,
        uncovered.scenario_id: False,
    }


def test_project_coverage_returns_empty_mapping_without_inputs() -> None:
    assert ReportService().coverage((), ()) == {}


def test_project_coverage_from_events_marks_covered_and_uncovered_scenarios(
    scenario_position,
    check,
) -> None:
    uncovered = scenario_position.model_copy(
        update={"scenario_id": "uncovered-scenario"}
    )
    event = CoverageUpdated(
        check_id=check.check_id,
        method_id=check.method_id,
        invariant_id=check.invariant_id,
        scenario_id=scenario_position.scenario_id,
    )

    coverage = ReportService().coverage_from_events(
        (event,), (scenario_position, uncovered)
    )

    assert coverage == {
        scenario_position.scenario_id: True,
        uncovered.scenario_id: False,
    }


def test_project_coverage_from_events_ignores_duplicate_coverage_events(
    scenario_position,
    check,
) -> None:
    events = (
        CoverageUpdated(
            check_id=check.check_id,
            method_id=check.method_id,
            invariant_id=check.invariant_id,
            scenario_id=scenario_position.scenario_id,
        ),
        CoverageUpdated(
            check_id=f"{check.check_id}-repeat",
            method_id=check.method_id,
            invariant_id=check.invariant_id,
            scenario_id=scenario_position.scenario_id,
        ),
    )

    coverage = ReportService().coverage_from_events(events, (scenario_position,))

    assert coverage == {scenario_position.scenario_id: True}


def test_project_coverage_from_events_requires_coverage_event(
    scenario_position,
    denied_observation,
) -> None:
    events = (CheckCompleted(observation=denied_observation),)

    coverage = ReportService().coverage_from_events(events, (scenario_position,))

    assert coverage == {scenario_position.scenario_id: False}


def test_project_method_coverage_marks_covered_and_uncovered_methods(
    method_spec,
    check,
) -> None:
    uncovered = method_spec.model_copy(
        update={"method_id": "grpc:uncovered.Service.Get"}
    )
    event = CoverageUpdated(
        check_id=check.check_id,
        method_id=method_spec.method_id,
        invariant_id=check.invariant_id,
        scenario_id=check.scenario_id,
    )

    coverage = ReportService().method_coverage((event,), (method_spec, uncovered))

    assert coverage == {
        method_spec.method_id: True,
        uncovered.method_id: False,
    }


def test_project_method_and_action_coverage_are_separate(
    method_spec,
    check,
) -> None:
    event = CoverageUpdated(
        check_id=check.check_id,
        method_id=method_spec.method_id,
        invariant_id=check.invariant_id,
        scenario_id=check.scenario_id,
    )

    coverage = ReportService().method_action_coverage((event,), (method_spec,))

    assert coverage.methods == {method_spec.method_id: True}
    assert coverage.actions == {f"action:{method_spec.method_id}": True}


def test_project_invariant_coverage_marks_covered_and_uncovered_invariants(
    invariant,
    check,
) -> None:
    uncovered = invariant.model_copy(update={"invariant_id": "uncovered-invariant"})
    event = CoverageUpdated(
        check_id=check.check_id,
        method_id=check.method_id,
        invariant_id=invariant.invariant_id,
        scenario_id=check.scenario_id,
    )

    coverage = ReportService().invariant_coverage((event,), (invariant, uncovered))

    assert coverage == {
        invariant.invariant_id: True,
        uncovered.invariant_id: False,
    }


def test_project_scenarios_returns_single_scenario_group(
    scenario_position,
) -> None:
    assert ReportService().scenarios((scenario_position,)) == {
        _class_key(scenario_position): (scenario_position,)
    }


def test_project_scenarios_groups_same_equivalence_class(
    scenario_position,
) -> None:
    same_class = scenario_position.model_copy(
        update={"scenario_id": "same-class-scenario"}
    )

    assert ReportService().scenarios((scenario_position, same_class)) == {
        _class_key(scenario_position): (
            scenario_position,
            same_class,
        )
    }


def test_project_scenarios_separates_different_profiles(
    scenario_position,
) -> None:
    other_profile = scenario_position.model_copy(
        update={
            "scenario_id": "other-profile-scenario",
            "profile": scenario_position.profile.model_copy(
                update={"binding_level": "resource"}
            ),
        }
    )

    assert ReportService().scenarios((scenario_position, other_profile)) == {
        _class_key(scenario_position): (scenario_position,),
        _class_key(other_profile): (other_profile,),
    }


def test_project_scenarios_keeps_input_order_in_group(
    scenario_position,
) -> None:
    first = scenario_position.model_copy(update={"scenario_id": "first"})
    second = scenario_position.model_copy(update={"scenario_id": "second"})
    third = scenario_position.model_copy(update={"scenario_id": "third"})

    grouped = ReportService().scenarios((second, third, first))

    assert grouped == {_class_key(scenario_position): (second, third, first)}
