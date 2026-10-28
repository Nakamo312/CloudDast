from __future__ import annotations

import pytest

from cloud_dast.infrastructure import EventBus
from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
)
from cloud_dast.model.events import CheckCompleted, CoverageUpdated
from cloud_dast.runtime.execution.checks import run_check


class FakeTarget:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, check):
        self.calls.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary="Access denied",
            transport_status=HttpStatus(code=403),
        )


def test_run_check_executes_target_and_publishes_event(check) -> None:
    target = FakeTarget()
    bus = EventBus()
    events: list[CheckCompleted] = []
    bus.subscribe(CheckCompleted, events.append)

    observation = run_check(check, target, bus)

    assert target.calls == [check]
    assert observation.check_id == check.check_id
    assert observation.scenario_id == check.scenario_id
    assert len(events) == 1
    assert events[0].observation == observation
    # No accepted field-role fact exists in this unit scope, so the request is
    # redacted by default; method identity still survives for replay.
    assert events[0].check is None
    assert events[0].check_redacted is True
    assert events[0].method_id == check.method_id
    assert events[0].correlation_id == check.check_id


def test_run_check_keeps_method_id_when_request_is_redacted(check) -> None:
    sensitive_check = check.model_copy(
        update={"request": (("payload", "top-secret-value"),)}
    )
    target = FakeTarget()
    bus = EventBus()
    events: list[CheckCompleted] = []
    bus.subscribe(CheckCompleted, events.append)

    run_check(sensitive_check, target, bus)

    assert events[0].check is None
    assert events[0].check_redacted is True
    assert events[0].method_id == check.method_id


def test_run_check_publishes_method_id_for_three_hundred_checks(check) -> None:
    target = FakeTarget()
    bus = EventBus()
    events: list[CheckCompleted] = []
    bus.subscribe(CheckCompleted, events.append)

    for index in range(300):
        sensitive_check = check.model_copy(
            update={"request": (("payload", f"secret-{index}"),)}
        )
        run_check(sensitive_check, target, bus)

    assert len(events) == 300
    assert all(event.method_id == check.method_id for event in events)
    assert all(event.method_id is not None for event in events)


def test_run_check_publishes_completion_and_coverage_in_order(check) -> None:
    target = FakeTarget()
    bus = EventBus()
    published: list[str] = []
    bus.subscribe(CheckCompleted, lambda _: published.append("completed"))
    bus.subscribe(CoverageUpdated, lambda _: published.append("coverage"))

    run_check(check, target, bus)

    assert published == ["completed", "coverage"]


def test_run_check_carries_probe_marker_into_observation(check) -> None:
    probe_check = check.model_copy(update={"probe_marker": "dast-marker:check-1"})

    observation = run_check(probe_check, FakeTarget())

    assert observation.probe_marker == "dast-marker:check-1"


def test_run_check_publishes_coverage_event_with_provenance(check) -> None:
    target = FakeTarget()
    bus = EventBus()
    events: list[CoverageUpdated] = []
    bus.subscribe(CoverageUpdated, events.append)

    run_check(check, target, bus)

    assert len(events) == 1
    assert events[0].check_id == check.check_id
    assert events[0].scenario_id == check.scenario_id
    assert events[0].correlation_id == check.check_id


def test_run_check_rejects_observation_from_another_check(check) -> None:
    observation = Observation(
        check_id="another-check",
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="Access denied",
        transport_status=HttpStatus(code=403),
    )

    with pytest.raises(ValueError, match="another check"):
        run_check(check, lambda _: observation)


def test_run_check_rejects_observation_from_another_scenario(check) -> None:
    observation = Observation(
        check_id=check.check_id,
        scenario_id="another-scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="Access denied",
        transport_status=HttpStatus(code=403),
    )

    with pytest.raises(ValueError, match="another scenario"):
        run_check(check, lambda _: observation)
