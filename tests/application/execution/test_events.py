from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from cloud_dast.infrastructure import EventBus, JsonlEventStore
from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    EventScope,
    FindingRaised,
    InvestigationActionExecuted,
    InvestigationIntent,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.runtime.execution.checks import bind_event_context, run_check


def test_event_bus_dispatches_only_subscribed_type(finding) -> None:
    bus = EventBus()
    completed: list[CheckCompleted] = []
    raised: list[FindingRaised] = []

    bus.subscribe(CheckCompleted, completed.append)
    bus.subscribe(FindingRaised, raised.append)

    finding_event = FindingRaised(finding=finding)
    bus.publish(finding_event)

    assert completed == []
    assert raised == [finding_event]


def test_event_bus_serializes_concurrent_publishes(finding) -> None:
    bus = EventBus()
    state = {"active": 0, "max_active": 0, "events": 0}
    state_lock = threading.Lock()

    def handler(event: FindingRaised) -> None:
        del event
        with state_lock:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        time.sleep(0.005)
        with state_lock:
            state["active"] -= 1
            state["events"] += 1

    bus.subscribe(FindingRaised, handler)
    events = [FindingRaised(finding=finding) for _ in range(32)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(bus.publish, events))

    assert state["max_active"] == 1
    assert state["events"] == len(events)


def test_event_scope_rejects_unscoped_events_from_concurrent_runs() -> None:
    first = EventScope(campaign_id="campaign:one", run_id="run:one")
    second = EventScope(campaign_id="campaign:two", run_id="run:two")
    first_event = first.apply(
        QdlPathEvaluated(
            path_id="path:one",
            outcome="blocked",
            attempted_steps=0,
            step_count=1,
            probe_count=0,
            reason="setup unavailable",
        )
    )
    second_event = second.apply(
        QdlPathEvaluated(
            path_id="path:two",
            outcome="blocked",
            attempted_steps=0,
            step_count=1,
            probe_count=0,
            reason="budget exhausted",
        )
    )
    foreign_unscoped = QdlPathEvaluated(
        path_id="path:foreign",
        outcome="blocked",
        attempted_steps=0,
        step_count=1,
        probe_count=0,
        reason="legacy producer",
    )

    stream = (first_event, second_event, foreign_unscoped)
    assert first.run_events(stream) == (first_event,)
    assert second.run_events(stream) == (second_event,)


def test_event_scope_legacy_jsonl_migration_is_explicit() -> None:
    old = QdlPathEvaluated(
        path_id="path:old",
        outcome="blocked",
        attempted_steps=0,
        step_count=1,
        probe_count=0,
        reason="old JSONL",
    )
    current = QdlPathEvaluated(
        path_id="path:current",
        outcome="blocked",
        attempted_steps=0,
        step_count=1,
        probe_count=0,
        reason="legacy JSONL",
    )
    scope = EventScope(
        campaign_id="campaign:migrated",
        run_id="run:migrated",
        baseline_event_ids=frozenset({old.event_id}),
        accept_legacy_unscoped=True,
    )

    assert scope.run_events((old, current)) == (current,)


def test_check_events_carry_scope_and_execution_correlation(check) -> None:
    bus = EventBus()
    completed: list[CheckCompleted] = []
    coverage: list[CoverageUpdated] = []
    bus.subscribe(CheckCompleted, completed.append)
    bus.subscribe(CoverageUpdated, coverage.append)
    scope = EventScope(campaign_id="campaign:test", run_id="run:test")

    with bind_event_context(
        bus,
        scope=scope,
        action_id=check.method_id,
        path_id="path:test",
        step_id="step:test",
    ):
        run_check(check, lambda item: _observation(item), bus)

    assert completed[0].campaign_id == "campaign:test"
    assert completed[0].run_id == "run:test"
    assert completed[0].action_id == check.method_id
    assert completed[0].path_id == "path:test"
    assert completed[0].step_id == "step:test"
    assert completed[0].check_id == check.check_id
    assert completed[0].observation_id == completed[0].observation.observation_id
    assert coverage[0].path_id == "path:test"
    assert coverage[0].step_id == "step:test"


def _observation(check):
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="Access denied",
        transport_status=HttpStatus(code=403),
    )


def test_jsonl_event_store_roundtrips_typed_events(
    tmp_path,
    finding,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    event = FindingRaised(finding=finding)
    store.append(event)

    restored = next(iter(store.read()))

    assert restored == event


def test_jsonl_event_store_roundtrips_qdl_step_evaluation(tmp_path) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    event = QdlStepEvaluated(
        path_id="path:qdl",
        step_id="step:qdl",
        verdict=VerdictStatus.FAIL,
        phase="active",
        reason="QDL norm violated",
        step_index=0,
    )
    store.append(event)

    restored = next(iter(store.read()))

    assert restored == event


def test_jsonl_event_store_roundtrips_coverage_update(tmp_path, check) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    event = CoverageUpdated(
        check_id=check.check_id,
        method_id=check.method_id,
        invariant_id=check.invariant_id,
        scenario_id=check.scenario_id,
    )
    store.append(event)

    restored = next(iter(store.read()))

    assert restored == event


def test_jsonl_event_store_roundtrips_investigation_action_executed(
    tmp_path,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    intent = InvestigationIntent(
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
        payload=(
            ("secret_id", "secret-victim"),
            ("nested", ("value", 1, True, None)),
        ),
        identity="attacker",
        reason="Investigate cross-folder access",
    )
    observation = Observation(
        check_id="investigation-check",
        scenario_id="cross-folder-private",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="Access denied",
        transport_status=HttpStatus(code=403),
    )
    event = InvestigationActionExecuted(intent=intent, observation=observation)
    store.append(event)

    restored = next(iter(store.read()))

    assert restored.event_type == "investigation_action_executed"
    # No accepted field-role fact exists here, so even the id-named reference
    # is redacted by default before the event becomes durable.
    assert restored.intent.payload[0][0] == "secret_id"
    assert restored.intent.payload[0][1].startswith("redacted:sha256:")
    nested = restored.intent.payload[1]
    assert nested[0] == "nested"
    assert isinstance(nested[1], str)
    assert nested[1].startswith("redacted:sha256:")


def test_jsonl_event_store_rejects_duplicate_event_id(
    tmp_path,
    finding,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    event = FindingRaised(finding=finding)
    store.append(event)

    with pytest.raises(ValueError, match="duplicate event_id"):
        store.append(event)


def test_jsonl_event_store_truncates_partial_last_line(
    tmp_path,
    finding,
) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    event = FindingRaised(finding=finding)
    store.append(event)
    with path.open("ab") as stream:
        stream.write(b'{"event_type":"finding_raised"')

    restored_store = JsonlEventStore(path)

    assert list(restored_store.read()) == [event]


def test_jsonl_event_store_preserves_complete_last_line_without_newline(
    tmp_path,
    finding,
) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    event = FindingRaised(finding=finding)
    store.append(event)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))

    restored_store = JsonlEventStore(path)
    assert list(restored_store.read()) == [event]

    next_event = FindingRaised(finding=finding)
    restored_store.append(next_event)

    assert list(restored_store.read()) == [event, next_event]


def test_jsonl_event_store_rejects_corrupted_line_in_middle(
    tmp_path,
    finding,
) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(FindingRaised(finding=finding))
    path.write_bytes(b"not-json\n" + path.read_bytes())

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        JsonlEventStore(path)


def test_jsonl_event_store_appends_from_multiple_threads(
    tmp_path,
    finding,
) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    events = [FindingRaised(finding=finding) for _ in range(50)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(store.append, events))

    restored = list(store.read())
    assert len(restored) == len(events)
    assert len({event.event_id for event in restored}) == len(events)
