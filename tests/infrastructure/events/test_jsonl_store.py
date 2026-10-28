from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from multiprocessing import get_context
from pathlib import Path

import pytest

from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.infrastructure.events.jsonl_store import build_hash_chain_record
from cloud_dast.infrastructure.jsonl import JsonlFile, redact_json_payload
from cloud_dast.model import (
    AccessOutcome,
    Check,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    ComponentInvoked,
    InvestigationActionExecuted,
    InvestigationIntent,
    PhaseChanged,
    QdlStepEvaluated,
)


def _event(step_id: str) -> QdlStepEvaluated:
    return QdlStepEvaluated(
        path_id="path:test",
        step_id=step_id,
        verdict=VerdictStatus.FAIL,
        phase="active",
        reason="test",
        step_index=0,
    )


def _append_from_process(path: str, worker: int) -> None:
    JsonlEventStore(path).append(_event(f"step:{worker}"))


def test_phase_changed_roundtrips_typed_event(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    event = PhaseChanged(phase="executing")

    JsonlEventStore(path).append(event)

    assert tuple(JsonlEventStore(path).read()) == (event,)


def test_component_invoked_roundtrips_typed_event(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    event = ComponentInvoked(
        component="generator:grammar",
        input_digest="digest",
        input_completeness={"sink_facts": 3, "probe_fields": 2, "dialects": 1},
        fallback_modes=("generic",),
        invocation_id="invocation",
        check_id="check",
        observation_id="observation",
        path_id="path",
    )

    JsonlEventStore(path).append(event)

    assert tuple(JsonlEventStore(path).read()) == (event,)


def test_separate_process_writers_keep_one_valid_event_per_line(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    workers = [
        get_context("fork").Process(
            target=_append_from_process, args=(str(path), index)
        )
        for index in range(8)
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
        assert worker.exitcode == 0

    events = list(JsonlEventStore(path).read())
    assert len(events) == len(workers)
    assert len({event.event_id for event in events}) == len(workers)
    assert {event.step_id for event in events} == {
        f"step:{index}" for index in range(len(workers))
    }


def test_writer_reconciles_tail_written_by_another_store(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    first = JsonlEventStore(path)
    second = JsonlEventStore(path)

    first.append(_event("step:first"))
    second.append(_event("step:second"))

    assert [event.step_id for event in JsonlEventStore(path).read()] == [
        "step:first",
        "step:second",
    ]


def test_normal_append_does_not_read_complete_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))

    def fail_read_bytes(_: Path) -> bytes:
        raise AssertionError("normal append must not read the complete file")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    store.append(_event("step:second"))

    assert [event.step_id for event in store.read()] == [
        "step:first",
        "step:second",
    ]


def test_read_new_tracks_each_consumer_independently(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))

    assert [event.step_id for event in store.read_new("consumer-a")] == ["step:first"]
    store.append(_event("step:second"))

    assert [event.step_id for event in store.read_new("consumer-a")] == ["step:second"]
    assert [event.step_id for event in store.read_new("consumer-b")] == [
        "step:first",
        "step:second",
    ]
    assert store.read_new("consumer-a") == ()


def test_read_new_reconciles_tail_written_by_another_store(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    first = JsonlEventStore(path)
    second = JsonlEventStore(path)

    first.append(_event("step:first"))
    assert [event.step_id for event in second.read_new("consumer")] == ["step:first"]
    first.append(_event("step:second"))

    assert [event.step_id for event in second.read_new("consumer")] == ["step:second"]


def test_read_does_not_hold_the_file_lock_while_yielding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    original_locked = JsonlFile.locked
    lock_is_active = False

    @contextmanager
    def locked(self: JsonlFile):
        nonlocal lock_is_active
        lock_is_active = True
        with original_locked(self):
            yield
        lock_is_active = False

    monkeypatch.setattr(JsonlFile, "locked", locked)
    events = store.read()

    assert next(events).step_id == "step:first"
    assert lock_is_active is False
    assert list(events) == []


def test_check_event_does_not_persist_secret_request_value(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    check = Check(
        invariant_id="invariant",
        method_id="method",
        scenario_id="scenario",
        request=(("payload", "top-secret-value"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
    )

    event = CheckCompleted(check=check, observation=observation)
    assert event.check is None
    assert event.check_redacted is True

    JsonlEventStore(path).append(event)
    raw = path.read_text(encoding="utf-8")
    assert "top-secret-value" not in raw
    persisted = tuple(JsonlEventStore(path).read())
    assert persisted[0].check is None
    assert persisted[0].check_redacted is True
    assert persisted[0].method_id == check.method_id


def test_check_event_redacts_id_named_fields_without_accepted_roles(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    check = Check(
        invariant_id="invariant",
        method_id="method",
        scenario_id="scenario",
        request=(("session_id", "session-secret"),),
        identities=("attacker",),
    )
    event = CheckCompleted(
        check=check,
        observation=Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary="denied",
        ),
    )

    JsonlEventStore(path).append(event)
    raw = path.read_text(encoding="utf-8")
    assert "session-secret" not in raw
    restored = tuple(JsonlEventStore(path).read())
    assert restored[0].check is None
    assert restored[0].check_redacted is True
    assert restored[0].method_id == check.method_id


def test_check_event_redacts_full_response_values(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        response_tree=(("payload.token", "tok-full-fidelity"),),
    )

    JsonlEventStore(path).append(CheckCompleted(observation=observation))

    raw = path.read_text(encoding="utf-8")
    assert "tok-full-fidelity" not in raw
    persisted = tuple(JsonlEventStore(path).read())
    value = persisted[0].observation.response_tree[0][1]
    assert isinstance(value, str)
    assert value.startswith("redacted:sha256:")
    assert "tok-full-fidelity" not in value


def test_investigation_event_redacts_fields_without_accepted_roles(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    intent = InvestigationIntent(
        method_id="get",
        payload=(("password", "secret-value"), ("resource_id", "resource-1")),
        identity="attacker",
        reason="investigate",
    )
    observation = Observation(
        check_id="check-1",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
    )

    JsonlEventStore(path).append(
        InvestigationActionExecuted(intent=intent, observation=observation)
    )

    raw = path.read_text(encoding="utf-8")
    assert "secret-value" not in raw
    assert "resource-1" not in raw
    persisted = tuple(JsonlEventStore(path).read())
    assert persisted[0].intent.payload[0][1].startswith("redacted:sha256:")
    assert persisted[0].intent.payload[1][1].startswith("redacted:sha256:")


def test_redact_json_payload_retains_only_role_accepted_fields() -> None:
    payload = json.dumps(
        {
            "request": [
                ["order_id", "order-victim"],
                ["session_id", "session-secret"],
            ]
        }
    ).encode("utf-8")

    redacted = json.loads(redact_json_payload(payload, retained_fields={"order_id"}))

    assert redacted["request"][0] == ["order_id", "order-victim"]
    assert redacted["request"][1][0] == "session_id"
    assert redacted["request"][1][1].startswith("redacted:sha256:")


def test_redact_json_payload_reports_missing_roles_as_deficits(
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = json.dumps({"request": [["session_id", "session-secret"]]}).encode(
        "utf-8"
    )

    with caplog.at_level("WARNING", logger="cloud_dast.infrastructure.jsonl"):
        redact_json_payload(payload)

    assert "session_id" in caplog.text
    assert "replay-safe roles" in caplog.text


def test_jsonl_artifacts_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "private-events" / "events.jsonl"

    previous_umask = os.umask(0o000)
    try:
        JsonlEventStore(path).append(_event("step:first"))
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.with_name(path.name + ".lock").stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_event_store_persists_a_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)

    store.append(_event("step:first"))
    store.append(_event("step:second"))

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[0]["integrity"]["previous"] == "0" * 64
    assert records[1]["integrity"]["previous"] == records[0]["integrity"]["hash"]
    assert records[1]["integrity"]["version"] == 1


def test_event_store_rejects_tampered_event_payload(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    store.append(_event("step:second"))
    lines = path.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[0])
    record["event"]["step_id"] = "step:attacker"
    lines[0] = json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(b"".join(lines))

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        tuple(JsonlEventStore(path).read())


def test_event_store_rejects_reordered_events(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    store.append(_event("step:second"))
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(reversed(lines)))

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        tuple(JsonlEventStore(path).read())


def test_event_store_rejects_an_unwrapped_injected_event(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    with path.open("ab") as stream:
        stream.write(_event("step:injected").model_dump_json().encode() + b"\n")

    with pytest.raises(ValueError, match="invalid event JSON at line 2"):
        tuple(JsonlEventStore(path).read())


def test_event_store_rejects_uncovered_event_fields(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    payload = _event("step:first").model_dump(mode="json")
    payload["injected"] = "not-a-domain-event-field"
    record = build_hash_chain_record(payload, "0" * 64)
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        JsonlEventStore(path)


def test_event_store_rejects_uncovered_record_fields(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["uncovered"] = "outside the chain hash"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        JsonlEventStore(path)


def test_event_store_rejects_a_tampered_record_hash(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)
    store.append(_event("step:first"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["integrity"]["hash"] = "a" * 64
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid event JSON at line 1"):
        JsonlEventStore(path)
