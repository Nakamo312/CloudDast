from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from cloud_dast.contracts.metrics import CampaignTimingSnapshot
from cloud_dast.model import VerdictStatus
from cloud_dast.model.events import ComponentInvoked, PhaseChanged
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState


def test_intent_lifecycle_rejects_invalid_transitions() -> None:
    metrics = CampaignMetrics()
    metrics.set_intent_state("intent", IntentState.PENDING)
    metrics.set_intent_state("intent", IntentState.EXECUTING)
    metrics.set_intent_state("intent", IntentState.UNSCOREABLE)
    metrics.set_intent_state("intent", IntentState.EXECUTING)
    metrics.set_intent_state("intent", IntentState.VERIFIED)

    with pytest.raises(ValueError, match="invalid intent transition"):
        metrics.set_intent_state("intent", IntentState.PENDING)


def test_pending_intent_reinitialization_is_idempotent() -> None:
    metrics = CampaignMetrics()
    metrics.set_intent_state("intent", IntentState.PENDING, letter="A")
    metrics.set_intent_state("intent", IntentState.PENDING, letter="B")

    assert metrics.intent_state("intent") is IntentState.PENDING
    assert metrics.snapshot().intent_labels["intent"] == "B"


def test_intent_lifecycle_must_start_pending() -> None:
    metrics = CampaignMetrics()

    with pytest.raises(ValueError, match="intent lifecycle must start at PENDING"):
        metrics.set_intent_state("intent", IntentState.EXECUTING)


def test_intent_terminal_states_have_no_outgoing_transitions() -> None:
    for terminal in (IntentState.VERIFIED, IntentState.BLOCKED):
        metrics = CampaignMetrics()
        metrics.set_intent_state("intent", IntentState.PENDING)
        metrics.set_intent_state("intent", IntentState.EXECUTING)
        metrics.set_intent_state("intent", terminal)

        with pytest.raises(ValueError, match="invalid intent transition"):
            metrics.set_intent_state("intent", IntentState.EXECUTING)


def test_concurrent_updates_preserve_runtime_counters() -> None:
    metrics = CampaignMetrics()
    updates = 200

    def update(_: int) -> None:
        metrics.model_request_started("grounding roles")
        metrics.record_tokens(1, 2, cached_input_tokens=1, phase="grounding:roles")
        metrics.record_generator_outcome("action:get", "strategy", VerdictStatus.PASS)
        metrics.record_finding()
        metrics.record_diff_pair("payload")
        metrics.record_grounding_cache_hit("roles")
        metrics.model_request_finished()

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(update, range(updates)))

    snapshot = metrics.snapshot()
    assert snapshot.model_requests_active == 0
    assert snapshot.model_requests_completed == updates
    assert snapshot.tokens.input_tokens == updates
    assert snapshot.tokens.cached_input_tokens == updates
    assert snapshot.tokens.output_tokens == updates * 2
    assert snapshot.tokens.request_count == updates
    assert snapshot.tokens_by_phase["grounding:roles"].request_count == updates
    assert snapshot.total_checks == updates
    assert snapshot.total_findings == updates
    assert snapshot.diff_pairs_evaluated == updates
    assert snapshot.diff_pairs_by_mode == {"payload": updates}
    assert snapshot.grounding_cache_hits == updates


def test_concurrent_intent_updates_preserve_lifecycle() -> None:
    metrics = CampaignMetrics()
    updates = 200

    def update(index: int) -> None:
        intent_id = f"intent:{index}"
        metrics.set_intent_state(intent_id, IntentState.PENDING, letter="A")
        metrics.set_intent_state(intent_id, IntentState.EXECUTING)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(update, range(updates)))

    snapshot = metrics.snapshot()
    assert snapshot.intent_states == {
        f"intent:{index}": IntentState.EXECUTING.value for index in range(updates)
    }
    assert snapshot.intent_labels == {
        f"intent:{index}": "A" for index in range(updates)
    }


def test_phase_events_populate_campaign_timing_snapshot() -> None:
    metrics = CampaignMetrics()
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    metrics.record_phase(PhaseChanged(phase="qdl_planning", occurred_at=started_at))
    metrics.record_phase(
        PhaseChanged(
            phase="executing",
            occurred_at=started_at + timedelta(minutes=10),
        )
    )
    metrics.record_phase(
        PhaseChanged(
            phase="evaluating",
            occurred_at=started_at + timedelta(minutes=25),
        )
    )
    metrics.record_phase(
        PhaseChanged(
            phase="finished",
            occurred_at=started_at + timedelta(minutes=30),
        )
    )

    timing = metrics.snapshot().timing

    assert isinstance(timing, CampaignTimingSnapshot)
    assert timing.wall_time == timedelta(minutes=30)
    assert timing.phase_elapsed == {
        "qdl_planning": timedelta(minutes=10),
        "executing": timedelta(minutes=15),
        "evaluating": timedelta(minutes=5),
        "finished": timedelta(),
    }


def test_component_events_populate_activity_snapshot() -> None:
    metrics = CampaignMetrics()
    metrics.record_component_event(
        ComponentInvoked(
            component="generator:grammar",
            input_digest="digest",
            input_completeness={"sink_facts": 2, "probe_fields": 1},
            fallback_modes=(),
            invocation_id="invocation",
            check_id="check",
            observation_id="observation",
            path_id="path",
        )
    )

    activity = metrics.snapshot().component_activity["generator:grammar"]

    assert activity.invocations == 1
    assert activity.input_completeness == {"sink_facts": 2, "probe_fields": 1}
    assert activity.summary()["correlations"]["complete"] == 1


def test_token_snapshots_stay_detached_from_later_updates() -> None:
    metrics = CampaignMetrics()
    metrics.record_tokens(10, 3, cached_input_tokens=4, phase="grounding:roles")
    before = metrics.snapshot()
    metrics.record_tokens(5, 2, cached_input_tokens=1, phase="grounding:roles")
    after = metrics.snapshot()

    assert before.tokens.input_tokens == 10
    assert before.tokens.output_tokens == 3
    assert before.tokens.cached_input_tokens == 4
    assert before.tokens.request_count == 1
    assert before.tokens_by_phase["grounding:roles"] == before.tokens
    assert after.tokens.input_tokens == 15
    assert after.tokens.output_tokens == 5
    assert after.tokens.cached_input_tokens == 5
    assert after.tokens.request_count == 2
    assert after.tokens_by_phase["grounding:roles"] == after.tokens


def test_snapshot_is_immutable_and_keeps_summary_shape() -> None:
    metrics = CampaignMetrics()
    metrics.set_intent_state("intent", IntentState.PENDING, letter="A")
    metrics.set_intent_state("intent", IntentState.EXECUTING)
    metrics.record_tokens(10, 5, cached_input_tokens=4, phase="grounding:roles")
    metrics.set_model_id("test-model")

    snapshot = metrics.snapshot()

    with pytest.raises(TypeError):
        snapshot.intent_states["intent"] = "blocked"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        snapshot.model_id = "other-model"  # type: ignore[misc]

    summary = snapshot.summary()
    assert snapshot.intent_states == {"intent": "executing"}
    assert summary["intents"] == {
        "total": 1,
        "pending": 0,
        "ready": 0,
        "executing": 1,
        "verified": 0,
        "unscoreable": 0,
        "blocked": 0,
    }
    assert summary["model"] == "test-model"
