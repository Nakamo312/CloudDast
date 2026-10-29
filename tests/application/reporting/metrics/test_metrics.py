from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from cloud_dast.contracts.metrics import (
    CampaignMetricsSnapshot,
    CampaignTimingSnapshot,
    TokenUsageSnapshot,
    measure_campaign_timing,
    measure_component_activity,
)
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    ComponentSkipped,
    DomainEvent,
    DownstreamDecision,
    PhaseChanged,
    measure_event_time_bounds,
)


def test_measure_event_time_bounds_returns_none_without_events() -> None:
    assert measure_event_time_bounds(()) is None


def test_measure_event_time_bounds_uses_min_and_max_timestamps() -> None:
    first = DomainEvent(occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
    middle = DomainEvent(occurred_at=first.occurred_at + timedelta(minutes=5))
    last = DomainEvent(occurred_at=first.occurred_at + timedelta(minutes=10))

    assert measure_event_time_bounds((middle, first, last)) == (
        first.occurred_at,
        last.occurred_at,
    )


def test_measure_campaign_timing_returns_empty_snapshot_without_events() -> None:
    timing = measure_campaign_timing(())

    assert timing == CampaignTimingSnapshot()
    assert timing.wall_time == timedelta()
    assert timing.phase_elapsed == {}


def test_measure_campaign_timing_uses_latest_event_without_phase_events() -> None:
    first = DomainEvent(occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
    last = DomainEvent(occurred_at=first.occurred_at + timedelta(minutes=12))

    timing = measure_campaign_timing((first, last))

    assert timing.wall_time == timedelta(minutes=12)
    assert timing.phase_elapsed == {}


def test_measure_campaign_timing_aggregates_phase_elapsed() -> None:
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    events = (
        DomainEvent(occurred_at=started_at),
        PhaseChanged(phase="qdl_planning", occurred_at=started_at),
        DomainEvent(occurred_at=started_at + timedelta(minutes=5)),
        PhaseChanged(
            phase="executing",
            occurred_at=started_at + timedelta(minutes=10),
        ),
        DomainEvent(occurred_at=started_at + timedelta(minutes=20)),
        PhaseChanged(
            phase="evaluating",
            occurred_at=started_at + timedelta(minutes=25),
        ),
        PhaseChanged(
            phase="finished",
            occurred_at=started_at + timedelta(minutes=30),
        ),
        DomainEvent(occurred_at=started_at + timedelta(minutes=35)),
    )

    timing = measure_campaign_timing(events)

    assert timing.wall_time == timedelta(minutes=30)
    assert timing.phase_elapsed == {
        "qdl_planning": timedelta(minutes=10),
        "executing": timedelta(minutes=15),
        "evaluating": timedelta(minutes=5),
        "finished": timedelta(),
    }


def test_measure_campaign_timing_deduplicates_replayed_events() -> None:
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    planning = PhaseChanged(phase="qdl_planning", occurred_at=started_at)
    executing = PhaseChanged(
        phase="executing",
        occurred_at=started_at + timedelta(minutes=3),
    )

    timing = measure_campaign_timing((planning, executing, planning, executing))

    assert timing.wall_time == timedelta(minutes=3)
    assert timing.phase_elapsed == {
        "qdl_planning": timedelta(minutes=3),
        "executing": timedelta(),
    }


def test_measure_campaign_timing_accumulates_repeated_phases() -> None:
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    events = (
        PhaseChanged(phase="executing", occurred_at=started_at),
        PhaseChanged(
            phase="evaluating",
            occurred_at=started_at + timedelta(minutes=2),
        ),
        PhaseChanged(
            phase="executing",
            occurred_at=started_at + timedelta(minutes=5),
        ),
        PhaseChanged(
            phase="finished",
            occurred_at=started_at + timedelta(minutes=8),
        ),
    )

    timing = measure_campaign_timing(events)

    assert timing.phase_elapsed == {
        "executing": timedelta(minutes=5),
        "evaluating": timedelta(minutes=3),
        "finished": timedelta(),
    }


def test_campaign_metrics_snapshot_contains_timing_and_summary() -> None:
    timing = CampaignTimingSnapshot(
        wall_time=timedelta(minutes=30),
        phase_elapsed={
            "qdl_planning": timedelta(minutes=10),
            "executing": timedelta(minutes=20),
        },
    )
    snapshot = CampaignMetricsSnapshot(timing=timing)

    assert snapshot.timing is not timing
    assert snapshot.timing == timing
    assert snapshot.summary()["timing"] == {
        "wall_time": 1800.0,
        "phase_elapsed": {
            "qdl_planning": 600.0,
            "executing": 1200.0,
        },
    }


def test_campaign_timing_snapshot_is_immutable() -> None:
    timing = CampaignTimingSnapshot(
        wall_time=timedelta(minutes=1),
        phase_elapsed={"executing": timedelta(seconds=30)},
    )

    with pytest.raises(FrozenInstanceError):
        timing.wall_time = timedelta(minutes=2)  # type: ignore[misc]
    with pytest.raises(TypeError):
        timing.phase_elapsed["evaluating"] = timedelta(seconds=1)  # type: ignore[index]


def test_component_activity_distinguishes_zero_selections_from_zero_witnesses() -> None:
    never_selected = measure_component_activity(
        (
            ComponentSkipped(
                component="generator:grammar",
                reason="disabled_by_flag",
            ),
        )
    )
    selected_without_witnesses = measure_component_activity(
        (
            *(
                ComponentInvoked(
                    component="generator:grammar",
                    input_digest=f"digest-{index}",
                    input_completeness={"sink_facts": 3},
                    invocation_id=f"invocation-{index}",
                )
                for index in range(50)
            ),
            ComponentOutput(
                component="generator:grammar",
                summary={
                    "candidates_produced": 50,
                    "candidates_survived_prefilter": 50,
                    "candidates_survived_guardrail": 50,
                    "scored": 50,
                    "witnesses": 0,
                },
            ),
            DownstreamDecision(
                component="generator:grammar",
                consumed=True,
                by="oracle",
                outcome="pass",
            ),
        )
    )

    assert never_selected["generator:grammar"].invocations == 0
    assert never_selected["generator:grammar"].skipped == 1
    assert never_selected["generator:grammar"].skip_reasons == {"disabled_by_flag": 1}

    activity = selected_without_witnesses["generator:grammar"]
    assert activity.invocations == 50
    assert activity.witnesses == 0
    assert activity.activation_proven is True


def test_component_activity_reports_input_completeness_and_fallbacks() -> None:
    activity = measure_component_activity(
        (
            ComponentInvoked(
                component="generator:grammar",
                input_digest="digest",
                input_completeness={
                    "sink_facts": 3,
                    "probe_fields": 2,
                    "dialects": 1,
                },
                fallback_modes=(),
                invocation_id="invocation",
                check_id="check",
                observation_id="observation",
                path_id="path",
            ),
            ComponentSkipped(
                component="generator:grammar",
                reason="empty_sink_facts",
                input_digest="empty-digest",
                input_completeness={"sink_facts": 0},
                fallback_modes=("generic",),
            ),
        )
    )["generator:grammar"]

    assert activity.input_completeness == {
        "sink_facts": 3,
        "probe_fields": 2,
        "dialects": 1,
    }
    assert activity.fallback_modes == {"generic": 1}
    assert activity.inputs_non_empty == 1
    assert any(correlation.is_complete for correlation in activity.correlations)


def test_zero_promotion_conversion_marks_consultation_skipped() -> None:
    events = []
    for index in range(3):
        invocation_id = f"consultation:deficit-{index}:0"
        events.extend(
            (
                ComponentInvoked(
                    component="consultation:alternatives",
                    input_digest=f"digest-{index}",
                    input_completeness={"observation_ids": 1},
                    invocation_id=invocation_id,
                    correlation_id=f"deficit-{index}",
                ),
                ComponentOutput(
                    component="consultation:alternatives",
                    summary={"proposals": 1, "parked": 2, "promoted": 0},
                    invocation_id=invocation_id,
                    correlation_id=f"deficit-{index}",
                ),
            )
        )

    activity = measure_component_activity(events)["consultation:alternatives"]

    assert activity.proposals == 3
    assert activity.parked == 6
    assert activity.promoted == 0
    assert activity.promotion_conversion == 0.0
    assert activity.skipped == 1
    assert activity.skip_reasons == {"promotion_conversion_zero": 1}


def test_gate_component_with_missing_evidence_decisions_is_activated() -> None:
    events = []
    for index in range(10):
        invocation_id = f"evidence_gate:work-{index}:0"
        events.extend(
            (
                ComponentInvoked(
                    component="evidence_gate:observation_required",
                    kind="gate",
                    input_digest=f"digest-{index}",
                    input_completeness={"deficits": 1},
                    invocation_id=invocation_id,
                    correlation_id=f"work-{index}",
                ),
                DownstreamDecision(
                    component="evidence_gate:observation_required",
                    kind="gate",
                    consumed=False,
                    by="consultation_outcome_policy",
                    outcome="missing_evidence",
                    invocation_id=invocation_id,
                    correlation_id=f"work-{index}",
                ),
            )
        )

    activity = measure_component_activity(events)["evidence_gate:observation_required"]

    assert activity.kind == "gate"
    assert activity.invocations == 10
    assert activity.inputs_non_empty == 10
    assert activity.downstream_rejected == 10
    assert activity.downstream_outcomes == {"missing_evidence": 10}
    assert activity.activation_failures == ()
    assert activity.activation_proven is True
    summary = activity.summary()
    assert summary["kind"] == "gate"
    assert summary["activation"] == {"proven": True, "failures": []}


def test_gate_component_without_decisions_is_not_activated() -> None:
    activity = measure_component_activity(
        (
            ComponentInvoked(
                component="evidence_gate:observation_required",
                kind="gate",
                input_digest="digest",
                input_completeness={"deficits": 1},
            ),
        )
    )["evidence_gate:observation_required"]

    assert activity.activation_failures == ("decisions=0",)
    assert activity.activation_proven is False


def test_gate_activation_does_not_require_producer_controls() -> None:
    activity = measure_component_activity(
        (
            ComponentInvoked(
                component="policy_gate",
                kind="gate",
                input_digest="digest",
                input_completeness={"requests": 2},
            ),
            DownstreamDecision(
                component="policy_gate",
                kind="gate",
                consumed=False,
                by="policy",
                outcome="rejected",
            ),
        )
    )["policy_gate"]

    # A gate that only decides has zero producer counters by design; the
    # producer checklist must not be applied to it.
    assert activity.candidates_produced == 0
    assert activity.scored == 0
    assert activity.downstream_consumed == 0
    assert activity.activation_proven is True


def test_component_kind_conflict_is_rejected() -> None:
    with pytest.raises(ValueError, match="conflicting kinds"):
        measure_component_activity(
            (
                ComponentInvoked(
                    component="component",
                    kind="gate",
                    input_digest="digest",
                    input_completeness={"deficits": 1},
                ),
                ComponentOutput(
                    component="component",
                    summary={"candidates_produced": 1},
                ),
            )
        )


def test_activation_requires_one_correlated_invocation_chain() -> None:
    activity = measure_component_activity(
        (
            ComponentInvoked(
                component="generator:grammar",
                input_digest="digest-a",
                input_completeness={"sink_facts": 1},
                invocation_id="invocation-a",
            ),
            ComponentOutput(
                component="generator:grammar",
                summary={
                    "candidates_produced": 1,
                    "candidates_survived_prefilter": 1,
                    "candidates_survived_guardrail": 1,
                    "scored": 1,
                },
                invocation_id="invocation-a",
            ),
            DownstreamDecision(
                component="generator:grammar",
                consumed=True,
                by="oracle",
                outcome="pass",
                invocation_id="invocation-b",
            ),
        )
    )["generator:grammar"]

    assert activity.candidates_produced == 1
    assert activity.downstream_consumed == 1
    assert activity.activation_proven is False
    assert "downstream_consumed=0" in activity.activation_failures


def test_component_activity_deduplicates_semantic_replay() -> None:
    event = ComponentInvoked(
        component="generator:grammar",
        input_digest="digest",
        input_completeness={"sink_facts": 1},
        invocation_id="invocation",
    )

    activity = measure_component_activity(
        (event, event.model_copy(update={"event_id": "replay"}))
    )

    assert activity["generator:grammar"].invocations == 1


def test_token_usage_rejects_invalid_cache_accounting() -> None:
    with pytest.raises(ValueError, match="cached input tokens"):
        TokenUsageSnapshot(input_tokens=3, cached_input_tokens=4)

    usage = TokenUsageSnapshot(input_tokens=3, cached_input_tokens=3)
    assert 0.0 <= usage.cache_hit_rate <= 1.0


def test_promotion_fact_counts_do_not_duplicate_downstream_decisions() -> None:
    activity = measure_component_activity(
        (
            ComponentOutput(
                component="consultation:alternatives",
                summary={
                    "proposals": 1,
                    "parked": 1,
                    "promoted": 1,
                    "promoted_facts": 3,
                },
                invocation_id="consultation:deficit:0",
            ),
            DownstreamDecision(
                component="consultation:alternatives",
                consumed=True,
                by="promotion_policy",
                outcome="promoted",
                invocation_id="consultation:deficit:0",
            ),
        )
    )["consultation:alternatives"]

    assert activity.promoted == 1
    assert activity.promoted_facts == 3
    assert activity.promotion_conversion == 1.0


def test_campaign_metrics_snapshot_exposes_component_activity_summary() -> None:
    activity = measure_component_activity(
        (
            ComponentInvoked(
                component="generator:grammar",
                input_digest="digest",
                input_completeness={"sink_facts": 1},
                invocation_id="invocation",
            ),
        )
    )["generator:grammar"]
    snapshot = CampaignMetricsSnapshot(
        component_activity={"generator:grammar": activity}
    )

    summary = snapshot.summary()["component_activity"]

    assert snapshot.component_activity["generator:grammar"] is activity
    assert summary["generator:grammar"]["invocations"] == 1
    assert summary["generator:grammar"]["activation"]["proven"] is False
