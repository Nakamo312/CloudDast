from __future__ import annotations

import pytest

import cloud_dast.verification.oracles.marker
from cloud_dast.config import OOB_PROBE_TIMEOUT_SECONDS
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    GrpcStatus,
    HttpStatus,
    JsonValue,
    Observation,
    PrincipalRef,
    ResponseData,
    Severity,
    TransportStatus,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.runtime import oob
from cloud_dast.verification.oracles import field_exposure, latency, primitive_router
from cloud_dast.verification.oracles import oob as verification_oob
from cloud_dast.verification.oracles.latency import AvailabilityOracle


def _attacker_scenario(scenario):
    return scenario.model_copy(
        update={
            "stand": scenario.stand.model_copy(
                update={
                    "principals": (
                        PrincipalRef(principal_id="attacker", principal_type="user"),
                    )
                }
            )
        }
    )


from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    duration,
    external_call,
    field,
    has,
    reached,
)


class _ReadyEventStore:
    def __init__(self, event: EvidenceEvent | None = None) -> None:
        self.event = event
        self.timeouts: list[float] = []
        self.blocked_reason_value: str | None = None

    def record(self, event: EvidenceEvent) -> None:
        self.event = event

    def wait_for(
        self,
        marker: str,
        timeout: float,
        *,
        channel: str | None = None,
    ) -> EvidenceEvent | None:
        self.timeouts.append(timeout)
        return (
            self.event
            if self.event
            and self.event.correlation_id == marker
            and (channel is None or self.event.channel == channel)
            else None
        )

    def ready(self) -> bool:
        return True

    def set_ready(self, ready: bool) -> None:
        self.blocked_reason_value = None if ready else "listener is not ready"

    def block(self, reason: str) -> None:
        self.blocked_reason_value = reason

    def blocked_reason(self) -> str | None:
        return self.blocked_reason_value


def _invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="machine-checkable QDL norm",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:inv"), effect),
        ),
    )


def _observation(
    *,
    observed_outcome: AccessOutcome = AccessOutcome.ALLOWED,
    response_summary: str = "OK",
    transport_status: TransportStatus | None = None,
    output: ResponseData | None = None,
    duration_ms: float | None = None,
    probe_marker: str | None = None,
    error_reason: str | None = None,
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=observed_outcome,
        response_summary=response_summary,
        transport_status=transport_status,
        output=output,
        duration_ms=duration_ms,
        probe_marker=probe_marker,
        error_reason=error_reason,
        response_tree=response_tree,
    )


def test_field_exposure_detects_forbidden_response_field(
    scenario_position,
) -> None:
    effect = has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:secret"), Atom(value="private_key")),
    )
    observation = _observation(
        output=ResponseData(fields=(("private_key", "PEM"), ("id", "secret-1")))
    )

    verdict = field_exposure.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        scenario=_attacker_scenario(scenario_position),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True


def test_field_exposure_passes_when_forbidden_fields_are_absent(
    scenario_position,
) -> None:
    effect = has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:secret"), Atom(value="private_key")),
    )
    observation = _observation(
        response_tree=(("id", "secret-1"),),
    )

    verdict = field_exposure.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        scenario=_attacker_scenario(scenario_position),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.negative_scope == ("response_tree",)


def test_latency_requires_runtime_baseline() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(duration_ms=111.0)

    no_baseline = latency.Oracle().evaluate_policy(_invariant(effect), (observation,))
    with_baseline = latency.Oracle(
        {"get-secret": latency.Baseline.from_durations("get-secret", (100, 100, 100))}
    ).evaluate_policy(_invariant(effect), (observation,))

    assert no_baseline.status is VerdictStatus.UNSCOREABLE
    assert with_baseline.status is VerdictStatus.FAIL
    assert with_baseline.grounded is True


def test_latency_uses_runtime_baseline_threshold() -> None:
    loose_norm = duration(Atom(value="action:get-secret"), Atom(value=200))
    tight_norm = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(duration_ms=111.0)
    tight_baseline = latency.Oracle(
        {
            "get-secret": latency.Baseline.from_durations(
                "get-secret",
                (100.0, 100.0, 100.0),
            )
        }
    )
    loose_baseline = latency.Oracle(
        {
            "get-secret": latency.Baseline.from_durations(
                "get-secret",
                (200.0, 200.0, 200.0),
            )
        }
    )

    tight_verdict = tight_baseline.evaluate_policy(
        _invariant(loose_norm),
        (observation,),
    )
    loose_verdict = loose_baseline.evaluate_policy(
        _invariant(tight_norm),
        (observation,),
    )

    assert tight_verdict.status is VerdictStatus.FAIL
    assert "runtime baseline" in tight_verdict.rationale
    assert loose_verdict.status is VerdictStatus.PASS
    assert "runtime baseline" in loose_verdict.rationale


def test_latency_scores_worst_case_duration_in_trace() -> None:
    effect = duration(Atom(value="action:orders.Get"), Atom(value=200))
    baseline = latency.Baseline(
        method_id="orders.Get",
        median_ms=2.0,
        mad_ms=0.0,
        threshold_ms=3.9,
        samples=3,
    )
    oracle = latency.Oracle({"orders.Get": baseline})
    observations = (
        _observation(duration_ms=2.0),
        _observation(duration_ms=154.0),
        _observation(duration_ms=2.0),
    )

    verdict = oracle.evaluate_policy(_invariant(effect), observations)

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert observations[1].observation_id in verdict.evidence_refs
    assert "worst-case duration 154.000 ms" in verdict.rationale

    passing = oracle.evaluate_policy(
        _invariant(effect),
        (_observation(duration_ms=2.0),),
    )

    assert passing.status is VerdictStatus.PASS


def test_paired_latency_scores_worst_case_duration_in_trace() -> None:
    effect = duration(Atom(value="action:orders.Get"), Atom(value=110))
    baseline = latency.Baseline(
        method_id="orders.Get",
        median_ms=0.0,
        mad_ms=0.0,
        threshold_ms=3.9,
        samples=3,
        paired=True,
    )
    oracle = latency.Oracle({"orders.Get": baseline})
    observations = (
        _observation(duration_ms=2.0),
        _observation(duration_ms=154.0),
        _observation(duration_ms=2.0),
    )

    verdict = oracle.evaluate_policy(_invariant(effect), observations)

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert observations[1].observation_id in verdict.evidence_refs
    assert observations[0].observation_id in verdict.evidence_refs


def test_latency_scores_delivered_error_response() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=200))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        transport_status=HttpStatus(code=500),
        duration_ms=111.0,
        response_tree=(("error", "unavailable"),),
    )
    oracle = latency.Oracle(
        {
            "get-secret": latency.Baseline.from_durations(
                "get-secret",
                (100.0, 100.0, 100.0),
            )
        }
    )

    verdict = oracle.evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "latency"
    assert verdict.grounded is True


def test_availability_scores_explicit_timeout_at_configured_deadline() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(
        observed_outcome=AccessOutcome.UNKNOWN,
        transport_status=HttpStatus(code=504),
        duration_ms=111.0,
        error_reason="context deadline exceeded",
    )

    verdict = AvailabilityOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "availability"
    assert verdict.grounded is True
    assert "configured deadline" in verdict.rationale


def test_availability_scores_status_only_timeout_projection() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(
        observed_outcome=AccessOutcome.UNKNOWN,
        transport_status=HttpStatus(code=504),
        duration_ms=111.0,
    )

    verdict = AvailabilityOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "availability"
    assert verdict.grounded is True


def test_availability_scores_grpc_deadline_exceeded_projection() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(
        observed_outcome=AccessOutcome.UNKNOWN,
        transport_status=GrpcStatus(code="DEADLINE_EXCEEDED"),
        duration_ms=111.0,
    )

    verdict = AvailabilityOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "availability"
    assert verdict.grounded is True


def test_availability_requires_timeout_to_reach_configured_deadline() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        duration_ms=50.0,
        error_reason="connection timed out",
    )

    verdict = AvailabilityOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "before the configured deadline" in verdict.rationale


def test_latency_delegates_explicit_timeout_to_availability_oracle() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=110))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        duration_ms=111.0,
        error_reason="connection timed out",
    )
    oracle = latency.Oracle(
        {
            "get-secret": latency.Baseline.from_durations(
                "get-secret",
                (100.0, 100.0, 100.0),
            )
        }
    )

    verdict = oracle.evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "availability"


def test_delivered_gateway_timeout_remains_latency_evidence() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=200))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        transport_status=HttpStatus(code=504),
        duration_ms=111.0,
        error_reason="Gateway Timeout",
        response_tree=(("message", "upstream unavailable"),),
    )
    oracle = latency.Oracle(
        {
            "get-secret": latency.Baseline.from_durations(
                "get-secret",
                (100.0, 100.0, 100.0),
            )
        }
    )

    verdict = oracle.evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "latency"


def test_latency_oracle_exposes_baseline_availability() -> None:
    oracle = latency.Oracle()

    assert oracle.has_baseline("action:get-secret") is False

    oracle.update_baseline("action:get-secret", (100.0, 102.0, 104.0))

    assert oracle.has_baseline("get-secret") is True


def test_marker_reflection_and_absence_do_not_prove_sink() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    reached_observation = _observation(
        output=ResponseData(fields=(("rendered", "dast-marker-42"),)),
        probe_marker="dast-marker-42",
    )
    absent_observation = _observation(
        response_tree=(("rendered", "ordinary"),),
        probe_marker="dast-marker-42",
    )

    oracle = cloud_dast.verification.oracles.marker.Oracle()

    assert oracle.evaluate_policy(
        _invariant(effect),
        (reached_observation,),
        probe_fields=("template",),
    ).status is (VerdictStatus.UNSCOREABLE)
    assert oracle.evaluate_policy(
        _invariant(effect),
        (absent_observation,),
        probe_fields=("template",),
    ).status is (VerdictStatus.UNSCOREABLE)


def test_marker_absence_without_complete_response_scope_is_unscoreable() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        output=ResponseData(fields=(("rendered", "ordinary"),)),
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == [
        "incomplete_negative_scope"
    ]


def test_marker_uses_candidate_probe_marker() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        output=ResponseData(fields=(("rendered", "dast-marker-42-check-1"),)),
        probe_marker="dast-marker-42-check-1",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deficits[0].kind == "echo_witness"


@pytest.mark.parametrize("probe_marker", [None, ""])
def test_marker_rejects_unattributed_norm_marker_fallback(
    probe_marker: str | None,
) -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        output=ResponseData(fields=(("rendered", "dast-marker-42"),)),
        probe_marker=probe_marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "candidate probe marker" in verdict.rationale


def test_marker_nested_debug_reflection_is_unscoreable() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        response_tree=(
            ("debug.trace", "ordinary"),
            ("debug.rendered", "dast-marker-42"),
        ),
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True


@pytest.mark.parametrize(
    "error_reason",
    [
        "coupon 'dastpayload85f9065e2265' not found",
        "coupon benign-dastpayload85f9065e2265 not found",
    ],
)
def test_marker_ignores_resource_not_found_echo(error_reason: str) -> None:
    marker = "dastpayload85f9065e2265"
    effect = reached(Atom(value="action:render-template"), Atom(value=marker))
    observation = _observation(
        observed_outcome=AccessOutcome.UNKNOWN,
        response_summary="gRPC status: NOT_FOUND",
        transport_status=GrpcStatus(code="NOT_FOUND"),
        error_reason=error_reason,
        probe_marker=marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_structured_error_name_does_not_prove_sink() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        output=ResponseData(
            fields=(("error_message", "unrecognized token: 'dast-marker-42'"),)
        ),
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "not a grounded sink witness" in verdict.rationale


def test_marker_diagnostic_without_sink_trace_is_unscoreable() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        response_summary="gRPC status: UNKNOWN",
        transport_status=GrpcStatus(code="UNKNOWN"),
        error_reason="parse error near 'dast-marker-42'",
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "not a grounded sink witness" in verdict.rationale


def test_marker_ignores_successful_unstructured_summary_echo() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        response_summary="echo dast-marker-42",
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale


def test_marker_ignores_non_string_tree_leaves() -> None:
    effect = reached(Atom(value="action:render-template"), Atom(value="dast-marker-42"))
    observation = _observation(
        response_tree=(("count", 42),),
        probe_marker="dast-marker-42",
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE


def test_oob_oracle_uses_asynchronous_callback_evidence() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"), Atom(value="dast-oob-marker")
    )
    observation = _observation(probe_marker="dast-oob-marker")
    event = EvidenceEvent(
        channel="oob", correlation_id="dast-oob-marker", source="10.0.0.8"
    )

    oracle = oob.Coordinator(
        _ReadyEventStore(event), verification_oob.Oracle(), wait_seconds=0.0
    )
    verdict = oracle.evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert observation.observation_id in verdict.evidence_refs
    assert event.event_id in verdict.evidence_refs


def test_oob_oracle_uses_candidate_probe_marker() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"), Atom(value="dast-oob-marker")
    )
    observation = _observation(probe_marker="dast-oob-marker-check-1")
    wrong_event = EvidenceEvent(
        channel="oob", correlation_id="dast-oob-marker", source="10.0.0.8"
    )
    matching_event = EvidenceEvent(
        channel="oob",
        correlation_id="dast-oob-marker-check-1",
        source="10.0.0.8",
    )

    wrong_verdict = oob.Coordinator(
        _ReadyEventStore(wrong_event), verification_oob.Oracle(), wait_seconds=0.0
    ).evaluate_policy(_invariant(effect), (observation,))
    matching_verdict = oob.Coordinator(
        _ReadyEventStore(matching_event), verification_oob.Oracle(), wait_seconds=0.0
    ).evaluate_policy(_invariant(effect), (observation,))

    assert wrong_verdict.status is VerdictStatus.UNSCOREABLE
    assert matching_verdict.status is VerdictStatus.FAIL


def test_oob_oracle_rejects_unattributed_norm_marker_fallback() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"),
        Atom(value="dast-oob-marker"),
    )
    observation = _observation()
    event = EvidenceEvent(
        channel="oob", correlation_id="dast-oob-marker", source="10.0.0.8"
    )

    verdict = oob.Coordinator(
        _ReadyEventStore(event), verification_oob.Oracle(), wait_seconds=0.0
    ).evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "candidate probe marker" in verdict.rationale


def test_oob_oracle_timeout_is_negative_evidence_not_grounded_pass() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"),
        Atom(value="dast-oob-marker-check-1"),
    )
    observation = _observation(probe_marker="dast-oob-marker-check-1")

    verdict = oob.Coordinator(
        _ReadyEventStore(), verification_oob.Oracle(), wait_seconds=0.0
    ).evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "negative evidence" in verdict.rationale
    assert "not a grounded pass" in verdict.rationale


def test_oob_oracle_uses_configured_probe_timeout() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"),
        Atom(value="dast-oob-marker-check-1"),
    )
    observation = _observation(probe_marker="dast-oob-marker-check-1")
    store = _ReadyEventStore()

    verdict = oob.Coordinator(store, verification_oob.Oracle()).evaluate_policy(
        _invariant(effect), (observation,)
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert store.timeouts == [0.0, OOB_PROBE_TIMEOUT_SECONDS]
    assert "no out-of-band callback arrived" in verdict.rationale


def test_oob_oracle_re_evaluates_late_callback() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"),
        Atom(value="dast-oob-marker-check-1"),
    )
    observation = _observation(probe_marker="dast-oob-marker-check-1")
    store = _ReadyEventStore()
    oracle = oob.Coordinator(store, verification_oob.Oracle(), wait_seconds=0.0)

    timed_out = oracle.evaluate_policy(_invariant(effect), (observation,))
    event = EvidenceEvent(
        channel="oob", correlation_id="dast-oob-marker-check-1", source="10.0.0.8"
    )
    store.record(event)
    late = oracle.evaluate_policy(_invariant(effect), (observation,))

    assert timed_out.status is VerdictStatus.UNSCOREABLE
    assert late.status is VerdictStatus.FAIL
    assert late.grounded is True
    assert event.event_id in late.evidence_refs


def test_oob_oracle_reports_blocked_channel_reason() -> None:
    effect = external_call(
        Atom(value="action:fetch-url"),
        Atom(value="dast-oob-marker"),
    )
    observation = _observation(probe_marker="dast-oob-marker-check-1")
    store = _ReadyEventStore()
    store.block("listener port is unavailable")

    verdict = oob.Coordinator(
        store, verification_oob.Oracle(), wait_seconds=0.0
    ).evaluate_policy(
        _invariant(effect),
        (observation,),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "listener port is unavailable" in verdict.rationale


def test_primitive_router_dispatches_marker_norm(
    method_spec,
    scenario_position,
) -> None:
    effect = reached(Atom(value=method_spec.method_id), Atom(value="dast-marker-42"))
    observation = _observation(
        output=ResponseData(fields=(("rendered", "dast-marker-42"),)),
        probe_marker="dast-marker-42",
    )

    verdict = primitive_router.Oracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.model_id == "marker"


def test_primitive_router_without_norm_fact_is_unscoreable(
    method_spec,
    scenario_position,
) -> None:
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )

    verdict = primitive_router.Oracle().evaluate_policy(
        invariant,
        (_observation(),),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
