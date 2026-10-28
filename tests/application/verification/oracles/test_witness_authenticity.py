from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
    ResponseData,
    Severity,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    duration,
    external_call,
    reached,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles import (
    LatencyBaseline,
    LatencyOracle,
    MarkerOracle,
    OobOracle,
)


class _ReadyEventStore:
    def __init__(self, event: EvidenceEvent | None = None) -> None:
        self.event = event

    def record(self, event: EvidenceEvent) -> None:
        self.event = event

    def wait_for(
        self,
        marker: str,
        timeout: float,
        *,
        channel: str | None = None,
    ) -> EvidenceEvent | None:
        del timeout
        return (
            self.event
            if self.event.correlation_id == marker
            and (channel is None or self.event.channel == channel)
            else None
        )

    def ready(self) -> bool:
        return True

    def set_ready(self, ready: bool) -> None:
        del ready

    def block(self, reason: str) -> None:
        del reason

    def blocked_reason(self) -> str | None:
        return None


def _invariant(effect: object) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant",
        norm_id="norm",
        statement="witness must be authentic",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm"), effect),
        ),
    )


def _observation(**updates: object) -> Observation:
    values = {
        "check_id": "check",
        "scenario_id": "scenario",
        "observed_outcome": AccessOutcome.ALLOWED,
        "response_summary": "allowed",
    }
    values.update(updates)
    return Observation(**values)


def test_oob_oracle_requires_an_authenticated_source() -> None:
    marker = "dast-oob-candidate"
    effect = external_call(Atom(value="action:fetch-url"), Atom(value=marker))
    observation = _observation(probe_marker=marker)
    valid = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
    disallowed = EvidenceEvent(
        channel="oob", correlation_id=marker, source="192.0.2.10"
    )
    missing = EvidenceEvent(channel="oob", correlation_id=marker)

    accepted = OobOracle(
        _ReadyEventStore(valid),
        wait_seconds=0.0,
        allowed_sources=("10.0.0.0/24",),
    ).evaluate_policy(_invariant(effect), (observation,))
    rejected = OobOracle(
        _ReadyEventStore(disallowed),
        wait_seconds=0.0,
        allowed_sources=("10.0.0.0/24",),
    ).evaluate_policy(_invariant(effect), (observation,))
    without_source = OobOracle(
        _ReadyEventStore(missing),
        wait_seconds=0.0,
    ).evaluate_policy(_invariant(effect), (observation,))

    assert accepted.status is VerdictStatus.FAIL
    assert accepted.grounded is True
    assert rejected.status is VerdictStatus.UNSCOREABLE
    assert "not in the allowed source policy" in rejected.rationale
    assert without_source.status is VerdictStatus.UNSCOREABLE
    assert "no source address" in without_source.rationale


def test_oob_oracle_adversarial_target_does_not_score_callback() -> None:
    marker = "dast-oob-candidate"
    effect = external_call(Atom(value="action:fetch-url"), Atom(value=marker))
    observation = _observation(probe_marker=marker)
    event = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")

    verdict = OobOracle(
        _ReadyEventStore(event),
        wait_seconds=0.0,
        allowed_sources=("10.0.0.8",),
        adversarial_target=True,
    ).evaluate_policy(_invariant(effect), (observation,))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "adversarial target policy" in verdict.rationale


def test_marker_sink_type_and_field_do_not_prove_effect() -> None:
    marker = "dast-marker-candidate"
    effect = reached(Atom(value="action:render"), Atom(value=marker))
    observation = _observation(
        output=ResponseData(fields=(("template", marker),)),
        response_tree=(("template", marker),),
        probe_marker=marker,
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False


def test_marker_request_echo_is_not_a_sink_witness() -> None:
    marker = "dast-marker-candidate"
    effect = reached(Atom(value="action:render"), Atom(value=marker))
    observation = _observation(
        output=ResponseData(fields=(("request.template", marker),)),
        response_tree=(("request.template", marker),),
        probe_marker=marker,
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_probe_field_without_sink_type_is_only_reflection() -> None:
    marker = "dast-marker-candidate"
    effect = reached(Atom(value="action:render"), Atom(value=marker))
    observation = _observation(
        output=ResponseData(fields=(("template", marker),)),
        response_tree=(("template", marker),),
        probe_marker=marker,
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_error_witness_requires_the_probe_sink_type() -> None:
    marker = "dast-marker-candidate"
    effect = reached(Atom(value="action:render"), Atom(value=marker))
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        response_summary=f"parse error near {marker}",
        transport_status=HttpStatus(code=500),
        error_reason=f"parse error near {marker}",
        probe_marker=marker,
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"unrelated": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_adversarial_target_requires_corroboration() -> None:
    marker = "dast-marker-candidate"
    effect = reached(Atom(value="action:render"), Atom(value=marker))
    observation = _observation(
        output=ResponseData(fields=(("rendered", marker),)),
        response_tree=(("rendered", marker),),
        probe_marker=marker,
    )

    verdict = MarkerOracle(adversarial_target=True).evaluate_policy(
        _invariant(effect),
        (observation,),
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "adversarial target policy" in verdict.rationale


def test_paired_latency_baseline_requires_control_observation() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=100))
    baseline = LatencyBaseline.from_paired_durations(
        "get-secret",
        ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
    )
    oracle = LatencyOracle({"get-secret": baseline})

    verdict = oracle.evaluate_policy(
        _invariant(effect),
        (_observation(duration_ms=106.0),),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "no delivered control observation" in verdict.rationale


def test_paired_latency_control_must_not_be_a_marker_probe() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=100))
    baseline = LatencyBaseline.from_paired_durations(
        "get-secret",
        ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
    )
    previous_probe = _observation(
        duration_ms=100.0,
        probe_marker="dast-latency-marker",
    )
    probe = _observation(duration_ms=106.0)
    oracle = LatencyOracle({"get-secret": baseline})

    verdict = oracle.evaluate_policy(
        _invariant(effect),
        (previous_probe, probe),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "no delivered control observation" in verdict.rationale


def test_paired_latency_baseline_scores_control_and_probe_pair() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=100))
    baseline = LatencyBaseline.from_paired_durations(
        "get-secret",
        ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
    )
    control = _observation(duration_ms=100.0)
    probe = _observation(duration_ms=106.0)
    oracle = LatencyOracle({"get-secret": baseline})

    verdict = oracle.evaluate_policy(_invariant(effect), (control, probe))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert control.observation_id in verdict.evidence_refs
    assert "paired control" in verdict.rationale


def test_adversarial_latency_baseline_is_not_scoreable() -> None:
    effect = duration(Atom(value="action:get-secret"), Atom(value=100))
    observation = _observation(duration_ms=106.0)
    inflated = LatencyOracle(
        {
            "get-secret": LatencyBaseline.from_durations(
                "get-secret",
                (900.0, 900.0, 900.0),
            )
        },
        adversarial_target=True,
    )
    deflated = LatencyOracle(
        {
            "get-secret": LatencyBaseline.from_durations(
                "get-secret",
                (1.0, 1.0, 1.0),
            )
        },
        adversarial_target=True,
    )

    inflated_verdict = inflated.evaluate_policy(_invariant(effect), (observation,))
    deflated_verdict = deflated.evaluate_policy(_invariant(effect), (observation,))

    assert inflated_verdict.status is VerdictStatus.UNSCOREABLE
    assert deflated_verdict.status is VerdictStatus.UNSCOREABLE
    assert inflated_verdict.grounded is False
    assert deflated_verdict.grounded is False
    assert "adversarial target policy" in inflated_verdict.rationale
