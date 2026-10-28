from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    JsonValue,
    Observation,
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
    KnownContentWitness,
    LatencyBaseline,
    LatencyOracle,
    ObservationPair,
    PrimitiveOracleRouter,
    WitnessSignalOracle,
    extract_witness_signals,
)
from cloud_dast.verification.oracles.oob import OobOracle


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
            if self.event
            and self.event.correlation_id == marker
            and (channel is None or self.event.channel == channel)
            else None
        )

    def ready(self) -> bool:
        return True

    def blocked_reason(self) -> str | None:
        return None


def _invariant(effect: object) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:witness",
        norm_id="threat:witness",
        statement="witness signal must be deterministic",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:witness"), effect),
        ),
    )


def _observation(
    *,
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
    duration_ms: float | None = None,
    probe_marker: str | None = None,
) -> Observation:
    return Observation(
        check_id="check:grammar",
        scenario_id="scenario:grammar",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="delivered response",
        response_tree=response_tree,
        duration_ms=duration_ms,
        probe_marker=probe_marker,
    )


def test_signal_extraction_is_independent_of_expected_class() -> None:
    marker = "dast-polymorphic-candidate"
    control = _observation(
        response_tree=(("response.count", 1),),
        duration_ms=100.0,
    )
    treatment = _observation(
        response_tree=(
            ("response.count", 2),
            ("response.file", "known-file-content"),
            ("response.rendered", marker),
        ),
        duration_ms=106.0,
        probe_marker=marker,
    )

    signals = extract_witness_signals(
        (control, treatment),
        method_id="search",
        probe_fields=("query", "path"),
        sink_types={"query": "interpreter", "path": "filesystem"},
        known_content=KnownContentWitness(content="known-file-content"),
        oob_events=(
            EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8"),
        ),
    )

    assert {signal.kind for signal in signals} == {
        "marker_echo",
        "latency_delta",
        "oob_callback",
        "content_delta",
        "known_content",
    }
    assert all(signal.action_id == "action:search" for signal in signals)


def test_configured_oob_oracle_contributes_a_nonblocking_signal() -> None:
    marker = "dast-oob-candidate"
    oracle = WitnessSignalOracle(
        oob_oracle=OobOracle(
            _ReadyEventStore(
                EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
            ),
            wait_seconds=0.0,
        )
    )

    signals = oracle.extract_signals(
        (_observation(probe_marker=marker),),
        method_id="run",
    )

    assert [signal.kind for signal in signals] == ["oob_callback"]
    assert signals[0].evidence_refs[1]


def test_content_delta_pair_changes_the_grounded_witness_path() -> None:
    invariant = _invariant(duration(Atom(value="action:search"), Atom(value=100)))
    pair = ObservationPair(
        control=_observation(response_tree=(("response.count", 1),)),
        treatment=_observation(response_tree=(("response.count", 2),)),
        witness_path="count",
    )

    verdict = WitnessSignalOracle().evaluate_pair(
        invariant,
        pair,
        method_id="search",
        probe_fields=("query",),
        sink_types={"query": "interpreter"},
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "content-delta"
    assert verdict.deterministic is True
    assert verdict.grounded is True


def test_content_delta_pair_requires_a_response_difference() -> None:
    invariant = _invariant(duration(Atom(value="action:search"), Atom(value=100)))
    pair = ObservationPair(
        control=_observation(response_tree=(("response.count", 1),)),
        treatment=_observation(response_tree=(("response.count", 1),)),
        witness_path="count",
    )

    verdict = WitnessSignalOracle().evaluate_pair(
        invariant,
        pair,
        method_id="search",
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.model_id == "content-delta"


def test_content_delta_pair_rejects_request_echo() -> None:
    invariant = _invariant(duration(Atom(value="action:search"), Atom(value=100)))
    pair = ObservationPair(
        control=_observation(response_tree=(("request.echo", "one"),)),
        treatment=_observation(response_tree=(("request.echo", "two"),)),
        witness_path="echo",
    )

    verdict = WitnessSignalOracle().evaluate_pair(
        invariant,
        pair,
        method_id="search",
        probe_fields=("query",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "echoed request field" in verdict.rationale


def test_latency_signal_uses_a_paired_baseline_without_sink_dispatch() -> None:
    invariant = _invariant(duration(Atom(value="action:search"), Atom(value=100)))
    oracle = WitnessSignalOracle(
        latency_oracle=LatencyOracle(
            {
                "search": LatencyBaseline.from_paired_durations(
                    "search",
                    ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
                )
            }
        )
    )

    verdict = oracle.evaluate_policy(
        invariant,
        (
            _observation(duration_ms=100.0),
            _observation(duration_ms=106.0),
        ),
        method_id="search",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "latency"
    assert verdict.grounded is True


def test_known_content_is_a_class_free_witness() -> None:
    marker = "dast-known-content-candidate"
    invariant = _invariant(reached(Atom(value="action:read"), Atom(value=marker)))
    observation = _observation(
        response_tree=(("response.file", "known-file-content"),),
        probe_marker=marker,
    )

    verdict = WitnessSignalOracle().evaluate_known_content(
        invariant,
        observation,
        KnownContentWitness(content="known-file-content"),
        method_id="read",
        probe_fields=("path",),
        sink_types={"path": "filesystem"},
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "known-content"
    assert verdict.grounded is True


def test_known_content_delta_requires_control_absence() -> None:
    marker = "dast-known-content-candidate"
    invariant = _invariant(reached(Atom(value="action:read"), Atom(value=marker)))
    control = _observation(response_tree=(("response.message", "not found"),))
    treatment = _observation(
        response_tree=(("response.file", "known-file-content"),),
        probe_marker=marker,
    )

    verdict = WitnessSignalOracle().evaluate_known_content_pair(
        invariant,
        control,
        treatment,
        KnownContentWitness(content="known-file-content"),
        method_id="read",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "known-content-delta"
    assert verdict.grounded is True


def test_router_scores_marker_without_production_class_dispatch(
    method_spec,
    scenario_position,
) -> None:
    marker = "dast-polymorphic-candidate"
    invariant = _invariant(
        reached(Atom(value=f"action:{method_spec.method_id}"), Atom(value=marker))
    )
    observation = _observation(
        response_tree=(("response.entity", marker),),
        probe_marker=marker,
    )

    verdict = PrimitiveOracleRouter().evaluate_policy(
        invariant,
        (observation,),
        method=method_spec,
        scenario=scenario_position,
        probe_fields=("xml",),
        sink_types={"xml": "xml_parser"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.model_id == "marker"


def test_router_scores_latency_without_production_class_dispatch(
    method_spec,
    scenario_position,
) -> None:
    invariant = _invariant(
        duration(
            Atom(value=f"action:{method_spec.method_id}"),
            Atom(value=100),
        )
    )
    router = PrimitiveOracleRouter(
        latency_oracle=LatencyOracle(
            {
                method_spec.method_id: LatencyBaseline.from_paired_durations(
                    method_spec.method_id,
                    ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
                )
            }
        )
    )

    verdict = router.evaluate_policy(
        invariant,
        (_observation(duration_ms=100.0), _observation(duration_ms=106.0)),
        method=method_spec,
        scenario=scenario_position,
        sink_types={"command": "command_shell"},
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "latency"


def test_router_scores_oob_without_production_class_dispatch(
    method_spec,
    scenario_position,
) -> None:
    marker = "dast-polymorphic-candidate"
    invariant = _invariant(
        external_call(
            Atom(value=f"action:{method_spec.method_id}"),
            Atom(value=marker),
        )
    )
    router = PrimitiveOracleRouter(
        oob_oracle=OobOracle(
            _ReadyEventStore(
                EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
            ),
            wait_seconds=0.0,
        )
    )

    verdict = router.evaluate_policy(
        invariant,
        (_observation(probe_marker=marker),),
        method=method_spec,
        scenario=scenario_position,
        sink_types={"xml": "xml_parser"},
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "oob"


def test_renderer_marker_remains_candidate_tier_without_class_wrapper(
    method_spec,
    scenario_position,
) -> None:
    marker = "dast-renderer-candidate"
    invariant = _invariant(
        reached(Atom(value=f"action:{method_spec.method_id}"), Atom(value=marker))
    )
    observation = _observation(
        response_tree=(("response.rendered", marker),),
        probe_marker=marker,
    )

    verdict = PrimitiveOracleRouter().evaluate_policy(
        invariant,
        (observation,),
        method=method_spec,
        scenario=scenario_position,
        probe_fields=("html",),
        sink_types={"html": "renderer"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.model_id == "marker"
    assert "candidate-tier" in verdict.rationale
