from __future__ import annotations

import pytest

from cloud_dast.api import extract_witness_signals
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    JsonValue,
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
from cloud_dast.runtime import oob
from cloud_dast.verification.oracles import (
    KnownContentWitness,
    ObservationPair,
    latency,
    primitive_router,
    witness,
)
from cloud_dast.verification.oracles import oob as verification_oob


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
    oracle = witness.Oracle(
        oob_oracle=oob.Coordinator(
            _ReadyEventStore(
                EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
            ),
            verification_oob.Oracle(),
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

    verdict = witness.Oracle().evaluate_pair(
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

    verdict = witness.Oracle().evaluate_pair(
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

    verdict = witness.Oracle().evaluate_pair(
        invariant,
        pair,
        method_id="search",
        probe_fields=("query",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "echoed request field" in verdict.rationale


@pytest.mark.parametrize(
    ("response_path", "sink_type", "expected"),
    [
        ("request.query", "interpreter", VerdictStatus.UNSCOREABLE),
        ("response.query", "", VerdictStatus.UNSCOREABLE),
        ("response.query", "   ", VerdictStatus.UNSCOREABLE),
        ("response.QUERY", "interpreter", VerdictStatus.FAIL),
    ],
)
def test_content_delta_preserves_echo_and_sink_precedence(
    response_path: str, sink_type: str, expected: VerdictStatus
) -> None:
    pair = ObservationPair(
        control=_observation(response_tree=((response_path, ("before",)),)),
        treatment=_observation(response_tree=((response_path, ("after",)),)),
        witness_path=".QuErY.",
    )

    verdict = witness.Oracle().evaluate_pair(
        _invariant(duration(Atom(value="action:search"), Atom(value=100))),
        pair,
        method_id="search",
        probe_fields=("QUERY",),
        sink_types={"query": sink_type},
    )

    assert verdict.status is expected
    assert verdict.grounded is (expected is VerdictStatus.FAIL)
    if expected is VerdictStatus.UNSCOREABLE:
        assert verdict.rationale == "witness path is only an echoed request field"


@pytest.mark.parametrize(
    ("control_value", "treatment_value", "expected"),
    [
        ("absent", ("known-content",), VerdictStatus.FAIL),
        (("known-content",), ("known-content",), VerdictStatus.PASS),
        ("absent", "prefix-known-content-suffix", VerdictStatus.PASS),
    ],
)
def test_known_content_pair_requires_exact_selected_treatment_only_content(
    control_value: JsonValue, treatment_value: JsonValue, expected: VerdictStatus
) -> None:
    control = _observation(response_tree=(("response.File", control_value),))
    treatment = _observation(
        response_tree=(
            ("response.File", treatment_value),
            ("response.other", "known-content"),
        ),
        probe_marker="candidate",
    )

    verdict = witness.Oracle().evaluate_known_content_pair(
        _invariant(reached(Atom(value="action:read"), Atom(value="sink:file"))),
        control,
        treatment,
        KnownContentWitness(content="known-content", response_path=".FILE."),
        method_id="read",
    )

    assert verdict.status is expected
    assert verdict.evidence_refs == (control.observation_id, treatment.observation_id)


@pytest.mark.parametrize(
    ("method_id", "marker", "rationale"),
    [
        ("other", None, "QDL norm action does not match the executed method"),
        ("read", None, "treatment has no candidate marker"),
        ("read", "candidate", "paired response evidence is incomplete"),
    ],
)
def test_known_content_pair_preserves_diagnostic_order(
    method_id: str, marker: str | None, rationale: str
) -> None:
    control = _observation(response_tree=(("response.file", "absent"),))
    treatment = _observation(
        response_tree=(("response.file", "known-content"),), probe_marker=marker
    ).model_copy(update={"output": ResponseData(field_names=("not_available",))})

    verdict = witness.Oracle().evaluate_known_content_pair(
        _invariant(reached(Atom(value="action:read"), Atom(value="sink:file"))),
        control,
        treatment,
        KnownContentWitness(content="known-content"),
        method_id=method_id,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.rationale == rationale


def test_latency_signal_uses_a_paired_baseline_without_sink_dispatch() -> None:
    invariant = _invariant(duration(Atom(value="action:search"), Atom(value=100)))
    oracle = witness.Oracle(
        latency_oracle=latency.Oracle(
            {
                "search": latency.Baseline.from_paired_durations(
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

    verdict = witness.Oracle().evaluate_known_content(
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

    verdict = witness.Oracle().evaluate_known_content_pair(
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

    verdict = primitive_router.Oracle().evaluate_policy(
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
    router = primitive_router.Oracle(
        witness_oracle=witness.Oracle(
            latency_oracle=latency.Oracle(
                {
                    method_spec.method_id: latency.Baseline.from_paired_durations(
                        method_spec.method_id,
                        ((100.0, 100.0), (100.0, 101.0), (100.0, 102.0)),
                    )
                }
            )
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
    router = primitive_router.Oracle(
        witness_oracle=witness.Oracle(
            oob_oracle=oob.Coordinator(
                _ReadyEventStore(
                    EvidenceEvent(
                        channel="oob", correlation_id=marker, source="10.0.0.8"
                    )
                ),
                verification_oob.Oracle(),
                wait_seconds=0.0,
            )
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

    verdict = primitive_router.Oracle().evaluate_policy(
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
