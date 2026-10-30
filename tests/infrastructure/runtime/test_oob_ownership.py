"""Behavior pins for moving OOB collection out of verification."""

from __future__ import annotations

from dataclasses import replace
from functools import partial

import pytest

from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.infrastructure.events import EventBus, JsonlEventStore
from cloud_dast.infrastructure.runtime import MemoryEvidenceChannel
from cloud_dast.model import AccessOutcome, Check, Observation, Severity, VerdictStatus
from cloud_dast.model.events import FindingRaised
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, external_call
from cloud_dast.runtime import oob
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.verification.oracles import oob as verification_oob
from cloud_dast.verification.oracles.primitive_router import PrimitiveOracleRouter


@pytest.fixture
def create_collector():
    return partial(oob.Coordinator, oracle=verification_oob.Oracle())


def _invariant(tag: str, method_id: str = "fetch") -> InvariantProjection:
    return InvariantProjection(
        invariant_id=tag,
        norm_id=f"norm:{tag}",
        statement="outbound callback must not occur",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:{tag}"),
                external_call(
                    Atom(value=f"action:{method_id}"), Atom(value="sink:net")
                ),
            ),
        ),
    )


def _observation(tag: str, marker: str) -> Observation:
    return Observation(
        observation_id=f"observation:{tag}",
        check_id=f"check:{tag}",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        probe_marker=marker,
    )


class _VirtualChannel(MemoryEvidenceChannel):
    def __init__(self):
        self.now = 0.0
        self.waits = []
        super().__init__(clock=lambda: self.now)
        self.set_ready(True)

    def wait_for(self, correlation_id, timeout, *, channel=None):
        self.waits.append(timeout)
        self.now += timeout
        return super().wait_for(correlation_id, 0.0, channel=channel)


def test_pending_sweep_uses_one_deadline_and_keeps_late_candidates(create_collector):
    channel = _VirtualChannel()
    collector = create_collector(channel, wait_seconds=0.0, clock=lambda: channel.now)
    observations = tuple(_observation(tag, tag) for tag in ("a", "b", "c"))
    for observation in observations:
        collector.evaluate_policy(_invariant("norm"), (observation,), method_id="fetch")
    channel.waits.clear()

    assert collector.reevaluate_pending(timeout=5.0) == {}
    assert channel.now == 5.0
    assert [timeout for timeout in channel.waits if timeout > 0] == [5.0]

    for observation in observations:
        channel.record(
            EvidenceEvent(
                channel="oob",
                correlation_id=observation.probe_marker,
                source="10.0.0.8",
            )
        )
    late = collector.reevaluate_pending(timeout=0.0)
    assert tuple(late) == tuple(item.observation_id for item in observations)
    assert all(verdict.status is VerdictStatus.FAIL for verdict in late.values())
    assert collector.reevaluate_pending(timeout=0.0) == {}


def test_pending_capacity_refresh_preserves_surviving_callbacks(create_collector):
    channel = _VirtualChannel()
    collector = create_collector(channel, wait_seconds=0.0, pending_capacity=2)
    for tag in ("a", "b", "a", "c"):
        collector.evaluate_policy(_invariant("norm"), (_observation(tag, tag),))
    for tag in ("a", "b", "c"):
        channel.record(
            EvidenceEvent(channel="oob", correlation_id=tag, source="10.0.0.8")
        )

    late = collector.reevaluate_pending(timeout=0.0)

    assert tuple(late) == ("observation:a", "observation:c")
    assert all(verdict.status is VerdictStatus.FAIL for verdict in late.values())


@pytest.mark.parametrize("same_observation", [True, False])
def test_same_marker_two_norms_preserves_last_registration(
    create_collector, same_observation
):
    channel = _VirtualChannel()
    collector = create_collector(channel, wait_seconds=0.0)
    first = _observation("first", "shared")
    second = first if same_observation else _observation("second", "shared")
    for invariant, observation in (
        (_invariant("first"), first),
        (_invariant("second"), second),
    ):
        verdict = collector.evaluate_policy(
            invariant, (observation,), method_id="fetch"
        )
        assert verdict.status is VerdictStatus.UNSCOREABLE
    event = EvidenceEvent(channel="oob", correlation_id="shared", source="10.0.0.8")
    channel.record(event)

    late = collector.reevaluate_pending(timeout=0.0)

    assert tuple(late) == (second.observation_id,)
    assert late[second.observation_id].evidence_refs == (
        second.observation_id,
        event.event_id,
    )
    assert collector.reevaluate_pending(timeout=0.0) == {}


def test_late_oob_router_verdict_passes_final_finding_gate(
    create_collector, method_spec, scenario_position, tmp_path
):
    channel = MemoryEvidenceChannel()
    channel.set_ready(True)
    collector = create_collector(channel, wait_seconds=0.0)
    router = PrimitiveOracleRouter(oob_oracle=collector)
    invariant = _invariant("late", method_spec.method_id)
    observation = _observation("late", "unique-candidate")
    check = Check(
        check_id=observation.check_id,
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=observation.scenario_id,
        request=(),
        identities=("attacker",),
    )
    verdict = router.evaluate_policy(
        invariant, (observation,), method=method_spec, scenario=scenario_position
    )
    key = (observation.observation_id, invariant.invariant_id)
    execution = ExecutionResult(
        (observation,),
        (check,),
        {key: ObservationProvenance(None, "path", "step", invariant.invariant_id)},
        {key: verdict},
    )
    journal = JsonlEventStore(tmp_path / "events.jsonl")
    bus = EventBus()
    bus.subscribe(FindingRaised, journal.append)
    evaluator = FindingEvaluator(EventProjection(bus, journal))
    assert (
        evaluator.evaluate(execution, {invariant.invariant_id: invariant}).findings
        == ()
    )

    callback = EvidenceEvent(
        channel="oob", correlation_id=observation.probe_marker, source="10.0.0.8"
    )
    channel.record(callback)
    late = collector.reevaluate_pending(timeout=0.0)
    execution = replace(
        execution, policy_verdicts={key: late[observation.observation_id]}
    )
    result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    assert len(result.findings) == 1
    assert result.findings[0].evidence_refs == (
        observation.observation_id,
        callback.event_id,
    )
    assert result.replayed_findings == result.findings
