from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Check,
    Observation,
    PolicyVerdict,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import DomainEvent, FindingRaised
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, reached
from cloud_dast.verification.finding_evaluator import FindingEvaluator
from cloud_dast.verification.findings import (
    attach_finding_identity,
)


@dataclass(frozen=True, slots=True)
class _WitnessCase:
    check: Check
    observation: Observation
    verdict: PolicyVerdict
    minimal_check: Check


class _EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="ship-order-unpaid",
        norm_id="ship-order",
        statement="attacker must not ship an unpaid order",
        severity=Severity.HIGH,
    )


def _case(
    index: int,
    *,
    request: tuple[tuple[str, object], ...],
    sink_ids: tuple[str, ...] = ("sink:unpaid_shipment",),
    probe_fields: tuple[str, ...] = ("note",),
    witness_kind: str = "marker",
    minimal_request: tuple[tuple[str, object], ...] | None = None,
) -> _WitnessCase:
    check = Check(
        check_id=f"check:{index}",
        invariant_id="ship-order-unpaid",
        method_id="grpc:shop.OrderService.ShipOrder",
        scenario_id="scenario:cross-folder",
        request=request,
        identities=("principal:attacker",),
    )
    observation = Observation(
        observation_id=f"observation:{index}",
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="order shipped",
    )
    verdict = PolicyVerdict(
        status=VerdictStatus.FAIL,
        confidence=1.0,
        rationale="forbidden sink marker was observed",
        evidence_refs=(observation.observation_id,),
        model_id=witness_kind,
        sink_ids=sink_ids,
        probe_fields=probe_fields,
        deterministic=True,
        grounded=True,
    )
    minimal_check = check
    if minimal_request is not None:
        minimal_check = check.model_copy(
            update={
                "check_id": f"minimal:{index}",
                "request": minimal_request,
            }
        )
    return _WitnessCase(
        check=check,
        observation=observation,
        verdict=verdict,
        minimal_check=minimal_check,
    )


def _evaluate(*cases: _WitnessCase):
    events = _EventLog()
    execution = ExecutionResult(
        observations=tuple((case.observation for case in cases)),
        checks=tuple((case.check for case in cases)),
        provenance={
            (
                case.observation.observation_id,
                case.check.invariant_id,
            ): ObservationProvenance("goal", "path", "step", case.check.invariant_id)
            for case in cases
        },
        policy_verdicts={
            (case.observation.observation_id, case.check.invariant_id): case.verdict
            for case in cases
        },
        minimal_checks={
            (
                case.observation.observation_id,
                case.check.invariant_id,
            ): case.minimal_check
            for case in cases
        },
    )
    invariant = _invariant()
    result = FindingEvaluator(events, events).evaluate(
        execution,
        {invariant.invariant_id: invariant},
    )
    return result, events


def test_repeated_fingerprint_merges_payload_variants_as_witnesses() -> None:
    first = _case(
        1,
        request=(("order_id", "order-victim-1"), ("note", "payload-one")),
    )
    second = _case(
        2,
        request=(("order_id", "order-victim-2"), ("note", "payload-two")),
    )

    result, events = _evaluate(first, second)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.observation_id == first.observation.observation_id
    assert finding.evidence_refs == (
        first.observation.observation_id,
        second.observation.observation_id,
    )
    assert sum(isinstance(event, FindingRaised) for event in events.events) == 1


def test_sink_probe_field_and_witness_kind_change_finding_identity() -> None:
    base = _case(
        1,
        request=(("order_id", "order-victim"), ("note", "payload")),
    )
    other_sink = _case(
        2,
        request=(("order_id", "order-victim"), ("note", "payload")),
        sink_ids=("sink:refund_reuse",),
    )
    other_probe_field = _case(
        3,
        request=(("order_id", "order-victim"), ("label", "payload")),
        probe_fields=("label",),
    )
    other_witness = _case(
        4,
        request=(("order_id", "order-victim"), ("note", "payload")),
        witness_kind="oob",
    )

    result, _ = _evaluate(base, other_sink, other_probe_field, other_witness)

    assert len(result.findings) == 4
    keys = {finding.fingerprint.key for finding in result.findings}
    assert len(keys) == 4
    assert {finding.evidence_refs for finding in result.findings} == {
        (case.observation.observation_id,)
        for case in (base, other_sink, other_probe_field, other_witness)
    }


def test_shorter_witness_updates_minimal_poc() -> None:
    long_request = (("order_id", "order-victim"), ("note", "aaaaaaaaaa"))
    short_request = (("order_id", "order-victim"), ("note", "a"))
    first = _case(
        1,
        request=long_request,
        minimal_request=long_request,
    )
    second = _case(
        2,
        request=long_request,
        minimal_request=short_request,
    )

    result, _ = _evaluate(first, second)

    assert len(result.findings) == 1
    assert result.findings[0].minimal_poc == short_request


def test_verdict_identity_is_projected_from_the_formal_sink_norm() -> None:
    action = Atom(value="action:shop.OrderService.ShipOrder")
    invariant = InvariantProjection(
        invariant_id="ship-order-unpaid",
        norm_id="ship-order",
        statement="attacker must not ship an unpaid order",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:ship-order-unpaid"),
                reached(action, Atom(value="sink:unpaid_shipment")),
            ),
        ),
    )
    verdict = PolicyVerdict(
        status=VerdictStatus.FAIL,
        confidence=1.0,
        rationale="forbidden sink marker was observed",
        model_id="marker",
        deterministic=True,
        grounded=True,
    )

    attached = attach_finding_identity(
        verdict,
        invariant=invariant,
        probe_fields=("note",),
    )

    assert attached.sink_ids == ("sink:unpaid_shipment",)
    assert attached.probe_fields == ("note",)
