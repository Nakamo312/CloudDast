from __future__ import annotations

from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Check,
    GrpcStatus,
    Observation,
    PolicyVerdict,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    DomainEvent,
    FindingRaised,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    field,
    has,
)
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.execution.runner import EventProjection


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


def _declaration(term: object, type_name: str) -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("is"),
        args=(term, Atom(value=type_name)),  # type: ignore[arg-type]
    )


def _lead_graph() -> QdlGraph:
    witness = field(Atom(value="resource:user"), Atom(value="email"))
    lead_norm = Atom(value="norm:lead:sensitive:0123456789ab")
    return QdlGraph(
        facts=(
            _declaration(Atom(value="principal:attacker"), "Principal"),
            _declaration(Atom(value="resource:user"), "Resource"),
            _declaration(witness, "OutputField"),
            _declaration(lead_norm, "Norm"),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("prevents"),
                args=(
                    lead_norm,
                    has(Atom(value="principal:attacker"), witness),
                ),
            ),
        )
    )


def _execution() -> ExecutionResult:
    return ExecutionResult(
        observations=(), checks=(), provenance={}, policy_verdicts={}
    )


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:denied-read",
        norm_id="norm:denied-read",
        statement="caller must be denied",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:denied-read"),
                allowed(Atom(value="action:get-secret")),
            ),
        ),
    )


def _grounded_failure_execution(invariant: InvariantProjection) -> ExecutionResult:
    check = Check(
        invariant_id=invariant.invariant_id,
        method_id="grpc:nsfy.shop.v1.OrderService.Method",
        scenario_id="scenario",
        request=(("order_id", "order-victim"),),
        identities=("attacker",),
    )
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="gRPC status: OK",
        transport_status=GrpcStatus(code="OK"),
    )
    return ExecutionResult(
        observations=(observation,),
        checks=(check,),
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale="IAM-grounded expected outcome is DENIED",
                evidence_refs=(observation.observation_id,),
                model_id="grounded-outcome",
                deterministic=True,
                grounded=True,
            )
        },
    )


def test_lead_is_visible_unscoreable_and_never_a_finding() -> None:
    events = _EventLog()
    evaluator = FindingEvaluator(EventProjection(events, events))

    result = evaluator.evaluate(_execution(), {}, graph=_lead_graph())

    assert result.findings == ()
    assert not any(isinstance(event, FindingRaised) for event in events.events)
    assert len(evaluator.leads) == 1
    lead = evaluator.leads[0]
    assert lead.norm_id == "norm:lead:sensitive:0123456789ab"
    assert lead.role == "sensitive"
    assert lead.verdict.status is VerdictStatus.UNSCOREABLE
    assert lead.verdict.deterministic is True
    assert lead.verdict.grounded is False


def test_grounded_failure_still_raises_a_finding_next_to_a_lead() -> None:
    events = _EventLog()
    evaluator = FindingEvaluator(EventProjection(events, events))
    invariant = _invariant()
    execution = _grounded_failure_execution(invariant)
    events.append(
        CheckCompleted(
            check=execution.checks[0],
            observation=execution.observations[0],
        )
    )

    result = evaluator.evaluate(
        execution,
        {invariant.invariant_id: invariant},
        graph=_lead_graph(),
    )

    assert len(result.findings) == 1
    assert result.findings[0].invariant_id == invariant.invariant_id
    assert any(isinstance(event, FindingRaised) for event in events.events)
    assert len(evaluator.leads) == 1
    assert evaluator.leads[0].verdict.status is VerdictStatus.UNSCOREABLE


def test_graph_without_leads_reports_no_leads() -> None:
    events = _EventLog()
    evaluator = FindingEvaluator(EventProjection(events, events))

    result = evaluator.evaluate(_execution(), {})

    assert result.findings == ()
    assert evaluator.leads == ()
