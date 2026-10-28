from __future__ import annotations

from cloud_dast.api import (
    ExecutionResult,
    ObservationProvenance,
)
from cloud_dast.model import (
    Check,
    HttpStatus,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import DomainEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    input_field,
)
from cloud_dast.verification.finding_evaluator import FindingEvaluator
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict


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


def _execution(
    invariant: InvariantProjection, observation: Observation
) -> ExecutionResult:
    check = Check(
        check_id="check",
        invariant_id=invariant.invariant_id,
        method_id="grpc:test.Service.Method",
        scenario_id="scenario",
        request=(("resource_id", "resource-victim"),),
        identities=("attacker",),
    )
    return ExecutionResult(
        observations=(observation,),
        checks=(check,),
        traces={observation.observation_id: (observation,)},
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={},
    )


def test_model_fail_does_not_raise_a_finding() -> None:
    invariant = _invariant()
    observation = _observation()
    events = _EventLog()
    evaluator = FindingEvaluator(events, events)

    result = evaluator.evaluate(_execution(invariant, observation), {"i": invariant})

    assert result.findings == ()


def test_grounded_deterministic_fail_raises_a_finding() -> None:
    invariant = _invariant()
    observation = _observation()
    events = _EventLog()
    evaluator = FindingEvaluator(events, events)
    execution = _execution(invariant, observation)
    execution = ExecutionResult(
        observations=execution.observations,
        checks=execution.checks,
        traces=execution.traces,
        provenance=execution.provenance,
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale="IAM expected denial but the target allowed the call",
                model_id="grounded-outcome",
                deterministic=True,
                grounded=True,
            )
        },
    )

    result = evaluator.evaluate(execution, {"i": invariant})

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_class == "classification_deficit"
    assert result.findings[0].classification_deficits == ("missing_norm_fact",)
    assert result.replayed_findings == result.findings


def test_changed_finding_receives_qdl_classifications() -> None:
    invariant = _changed_invariant()
    observation = _observation()
    events = _EventLog()
    evaluator = FindingEvaluator(events, events)
    execution = _execution(invariant, observation)
    execution = ExecutionResult(
        observations=execution.observations,
        checks=execution.checks,
        traces=execution.traces,
        provenance=execution.provenance,
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale="forbidden resource field changed between paired reads",
                model_id="differential",
                deterministic=True,
                grounded=True,
            )
        },
    )

    result = evaluator.evaluate(
        execution,
        {invariant.invariant_id: invariant},
        graph=_privileged_scope_graph(),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vulnerability_class == "mass_assignment"
    assert finding.cwe == ("CWE-915",)
    assert finding.owasp == ("API3",)
    assert finding.stride == ("T",)


def test_changed_finding_without_role_fact_receives_deficit() -> None:
    invariant = _changed_invariant()
    observation = _observation()
    events = _EventLog()
    evaluator = FindingEvaluator(events, events)
    execution = _execution(invariant, observation)
    execution = ExecutionResult(
        observations=execution.observations,
        checks=execution.checks,
        traces=execution.traces,
        provenance=execution.provenance,
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale="forbidden resource field changed between paired reads",
                model_id="differential",
                deterministic=True,
                grounded=True,
            )
        },
    )

    result = evaluator.evaluate(
        execution,
        {invariant.invariant_id: invariant},
        graph=QdlGraph(),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vulnerability_class == "classification_deficit"
    assert finding.classification_deficits == ("missing_input_role",)
    assert finding.cwe
    assert finding.owasp
    assert finding.stride


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="i",
        norm_id="t",
        statement="caller must be denied",
        severity=Severity.HIGH,
    )


def _changed_invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="i",
        norm_id="t",
        statement="caller must not change the privileged scope",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:no-scope-change"),
                changed(Atom(value="resource:api_key"), Atom(value="scope")),
            ),
        ),
    )


def _privileged_scope_graph() -> QdlGraph:
    action = Atom(value="action:grpc:test.Service.Method")
    scope = input_field(action, Atom(value="scope"))
    return QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(scope, Atom(value="Field")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("has"),
                args=(scope, Atom(value="privileged")),
            ),
        )
    )


def _observation() -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome="allowed",
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )
