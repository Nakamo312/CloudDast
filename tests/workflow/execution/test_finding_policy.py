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
    allowed,
    changed,
    field,
    has,
    identity,
)
from cloud_dast.verification.finding_evaluator import FindingEvaluator


class _EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}
        self.read_calls = 0

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self):
        self.read_calls += 1
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _allowed_invariant(action_value: str, invariant_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"norm:{invariant_id}",
        statement="caller must be denied",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:{invariant_id}"),
                allowed(Atom(value=f"action:{action_value}")),
            ),
        ),
    )


def _changed_invariant(invariant_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"norm:{invariant_id}",
        statement="privileged field must not change",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:{invariant_id}"),
                changed(
                    Atom(value="resource:order"),
                    Atom(value="total"),
                ),
            ),
        ),
    )


def _identity_invariant(invariant_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"norm:{invariant_id}",
        statement="attacker must not assume the victim identity",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:{invariant_id}"),
                identity(
                    Atom(value="principal:attacker"),
                    Atom(value="principal:victim"),
                ),
            ),
        ),
    )


def _sensitive_exposure_invariant(invariant_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"norm:{invariant_id}",
        statement="private field must not be disclosed",
        severity=Severity.MEDIUM,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:{invariant_id}"),
                has(
                    Atom(value="principal:attacker"),
                    field(
                        Atom(value="resource:user"),
                        Atom(value="email"),
                    ),
                ),
            ),
        ),
    )


def _check(
    invariant: InvariantProjection,
    request: tuple[tuple[str, object], ...],
) -> Check:
    return Check(
        invariant_id=invariant.invariant_id,
        method_id="grpc:nsfy.shop.v1.OrderService.Method",
        scenario_id="scenario",
        request=request,
        identities=("attacker",),
    )


def _observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="gRPC status: OK",
        transport_status=GrpcStatus(code="OK"),
    )


def _verdict(
    rationale: str,
    *,
    status: VerdictStatus = VerdictStatus.FAIL,
    deterministic: bool = True,
    grounded: bool = True,
) -> PolicyVerdict:
    return PolicyVerdict(
        status=status,
        confidence=1.0,
        rationale=rationale,
        model_id="grounded-outcome",
        negative_scope=("observed_policy_outcome",)
        if status is VerdictStatus.PASS
        else (),
        deterministic=deterministic,
        grounded=grounded,
    )


def _evaluate(
    invariant: InvariantProjection,
    check: Check,
    observation: Observation,
    verdict: PolicyVerdict,
    provenance: dict[tuple[str, str], ObservationProvenance] | None = None,
) -> tuple[object, _EventLog]:
    events = _EventLog()
    events.append(CheckCompleted(check=check, observation=observation))
    evaluator = FindingEvaluator(events, events)
    execution = ExecutionResult(
        observations=(observation,),
        checks=(check,),
        provenance=provenance
        if provenance is not None
        else {
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={(observation.observation_id, invariant.invariant_id): verdict},
    )
    result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})
    return result, events


def test_evaluation_uses_incremental_projection_without_full_reads() -> None:
    invariant = _allowed_invariant("list-orders", "ordinary-list")
    check = _check(invariant, (("page_size", 10),))
    observation = _observation(check)
    events = _EventLog()
    evaluator = FindingEvaluator(events, events)
    assert evaluator.events == ()

    events.append(CheckCompleted(check=check, observation=observation))
    execution = ExecutionResult(
        observations=(observation,),
        checks=(check,),
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): _verdict(
                "IAM-grounded expected outcome is DENIED"
            )
        },
    )

    result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    assert len(result.findings) == 1
    assert any(isinstance(event, FindingRaised) for event in evaluator.events)
    assert events.read_calls == 0


def test_grounded_ordinary_permission_gap_raises_a_finding() -> None:
    invariant = _allowed_invariant("list-orders", "ordinary-list")
    check = _check(invariant, (("page_size", 10),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.list"
    )

    result, events = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1
    assert any(isinstance(event, FindingRaised) for event in events.events)
    assert any(
        isinstance(event, CheckCompleted)
        and event.observation.observation_id == observation.observation_id
        for event in events.events
    )


def test_privileged_permission_gap_raises_a_finding() -> None:
    invariant = _allowed_invariant("delete-order", "admin-delete")
    check = _check(invariant, (("force", True),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.admin"
    )

    result, events = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1
    assert result.findings[0].invariant_id == invariant.invariant_id
    assert any(isinstance(event, FindingRaised) for event in events.events)


def test_m1_fla_admin_delete_remains_a_finding() -> None:
    invariant = _allowed_invariant("delete-order", "fla-admin-delete")
    check = _check(invariant, (("order_id", "order-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.admin"
    )

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_class == "function_level_authz"


def test_object_reference_victim_raises_a_finding() -> None:
    invariant = _identity_invariant("bola-order-read")
    check = _check(invariant, (("order_id", "order-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get"
    )

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_class == "bola"


def test_field_names_do_not_change_verdict_or_path() -> None:
    invariant = _allowed_invariant("get-order", "field-invariance")
    object_check = _check(invariant, (("order_id", "order-victim"),))
    neutral_check = _check(invariant, (("page_size", 10),))
    object_observation = _observation(object_check)
    neutral_observation = _observation(neutral_check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get"
    )
    provenance = {
        (
            object_observation.observation_id,
            invariant.invariant_id,
        ): ObservationProvenance(
            "goal:same", "path:same", "step:same", invariant.invariant_id
        ),
        (
            neutral_observation.observation_id,
            invariant.invariant_id,
        ): ObservationProvenance(
            "goal:same", "path:same", "step:same", invariant.invariant_id
        ),
    }

    object_result, _ = _evaluate(
        invariant,
        object_check,
        object_observation,
        verdict,
        provenance,
    )
    neutral_result, _ = _evaluate(
        invariant,
        neutral_check,
        neutral_observation,
        verdict,
        provenance,
    )

    assert len(object_result.findings) == len(neutral_result.findings) == 1
    assert (
        [finding.path_id for finding in object_result.findings]
        == [finding.path_id for finding in neutral_result.findings]
        == ["path:same"]
    )


def test_mutating_resource_effect_raises_a_finding() -> None:
    invariant = _changed_invariant("mass-assign-total")
    check = _check(invariant, (("total", "100"),))
    observation = _observation(check)
    verdict = _verdict("privileged field changed")

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1


def test_sensitive_exposure_effect_raises_a_finding() -> None:
    invariant = _sensitive_exposure_invariant("disclose-user-email")
    check = _check(invariant, (("user_id", "user-victim"),))
    observation = _observation(check)
    verdict = _verdict("private email field was returned")

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1


def test_only_deterministic_grounded_failures_raise_findings() -> None:
    invariant = _allowed_invariant("get-order", "bola-order-read")
    check = _check(invariant, (("order_id", "order-victim"),))
    observation = _observation(check)

    ungrounded = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        grounded=False,
    )
    nondeterministic = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        deterministic=False,
    )

    ungrounded_result, ungrounded_events = _evaluate(
        invariant, check, observation, ungrounded
    )
    nondeterministic_result, nondeterministic_events = _evaluate(
        invariant, check, observation, nondeterministic
    )

    assert ungrounded_result.findings == ()
    assert nondeterministic_result.findings == ()
    assert not any(
        isinstance(event, FindingRaised) for event in ungrounded_events.events
    )
    assert not any(
        isinstance(event, FindingRaised) for event in nondeterministic_events.events
    )


def test_control_outcome_does_not_raise_a_finding() -> None:
    invariant = _allowed_invariant("get-invoice", "control-invoice-read")
    check = _check(invariant, (("invoice_id", "invoice-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is ALLOWED; "
        "principal has every permission required by the method",
        status=VerdictStatus.PASS,
    )

    result, events = _evaluate(invariant, check, observation, verdict)

    assert result.findings == ()
    assert not any(isinstance(event, FindingRaised) for event in events.events)
