from __future__ import annotations

from threading import Event, Thread
from unittest.mock import Mock, call, patch

import pytest

from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.infrastructure.events import EventBus
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
    Struct,
    allowed,
    changed,
    duration,
    field,
    has,
    identity,
)
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.verification.findings import collect
from cloud_dast.verification.oracles import latency
from cloud_dast.verification.taxonomy import ClassificationFacts


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
    evidence_refs: tuple[str, ...],
    status: VerdictStatus = VerdictStatus.FAIL,
    deterministic: bool = True,
    grounded: bool = True,
) -> PolicyVerdict:
    return PolicyVerdict(
        status=status,
        confidence=1.0,
        rationale=rationale,
        model_id="grounded-outcome",
        evidence_refs=evidence_refs,
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
    evaluator = FindingEvaluator(EventProjection(events, events))
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
    evaluator = FindingEvaluator(EventProjection(events, events))
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
                "IAM-grounded expected outcome is DENIED",
                evidence_refs=(observation.observation_id,),
            )
        },
    )

    result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    assert len(result.findings) == 1
    assert any(isinstance(event, FindingRaised) for event in evaluator.events)
    assert events.read_calls == 0


@pytest.mark.parametrize("physical", [False, True])
def test_evaluation_uses_current_registry_and_original_check(physical) -> None:
    invariant = _allowed_invariant("list-orders", "current-registry")
    check = _check(invariant, (("actual", "request"),) if physical else ()).model_copy(
        update={"invariant_id": "generation:old"}
    )
    observation = _observation(check)
    events = _EventLog()
    journal_check = check.model_copy(
        update={"request": (), "identities": ("foreign",), "invariant_id": "old"}
    )
    event = CheckCompleted(check=journal_check, observation=observation)
    assert event.check is not None
    events.append(event)
    projection = EventProjection(events, events)
    evaluator = FindingEvaluator(projection)
    key = observation.observation_id, invariant.invariant_id
    execution = ExecutionResult(
        (observation,),
        (check,) if physical else (),
        {key: ObservationProvenance(None, "path", "step", invariant.invariant_id)},
        {
            key: _verdict(
                "recorded witness", evidence_refs=(observation.observation_id,)
            )
        },
    )

    assert projection.refresh() == (event,)
    assert evaluator.evaluate(execution, {}).findings == ()
    result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.minimal_poc == check.request
    assert finding.invariant_id == invariant.invariant_id != check.invariant_id
    assert finding.observation_id == observation.observation_id
    assert finding.method_id == check.method_id
    assert finding.scenario_id == observation.scenario_id
    assert finding.norm_fact == invariant.norm_fact
    assert (finding.goal_id, finding.path_id, finding.step_id) == (None, "path", "step")
    assert finding.rationale == "recorded witness"
    assert finding.confidence == 1.0
    assert finding.evidence_refs == (observation.observation_id,)
    assert finding.title == f"Security policy violated: {invariant.invariant_id}"
    assert finding.description == invariant.statement
    assert finding.remediation == "Review and enforce the invariant's security policy."
    assert result.replayed_observations == (observation,)
    assert result.replayed_findings == result.findings
    assert len(events._cursors) == 1
    assert events.read_calls == 0


def test_evaluation_refreshes_around_publication_and_repeats_current_decision() -> None:
    invariant = _allowed_invariant("list-orders", "publication-order")
    check = _check(invariant, ())
    observation = _observation(check)
    event = CheckCompleted(check=check, observation=observation, correlation_id="input")
    events = _EventLog()
    events.append(event)
    bus = EventBus()
    callbacks: list[FindingRaised] = []
    bus.subscribe(FindingRaised, events.append)
    bus.subscribe(FindingRaised, callbacks.append)
    evaluator = FindingEvaluator(EventProjection(bus, events))
    key = observation.observation_id, invariant.invariant_id
    execution = ExecutionResult(
        (observation,),
        (check,),
        {key: ObservationProvenance("goal", "path", "step", invariant.invariant_id)},
        {
            key: _verdict(
                "recorded witness", evidence_refs=(observation.observation_id,)
            )
        },
    )
    trace = Mock()
    with (
        patch.object(events, "read_new", wraps=events.read_new) as refresh,
        patch.object(bus, "publish", wraps=bus.publish) as publish,
    ):
        trace.attach_mock(refresh, "refresh")
        trace.attach_mock(publish, "publish")
        result = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    raised = events.events[-1]
    assert trace.mock_calls == [
        call.refresh(next(iter(events._cursors))),
        call.publish(raised),
        call.refresh(next(iter(events._cursors))),
    ]
    assert isinstance(raised, FindingRaised)
    assert raised.correlation_id == check.check_id
    assert raised.campaign_id is None and raised.run_id is None
    assert raised.finding.goal_id == "goal"
    assert raised.finding.path_id == "path" and raised.finding.step_id == "step"
    assert raised.finding.evidence_refs == (observation.observation_id,)
    assert result.replayed_findings == result.findings
    assert evaluator.events == (event, raised)
    assert callbacks == [raised]

    repeated = evaluator.evaluate(execution, {invariant.invariant_id: invariant})

    assert len(repeated.findings) == 1
    assert repeated.findings[0].finding_id != result.findings[0].finding_id
    assert repeated.findings[0].fingerprint == result.findings[0].fingerprint
    assert repeated.replayed_findings == repeated.findings
    assert events.events[:2] == [event, raised]
    assert len(events.events) == 3
    assert callbacks == events.events[1:]
    assert events.read_calls == 0


def test_owner_refresh_keeps_background_publications_in_order() -> None:
    invariant = _allowed_invariant("list-orders", "background-publication")
    check = _check(invariant, ())
    observation = _observation(check)
    first = CheckCompleted(check=check, observation=observation)
    second = CheckCompleted(check=check, observation=observation)
    events = _EventLog()
    bus = EventBus()
    bus.subscribe(CheckCompleted, events.append)
    projection = EventProjection(bus, events)
    ready, release = Event(), Event()

    def publish() -> None:
        bus.publish(first)
        ready.set()
        if release.wait(5):
            bus.publish(second)

    worker = Thread(target=publish)
    worker.start()
    try:
        assert ready.wait(5)
        assert projection.refresh() == (first,)
    finally:
        release.set()
        worker.join(5)

    assert not worker.is_alive()
    assert projection.refresh() == (first, second)
    assert projection.refresh() == (first, second)
    assert len(events._cursors) == 1
    assert events.read_calls == 0


@pytest.mark.parametrize(
    "norm_kind",
    [
        "accepted",
        "missing",
        "proposal",
        "runtime",
        "report",
        "contract",
        "not-norm",
        "unsupported",
    ],
)
@pytest.mark.parametrize("evidence_kind", ["own", "empty", "foreign"])
def test_final_finding_requires_norm_and_recorded_evidence(
    norm_kind, evidence_kind
) -> None:
    invariant = _allowed_invariant("list-orders", "finding-admission")
    if norm_kind == "missing":
        invariant = invariant.model_copy(update={"norm_fact": None})
    elif norm_kind in {"proposal", "runtime", "report", "contract"}:
        invariant = invariant.model_copy(
            update={
                "norm_fact": invariant.norm_fact.model_copy(
                    update={"context": Context(norm_kind)}
                )
            }
        )
    elif norm_kind == "not-norm":
        invariant = invariant.model_copy(
            update={
                "norm_fact": Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(Atom(value="norm:fake"), Atom(value="Norm")),
                )
            }
        )
    elif norm_kind == "unsupported":
        invariant = invariant.model_copy(
            update={
                "norm_fact": Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("prevents"),
                    args=(
                        Atom(value="norm:unsupported"),
                        Struct(name="create", args=(Atom(value="resource:r"),)),
                    ),
                )
            }
        )
    check = _check(invariant, ())
    observation = _observation(check)
    refs = {
        "own": (observation.observation_id,),
        "empty": (),
        "foreign": ("observation:another-candidate",),
    }[evidence_kind]
    verdict = _verdict("deterministic witness", evidence_refs=refs).model_copy(
        update={"evidence_refs": refs}
    )

    result, events = _evaluate(invariant, check, observation, verdict)

    admissible = norm_kind == "accepted" and evidence_kind == "own"
    assert bool(result.findings) is admissible
    assert (
        any(isinstance(event, FindingRaised) for event in events.events) is admissible
    )


def test_finding_retains_recorded_worst_latency_witness() -> None:
    method = "grpc:nsfy.shop.v1.OrderService.Method"
    invariant = _allowed_invariant(method, "latency")
    invariant = invariant.model_copy(
        update={
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:latency"),
                    duration(Atom(value=f"action:{method}"), Atom(value=110)),
                ),
            )
        }
    )
    check = _check(invariant, ())
    previous = _observation(check).model_copy(update={"duration_ms": 1000.0})
    current = _observation(check).model_copy(update={"duration_ms": 10.0})
    oracle = latency.Oracle()
    oracle.update_baseline(method, (10.0, 10.0, 10.0))
    verdict = oracle.evaluate_policy(invariant, (previous, current), method_id=method)
    assert verdict.status is VerdictStatus.FAIL
    assert verdict.evidence_refs == (previous.observation_id,)
    events = _EventLog()
    execution = ExecutionResult(
        observations=(previous, current),
        checks=(check,),
        provenance={
            (current.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={(current.observation_id, invariant.invariant_id): verdict},
    )

    result = FindingEvaluator(EventProjection(events, events)).evaluate(
        execution, {invariant.invariant_id: invariant}
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence_refs == (previous.observation_id,)


def test_grounded_ordinary_permission_gap_raises_a_finding() -> None:
    invariant = _allowed_invariant("list-orders", "ordinary-list")
    check = _check(invariant, (("page_size", 10),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.list",
        evidence_refs=(observation.observation_id,),
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
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.admin",
        evidence_refs=(observation.observation_id,),
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
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.admin",
        evidence_refs=(observation.observation_id,),
    )

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_class == "function_level_authz"


def test_object_reference_victim_raises_a_finding() -> None:
    invariant = _identity_invariant("bola-order-read")
    check = _check(invariant, (("order_id", "order-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        evidence_refs=(observation.observation_id,),
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
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        evidence_refs=(
            object_observation.observation_id,
            neutral_observation.observation_id,
        ),
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
    assert (
        object_result.findings[0].vulnerability_class
        == neutral_result.findings[0].vulnerability_class
        == "function_level_authz"
    )


def test_mutating_resource_effect_raises_a_finding() -> None:
    invariant = _changed_invariant("mass-assign-total")
    check = _check(invariant, (("total", "100"),))
    observation = _observation(check)
    verdict = _verdict(
        "privileged field changed", evidence_refs=(observation.observation_id,)
    )

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1


def test_sensitive_exposure_effect_raises_a_finding() -> None:
    invariant = _sensitive_exposure_invariant("disclose-user-email")
    check = _check(invariant, (("user_id", "user-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "private email field was returned", evidence_refs=(observation.observation_id,)
    )

    result, _ = _evaluate(invariant, check, observation, verdict)

    assert len(result.findings) == 1


def test_only_deterministic_grounded_failures_raise_findings() -> None:
    invariant = _allowed_invariant("get-order", "bola-order-read")
    check = _check(invariant, (("order_id", "order-victim"),))
    observation = _observation(check)

    ungrounded = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        grounded=False,
        evidence_refs=(observation.observation_id,),
    )
    nondeterministic = _verdict(
        "IAM-grounded expected outcome is DENIED; missing permissions: nsfy.order.get",
        deterministic=False,
        evidence_refs=(observation.observation_id,),
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


@pytest.mark.parametrize("status", [VerdictStatus.PASS, VerdictStatus.UNSCOREABLE])
def test_control_outcome_does_not_raise_a_finding(status) -> None:
    invariant = _allowed_invariant("get-invoice", "control-invoice-read")
    check = _check(invariant, (("invoice_id", "invoice-victim"),))
    observation = _observation(check)
    verdict = _verdict(
        "IAM-grounded expected outcome is ALLOWED; principal has every permission required by the method",
        status=status,
        evidence_refs=(observation.observation_id,),
    )

    result, events = _evaluate(invariant, check, observation, verdict)

    assert result.findings == ()
    assert not any(isinstance(event, FindingRaised) for event in events.events)


@pytest.mark.parametrize("association", ["check", "scenario"])
@pytest.mark.parametrize("invalid_minimal", [False, True])
@pytest.mark.parametrize("admitted", [False, True])
def test_collect_keeps_admission_and_argument_error_order(
    association, invalid_minimal, admitted
) -> None:
    invariant = _allowed_invariant("get-order", "association-guard")
    check = _check(invariant, (("order_id", "victim"),))
    observation = _observation(check)
    mapped_check = check
    if association == "check":
        mapped_check = check.model_copy(update={"check_id": "foreign"})
    else:
        observation = observation.model_copy(update={"scenario_id": "foreign"})
    verdict = _verdict(
        "recorded witness",
        evidence_refs=(observation.observation_id,),
        status=VerdictStatus.FAIL if admitted else VerdictStatus.PASS,
    )
    key = observation.observation_id, invariant.invariant_id
    execution = ExecutionResult(
        (observation,),
        (check,),
        {key: ObservationProvenance(None, "path", "step", invariant.invariant_id)},
        {key: verdict},
        {key: None} if invalid_minimal else {},
    )
    if not admitted:
        assert (
            collect(
                execution,
                {invariant.invariant_id: invariant},
                {observation.check_id: mapped_check},
                ClassificationFacts(),
            )
            == ()
        )
        return

    error = AttributeError if invalid_minimal else ValueError
    message = (
        "'NoneType' object has no attribute 'request'"
        if invalid_minimal
        else "observation does not belong to the check"
        if association == "check"
        else "observation scenario does not belong to the check"
    )
    with pytest.raises(error, match=message):
        collect(
            execution,
            {invariant.invariant_id: invariant},
            {observation.check_id: mapped_check},
            ClassificationFacts(),
        )
