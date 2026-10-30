"""Partial-failure semantics for differential execution boundaries."""

from __future__ import annotations

import threading

import pytest

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.plan import QdlExecutionStep, VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.model.events import CheckCompleted, DomainEvent
from cloud_dast.qdl.graph import Atom, input_field, output_field
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import (
    Checker,
    ConcurrencyPartialResult,
    PairPartialResult,
    PartialExecutionError,
    ReadBackPartialResult,
)
from cloud_dast.verification.differential.contracts import DifferentialSpec
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    """Thread-safe publisher and in-memory event store for tests."""

    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}
        self._lock = threading.Lock()

    def publish(self, event: DomainEvent) -> None:
        with self._lock:
            self.events.append(event)

    def append(self, event: DomainEvent) -> None:
        self.publish(event)

    def read(self):
        with self._lock:
            return iter(tuple(self.events))

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        with self._lock:
            cursor = self._cursors.setdefault(consumer_id, 0)
            events = tuple(self.events[cursor:])
            self._cursors[consumer_id] = len(self.events)
            return events


def _check(identities: tuple[str, ...]) -> Check:
    return Check(
        invariant_id="invariant",
        method_id="action:get",
        scenario_id="scenario",
        request=(("secret_id", None),),
        identities=identities,
    )


def _forwarded_check() -> Check:
    return Check(
        invariant_id="invariant",
        method_id="action:get",
        scenario_id="scenario",
        request=(("forwarded", None),),
        identities=("attacker",),
    )


def _stateful_check(
    method_id: str,
    request: tuple[tuple[str, object], ...],
) -> Check:
    return Check(
        invariant_id="invariant",
        method_id=method_id,
        scenario_id="scenario",
        request=request,
        identities=("attacker",),
    )


def _observation(
    check: Check,
    *,
    value: str,
    field_name: str = "secret_id",
) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="executed",
        transport_status=HttpStatus(code=200),
        output=ResponseData(fields=((field_name, value),)),
    )


class PairFailureTarget:
    """Complete the control leg and fail the treatment leg."""

    def __init__(self, fail_identity: str) -> None:
        self.fail_identity = fail_identity
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        identity = check.identities[0]
        if identity == self.fail_identity:
            raise RuntimeError("treatment transport failed")
        return _observation(check, value=f"{identity}-output")


class ReadbackFailureTarget:
    """Complete seed/read/write legs and fail the read-after leg."""

    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        if len(self.executed) == 4:
            raise RuntimeError("read-after transport failed")
        outputs = {
            "seed-state": "seed-resource",
            "read-resource": "seed-resource",
            "followup-read": "seed-resource",
            "write-resource": "written-resource",
        }
        return _observation(
            check,
            value=outputs[check.method_id],
            field_name="resource_id",
        )


class ProbeFailureTarget:
    """Fail one probe and complete the other probes."""

    def __init__(self, fail_check_id: str) -> None:
        self.fail_check_id = fail_check_id
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        if check.check_id == self.fail_check_id:
            raise RuntimeError("probe transport failed")
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="parallel probe",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("forwarded", f"probe-{check.check_id}"),)),
        )


def _completed_check_ids(events: EventLog) -> list[str]:
    return [
        event.observation.check_id
        for event in events.events
        if isinstance(event, CheckCompleted)
    ]


def _set_forwarding(checker, source, destinations, other_methods=()):
    scenario = ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )
    source_method, source_field = source
    couplings = tuple(
        (
            output_field(Atom(value=source_method), Atom(value=source_field)),
            input_field(Atom(value=method), Atom(value=name)),
            "eq",
        )
        for method, name in destinations
    )
    methods = dict(
        ((method, name) for method, name in (source, *destinations, *other_methods))
    )
    bindings = []
    for method_id, name in methods.items():
        method = MethodSpec(
            method_id=method_id,
            service="svc",
            name=method_id,
            layer=EndpointLayer.PRIVATE,
            fields=(FieldSpec(name=name, type="string"),),
        )
        plan = VerificationPlan(
            plan_id=method_id,
            invariant_id="invariant",
            method_id=method_id,
            couplings=couplings,
        )
        bindings.append((plan, method, scenario))
    checker.set_coupling_context(tuple(bindings))


def test_pair_failure_preserves_leg_evidence_events_and_snapshot() -> None:
    target = PairFailureTarget("treatment")
    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    _set_forwarding(
        checker,
        ("seed-get", "secret_id"),
        (("followup-get", "secret_id"),),
        (("action:get", "secret_id"),),
    )
    seed = _check(("seeder",)).model_copy(update={"method_id": "seed-get"})
    control = _check(("control",))
    treatment = _check(("treatment",))
    assert checker.execute_check(seed) is not None

    with pytest.raises(PartialExecutionError) as caught:
        checker.execute_pair(control, treatment)

    partial = caught.value.partial_result
    assert isinstance(partial, PairPartialResult)
    assert partial.control is not None
    assert partial.control[0].check_id == control.check_id
    assert partial.treatment is None
    assert [check.check_id for check in partial.checks] == [
        control.check_id,
        treatment.check_id,
    ]
    assert [observation.check_id for observation in partial.observations] == [
        control.check_id
    ]
    assert [check.check_id for check in partial.failed_checks] == [treatment.check_id]
    assert _completed_check_ids(events) == [seed.check_id, control.check_id]

    followup = checker.execute_check(
        _check(("seeder",)).model_copy(update={"method_id": "followup-get"})
    )
    assert followup is not None
    assert dict(checker.checks[-1].request)["secret_id"] == "seeder-output"


@pytest.mark.parametrize("blocked", [(0,), (1,), (0, 1)])
@pytest.mark.parametrize("payload", [False, True])
def test_blocked_pair_retains_only_current_attempts(
    method_spec, scenario_position, verification_plan, invariant, blocked, payload
):
    events = EventLog()
    attempted = []
    admitted = []

    class Guardrail:
        def allows(self, check):
            admitted.append(check)
            return len(admitted) - 1 not in blocked

    def target(check):
        attempted.append(check)
        return _observation(check, value="completed")

    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    seed = _check(("seed",))
    assert checker.execute_check(seed) is not None
    # Exclude prior campaign history from both the receipt and pair spending.
    checker._guardrail = Guardrail()
    runner = assemble_runner(checker, EventProjection(events, events))
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="note", type="string"),)}
    )
    step = QdlExecutionStep(
        step_id="step:partial",
        goal_id="goal:partial",
        plan=verification_plan,
        method=method,
        scenario=scenario_position,
        invariant=invariant,
    )
    owner = scenario_position.model_copy(
        update={
            "scenario_id": "owner",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    budget = CallLimits(2)
    budget.begin_differential_round()
    options = {"mutable_fields": ("note",), "canary": "pin-canary"} if payload else {}
    mode = "payload" if payload else "differential"
    with pytest.raises(PartialExecutionError) as caught:
        runner.differential.execute_step_pair(
            step,
            None if payload else DifferentialSpec(owner, scenario_position),
            budget,
            **options,
        )

    assert str(caught.value) == (
        f"{mode} pair for step step:partial requires both legs to pass the guardrail"
    )
    partial = caught.value.partial_result
    completed = tuple(attempted[1:])
    assert partial.checks == completed
    assert partial.failed_checks == ()
    assert tuple(obs.check_id for obs in partial.observations) == tuple(
        check.check_id for check in completed
    )
    for index, leg in enumerate((partial.control, partial.treatment)):
        if index in blocked:
            assert leg is None
        else:
            assert leg is not None
            assert leg[0] is admitted[index]
            assert leg[1] is partial.observations[0]
    assert budget.live_calls == budget.diff_legs == len(completed)
    assert _completed_check_ids(events) == [seed.check_id] + [
        check.check_id for check in completed
    ]


def test_readback_failure_preserves_completed_legs_and_events() -> None:
    target = ReadbackFailureTarget()
    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    _set_forwarding(
        checker,
        ("seed-state", "resource_id"),
        (("write-resource", "resource_id"), ("followup-read", "resource_id")),
        (("read-resource", "resource_id"),),
    )
    seed = _stateful_check(
        "seed-state",
        (("resource_id", None), ("url", None)),
    )
    read = _stateful_check("read-resource", (("resource_id", "seed-resource"),))
    write = _stateful_check(
        "write-resource",
        (("resource_id", None), ("payload", None)),
    ).model_copy(update={"probe_marker": "dast-readback-canary"})
    assert checker.execute_check(seed) is not None

    with pytest.raises(PartialExecutionError) as caught:
        checker.execute_readback(
            write,
            read,
            resource_binding="resource_id",
        )

    partial = caught.value.partial_result
    assert isinstance(partial, ReadBackPartialResult)
    assert partial.read_before is not None
    assert partial.write is not None
    assert partial.read_after is None
    assert len(partial.checks) == 3
    assert len(partial.observations) == 2
    assert len(partial.failed_checks) == 1
    assert _completed_check_ids(events) == [
        seed.check_id,
        partial.read_before[0].check_id,
        partial.write[0].check_id,
    ]

    followup = checker.execute_check(
        _stateful_check("followup-read", (("resource_id", None),))
    )
    assert followup is not None
    assert dict(checker.checks[-1].request)["resource_id"] == "seed-resource"


def test_concurrency_failure_preserves_successful_probes_and_events() -> None:
    probes = tuple(_forwarded_check() for _ in range(4))
    target = ProbeFailureTarget(probes[1].check_id)
    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    _set_forwarding(
        checker,
        ("seed-get", "forwarded"),
        (("followup-get", "forwarded"),),
        (("action:get", "forwarded"),),
    )
    seed = _forwarded_check().model_copy(
        update={"identities": ("seeder",), "method_id": "seed-get"}
    )
    seeded = checker.execute_check(seed)
    assert seeded is not None

    with pytest.raises(PartialExecutionError) as caught:
        checker.execute_parallel_batch(probes, max_workers=4)

    partial = caught.value.partial_result
    assert isinstance(partial, ConcurrencyPartialResult)
    assert [check.check_id for check, _ in partial.probes] == [
        probes[0].check_id,
        probes[2].check_id,
        probes[3].check_id,
    ]
    assert [check.check_id for check in partial.checks] == [
        probe.check_id for probe in probes
    ]
    assert [check.check_id for check in partial.failed_checks] == [probes[1].check_id]
    assert set(_completed_check_ids(events)) == {
        seed.check_id,
        probes[0].check_id,
        probes[2].check_id,
        probes[3].check_id,
    }

    followup = checker.execute_check(
        _forwarded_check().model_copy(
            update={"identities": ("seeder",), "method_id": "followup-get"}
        )
    )
    assert followup is not None
    assert dict(checker.checks[-1].request)["forwarded"] == f"probe-{seed.check_id}"


def test_concurrency_failure_counts_attempted_probes_in_budget() -> None:
    probes = tuple(_forwarded_check() for _ in range(4))
    target = ProbeFailureTarget(probes[1].check_id)
    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    service = checker
    runner = assemble_runner(service, EventProjection(events, events))
    budget = CallLimits(4)
    budget.begin_differential_round()

    with pytest.raises(PartialExecutionError):
        runner.differential.execute_concurrency_batch(
            probes,
            read_before=None,
            read_after=None,
            max_workers=4,
            budget=budget,
        )

    assert budget.live_calls == 4
    assert budget.diff_legs == 4
    assert service.checks == probes


def test_parallel_errors_keep_input_order_and_skip_read_after() -> None:
    probes = tuple(_forwarded_check() for _ in range(3))
    after = _forwarded_check()
    second_failed = threading.Event()
    first_error = RuntimeError("first input failed")
    second_error = RuntimeError("second input failed earlier")
    invoked = []

    def target(check):
        invoked.append(check.check_id)
        if check.check_id == probes[0].check_id:
            assert second_failed.wait(3)
            raise first_error
        if check.check_id == probes[1].check_id:
            raise second_error
        # With two workers, this probe starts after the second future fails.
        second_failed.set()
        return _observation(check, value="successful")

    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    with pytest.raises(PartialExecutionError) as caught:
        checker.execute_parallel_batch(probes, read_after=after, max_workers=2)

    partial = caught.value.partial_result
    assert caught.value.__cause__ is first_error
    assert [check.check_id for check, _ in partial.probes] == [probes[2].check_id]
    assert [check.check_id for check in partial.failed_checks] == [
        check.check_id for check in probes[:2]
    ]
    assert after.check_id not in invoked
    assert set(_completed_check_ids(events)) == {probes[2].check_id}
    assert checker.checks == probes


@pytest.mark.parametrize("failure_stage", ["submit", "shutdown"])
def test_parallel_pool_failure_keeps_evidence_and_original_cause(
    monkeypatch, failure_stage
) -> None:
    from concurrent.futures import Future

    from cloud_dast.runtime.execution import checks

    probes = tuple(_forwarded_check() for _ in range(2))
    probe_error = RuntimeError("probe failed")
    pool_error = RuntimeError(f"pool {failure_stage} failed")
    events = EventLog()

    class FailingPool:
        def __init__(self, *, max_workers):
            assert max_workers == 2
            self.submitted = 0

        def __enter__(self):
            return self

        def submit(self, function, check, target, publisher):
            self.submitted += 1
            if failure_stage == "submit" and self.submitted == 2:
                raise pool_error
            future = Future()
            if failure_stage == "shutdown" and self.submitted == 1:
                future.set_exception(probe_error)
            else:
                future.set_result(function(check, target, publisher))
            return future

        def __exit__(self, *args):
            if failure_stage == "shutdown":
                raise pool_error

    monkeypatch.setattr(checks, "ThreadPoolExecutor", FailingPool)
    checker = Checker(
        lambda check: _observation(check, value="successful"),
        TemplateGenerator(),
        AllowAllGuardrail(),
        events,
    )
    with pytest.raises(PartialExecutionError) as caught:
        checker.execute_parallel_batch(probes, max_workers=2)
    partial = caught.value.partial_result
    assert checker.checks == probes
    if failure_stage == "submit":
        assert caught.value.__cause__ is pool_error
        assert partial.probes == ()
        assert partial.failed_checks == probes
        assert _completed_check_ids(events) == [probes[0].check_id]
    else:
        assert caught.value.__cause__ is probe_error
        assert [check for check, _ in partial.probes] == [probes[1]]
        assert partial.failed_checks == (probes[0],)
        assert _completed_check_ids(events) == [probes[1].check_id]
