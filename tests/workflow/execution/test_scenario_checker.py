"""Checker stateful forwarding and isolated differential execution."""

from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    BindingRef,
    Check,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    PrincipalRef,
    ResourceRef,
    ResponseData,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import Atom, input_field, output_field
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


class EchoIdentityTarget:
    """Echo the executing identity back as a response field."""

    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        identity = check.identities[0]
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="echoed",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("secret_id", f"{identity}-output"),)),
        )


def _check(identities: tuple[str, ...]) -> Check:
    return Check(
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        request=(("secret_id", None),),
        identities=identities,
    )


def _stateful_check(
    method_id: str,
    request: tuple[tuple[str, object], ...],
) -> Check:
    return Check(
        invariant_id="inv",
        method_id=method_id,
        scenario_id="scenario",
        request=request,
        identities=("attacker",),
    )


class ForwardingTarget:
    """Return fixed structured fields for the first stateful method."""

    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        output = (
            ResponseData(fields=(("url", "https://hook.example"), ("data", "payload")))
            if check.method_id == "set-webhook"
            else None
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="executed",
            transport_status=HttpStatus(code=200),
            output=output,
        )


class ReadbackTarget:
    """Return state-changing outputs for read-back execution."""

    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        outputs = {
            "seed-state": (("resource_id", "seed-resource"), ("url", "seed-url")),
            "write-resource": (
                ("resource_id", "written-resource"),
                ("url", "write-url"),
            ),
        }
        output = ResponseData(fields=outputs.get(check.method_id, ()))
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="executed",
            transport_status=HttpStatus(code=200),
            output=output,
        )


def test_undeclared_outputs_are_not_forwarded() -> None:
    target = ForwardingTarget()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())
    seed = _stateful_check("set-webhook", (("callback", None),))
    parse = _stateful_check("parse-config", (("data", None),))
    fetch = _stateful_check("get-webhook", (("url", None),))

    assert checker.execute_check(seed) is not None
    assert checker.execute_check(parse) is not None
    assert checker.execute_check(fetch) is not None

    # No declared coupling: even an identically named output is not a source.
    assert dict(checker.checks[1].request) == {"data": None}
    # Candidate identity remains intact when no output binding is declared.
    assert dict(checker.checks[2].request) == {"url": None}
    assert [check.check_id for check in checker.checks] == [
        seed.check_id,
        parse.check_id,
        fetch.check_id,
    ]


def test_execute_readback_shares_snapshot_and_restores_outputs() -> None:
    target = ReadbackTarget()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())
    seed = _stateful_check(
        "seed-state",
        (("resource_id", None), ("url", None)),
    )
    read = _stateful_check("read-resource", (("resource_id", None),))
    write = _stateful_check(
        "write-resource",
        (("resource_id", None), ("payload", None)),
    ).model_copy(update={"probe_marker": "dast-readback-canary"})

    assert checker.execute_check(seed) is not None
    result = checker.execute_readback(
        write,
        read,
        resource_binding="resource_id",
    )

    assert dict(result.read_before_check.request) == {"resource_id": None}
    assert dict(result.write_check.request) == {
        "resource_id": None,
        "payload": None,
    }
    # The write response rebinds the resource id, but its unrelated ``url``
    # field cannot leak into the read-after request.
    assert dict(result.read_after_check.request) == {"resource_id": "written-resource"}

    followup = checker.execute_check(
        _stateful_check("read-resource", (("resource_id", None),))
    )
    assert followup is not None
    assert dict(checker.checks[-1].request) == {"resource_id": None}
    assert len(checker.checks) == 5


def test_execute_readback_rejects_an_unmarked_write_leg() -> None:
    target = ReadbackTarget()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())
    read = _stateful_check("read-resource", (("resource_id", None),))
    write = _stateful_check(
        "write-resource",
        (("resource_id", None), ("payload", None)),
    )

    with pytest.raises(ValueError, match="marked write check"):
        checker.execute_readback(write, read, resource_binding="resource_id")

    assert target.executed == []


def test_execute_pair_shares_snapshot_and_restores_outputs() -> None:
    target = EchoIdentityTarget()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())

    seeded = checker.execute_check(_check(("seeder",)))
    assert seeded is not None

    first, second = checker.execute_pair(
        _check(("control",)),
        _check(("treatment",)),
    )
    assert first is not None
    assert second is not None

    # Neither leg receives an undeclared response from a different identity.
    assert dict(first[0].request) == {"secret_id": None}
    assert dict(second[0].request) == {"secret_id": None}
    assert first[1].observed_outcome is AccessOutcome.ALLOWED
    assert second[1].observed_outcome is AccessOutcome.ALLOWED

    # The pair restores the snapshot: a later check continues from the state
    # captured before the pair, not from the treatment response.
    followup = checker.execute_check(_check(("followup",)))
    assert followup is not None
    assert dict(target.executed[-1].request) == {"secret_id": None}
    assert len(checker.checks) == 4


class CoupledTarget:
    def __init__(self, values=("observed-id",)):
        self.values = iter(values)
        self.executed = []
        self.observation_update = {}

    def __call__(self, check):
        self.executed.append(check)
        fields = (("id", next(self.values)),) if check.method_id == "make" else ()
        observation = Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="executed",
            output=ResponseData(fields=fields),
        )
        return observation.model_copy(update=self.observation_update)


class RecordingGuardrail:
    def __init__(self):
        self.checks = []

    def allows(self, check):
        self.checks.append(check)
        return True


def _scenario(name="scenario"):
    return ScenarioPosition(
        scenario_id=name,
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


def _coupling_context(service, *, field=None, reverse=False, extra=(), scenarios=None):
    source = output_field(Atom(value="action:make"), Atom(value="id"))
    destination = input_field(Atom(value="action:use"), Atom(value="widget_id"))
    coupling = (destination, source, "eq") if reverse else (source, destination, "eq")
    bindings = []
    for name in ("make", "use"):
        method = MethodSpec(
            method_id=name,
            service="svc",
            name=name,
            layer=EndpointLayer.PRIVATE,
            fields=()
            if name == "make"
            else (field or FieldSpec(name="widget_id", type="string"),),
        )
        plan = VerificationPlan(
            plan_id=f"plan:{name}",
            invariant_id="inv",
            method_id=name,
            couplings=(coupling, *extra),
        )
        bindings.append(
            (plan, method, _scenario() if scenarios is None else scenarios[name])
        )
    service.set_coupling_context(tuple(bindings))
    return tuple(bindings)


def _coupled_service(values=("observed-id",), **context):
    target = CoupledTarget(values)
    guardrail = RecordingGuardrail()
    checker = Checker(target, TemplateGenerator(), guardrail)
    service = checker
    _coupling_context(service, **context)
    return service, target, guardrail


@pytest.mark.parametrize("reverse", [False, True])
def test_declared_renamed_output_is_bound_before_guardrail(reverse):
    service, target, guardrail = _coupled_service(reverse=reverse)
    make = _stateful_check("make", ())
    use = _stateful_check("use", (("widget_id", None),))
    assert service.execute_check(make) is not None
    assert service.execute_check(use) is not None
    assert dict(target.executed[-1].request) == {"widget_id": "observed-id"}
    assert guardrail.checks[-1] == target.executed[-1]
    assert target.executed[-1].check_id == use.check_id


def test_missing_source_defers_before_guardrail_and_target():
    service, target, guardrail = _coupled_service()
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert target.executed == guardrail.checks == []


@pytest.mark.parametrize(
    "change",
    [
        {"identities": ("other",)},
        {"scenario_id": "other"},
        {"method_id": "other"},
    ],
)
def test_coupling_cannot_use_foreign_execution(change):
    service, target, guardrail = _coupled_service()
    assert (
        service.execute_check(_stateful_check("make", ()).model_copy(update=change))
        is not None
    )
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"check_id": "foreign"},
        {"scenario_id": "foreign"},
        {"auth_failed": True},
        {"observed_outcome": AccessOutcome.ERROR},
        {"error_reason": "failed"},
        {"observed_outcome": AccessOutcome.DENIED},
    ],
)
def test_coupling_rejects_untrusted_observation_metadata(change):
    service, target, guardrail = _coupled_service()
    target.observation_update = change
    if "check_id" in change or "scenario_id" in change:
        with pytest.raises(ValueError, match="another check|another scenario"):
            service.execute_check(_stateful_check("make", ()))
    else:
        service.execute_check(_stateful_check("make", ()))
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


@pytest.mark.parametrize("value", [None, 7, True, ("id",)])
def test_coupling_rejects_incompatible_output(value):
    service, target, guardrail = _coupled_service(values=(value,))
    service.execute_check(_stateful_check("make", ()))
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


def test_coupling_does_not_overwrite_concrete_mutation():
    service, target, guardrail = _coupled_service()
    service.execute_check(_stateful_check("make", ()))
    mutation = _stateful_check("use", (("widget_id", "mutated-id"),))
    assert service.execute_check(mutation) is None
    assert mutation.request == (("widget_id", "mutated-id"),)
    assert len(target.executed) == len(guardrail.checks) == 1
    matching = _stateful_check("use", (("widget_id", "observed-id"),))
    assert service.execute_check(matching) is not None
    assert target.executed[-1] == matching


def test_repeated_source_uses_current_live_occurrence():
    service, target, guardrail = _coupled_service(values=("one", "two"))
    service.execute_check(_stateful_check("make", ()))
    service.execute_check(_stateful_check("make", ()))
    assert (
        service.execute_check(_stateful_check("use", (("widget_id", None),)))
        is not None
    )
    assert dict(target.executed[-1].request) == {"widget_id": "two"}
    assert len(target.executed) == len(guardrail.checks) == 3


@pytest.mark.parametrize("status,allowed", [(200, True), (404, False), (500, False)])
def test_latest_transport_error_cannot_supply_value(status, allowed):
    service, target, guardrail = _coupled_service(values=("older", "latest"))
    service.execute_check(_stateful_check("make", ()))
    target.observation_update = {"transport_status": HttpStatus(code=status)}
    service.execute_check(_stateful_check("make", ()))
    result = service.execute_check(_stateful_check("use", (("widget_id", None),)))
    assert (result is not None) == allowed
    assert len(target.executed) == len(guardrail.checks) == 2 + int(allowed)
    if allowed:
        assert dict(target.executed[-1].request) == {"widget_id": "latest"}


def test_absent_sibling_consumer_does_not_constrain_active_path():
    sibling = (
        output_field(Atom(value="action:make"), Atom(value="id")),
        input_field(Atom(value="action:other-use"), Atom(value="foreign_id")),
        "eq",
    )
    service, target, guardrail = _coupled_service(extra=(sibling,))
    assert service.execute_check(_stateful_check("make", ())) is not None
    assert (
        service.execute_check(_stateful_check("use", (("widget_id", None),)))
        is not None
    )
    assert dict(target.executed[-1].request) == {"widget_id": "observed-id"}
    assert len(target.executed) == len(guardrail.checks) == 2


def test_absent_source_for_current_input_still_defers():
    missing_source = (
        output_field(Atom(value="action:absent"), Atom(value="id")),
        input_field(Atom(value="action:use"), Atom(value="widget_id")),
        "eq",
    )
    service, target, guardrail = _coupled_service(extra=(missing_source,))
    assert service.execute_check(_stateful_check("make", ())) is not None
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


def test_context_reset_cannot_reuse_prior_path_observation():
    service, target, guardrail = _coupled_service()
    service.execute_check(_stateful_check("make", ()))
    _coupling_context(service)
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


def test_pair_cannot_feed_its_control_output_into_treatment():
    service, target, guardrail = _coupled_service()
    control, treatment = service.execute_pair(
        _stateful_check("make", ()),
        _stateful_check("use", (("widget_id", None),)),
    )
    assert control is not None and treatment is None
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


@pytest.mark.parametrize(
    "field,value,allowed",
    [
        (FieldSpec(name="widget_id", type="int32", minimum=1, maximum=3), 2, True),
        (FieldSpec(name="widget_id", type="int32", minimum=1, maximum=3), 4, False),
        (FieldSpec(name="widget_id", type="int32"), True, False),
        (FieldSpec(name="widget_id", type="string", repeated=True), ("a", "b"), True),
        (
            FieldSpec(name="widget_id", type="string", enum_values=("a", "b")),
            "c",
            False,
        ),
    ],
)
def test_coupled_value_must_satisfy_destination_schema(field, value, allowed):
    service, target, guardrail = _coupled_service(values=(value,), field=field)
    service.execute_check(_stateful_check("make", ()))
    observation = service.execute_check(_stateful_check("use", (("widget_id", None),)))
    assert (observation is not None) == allowed
    assert len(target.executed) == len(guardrail.checks) == 1 + allowed


def test_method_specific_scenarios_share_bounded_compatible_context():
    scenarios = {"make": _scenario("make-scenario"), "use": _scenario("use-scenario")}
    service, target, guardrail = _coupled_service(scenarios=scenarios)
    service.execute_check(
        _stateful_check("make", ()).model_copy(update={"scenario_id": "make-scenario"})
    )
    result = service.execute_check(
        _stateful_check("use", (("widget_id", None),)).model_copy(
            update={"scenario_id": "use-scenario"}
        )
    )
    assert result is not None
    assert dict(target.executed[-1].request) == {"widget_id": "observed-id"}
    assert guardrail.checks[-1] == target.executed[-1]


@pytest.mark.parametrize("different", ["profile", "container"])
def test_declared_path_does_not_cross_incompatible_scenarios(different):
    source = _scenario("source")
    destination = _scenario("destination")
    if different == "profile":
        destination = destination.model_copy(
            update={
                "profile": destination.profile.model_copy(
                    update={"scope_relation": ScopeRelation.CROSS_FOLDER}
                )
            }
        )
    else:
        destination = destination.model_copy(
            update={
                "stand": StandState(
                    bindings=(
                        BindingRef(
                            principal_id="attacker", role="reader", folder_id="foreign"
                        ),
                    )
                )
            }
        )
    service, target, guardrail = _coupled_service(
        scenarios={"make": source, "use": destination}
    )
    service.execute_check(
        _stateful_check("make", ()).model_copy(update={"scenario_id": "source"})
    )
    result = service.execute_check(
        _stateful_check("use", (("widget_id", None),)).model_copy(
            update={"scenario_id": "destination"}
        )
    )
    assert result is None
    assert len(target.executed) == len(guardrail.checks) == 1


def test_real_template_symbolic_and_service_forward_observed_output():
    from cloud_dast_symbolic.solver import SymbolicPrefilter

    target = CoupledTarget()
    guardrail = RecordingGuardrail()
    service = Checker(target, TemplateGenerator(), guardrail)
    stand = StandState(
        principals=(PrincipalRef(principal_id="attacker", principal_type="user"),)
    )
    scenarios = {
        name: _scenario(f"scenario:{name}").model_copy(update={"stand": stand})
        for name in ("make", "use")
    }
    bindings = _coupling_context(service, scenarios=scenarios)
    invariant = InvariantProjection(
        invariant_id="inv", norm_id="norm", statement="test", severity=Severity.LOW
    )
    checks = []
    for plan, method, scenario in bindings:
        plan = plan.model_copy(update={"scenario_id": scenario.scenario_id})
        checks.append(
            service.generate_pair_checks(plan, method, invariant, scenario)[0]
        )
    assert dict(checks[1].request)["widget_id"] is None
    solution = SymbolicPrefilter().prefilter_sequence(
        checks, tuple((plan, method) for plan, method, _ in bindings)
    )
    assert solution.status == "deferred"
    for check in solution.checks:
        assert service.execute_check(check) is not None
    assert dict(target.executed[1].request) == {"widget_id": "observed-id"}
    assert guardrail.checks == target.executed


def test_scope_without_container_coordinates_requires_compatible_resources():
    source = _scenario("source")
    destination = _scenario("destination").model_copy(
        update={
            "stand": StandState(
                resources=(
                    ResourceRef(
                        service="svc", resource_type="widget", resource_id="foreign"
                    ),
                )
            )
        }
    )
    service, target, guardrail = _coupled_service(
        scenarios={"make": source, "use": destination}
    )
    service.execute_check(
        _stateful_check("make", ()).model_copy(update={"scenario_id": "source"})
    )
    result = service.execute_check(
        _stateful_check("use", (("widget_id", None),)).model_copy(
            update={"scenario_id": "destination"}
        )
    )
    assert result is None
    assert len(target.executed) == len(guardrail.checks) == 1


def test_parallel_batch_uses_declared_snapshot_and_retains_it():
    service, target, guardrail = _coupled_service()
    service.execute_check(_stateful_check("make", ()))
    result = service.execute_parallel_batch(
        tuple(_stateful_check("use", (("widget_id", None),)) for _ in range(3))
    )
    assert len(result.probes) == 3
    assert all(
        dict(check.request) == {"widget_id": "observed-id"}
        for check, _ in result.probes
    )
    assert (
        service.execute_check(_stateful_check("use", (("widget_id", None),)))
        is not None
    )
    assert dict(target.executed[-1].request) == {"widget_id": "observed-id"}


@pytest.mark.parametrize(
    "operator,left,right,allowed",
    [
        ("eq", 1, 2, False),
        ("eq", 2, 2, True),
        ("lt", 1, 2, True),
        ("lt", 2, 1, False),
        ("ne", (1, 2), (2, 2), False),
        ("ne", (1, 2), (2, 3), True),
    ],
)
def test_request_coupling_is_enforced_without_rewriting_mutation(
    operator, left, right, allowed
):
    target = CoupledTarget()
    guardrail = RecordingGuardrail()
    service = Checker(target, TemplateGenerator(), guardrail)
    method = MethodSpec(
        method_id="use",
        name="use",
        service="svc",
        layer=EndpointLayer.PRIVATE,
        fields=tuple(
            FieldSpec(name=name, type="int32", repeated=isinstance(left, tuple))
            for name in ("a", "b")
        ),
    )
    plan = VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id="use",
        couplings=(
            (
                input_field(Atom(value="use"), Atom(value="a")),
                input_field(Atom(value="use"), Atom(value="b")),
                operator,
            ),
        ),
    )
    service.set_coupling_context(((plan, method, _scenario()),))
    check = _stateful_check("use", (("a", left), ("b", right)))
    assert (service.execute_check(check) is not None) == allowed
    assert len(target.executed) == len(guardrail.checks) == int(allowed)
    assert check.request == (("a", left), ("b", right))


@pytest.mark.parametrize(
    "source_identity,value,execute_source,allowed",
    [
        ("attacker", 2, True, True),
        ("attacker", 3, True, False),
        ("other", 2, True, False),
        ("attacker", 2, False, False),
    ],
)
def test_cross_action_request_coupling_requires_prior_compatible_source(
    source_identity, value, execute_source, allowed
):
    target = CoupledTarget()
    guardrail = RecordingGuardrail()
    service = Checker(target, TemplateGenerator(), guardrail)
    coupling = (
        input_field(Atom(value="make"), Atom(value="a")),
        input_field(Atom(value="use"), Atom(value="b")),
        "eq",
    )
    bindings = []
    for action, name in (("make", "a"), ("use", "b")):
        method = MethodSpec(
            method_id=action,
            name=action,
            service="svc",
            layer=EndpointLayer.PRIVATE,
            fields=(FieldSpec(name=name, type="int32"),),
        )
        plan = VerificationPlan(
            plan_id=action, invariant_id="inv", method_id=action, couplings=(coupling,)
        )
        bindings.append((plan, method, _scenario()))
    service.set_coupling_context(tuple(bindings))
    if execute_source:
        assert (
            service.execute_check(
                _stateful_check("make", (("a", 2),)).model_copy(
                    update={"identities": (source_identity,)}
                )
            )
            is not None
        )
    observation = service.execute_check(_stateful_check("use", (("b", value),)))
    assert (observation is not None) == allowed
    assert len(target.executed) == int(execute_source) + int(allowed)


def test_unrelated_setup_uses_same_guardrail_without_entering_path_observations():
    service, target, guardrail = _coupled_service()
    setup = _stateful_check("setup", ()).model_copy(
        update={"scenario_id": "setup-scenario"}
    )
    assert service.execute_check(setup) is not None
    assert target.executed == guardrail.checks == [setup]
    assert service.execute_check(_stateful_check("use", (("widget_id", None),))) is None
    assert len(target.executed) == len(guardrail.checks) == 1


@pytest.mark.parametrize("count", [10, 100])
@pytest.mark.parametrize("failure", [None, "error", "cancel"])
def test_call_accounting_does_not_materialize_history(count, failure):
    from asyncio import CancelledError

    from cloud_dast.runtime.budget import CallLimits
    from cloud_dast.runtime.execution.calls import execute

    snapshots = []
    attempted = []
    error = (
        CancelledError("cancelled") if failure == "cancel" else RuntimeError("failed")
    )

    class Ledger(Checker):
        @property
        def checks(self):
            snapshot = super().checks
            snapshots.append(len(snapshot))
            return snapshot

    def target(check):
        attempted.append(check)
        if failure is not None and len(attempted) == count:
            raise error
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
        )

    checker = Ledger(target, TemplateGenerator(), AllowAllGuardrail())
    budget = CallLimits(count)

    def run():
        for index in range(count):
            check = _check(("attacker",)).model_copy(
                update={"check_id": f"check:{index}"}
            )
            execute(checker, None, check, budget)

    if failure is None:
        run()
    else:
        with pytest.raises(type(error)) as caught:
            run()
        assert caught.value is error
    assert budget.live_calls == len(attempted) == count
    assert snapshots == []
    snapshot = checker.checks
    assert len(snapshot) == count
    checker.reset_checks()
    assert len(snapshot) == count and checker.checks == ()


def test_receipt_queries_preserve_duplicate_identity_and_snapshot_order(
    scenario_position,
):
    from types import SimpleNamespace

    from cloud_dast.runtime.evidence_projection import Projection

    target = EchoIdentityTarget()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())
    first = _check(("first",)).model_copy(update={"check_id": "duplicate"})
    second = _check(("second",)).model_copy(update={"check_id": "duplicate"})
    observation = checker.execute_check(first)
    checker.execute_check(second)
    assert checker.count == 2
    assert checker.latest is second
    assert checker.find("duplicate") is first
    assert checker.find("missing") is None
    assert checker.identities_for(observation) == ("second",)
    assert checker.read_since(1) == (second,)
    snapshot = checker.read_since(0)
    projected = []
    projection = Projection(
        events=lambda: (),
        path_lookup=lambda _: None,
        checks=lambda: checker.checks,
        find_check=checker.find,
        formal_repository=None,
        observation_projector=SimpleNamespace(
            project=lambda *args, **kwargs: projected.append(kwargs["check"])
        ),
    )
    from cloud_dast.qdl.graph import QdlGraph

    # Persistence has always used the FIRST matching attempt, while identity
    # lookup deliberately uses the LAST; they are distinct historical views.
    projection.persist_observation(
        SimpleNamespace(
            method=SimpleNamespace(method_id="get-secret"), scenario=scenario_position
        ),
        observation,
        "service",
        graph=QdlGraph(),
        identities=("first",),
    )
    assert projected == [first]
    checker.reset_checks()
    assert snapshot == (first, second) and checker.read_since(0) == ()
    assert checker.count == 0 and checker.find("duplicate") is None
    assert checker.identities_for(observation) == ()
    with pytest.raises(IndexError):
        _ = checker.latest
