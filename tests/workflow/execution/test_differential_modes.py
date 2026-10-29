"""Contracts for the RFC §9.1 payload-pair and read-back modes."""

from __future__ import annotations

import pytest

from cloud_dast.composition.runtime import diff_modes_from_environment
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.qdl.field_roles import (
    CREDENTIAL_ROLE,
    OBJECT_REF_ROLE,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    create,
    input_field,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.differential.contracts import (
    PayloadPairSpec,
    ReadBackSpec,
    payload_canary,
    payload_fields,
    read_resource_binding,
    select_read_method,
)
from cloud_dast.verification.differential.modes import (
    MUTABLE_INPUT_ROLE,
    PAYLOAD_ROLE,
)


def _position(principal: str = "attacker") -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id=f"pos-{principal}",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service="shop",
                    resource_type="order",
                    resource_id="order-1001",
                ),
            ),
            principals=(PrincipalRef(principal_id=principal, principal_type="user"),),
        ),
    )


def _method(
    method_id: str,
    name: str,
    *,
    fields: tuple[FieldSpec, ...] = (),
    resource_types: frozenset[str] = frozenset({"order"}),
) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service="shop",
        name=name,
        layer=EndpointLayer.PUBLIC,
        resource_types=resource_types,
        fields=fields,
    )


UPDATE_FIELDS = (
    FieldSpec(name="order_id", type="string", required=True),
    FieldSpec(name="total", type="string"),
    FieldSpec(name="note", type="string"),
)


def _update_method() -> MethodSpec:
    return _method("shop.UpdateOrder", "UpdateOrder", fields=UPDATE_FIELDS)


def _get_method() -> MethodSpec:
    return _method(
        "shop.GetOrder",
        "GetOrder",
        fields=(FieldSpec(name="order_id", type="string", required=True),),
    )


def _baseline_check(method: MethodSpec, scenario: ScenarioPosition) -> Check:
    return Check(
        invariant_id="norm:test",
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=tuple((field.name, None) for field in method.fields),
        identities=("attacker",),
    )


def _field_role_graph(
    method: MethodSpec,
    roles: tuple[tuple[str, str], ...],
) -> QdlGraph:
    """Build a graph carrying one ``has(input_field, role)`` fact per field."""

    action = Atom(value=f"action:{method.method_id}")
    facts: list[Fact] = [_qfact("is", (action, Atom(value="Action")))]
    for field_name, role in roles:
        field = input_field(action, Atom(value=field_name))
        facts.extend(
            (
                _qfact("is", (field, Atom(value="InputField"))),
                _qfact("has", (field, Atom(value=role))),
            )
        )
    return QdlGraph(facts=tuple(facts))


def _execution_step(
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> QdlExecutionStep:
    plan = VerificationPlan(
        plan_id=f"plan:{method.method_id}",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
    )
    return QdlExecutionStep(
        step_id=f"step:{method.method_id}",
        goal_id=f"goal:{method.method_id}",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
    )


def _drain_deficits(deficits: DeficitQueue) -> tuple[object, ...]:
    # S30: per-field deficits on one action coalesce into one work item,
    # so draining collects every affected deficit behind each dispatch.
    drained = []
    while wave := deficits.pop_wave():
        for work_item in wave:
            drained.extend(work_item.deficits)
    return tuple(drained)


def test_payload_pair_from_baseline_mutates_only_payload_fields() -> None:
    method = _update_method()
    scenario = _position()
    baseline = _baseline_check(method, scenario)

    spec = PayloadPairSpec.from_baseline(
        method,
        scenario,
        baseline,
        canary=payload_canary(method.method_id),
        mutable_fields=("total", "note"),
    )

    baseline_request = dict(spec.baseline.request)
    treatment_request = dict(spec.treatment.request)
    # The resource key and identity bindings stay untouched on both legs.
    assert baseline_request["order_id"] is None
    assert treatment_request["order_id"] is None
    assert spec.baseline.identities == spec.treatment.identities == ("attacker",)
    # Payload fields carry the benign value and the quoted canary.
    assert baseline_request["total"] == f"benign-{payload_canary(method.method_id)}"
    assert treatment_request["total"] == f"'{payload_canary(method.method_id)}'"
    assert treatment_request["note"] == f"'{payload_canary(method.method_id)}'"
    assert spec.treatment.probe_marker == payload_canary(method.method_id)


def test_payload_role_selects_field_for_mutation() -> None:
    method = _update_method()
    scenario = _position()
    graph = _field_role_graph(method, (("total", PAYLOAD_ROLE),))

    mutable = payload_fields(method, resolve_field_roles(graph))

    assert mutable == ("total",)
    spec = PayloadPairSpec.from_baseline(
        method,
        scenario,
        _baseline_check(method, scenario),
        canary=payload_canary(method.method_id),
        mutable_fields=mutable,
    )
    treatment_request = dict(spec.treatment.request)
    assert treatment_request["total"] == f"'{payload_canary(method.method_id)}'"
    assert treatment_request["order_id"] is None
    assert treatment_request["note"] is None


def test_mutable_input_role_selects_field_for_mutation() -> None:
    method = _update_method()
    graph = _field_role_graph(method, (("note", MUTABLE_INPUT_ROLE),))

    assert payload_fields(method, resolve_field_roles(graph)) == ("note",)


def test_known_non_payload_roles_never_make_a_field_mutable() -> None:
    method = _update_method()
    graph = _field_role_graph(
        method,
        (
            ("order_id", OBJECT_REF_ROLE),
            ("total", "privileged"),
            ("note", CREDENTIAL_ROLE),
        ),
    )

    assert payload_fields(method, resolve_field_roles(graph)) == ()


def test_locale_currency_page_size_stay_immutable_and_report_deficits(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = _method(
        "shop.ListCatalog",
        "ListCatalog",
        fields=(
            FieldSpec(name="locale", type="string"),
            FieldSpec(name="currency", type="string"),
            FieldSpec(name="page_size", type="int64"),
        ),
    )
    # ``page_size`` carries a known non-mutable role; ``locale`` and
    # ``currency`` have no role fact at all.
    graph = _field_role_graph(method, (("page_size", "pagination"),))

    from cloud_dast.runtime.differential.specs import SpecResolver

    workflow = SpecResolver.__new__(SpecResolver)
    deficits = DeficitQueue()
    step = _execution_step(method, scenario_position, invariant)

    assert workflow.payload_fields(step, graph, deficits) == ()
    queued = _drain_deficits(deficits)
    by_field = {dict(deficit.context)["field"]: deficit for deficit in queued}
    assert set(by_field) == {"currency", "locale"}
    for field_name, deficit in by_field.items():
        assert deficit.predicate_class == "has"
        assert deficit.action == method.method_id
        assert dict(deficit.context) == {
            "coverage": "payload",
            "field": field_name,
        }


def test_payload_pair_rejects_identical_requests() -> None:
    method = _method(
        "shop.Read",
        "Read",
        fields=(FieldSpec(name="order_id", type="string", required=True),),
    )
    scenario = _position()
    check = _baseline_check(method, scenario)

    # A method with only the object reference has no payload field to vary:
    # the object-reference role is known, but it is not a mutable role.
    graph = _field_role_graph(method, (("order_id", OBJECT_REF_ROLE),))
    assert payload_fields(method, resolve_field_roles(graph)) == ()
    with pytest.raises(ValueError, match="must differ in request"):
        PayloadPairSpec.from_baseline(
            method,
            scenario,
            check,
            canary="canary",
            mutable_fields=(),
        )


def test_payload_pair_rejects_foreign_method_or_scenario() -> None:
    method = _update_method()
    scenario = _position()
    check = _baseline_check(method, scenario)
    treatment = check.model_copy(
        update={"request": (*check.request, ("extra", "value"))}
    )

    with pytest.raises(ValueError, match="does not belong to the paired method"):
        PayloadPairSpec(
            method=_get_method(),
            scenario=scenario,
            baseline=check,
            treatment=treatment,
        )
    with pytest.raises(ValueError, match="does not belong to the paired scenario"):
        PayloadPairSpec(
            method=method,
            scenario=_position("other"),
            baseline=check,
            treatment=treatment,
        )


def test_payload_pair_rejects_identity_variation() -> None:
    method = _update_method()
    scenario = _position()
    baseline = _baseline_check(method, scenario)
    treatment = baseline.model_copy(
        update={
            "identities": ("victim",),
            "request": (
                ("order_id", None),
                ("total", "value"),
            ),
        }
    )

    with pytest.raises(ValueError, match="same identities"):
        PayloadPairSpec(
            method=method,
            scenario=scenario,
            baseline=baseline,
            treatment=treatment,
        )


def test_readback_spec_validates_the_pairing_contract() -> None:
    write = _update_method()
    read = _get_method()

    spec = ReadBackSpec(
        write_method=write,
        read_method=read,
        resource_binding="order_id",
    )
    assert spec.resource_binding == "order_id"

    with pytest.raises(ValueError, match="must differ"):
        ReadBackSpec(
            write_method=write,
            read_method=write,
            resource_binding="order_id",
        )
    with pytest.raises(ValueError, match="field of the read method"):
        ReadBackSpec(
            write_method=write,
            read_method=read,
            resource_binding="user_id",
        )


def _qfact(
    predicate: str,
    args: tuple[object, ...],
    *,
    context: Context = Context.CONTRACT,
) -> Fact:
    predicate_object = (
        Predicate.from_schema(
            next(
                schema
                for schema in EXTENSION_PREDICATE_SCHEMAS
                if schema.name == predicate
            )
        )
        if predicate == "refers_to"
        else Predicate.from_name(predicate)
    )
    return Fact(context=context, predicate=predicate_object, args=args)


def _readback_graph(
    write: MethodSpec,
    *reads: MethodSpec,
    readback: bool = True,
    refers_to: bool = True,
    mutating: frozenset[str] = frozenset(),
) -> QdlGraph:
    write_action = Atom(value=f"action:{write.method_id}")
    resource = Atom(value="resource:order")
    facts = [
        _qfact("is", (write_action, Atom(value="Action"))),
        _qfact("is", (resource, Atom(value="ResourceType"))),
        _qfact("targets", (write_action, resource)),
    ]
    for read in reads:
        action = Atom(value=f"action:{read.method_id}")
        field = input_field(action, Atom(value="order_id"))
        facts.extend(
            (
                _qfact("is", (action, Atom(value="Action"))),
                _qfact("is", (field, Atom(value="InputField"))),
                _qfact("targets", (action, resource)),
                _qfact("has", (field, Atom(value="object_ref"))),
            )
        )
        if readback:
            facts.append(_qfact("has", (action, Atom(value="readback"))))
        if refers_to:
            facts.append(_qfact("refers_to", (field, resource)))
        if read.method_id in mutating:
            facts.append(
                _qfact(
                    "causes",
                    (action, create(resource)),
                    context=Context.ACCEPTED,
                )
            )
    return QdlGraph(facts=tuple(facts))


def test_select_read_method_requires_explicit_readback_fact() -> None:
    write = _update_method()
    unnamed = _method(
        "shop.AuditOrder",
        "AuditOrder",
        fields=(FieldSpec(name="order_id", type="string", required=True),),
    )

    assert (
        select_read_method(
            write,
            (unnamed,),
            graph=_readback_graph(write, unnamed, readback=False),
        )
        is None
    )
    assert (
        select_read_method(
            write,
            (unnamed,),
            graph=_readback_graph(write, unnamed),
        )
        is unnamed
    )


def test_select_read_method_excludes_graph_declared_mutators() -> None:
    write = _update_method()
    create = _method(
        "shop.CreateOrder",
        "CreateOrder",
        fields=(FieldSpec(name="order_id", type="string", required=True),),
    )
    reader = _get_method()
    graph = _readback_graph(
        write,
        create,
        reader,
        mutating=frozenset({create.method_id}),
    )

    # Graph evidence of mutation excludes the create action even when it
    # carries the readback role and an object-reference binding.
    assert select_read_method(write, (create, reader), graph=graph) is reader


def test_select_read_method_requires_shared_resource_and_binding() -> None:
    write = _update_method()
    other_type = _method(
        "shop.GetUser",
        "GetUser",
        fields=(FieldSpec(name="user_id", type="string", required=True),),
        resource_types=frozenset({"user"}),
    )
    no_binding = _method("shop.ListOrders", "ListOrders")
    graph = _readback_graph(write, other_type, no_binding)

    assert select_read_method(write, (other_type, no_binding), graph=graph) is None


def test_read_resource_binding_resolves_shared_resource_field() -> None:
    write = _update_method()
    read = _get_method()
    graph = _readback_graph(write, read)

    assert read_resource_binding(write, read, graph=graph) == "order_id"


def test_read_resource_binding_requires_refers_to_fact() -> None:
    write = _update_method()
    read = _get_method()
    graph = _readback_graph(write, read, refers_to=False)

    assert read_resource_binding(write, read, graph=graph) is None


def test_diff_modes_from_environment(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_DIFF_MODES", raising=False)
    assert diff_modes_from_environment() == frozenset({"factors"})

    monkeypatch.setenv(
        "CLOUD_DAST_DIFF_MODES",
        "payload,readback,timing,concurrency",
    )
    assert diff_modes_from_environment() == frozenset(
        {"payload", "readback", "timing", "concurrency"}
    )

    monkeypatch.setenv("CLOUD_DAST_DIFF_MODES", " FACTORS , ReadBack ")
    assert diff_modes_from_environment() == frozenset({"factors", "readback"})

    monkeypatch.setenv("CLOUD_DAST_DIFF_MODES", "")
    assert diff_modes_from_environment() == frozenset({"factors"})

    monkeypatch.setenv("CLOUD_DAST_DIFF_MODES", "factors,bogus")
    with pytest.raises(RuntimeError, match="CLOUD_DAST_DIFF_MODES"):
        diff_modes_from_environment()
