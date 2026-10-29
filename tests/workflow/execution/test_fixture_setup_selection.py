"""QDL typed references require explicit roles and targets.

Typed references come from QDL roles and targets. No field-name or
action-name heuristic may invent a reference or a predecessor.
"""

from __future__ import annotations

from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.field_roles import resolve_field_roles
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    create,
    input_field,
)
from cloud_dast.runtime.deficits import blocked_step_deficit
from cloud_dast.runtime.execution.metadata import decorate
from cloud_dast.runtime.reference_projection import (
    refers_to_targets_by_action,
    typed_object_refs,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)


def _fact(name: str, args: tuple[object, ...], *, context: Context = Context.CONTRACT):
    schema = next(
        (schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == name),
        None,
    )
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)  # type: ignore[arg-type]


def _method(method_id: str, resource_type: str, *fields: str) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service="svc",
        name=method_id.rsplit(".", 1)[-1],
        layer=EndpointLayer.PUBLIC,
        resource_types=frozenset({resource_type}),
        fields=tuple(
            FieldSpec(name=field, type="string", required=True) for field in fields
        ),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario:reference",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(resources=(), permissions_known=True),
    )


def _step(method: MethodSpec) -> QdlExecutionStep:
    invariant = InvariantProjection(
        invariant_id="invariant:reference",
        norm_id="norm:reference",
        statement="typed reference norm",
        severity=Severity.HIGH,
    )
    plan = VerificationPlan(
        plan_id="plan:reference",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id="scenario:reference",
    )
    return QdlExecutionStep(
        step_id="step:reference",
        goal_id="goal:reference",
        plan=plan,
        method=method,
        scenario=_scenario(),
        invariant=invariant,
        irreversible=False,
    )


def _path(step: QdlExecutionStep) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id="path:reference",
        goal_id="goal:reference",
        kind="invariant",
        description="typed reference path",
        steps=(step,),
    )


def _bound_step(graph: QdlGraph, consumer: MethodSpec):
    paths = decorate(
        [_path(_step(consumer))], graph, {consumer.method_id: consumer}, probe_fields={}
    )
    return paths[0].steps[0]


def _ship_order_graph(
    *,
    with_role: bool = True,
    with_refers_to: bool = True,
    with_create: bool = True,
) -> QdlGraph:
    """A CreateOrder→ShipOrder pair spelled without create/ship name hints."""

    ship = Atom(value="action:svc.submit")
    prepare = Atom(value="action:svc.prepare")
    field = input_field(ship, Atom(value="order_id"))
    order = Atom(value="order")
    facts: list[Fact] = [
        _fact("is", (ship, Atom(value="Action"))),
        _fact("is", (prepare, Atom(value="Action"))),
        _fact("is", (field, Atom(value="Field"))),
        _fact("is", (order, Atom(value="ResourceType"))),
    ]
    if with_role:
        facts.append(_fact("has", (field, Atom(value="object_ref"))))
    if with_refers_to:
        facts.append(_fact("refers_to", (field, order)))
    if with_create:
        facts.append(
            _fact(
                "causes",
                (prepare, create(order)),
                context=Context.ACCEPTED,
            )
        )
    return QdlGraph(facts=tuple(facts))


def test_typed_object_ref_view_requires_object_ref_role():
    # The field is even named ``order_id``, but a name is not a fact: without
    # has(input_field(a, f), object_ref) the refers_to target is not a
    # resource type.
    graph = _ship_order_graph(with_role=False)

    assert (
        typed_object_refs(
            refers_to_targets_by_action(graph), resolve_field_roles(graph)
        )
        == {}
    )

    consumer = _method("svc.submit", "order", "order_id")
    step = _bound_step(graph, consumer)

    assert step.plan.resource_types == ()
    assert step.plan.resource_params == ()


def test_object_ref_without_refers_to_stays_untyped_deficit():
    graph = _ship_order_graph(with_refers_to=False)
    consumer = _method("svc.submit", "order", "order_id")

    step = _bound_step(graph, consumer)
    assert step.plan.resource_types == ()
    deficit = blocked_step_deficit(_path(step), step, reason="missing_refers_to")
    assert deficit.predicate_class == "refers_to"
    assert dict(deficit.context)["field"] == "order_id"


def test_create_named_action_without_fact_is_never_selected():
    # The would-be producer is literally named CreateOrder, but without a
    # grounded causes(a, create(order)) effect there is no provider: the
    # absence of the fact is the deficit (stratified negation).
    graph = _ship_order_graph(with_create=False)
    consumer = _method("svc.submit", "order", "order_id")
    producer = _method("svc.CreateOrder", "order", "label")

    step = _bound_step(graph, consumer)
    assert step.plan.resource_types == (("order_id", "order"),)
    from cloud_dast.runtime.execution.view import build
    from cloud_dast.runtime.planning import QdlPlanner

    execution = build(
        QdlPlanner().plan(graph),
        graph,
        methods=(consumer, producer),
        scenarios_by_method={
            consumer.method_id: _scenario(),
            producer.method_id: _scenario(),
        },
    )
    assert execution.paths
    assert all(
        bound.method.method_id != producer.method_id
        for path in execution.paths
        for bound in path.steps
    )
