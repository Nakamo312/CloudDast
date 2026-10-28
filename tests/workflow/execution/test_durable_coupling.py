"""Real observation projection -> canonical graph -> scoped next-input binding."""

from __future__ import annotations

import pytest

from cloud_dast.binding import scenario_scope
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    BindingRef,
    EndpointLayer,
    FieldSpec,
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
from cloud_dast.model.events import CheckCompleted
from cloud_dast.qdl.couplings import all_couplings
from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    create,
    input_field,
    output_field,
    source,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.projection import (
    ObservationProjector,
)
from cloud_dast_fuzzing import TemplateGenerator

MAKE = Atom(value="action:widgets.Make")
USE = Atom(value="action:widgets.Use")
RESOURCE = Atom(value="resource:widget")
OUTPUT = output_field(MAKE, Atom(value="id"))
INPUT = input_field(USE, Atom(value="widget_id"))


def fact(name, *args, context=Context.RUNTIME):
    schema = next(
        (schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == name), None
    )
    return Fact(
        context=context,
        predicate=Predicate.from_schema(schema)
        if schema
        else Predicate.from_name(name),
        args=args,
    )


def declarations():
    effect = create(RESOURCE)
    declarations = tuple(
        fact("is", term, Atom(value=kind), context=Context.ACCEPTED)
        for term, kind in (
            (MAKE, "Action"),
            (USE, "Action"),
            (RESOURCE, "ResourceType"),
            (OUTPUT, "OutputField"),
            (INPUT, "InputField"),
            (effect, "Effect"),
        )
    )
    return QdlGraph(
        facts=declarations
        + (
            fact("causes", MAKE, effect, context=Context.ACCEPTED),
            fact("has", OUTPUT, Atom(value="object_ref"), context=Context.ACCEPTED),
            fact("refers_to", OUTPUT, RESOURCE, context=Context.ACCEPTED),
            fact("refers_to", INPUT, RESOURCE, context=Context.ACCEPTED),
            fact("coupled", OUTPUT, INPUT, Atom(value="eq"), context=Context.ACCEPTED),
        )
    )


def scenario(name, *, state="existing", scope=ScopeRelation.SAME_FOLDER):
    return ScenarioPosition(
        scenario_id=name,
        profile=ScenarioProfile(
            scope_relation=scope,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state=state,
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            principals=(PrincipalRef(principal_id="actor", principal_type="user"),)
        ),
    )


def bindings(*, source_scenario=None, destination_scenario=None, field_type="string"):
    couplings = all_couplings(declarations())
    result = []
    for action, position in (
        (MAKE, source_scenario or scenario("make")),
        (USE, destination_scenario or scenario("use")),
    ):
        method = MethodSpec(
            method_id=action.value.removeprefix("action:"),
            service="widgets",
            name=action.value,
            layer=EndpointLayer.PRIVATE,
            fields=()
            if action == MAKE
            else (FieldSpec(name="widget_id", type=field_type, required=True),),
        )
        plan = VerificationPlan(
            plan_id=action.value,
            method_id=method.method_id,
            invariant_id="inv",
            scenario_id=position.scenario_id,
            couplings=couplings[action.value],
        )
        result.append((plan, method, position))
    return tuple(result)


class Target:
    def __init__(self, value="live-id", outcome=AccessOutcome.ALLOWED):
        self.calls = []
        self.events = []
        self.value = value
        self.outcome = outcome
        self.raise_make = False

    def publish(self, event):
        self.events.append(event)

    def __call__(self, check):
        self.calls.append(check)
        if self.raise_make and check.method_id == "widgets.Make":
            raise RuntimeError("producer failed")
        fields = (
            (("id", self.value),)
            if check.method_id == "widgets.Make" and self.value is not None
            else ()
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=self.outcome,
            response_summary="executed",
            output=ResponseData(fields=fields),
        )


class Guardrail:
    def __init__(self):
        self.checks = []

    def allows(self, check):
        self.checks.append(check)
        return True


def workflow(context, *, graph=None, value="live-id", outcome=AccessOutcome.ALLOWED):
    target, guardrail = Target(value, outcome), Guardrail()
    service = Checker(target, TemplateGenerator(), guardrail, target)
    service.set_coupling_context(context, evidence_graph=graph)
    return service, target, guardrail


def generate(service, binding):
    plan, method, position = binding
    invariant = InvariantProjection(
        invariant_id="inv", norm_id="norm", statement="test", severity=Severity.LOW
    )
    return service.generate_pair_checks(plan, method, invariant, position)[0]


def history(value="durable-id", *, identity=("actor",), position=None):
    context = bindings(source_scenario=position)
    service, target, _ = workflow(context, value=value)
    check = generate(service, context[0]).model_copy(update={"identities": identity})
    observation = service.execute_check(check)
    observed_at = next(
        event.occurred_at.timestamp()
        for event in target.events
        if isinstance(event, CheckCompleted)
        and event.observation.observation_id == observation.observation_id
    )
    graph = ObservationProjector().project(
        observation,
        check.method_id,
        graph=declarations(),
        scope=scenario_scope(context[0][2]),
        identities=check.identities,
        observed_at=observed_at,
    )
    return QdlGraph.model_validate_json(
        merge_graphs(declarations(), graph).model_dump_json()
    ), observation


def test_durable_graph_binds_renamed_input_without_calling_producer():
    graph, _ = history()
    context = bindings(
        source_scenario=scenario("new-make", state="created"),
        destination_scenario=scenario("new-use", state="updated"),
    )
    service, target, guardrail = workflow(context, graph=graph)
    check = generate(service, context[1])
    assert dict(check.request)["widget_id"] is None
    assert service.execute_check(check) is not None
    assert len(target.calls) == 1 and target.calls[0].method_id == "widgets.Use"
    assert dict(target.calls[0].request)["widget_id"] == "durable-id"
    assert guardrail.checks == target.calls


def test_actual_producer_takes_precedence_over_durable_value():
    graph, _ = history()
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    service.execute_check(generate(service, context[0]))
    assert service.execute_check(generate(service, context[1])) is not None
    assert dict(target.calls[-1].request)["widget_id"] == "live-id"


@pytest.mark.parametrize(
    "value,outcome",
    [
        (None, AccessOutcome.ALLOWED),
        ("failed", AccessOutcome.DENIED),
        ("failed", AccessOutcome.ERROR),
    ],
)
def test_actual_unusable_producer_cannot_fall_back_to_history(value, outcome):
    graph, _ = history()
    context = bindings()
    service, target, guardrail = workflow(
        context, graph=graph, value=value, outcome=outcome
    )
    service.execute_check(generate(service, context[0]))
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 1


@pytest.mark.parametrize("foreign", ["identity", "scope", "method", "missing-check"])
def test_durable_source_requires_matching_provenance(foreign):
    graph, _ = history(
        identity=("other",) if foreign == "identity" else ("actor",),
        position=scenario("foreign", scope=ScopeRelation.CROSS_FOLDER)
        if foreign == "scope"
        else None,
    )
    if foreign in {"method", "missing-check"}:
        facts = []
        for f in graph.facts:
            if (
                f.predicate.name == "evidence"
                and isinstance(f.args[1], Struct)
                and f.args[1].name == "source"
            ):
                if (
                    f.args[1].args[0] == Atom(value="check")
                    and foreign == "missing-check"
                ):
                    continue
                if f.args[1].args[0] == Atom(value="method") and foreign == "method":
                    f = f.model_copy(
                        update={
                            "args": (
                                f.args[0],
                                source(Atom(value="method"), Atom(value="other")),
                            )
                        }
                    )
            facts.append(f)
        graph = QdlGraph(facts=tuple(facts))
    context = bindings()
    service, target, guardrail = workflow(context, graph=graph)
    assert service.execute_check(generate(service, context[1])) is None
    assert target.calls == guardrail.checks == []


@pytest.mark.parametrize(
    "revoked", ["observation", "instance", "value", "check", "field"]
)
def test_durable_revocations_block_binding(revoked):
    graph, observation = history()
    instance = next(
        f.args[1]
        for f in graph.facts
        if f.predicate.name == "has"
        and f.args[0] == OUTPUT
        and f.context == Context.RUNTIME
    )
    old = {
        "observation": Atom(value=observation.observation_id),
        "instance": instance,
        "value": Atom(value="durable-id"),
        "check": Atom(value=observation.check_id),
        "field": OUTPUT,
    }[revoked]
    extra = [
        fact("is", Atom(value="revocation"), Atom(value="Node")),
        fact("supersedes", Atom(value="revocation"), old),
    ]
    if not any(f.predicate.name == "is" and f.args[0] == old for f in graph.facts):
        extra.append(fact("is", old, Atom(value="Node")))
    graph = QdlGraph(facts=graph.facts + tuple(extra))
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    assert service.execute_check(generate(service, context[1])) is None
    assert target.calls == []


def test_ambiguous_durable_values_do_not_choose_latest():
    one, _ = history("one")
    two, _ = history("two")
    context = bindings()
    service, target, _ = workflow(context, graph=merge_graphs(one, two))
    assert service.execute_check(generate(service, context[1])) is None
    assert target.calls == []


def test_durable_binding_preserves_mutation_and_checks_destination_type():
    graph, _ = history()
    for context, value in (
        (bindings(), "mutation"),
        (bindings(field_type="int32"), None),
    ):
        service, target, _ = workflow(context, graph=graph)
        check = generate(service, context[1]).model_copy(
            update={"request": (("widget_id", value),)}
        )
        assert service.execute_check(check) is None
        assert check.request == (("widget_id", value),)
        assert target.calls == []


def test_new_context_without_graph_cannot_reuse_previous_durable_values():
    graph, _ = history()
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    service.set_coupling_context(context)
    assert service.execute_check(generate(service, context[1])) is None
    assert target.calls == []


def test_scenario_scope_excludes_method_scenario_hash_state_and_actual_identity():
    one = scenario("make", state="existing")
    two = scenario("use", state="created").model_copy(
        update={
            "stand": StandState(
                principals=(PrincipalRef(principal_id="other", principal_type="user"),)
            )
        }
    )
    assert scenario_scope(one) == scenario_scope(two)


def test_scenario_scope_retains_profile_and_container_boundaries():
    one = scenario("one")
    assert scenario_scope(one) != scenario_scope(
        scenario("two", scope=ScopeRelation.CROSS_FOLDER)
    )
    scopes = [
        one.model_copy(
            update={
                "stand": StandState(
                    bindings=(
                        BindingRef(
                            principal_id="actor", role="reader", folder_id=folder
                        ),
                    )
                )
            }
        )
        for folder in ("one", "two")
    ]
    assert scenario_scope(scopes[0]) != scenario_scope(scopes[1])


def test_scenario_scope_is_stable_for_resource_order_and_requires_typed_resources():
    one = ResourceRef(service="svc", resource_type="folder", resource_id="one")
    two = one.model_copy(update={"resource_id": "two"})
    position = scenario("scenario")
    left = position.model_copy(update={"stand": StandState(resources=(one, two))})
    right = position.model_copy(update={"stand": StandState(resources=(two, one))})
    assert scenario_scope(left) == scenario_scope(right)
    assert scenario_scope(left) != scenario_scope(position)


def test_actual_failed_call_cannot_be_masked_by_durable_evidence():
    graph, _ = history()
    context = bindings()
    service, target, guardrail = workflow(context, graph=graph)
    target.raise_make = True
    with pytest.raises(RuntimeError, match="producer failed"):
        service.execute_check(generate(service, context[0]))
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 1


def test_durable_identity_order_matches_effective_transport_identity():
    graph, _ = history(identity=("other", "actor"))
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    consumer = generate(service, context[1]).model_copy(
        update={"identities": ("actor", "other")}
    )
    assert service.execute_check(consumer) is None
    assert target.calls == []


def test_pair_restores_durable_snapshot_before_binding_treatment():
    graph, _ = history()
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    control, treatment = service.execute_pair(
        generate(service, context[0]), generate(service, context[1])
    )
    assert control is not None and treatment is not None
    assert dict(treatment[0].request)["widget_id"] == "durable-id"
    assert service.execute_check(generate(service, context[1])) is not None
    assert dict(target.calls[-1].request)["widget_id"] == "durable-id"


def test_superseded_output_instance_link_cannot_bind_historical_value():
    graph, _ = history()
    instance = next(
        f.args[1]
        for f in graph.facts
        if f.predicate.name == "has"
        and f.args[0] == OUTPUT
        and f.context == Context.RUNTIME
    )
    new_instance = Atom(value="replacement-instance")
    new_link = Struct(name="replacement", args=(OUTPUT, new_instance))
    old_link = Struct(name="replacement", args=(OUTPUT, instance))
    graph = QdlGraph(
        facts=graph.facts
        + (
            fact("is", new_instance, Atom(value="Resource")),
            fact("is", new_link, Atom(value="Node")),
            fact("supersedes", new_link, old_link),
        )
    )
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    assert service.execute_check(generate(service, context[1])) is None
    assert target.calls == []
