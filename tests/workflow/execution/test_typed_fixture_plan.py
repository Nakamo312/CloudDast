from __future__ import annotations

import dataclasses

import pytest

from cloud_dast.contracts.grammar import GrammarFacts
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
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    create,
    input_field,
    output_field,
    transition,
)
from cloud_dast.runtime.deficits import blocked_step_deficit
from cloud_dast.runtime.execution.metadata import decorate as _decorate_execution_paths
from cloud_dast.runtime.execution.metadata import (
    version_executable_inputs as _version_executable_inputs,
)
from cloud_dast.runtime.grammar_facts import (
    compile as compile_grammar,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast_fuzzing import TemplateGenerator


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


def _scenario(*resources: ResourceRef) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario:typed",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(resources=resources, permissions_known=True),
    )


def _step(
    method: MethodSpec,
    scenario: ScenarioPosition,
    *,
    invariant: InvariantProjection | None = None,
    plan: VerificationPlan | None = None,
) -> QdlExecutionStep:
    invariant = invariant or InvariantProjection(
        invariant_id="invariant:typed",
        norm_id="norm:typed",
        statement="typed reference norm",
        severity=Severity.HIGH,
    )
    plan = plan or VerificationPlan(
        plan_id="plan:typed",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
    )
    return QdlExecutionStep(
        step_id="step:typed",
        goal_id="goal:typed",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
        irreversible=False,
    )


def _path(step: QdlExecutionStep) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id="path:typed",
        goal_id="goal:typed",
        kind="invariant",
        description="typed reference path",
        steps=(step,),
    )


def _typed_graph(sink_type: str = "interpreter", dialect: str = "ansi") -> QdlGraph:
    consume = Atom(value="action:svc.consume")
    prepare = Atom(value="action:svc.prepare")
    field = input_field(consume, Atom(value="target_handle"))
    created = output_field(prepare, Atom(value="id"))
    item = Atom(value="catalog.item")
    sink = Atom(value="sink:shell")
    consume_change = changed(item, Atom(value="target_handle"))
    return QdlGraph(
        facts=(
            _fact("is", (consume, Atom(value="Action"))),
            _fact("is", (prepare, Atom(value="Action"))),
            _fact("is", (field, Atom(value="Field"))),
            _fact("is", (created, Atom(value="Field"))),
            _fact("is", (item, Atom(value="ResourceType"))),
            _fact("is", (sink, Atom(value=sink_type))),
            _fact("has", (field, Atom(value="object_ref"))),
            _fact("has", (created, Atom(value="object_ref"))),
            _fact("refers_to", (field, item)),
            _fact("reaches", (field, sink)),
            _fact("format", (field, Atom(value="text"))),
            _fact("constraint", (field, Atom(value="ne"), Atom(value="seed"))),
            _fact("dialect", (sink, Atom(value=dialect))),
            _fact(
                "causes",
                (consume, consume_change),
                context=Context.ACCEPTED,
            ),
            _fact(
                "causes",
                (prepare, create(item)),
                context=Context.ACCEPTED,
            ),
        )
    )


def _bound_step(
    sink_type: str = "interpreter",
    dialect: str = "ansi",
) -> QdlExecutionStep:
    graph = _typed_graph(sink_type, dialect)
    probe = _method("svc.consume", "catalog.item", "target_handle")
    step = _step(probe, _scenario())
    paths = _decorate_execution_paths(
        [_path(step)], graph, {probe.method_id: probe}, probe_fields={}
    )
    return paths[0].steps[0]


@pytest.mark.parametrize(
    ("sink_type", "dialect"),
    [
        ("interpreter", "ansi"),
        ("command_shell", "posix"),
    ],
)
def test_refers_to_and_effect_facts_preserve_typed_execution_metadata(
    sink_type: str,
    dialect: str,
) -> None:
    step = _bound_step(sink_type, dialect)

    assert step.plan.resource_types == (("target_handle", "catalog.item"),)
    assert step.plan.sink_types == (("target_handle", sink_type),)
    assert step.plan.grammar_formats == (("target_handle", "text"),)
    assert step.plan.grammar_constraints == (("target_handle", "ne", "seed"),)
    assert step.plan.grammar_dialects == (("target_handle", dialect),)


@pytest.mark.parametrize(
    "method_id", ["svc.consume", "action:svc.consume", "action:action:svc.consume"]
)
def test_method_grammar_survives_action_lookup_aliases(method_id):
    graph = _typed_graph()
    method = _method(method_id, "catalog.item", "target_handle")
    aliases = {method_id: method, f"action:{method_id}": method}
    (path,) = _decorate_execution_paths(
        [_path(_step(method, _scenario()))], graph, aliases, probe_fields={}
    )
    expected = compile_grammar(graph, [method_id])[method_id]
    assert GrammarFacts.from_plan(path.steps[0].plan) == expected
    if method_id in {"svc.consume", "action:svc.consume"}:
        assert expected.fields


def test_missing_refers_to_reports_reference_deficit() -> None:
    graph = _typed_graph()
    facts = tuple(fact for fact in graph.facts if fact.predicate.name != "refers_to")
    graph = QdlGraph(facts=facts)
    probe = _method("svc.consume", "catalog.item", "target_handle")
    step = _step(probe, _scenario())
    paths = _decorate_execution_paths(
        [_path(step)], graph, {probe.method_id: probe}, probe_fields={}
    )
    step = paths[0].steps[0]
    assert step.plan.resource_types == ()
    deficit = blocked_step_deficit(_path(step), step, reason="missing_refers_to")
    assert deficit.predicate_class == "refers_to"
    assert dict(deficit.context)["field"] == "target_handle"
    assert dict(deficit.context)["reason"] == "missing_refers_to"


def test_typed_seed_selects_resource_by_declared_type() -> None:
    method = _method("svc.consume", "catalog.item", "left_handle", "right_handle")
    scenario = _scenario(
        ResourceRef(service="svc", resource_type="catalog.item", resource_id="item-1"),
        ResourceRef(
            service="svc", resource_type="resources.folder", resource_id="folder-1"
        ),
    )
    invariant = InvariantProjection(
        invariant_id="invariant:typed",
        norm_id="norm:typed",
        statement="typed reference norm",
        severity=Severity.HIGH,
    )
    plan = VerificationPlan(
        plan_id="plan:typed",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        resource_types=(
            ("left_handle", "resources.folder"),
            ("right_handle", "catalog.item"),
        ),
    )

    check = TemplateGenerator().generate(plan, method, invariant, scenario)[0]

    assert dict(check.request) == {
        "left_handle": "folder-1",
        "right_handle": "item-1",
    }


def test_report_only_reason_does_not_change_path_id() -> None:
    method = _method("svc.consume", "catalog.item", "target_handle")
    scenario = _scenario()
    base_step = _step(method, scenario)
    changed_step = dataclasses.replace(base_step)
    first_deficit = blocked_step_deficit(_path(base_step), base_step, reason="first")
    second_deficit = blocked_step_deficit(
        _path(changed_step), changed_step, reason="second"
    )
    assert first_deficit.context != second_deficit.context
    assert first_deficit.work_item_key == second_deficit.work_item_key

    first = _version_executable_inputs([_path(base_step)])[0].path_id
    second = _version_executable_inputs([_path(changed_step)])[0].path_id

    assert first == second


def test_state_machine_norm_does_not_overwrite_scenario_state() -> None:
    method = _method("svc.consume", "catalog.item", "target_handle")
    scenario = _scenario()
    invariant = InvariantProjection(
        invariant_id="invariant:state",
        norm_id="norm:state",
        statement="state transition norm",
        severity=Severity.HIGH,
        norm_fact=_fact(
            "prevents",
            (
                Atom(value="norm:state"),
                transition(Atom(value="draft"), Atom(value="active")),
            ),
            context=Context.ACCEPTED,
        ),
    )
    step = _step(method, scenario, invariant=invariant)
    deficit = blocked_step_deficit(_path(step), step, reason="missing_state_semantics")

    assert dict(deficit.context)["required_state"] == "existing"
    assert dict(deficit.context)["required_state"] != "draft"


def test_typed_seed_never_confuses_resources_with_the_same_suffix():
    method = _method("svc.consume", "lockbox.secret", "handle")
    scenario = _scenario(
        ResourceRef(
            service="lockbox", resource_type="lockbox.secret", resource_id="lockbox-id"
        ),
        ResourceRef(service="kms", resource_type="kms.secret", resource_id="kms-id"),
    )
    step = _step(method, scenario)
    for resource_type, expected in [
        ("lockbox.secret", "lockbox-id"),
        ("kms.secret", "kms-id"),
    ]:
        plan = step.plan.model_copy(
            update={"resource_types": (("handle", resource_type),)}
        )
        check = TemplateGenerator().generate(plan, method, step.invariant, scenario)[0]
        assert dict(check.request)["handle"] == expected
    assert {resource.resource_id for resource in scenario.stand.resources} == {
        "lockbox-id",
        "kms-id",
    }


def test_object_reference_hint_uses_declared_type_over_mutated_seed():
    from cloud_dast.candidates import apply_seed_hints
    from cloud_dast.model import Check

    method = _method("svc.consume", "catalog.item", "handle")
    scenario = _scenario(
        ResourceRef(
            service="svc", resource_type="catalog.item", resource_id="live-item"
        )
    )
    seed = Check(
        invariant_id="norm:typed",
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=(("handle", "mutated"),),
        identities=("attacker",),
    )
    result = apply_seed_hints(
        seed,
        method,
        (("handle", "object_ref"),),
        scenario=scenario,
        resource_types=(("handle", "catalog.item"),),
    )
    assert dict(result.request)["handle"] == "live-item"
