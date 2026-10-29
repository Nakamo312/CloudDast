from __future__ import annotations

import pytest

from cloud_dast.contracts.assessment import BindingDeficit
from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    Variable,
    changed,
    external_call,
    input_field,
    reached,
)
from cloud_dast.qdl.reasoning import QdlSubgoal, derivable
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)


def _fact(name: str, *args, context: Context = Context.CONTRACT) -> Fact:
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)


def _build_graph(action: Atom, effect: Struct | None, *evidence: Fact) -> QdlGraph:
    field = input_field(action, Atom(value="secret_id"))
    facts = (
        _fact("is", action, Atom(value="Action")),
        _fact("is", field, Atom(value="Field")),
        _fact("is", Atom(value="norm:probe"), Atom(value="Norm")),
        _fact("is", Atom(value="probe-marker"), Atom(value="Resource")),
        _fact("is", Atom(value="resource:secret"), Atom(value="Resource")),
        *evidence,
    )
    if effect is not None:
        facts += (
            _fact(
                "prevents", Atom(value="norm:probe"), effect, context=Context.ACCEPTED
            ),
        )
    return QdlGraph(facts=facts)


def _paths(
    graph: QdlGraph,
    method: MethodSpec,
    scenario: ScenarioPosition,
    deficits: list[BindingDeficit] | None = None,
) -> tuple[QdlExecutionPath, ...]:
    return build(
        QdlPlanner().plan(graph),
        graph,
        methods=(method,),
        scenarios_by_method={method.method_id: scenario},
        binding_deficits=deficits,
    ).paths


def _norm_path(paths: tuple[QdlExecutionPath, ...]) -> QdlExecutionPath:
    return next(
        path
        for path in paths
        if any(step.invariant.norm_id == "norm:probe" for step in path.steps)
    )


@pytest.mark.parametrize("effect_name", ["reached", "external_call"])
@pytest.mark.parametrize("qualified", [False, True])
def test_marker_norm_retains_pending_path_and_requirement(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    effect_name: str,
    qualified: bool,
) -> None:
    action = Atom(value=("action:" if qualified else "") + method_spec.method_id)
    constructor = reached if effect_name == "reached" else external_call
    graph = _build_graph(action, constructor(action, Atom(value="probe-marker")))

    deficits: list[BindingDeficit] = []
    paths = _paths(graph, method_spec, scenario_position, deficits)
    path = _norm_path(paths)
    step = path.steps[0]

    assert path.scoreable
    assert step.plan.probe_fields == ()
    assert step.witness_requirement == QdlSubgoal(
        "probe_carrier", (action, Variable(name="AnyField"))
    )
    assert not derivable(step.witness_requirement, graph)
    assert not deficits
    smoke = next(path for path in paths if path.kind == "smoke")
    assert not smoke.scoreable
    assert smoke.steps[0].witness_requirement is None
    assert smoke.steps[0].invariant.norm_fact is None


@pytest.mark.parametrize("role", ["probe_target", "oob_target", "privileged"])
@pytest.mark.parametrize("effect_name", ["reached", "external_call"])
def test_accepted_carrier_populates_plan_and_versions_executable_path(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    role: str,
    effect_name: str,
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    constructor = reached if effect_name == "reached" else external_call
    effect = constructor(action, Atom(value="probe-marker"))
    graph = _build_graph(action, effect)
    carrier = _fact(
        "has",
        input_field(action, Atom(value="secret_id")),
        Atom(value=role),
        context=Context.ACCEPTED,
    )
    grounded = _build_graph(action, effect, carrier)

    pending = _norm_path(_paths(graph, method_spec, scenario_position))
    ready = _norm_path(_paths(grounded, method_spec, scenario_position))

    assert ready.steps[0].plan.probe_fields == ("secret_id",)
    assert ready.steps[0].witness_requirement == pending.steps[0].witness_requirement
    assert ready.steps[0].witness_requirement is not None
    assert derivable(ready.steps[0].witness_requirement, grounded)
    assert pending.path_id.split(":pv")[0] == ready.path_id.split(":pv")[0]
    assert pending.path_id != ready.path_id
    assert (
        ready.path_id
        == _norm_path(_paths(grounded, method_spec, scenario_position)).path_id
    )
    assert all(
        path.kind != "smoke"
        for path in _paths(grounded, method_spec, scenario_position)
    )


@pytest.mark.parametrize("effect_name", ["changed", "smoke"])
def test_differential_and_smoke_need_no_marker_carrier(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    effect_name: str,
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    effect = (
        changed(Atom(value="resource:secret"), Atom(value="secret_id"))
        if effect_name == "changed"
        else None
    )
    causal = (_fact("causes", action, effect),) if effect is not None else ()
    paths = _paths(
        _build_graph(action, effect, *causal), method_spec, scenario_position
    )

    path = _norm_path(paths) if effect is not None else paths[0]
    assert path.kind == ("invariant" if effect is not None else "smoke")
    assert path.steps[0].witness_requirement is None
    assert path.steps[0].plan.probe_fields == ()


@pytest.mark.parametrize("schema_field", [False, True])
def test_graph_carriers_are_intersected_with_method_schema(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    schema_field: bool,
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    unknown = input_field(action, Atom(value="graph_only"))
    carrier = input_field(
        action, Atom(value="secret_id" if schema_field else "graph_only")
    )
    graph = _build_graph(
        action,
        reached(action, Atom(value="probe-marker")),
        _fact("is", unknown, Atom(value="Field")),
        _fact("has", carrier, Atom(value="probe_target"), context=Context.ACCEPTED),
    )

    deficits: list[BindingDeficit] = []
    paths = _paths(graph, method_spec, scenario_position, deficits)
    step = _norm_path(paths).steps[0]

    assert step.witness_requirement is not None
    assert derivable(step.witness_requirement, graph)
    assert step.plan.probe_fields == (("secret_id",) if schema_field else ())
    assert any(path.kind == "smoke" for path in paths) is not schema_field
    assert deficits == (
        []
        if schema_field
        else [
            BindingDeficit(
                action=action.value,
                reason="probe_schema_mismatch",
                kind="incomplete_binding",
                context=(
                    ("graph_fields", '["graph_only"]'),
                    ("method_fields", '["secret_id"]'),
                ),
            )
        ]
    )


def test_proposal_carrier_cannot_enable_norm_execution(
    method_spec: MethodSpec, scenario_position: ScenarioPosition
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    graph = _build_graph(
        action,
        reached(action, Atom(value="probe-marker")),
        _fact(
            "has",
            input_field(action, Atom(value="secret_id")),
            Atom(value="probe_target"),
            context=Context.PROPOSAL,
        ),
    )

    paths = _paths(graph, method_spec, scenario_position)
    step = _norm_path(paths).steps[0]

    assert step.plan.probe_fields == ()
    assert step.witness_requirement is not None
    assert not derivable(step.witness_requirement, graph)
    assert any(path.kind == "smoke" for path in paths)


def test_pending_norm_smoke_retains_ordinary_typed_references(
    method_spec: MethodSpec, scenario_position: ScenarioPosition
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    graph = _build_graph(
        action,
        reached(action, Atom(value="probe-marker")),
        _fact(
            "has",
            input_field(action, Atom(value="secret_id")),
            Atom(value="object_ref"),
        ),
        _fact(
            "refers_to",
            input_field(action, Atom(value="secret_id")),
            Atom(value="resource:secret"),
        ),
    )

    paths = _paths(graph, method_spec, scenario_position)
    pending = _norm_path(paths).steps[0]
    smoke = next(path for path in paths if path.kind == "smoke").steps[0]

    assert smoke.witness_requirement is None
    assert smoke.plan.resource_params == pending.plan.resource_params == ("secret_id",)
    assert (
        smoke.plan.resource_types
        == pending.plan.resource_types
        == (("secret_id", "secret"),)
    )
    assert pending.witness_requirement is not None
    assert not derivable(pending.witness_requirement, graph)
    assert smoke.scenario == pending.scenario == scenario_position
