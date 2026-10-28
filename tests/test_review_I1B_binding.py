"""Resource scope and current effects through public file/SQLite/binder consumers."""

from pathlib import Path
from unittest.mock import Mock

import pytest

import cloud_dast
from cloud_dast.api import LiveRequest
from cloud_dast.composition.app_provider import FileMethodRepository
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import ResourceRef
from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    changed,
    input_field,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from tests.test_review_I1 import _manifest, _project


def fact(name, *args, context=Context.CONTRACT):
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)


def case(
    tmp_path,
    scenario,
    *,
    context=Context.CONTRACT,
    causal=True,
    same_resource=False,
    no_input=False,
    scope="targets",
):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    path = _manifest(tmp_path, ["grpc:svc.UpdateLeft", "grpc:svc.UpdateRight"])
    methods = FileMethodRepository(path)
    contract = _project(path).graph
    actions = tuple(
        Atom(value=canonical_action_id(m.method_id))
        for m in methods.list_methods("svc")
    )
    resources = (
        Atom(value="resource:tenant.record"),
        Atom(value="resource:task.record"),
    )
    effects = tuple(changed(r, Atom(value="status")) for r in resources)
    norm = Atom(value="norm:protect-left")
    facts = [
        *contract.facts,
        fact("is", norm, Atom(value="Norm")),
        fact("prevents", norm, effects[0], context=Context.ACCEPTED),
    ]
    facts.extend(fact("is", r, Atom(value="Resource")) for r in resources)
    for i, action in enumerate(actions):
        resource = resources[0] if same_resource else resources[i]
        if scope == "targets":
            facts.append(fact("targets", action, resource))
        elif scope == "refers_to":
            facts.append(
                fact("refers_to", input_field(action, Atom(value="status")), resource)
            )
        if causal:
            effect = effects[0] if same_resource else effects[i]
            facts.append(fact("causes", action, effect, context=context))
    if no_input:
        facts = [
            f
            for f in facts
            if not any(
                isinstance(a, Struct) and a.name == "input_field" for a in f.args
            )
        ]
    graph = QdlGraph(facts=tuple(facts))
    scenarios = Mock()
    stand = scenario.stand.model_copy(
        update={
            "resources": (
                ResourceRef(
                    service="svc", resource_type="tenant.record", resource_id="fixture"
                ),
            )
        }
    )
    scenarios.get_scenario.return_value = scenario.model_copy(update={"stand": stand})
    return methods, scenarios, graph, actions, effects, norm


def save(repository, graph):
    repository.save(
        "contract:svc", graph, provenance={}, adapter_version="test", mapping_report={}
    )


def bind(binder):
    return binder.bind(
        LiveRequest(
            service="svc",
            method_id="grpc:svc.UpdateLeft",
            principal_id="attacker",
            resource_id="fixture",
        ),
        formal_proposal=False,
    )


def methods_for_norm(binding, norm):
    return {
        s.method.method_id
        for p in binding.execution.paths
        for s in p.steps
        if s.invariant.norm_id == norm.value
    }


@pytest.mark.parametrize("context", list(Context))
def test_only_current_executable_causal_proof_binds_norm(
    tmp_path, scenario_position, context
):
    methods, scenarios, graph, _, _, norm = case(
        tmp_path, scenario_position, context=context
    )
    with SqliteFormalRepository(":memory:") as repository:
        save(repository, graph)
        binding = bind(
            ScenarioBinder(
                methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
            )
        )
    assert methods_for_norm(binding, norm) == (
        {"grpc:svc.UpdateLeft"}
        if context in {Context.CONTRACT, Context.ACCEPTED}
        else set()
    )


@pytest.mark.parametrize("scope", ["targets", "refers_to"])
def test_scope_without_cause_reports_deficit_instead_of_binding_neighbor(
    tmp_path, scenario_position, scope
):
    methods, scenarios, graph, _, _, norm = case(
        tmp_path, scenario_position, causal=False, scope=scope
    )
    with SqliteFormalRepository(":memory:") as repository:
        save(repository, graph)
        binding = bind(
            ScenarioBinder(
                methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
            )
        )
    assert methods_for_norm(binding, norm) == set()
    assert {
        d.action for d in binding.deficits if d.reason == "missing_causal_effect"
    } == {"grpc:svc.UpdateLeft"}


def test_same_resource_effect_binds_all_actual_producers(tmp_path, scenario_position):
    methods, scenarios, graph, _, _, norm = case(
        tmp_path, scenario_position, same_resource=True
    )
    with SqliteFormalRepository(":memory:") as repository:
        save(repository, graph)
        binding = bind(
            ScenarioBinder(
                methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
            )
        )
    assert methods_for_norm(binding, norm) == {
        m.method_id for m in methods.list_methods("svc")
    }


def test_causal_proof_does_not_require_name_matched_input_field_or_targets(
    tmp_path, scenario_position
):
    methods, scenarios, graph, _, _, norm = case(
        tmp_path, scenario_position, no_input=True, scope=None
    )
    with SqliteFormalRepository(":memory:") as repository:
        save(repository, graph)
        binding = bind(
            ScenarioBinder(
                methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
            )
        )
    assert methods_for_norm(binding, norm) == {"grpc:svc.UpdateLeft"}


@pytest.mark.parametrize("context", [Context.CONTRACT, Context.ACCEPTED])
def test_superseded_cause_cannot_be_resurrected_by_target_or_same_input_name(
    tmp_path, scenario_position, context
):
    methods, scenarios, graph, actions, effects, norm = case(
        tmp_path, scenario_position, context=context
    )
    new = changed(effects[0].args[0], Atom(value="replacement"))
    new_norm = Atom(value="norm:protect-replacement")
    updated = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", effects[0], Atom(value="Effect")),
            fact("is", new, Atom(value="Effect")),
            fact("causes", actions[0], new, context=context),
            fact("supersedes", new, effects[0], context=context),
            fact("is", new_norm, Atom(value="Norm")),
            fact("prevents", new_norm, new, context=Context.ACCEPTED),
        )
    )
    with SqliteFormalRepository(":memory:") as repository:
        save(repository, graph)
        binder = ScenarioBinder(
            methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
        )
        assert methods_for_norm(bind(binder), norm) == {"grpc:svc.UpdateLeft"}
        save(repository, updated)
        current = bind(binder)
        fresh = bind(
            ScenarioBinder(
                methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
            )
        )
    assert methods_for_norm(current, norm) == methods_for_norm(fresh, norm) == set()
    assert methods_for_norm(current, new_norm) == {"grpc:svc.UpdateLeft"}
    assert methods_for_norm(fresh, new_norm) == {"grpc:svc.UpdateLeft"}
    assert any(
        d.reason == "missing_causal_effect" and d.action == "grpc:svc.UpdateLeft"
        for d in current.deficits
    )
