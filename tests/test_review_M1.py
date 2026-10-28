from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.api import LiveRequest
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    allowed,
    changed,
    create,
    field,
    input_field,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_facts
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticNormCompiler,
    derive_field_roles,
    derive_primitive_supports,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.planning import (
    IncrementalQdlPlanner,
    QdlPlanner,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from tests.workflow.execution.test_binder_graph_diet import (
    FormalRepository,
    MethodRepo,
    ScenarioRepo,
    _save,
)


def fact(name, *args, context=Context.ACCEPTED):
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)


def supersede_role(graph, holder, old, new, context=Context.ACCEPTED):
    previous = Struct(name="replacement", args=(holder, Atom(value=old)))
    replacement = Struct(name="replacement", args=(holder, Atom(value=new)))
    return merge_facts(
        graph,
        (
            fact("is", Atom(value=old), Atom(value="Role"), context=context),
            fact("is", Atom(value=new), Atom(value="Role"), context=context),
            fact("has", holder, Atom(value=new), context=context),
            fact("is", previous, Atom(value="Node"), context=context),
            fact("is", replacement, Atom(value="Node"), context=context),
            fact("supersedes", replacement, previous, context=context),
        ),
    )


def effects(graph):
    return {
        f.args[1]
        for f in SemanticNormCompiler().compile(graph)
        if f.predicate.name == "prevents"
    }


def test_superseded_privileged_role_cannot_create_norm(method_spec, scenario_position):
    action, resource = Atom(value="action:a"), Atom(value="resource:r")
    holder = input_field(action, Atom(value="role"))
    effect = changed(resource, Atom(value="role"))
    base = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action"), context=Context.CONTRACT),
            fact("is", resource, Atom(value="Resource")),
            fact("is", holder, Atom(value="Field")),
            fact("targets", action, resource),
            fact("has", holder, Atom(value="privileged")),
        )
    )
    revised = supersede_role(base, holder, "privileged", "mutable_input")
    assert effect in effects(base)
    assert any(
        '"privileged"' in a
        for a in ClingoEngine().solve(base, closures={"current_has"})[0].atoms
        if a.startswith("current_has(")
    )
    assert {row.role for row in derive_field_roles(revised)} == {"mutable_input"}
    assert effect not in effects(revised)
    assert set(base.facts) <= set(revised.facts)

    repository = FormalRepository()
    _save(repository, f"contract:{method_spec.service}", base)
    binder = ScenarioBinder(
        MethodRepo((method_spec.model_copy(update={"method_id": "a"}),)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    request = LiveRequest(
        service=method_spec.service, principal_id="attacker", resource_id="r"
    )
    before = binder.bind(request, formal_proposal=False)
    assert any(i.effect == effect for i in before.plan.invariants)
    _save(repository, f"contract:{method_spec.service}", revised)
    binding = binder.bind(request, formal_proposal=False)
    assert all(i.effect != effect for i in binding.plan.invariants)
    assert fact("has", holder, Atom(value="privileged")) in binding.graph.facts


@pytest.mark.parametrize(
    "producer,consumer",
    [
        (Context.ACCEPTED, Context.CONTRACT),
        (Context.CONTRACT, Context.ACCEPTED),
        (Context.ACCEPTED, Context.ACCEPTED),
    ],
)
def test_effect_supersession_retracts_incremental_path(producer, consumer):
    a, b, c, r = (
        Atom(value=s) for s in ("action:a", "action:b", "action:c", "resource:r")
    )
    old, new = changed(r, Atom(value="old")), changed(r, Atom(value="new"))
    base = QdlGraph(
        facts=(
            *(
                fact("is", x, Atom(value="Action"), context=Context.CONTRACT)
                for x in (a, b, c)
            ),
            fact("is", r, Atom(value="Resource")),
            fact("is", old, Atom(value="Effect")),
            fact("is", new, Atom(value="Effect")),
            fact("causes", a, old, context=producer),
            fact("requires", b, old, context=consumer),
            fact("requires", c, new, context=consumer),
        )
    )
    planner = IncrementalQdlPlanner()
    before = planner.plan(base)
    assert [p.actions for p in before.attack_paths] == [("action:a", "action:b")]
    revised = merge_facts(
        base,
        (
            fact("causes", a, new, context=producer),
            fact("supersedes", new, old, context=producer),
        ),
    )
    current = planner.plan(revised)
    assert current == QdlPlanner().plan(revised)
    assert [p.actions for p in current.attack_paths] == [("action:a", "action:c")]
    assert set(base.facts) <= set(revised.facts)
    assert planner.plan(revised) == current


def test_role_supersession_retracts_incremental_reveal():
    a, b, r = (Atom(value=s) for s in ("action:a", "action:b", "resource:r"))
    witness = output_field(b, Atom(value="id"))
    base = QdlGraph(
        facts=(
            *(fact("is", x, Atom(value="Action")) for x in (a, b)),
            fact("is", r, Atom(value="Resource")),
            fact("is", witness, Atom(value="Field")),
            fact("causes", a, create(r)),
            fact("exposes", b, witness),
            fact("has", witness, Atom(value="object_ref")),
            fact("refers_to", witness, r),
        )
    )
    planner = IncrementalQdlPlanner()
    assert planner.plan(base).reveal_edges
    revised = supersede_role(base, witness, "object_ref", "identifier")
    current = planner.plan(revised)
    assert current == QdlPlanner().plan(revised)
    assert current.reveal_edges == ()
    assert current.attack_paths == ()


@pytest.mark.parametrize("on_output", [False, True])
def test_sensitive_roles_use_current_semantics(on_output):
    action, resource = Atom(value="action:a"), Atom(value="resource:r")
    witness = field(resource, Atom(value="value"))
    holder = output_field(action, Atom(value="value")) if on_output else witness
    base = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", resource, Atom(value="Resource")),
            fact("is", witness, Atom(value="Field")),
            *((fact("is", holder, Atom(value="Field")),) if on_output else ()),
            fact("exposes", action, witness),
            fact("has", holder, Atom(value="sensitive")),
        )
    )
    assert any(e.name == "has" for e in effects(base))
    revised = supersede_role(base, holder, "sensitive", "identifier")
    assert effects(revised) == set()
    assert all(row.role != "sensitive" for row in derive_field_roles(revised))
    assert set(base.facts) <= set(revised.facts)


@pytest.mark.parametrize("untrusted", [Context.PROPOSAL, Context.RUNTIME])
def test_untrusted_replacement_cannot_retract_executable_role(untrusted):
    action, resource = Atom(value="action:a"), Atom(value="resource:r")
    holder = input_field(action, Atom(value="role"))
    effect = changed(resource, Atom(value="role"))
    base = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", resource, Atom(value="Resource")),
            fact("is", holder, Atom(value="Field")),
            fact("targets", action, resource),
            fact("has", holder, Atom(value="privileged")),
        )
    )
    revised = supersede_role(
        base, holder, "privileged", "mutable_input", context=untrusted
    )
    assert effects(revised) == {effect}
    assert {row.role for row in derive_field_roles(revised)} == {"privileged"}


def test_rule_derived_supersession_invalidates_paths_and_effect_coverage():
    a, b, r = (Atom(value=s) for s in ("action:a", "action:b", "resource:r"))
    old, new = changed(r, Atom(value="old")), changed(r, Atom(value="new"))
    base = QdlGraph(
        facts=(
            *(fact("is", x, Atom(value="Action")) for x in (a, b)),
            fact("is", r, Atom(value="Resource")),
            fact("is", old, Atom(value="Effect")),
            fact("is", new, Atom(value="Effect")),
            fact("causes", a, old),
            fact("requires", b, old),
        ),
        rules=(
            Rule(
                body=(
                    fact("has", a, Atom(value="mutable_input")),
                    fact("is", new, Atom(value="Effect")),
                    fact("is", old, Atom(value="Effect")),
                ),
                head=(fact("supersedes", new, old),),
            ),
        ),
    )
    planner = IncrementalQdlPlanner()
    assert planner.plan(base).attack_paths
    assert any(row.effect == old for row in derive_primitive_supports(base))
    revised = merge_facts(base, (fact("has", a, Atom(value="mutable_input")),))
    assert planner.plan(revised) == QdlPlanner().plan(revised)
    assert planner.plan(revised).attack_paths == ()
    assert all(row.effect != old for row in derive_primitive_supports(revised))
    assert all(row.role != "state_transition" for row in derive_field_roles(revised))


def test_public_binder_rebind_retracts_superseded_edge(method_spec, scenario_position):
    a, b, r = (Atom(value=s) for s in ("action:a", "action:b", "resource:r"))
    old, new = changed(r, Atom(value="old")), changed(r, Atom(value="new"))
    base = QdlGraph(
        facts=(
            *(
                fact("is", x, Atom(value="Action"), context=Context.CONTRACT)
                for x in (a, b)
            ),
            fact("is", r, Atom(value="Resource")),
            fact("is", old, Atom(value="Effect")),
            fact("is", new, Atom(value="Effect")),
            fact("causes", a, old),
            fact("requires", b, old),
            fact("causes", b, allowed(b)),
            fact("is", Atom(value="norm:edge"), Atom(value="Norm")),
            fact("prevents", Atom(value="norm:edge"), old),
            fact("is", Atom(value="norm:final"), Atom(value="Norm")),
            fact("prevents", Atom(value="norm:final"), allowed(b)),
        )
    )
    repository = FormalRepository()
    _save(repository, f"contract:{method_spec.service}", base)
    methods = MethodRepo(
        tuple(method_spec.model_copy(update={"method_id": s}) for s in ("a", "b"))
    )

    def binder():
        return ScenarioBinder(
            methods,
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        )

    request = LiveRequest(
        service=method_spec.service, principal_id="attacker", resource_id="r"
    )
    reused = binder()
    before = reused.bind(request, formal_proposal=False)
    assert any(p.kind == "attack" and len(p.steps) == 2 for p in before.execution.paths)
    revised = merge_facts(base, (fact("supersedes", new, old),))
    _save(repository, f"contract:{method_spec.service}", revised)
    after = reused.bind(request, formal_proposal=False)
    fresh = binder().bind(request, formal_proposal=False)
    assert after.plan == fresh.plan
    assert after.plan.attack_paths == ()
    assert not any(p.kind == "attack" for p in after.execution.paths)
    assert set(base.facts) <= set(after.graph.facts)
