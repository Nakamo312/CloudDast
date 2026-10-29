"""Offline planner/binder contracts for ordinary value acquisition chains."""

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    allowed,
    changed,
    create,
    input_field,
    output_field,
)
from cloud_dast.runtime.execution.binding import bind_attack_path
from cloud_dast.runtime.planning import (
    IncrementalQdlPlanner,
    QdlPlanner,
)
from tests.workflow.execution.test_attack_chain_invariant_binding import (
    _method,
    _scenario,
)
from tests.workflow.execution.test_qdl_planner import entity, fact


def _build_graph(*, requires=False, coupling_context=Context.CONTRACT, reverse=False):
    a, b, c = (Atom(value=f"action:{name}") for name in ("alpha", "beta", "gamma"))
    resource = Atom(value="opaque")
    witness = output_field(b, Atom(value="token"))
    parameter = input_field(c, Atom(value="key"))
    endpoints = (parameter, witness) if reverse else (witness, parameter)
    facts = (
        *(entity(action.value, "Action", Context.CONTRACT) for action in (a, b, c)),
        entity(resource.value, "ResourceType", Context.CONTRACT),
        fact("is", (create(resource), Atom(value="Effect"))),
        fact("is", (witness, Atom(value="OutputField"))),
        fact("is", (parameter, Atom(value="Field"))),
        fact("causes", (a, create(resource))),
        fact("exposes", (b, witness)),
        fact("has", (witness, Atom(value="object_ref"))),
        fact("refers_to", (witness, resource)),
        fact("coupled", (*endpoints, Atom(value="eq")), coupling_context),
    )
    if requires:
        facts += (fact("requires", (b, create(resource))),)
    return QdlGraph(facts=facts)


def _path(graph, actions, *, planner=None):
    return next(
        path
        for path in (planner or QdlPlanner(max_depth=3)).plan(graph).attack_paths
        if path.actions == tuple(f"action:{action}" for action in actions)
    )


def _bind(path):
    return bind_attack_path(
        path,
        invariants={},
        invariants_by_action={},
        invariants_by_effect={},
        methods_by_action={
            action: _method(action.removeprefix("action:")) for action in path.actions
        },
        scenarios_by_action={action: _scenario() for action in path.actions},
    )


@pytest.mark.parametrize("reverse", (False, True))
def test_outputless_action_observer_consumer_needs_values_not_create_proof(reverse):
    graph = _build_graph(reverse=reverse)
    assert not graph.facts_for("requires")
    path = _path(graph, ("alpha", "beta", "gamma"))
    assert path.edge_effects == ((), ())
    bound = _bind(path)
    assert bound is not None
    assert [step.method.method_id for step in bound.steps] == ["alpha", "beta", "gamma"]
    assert all(not step.required_effects for step in bound.steps)
    assert all(step.invariant.norm_fact is None for step in bound.steps)


def test_reveal_alone_does_not_invent_a_causal_requirement():
    path = _path(_build_graph(), ("alpha", "beta"))
    assert path.edge_effects == ((),)
    assert _bind(path) is not None


def test_real_requirement_is_kept_even_when_value_edge_also_exists():
    path = _path(_build_graph(requires=True), ("alpha", "beta", "gamma"))
    effect = create(Atom(value="opaque"))
    assert path.edge_effects == ((effect,), ())
    bound = _bind(path)
    assert bound is not None
    assert bound.steps[0].required_effects == (effect,)
    assert bound.steps[0].invariant.norm_fact is None


@pytest.mark.parametrize("context", (Context.PROPOSAL, Context.REPORT))
def test_untrusted_coupling_cannot_extend_executable_chain(context):
    plan = QdlPlanner(max_depth=3).plan(_build_graph(coupling_context=context))
    assert all("action:gamma" not in path.actions for path in plan.attack_paths)


def test_bounded_walk_keeps_repeated_method_occurrences_and_step_identities():
    graph = _build_graph()
    beta, alpha = Atom(value="action:beta"), Atom(value="action:alpha")
    effect = allowed(beta)
    graph = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", (effect, Atom(value="Effect"))),
            fact("causes", (beta, effect)),
            fact("requires", (alpha, effect)),
        )
    )
    path = _path(graph, ("beta", "alpha", "beta", "gamma"))
    assert path.edge_effects == ((effect,), (), ())
    bound = _bind(path)
    assert bound is not None
    assert bound.steps[0].method == bound.steps[2].method
    assert len({step.step_id for step in bound.steps}) == 4
    assert path.supported
    assert not _path(graph, ("alpha", "beta", "gamma")).supported
    assert path.depth == 3
    assert all(
        path.depth <= 3 for path in QdlPlanner(max_depth=3).plan(graph).attack_paths
    )


def test_incremental_value_walk_matches_fresh_plan_with_context_provenance():
    graph = _build_graph(coupling_context=Context.ACCEPTED)
    fresh = QdlPlanner(max_depth=3).plan(graph)
    incremental = IncrementalQdlPlanner(max_depth=3).plan(graph)
    assert incremental.attack_paths == fresh.attack_paths
    path = _path(graph, ("alpha", "beta", "gamma"))
    assert path.context is Context.ACCEPTED


def test_direct_output_coupling_needs_no_create_declaration():
    graph = _build_graph()
    graph = QdlGraph(
        facts=tuple(f for f in graph.facts if f.predicate.name != "causes")
    )
    path = _path(graph, ("beta", "gamma"))
    assert path.edge_effects == ((),)
    assert _bind(path) is not None


def test_coupling_without_exposed_output_cannot_invent_a_value_source():
    graph = _build_graph()
    graph = QdlGraph(
        facts=tuple(f for f in graph.facts if f.predicate.name != "exposes")
    )
    assert not QdlPlanner(max_depth=3).plan(graph).attack_paths


def test_explicit_consumer_requires_is_not_proved_by_the_observer():
    graph = _build_graph()
    consumer = Atom(value="action:gamma")
    effect = create(Atom(value="opaque"))
    graph = QdlGraph(facts=(*graph.facts, fact("requires", (consumer, effect))))
    # C still requires creation, but A must not block independent B. Only
    # the direct A->C route carries the immediately gating causal effect.
    assert _path(graph, ("alpha", "gamma")).edge_effects == ((effect,),)
    assert _path(graph, ("alpha", "beta", "gamma")).edge_effects == ((), ())
    assert not any(
        f.predicate.name == "causes" and f.args[0] == Atom(value="action:beta")
        for f in graph.facts
    )


def test_and_requires_keeps_both_incoming_obligations_without_claiming_a_join():
    graph = _build_graph()
    producer, consumer = Atom(value="action:delta"), Atom(value="action:gamma")
    first = create(Atom(value="opaque"))
    second = allowed(producer)
    graph = QdlGraph(
        facts=(
            *graph.facts,
            entity(producer.value, "Action", Context.CONTRACT),
            fact("is", (second, Atom(value="Effect"))),
            fact("causes", (producer, second)),
            fact("requires", (consumer, first)),
            fact("requires", (consumer, second)),
        )
    )
    assert _path(graph, ("alpha", "gamma")).edge_effects == ((first,),)
    assert _path(graph, ("delta", "gamma")).edge_effects == ((second,),)
    assert {f.args[1] for f in graph.facts_for("requires")} == {first, second}


@pytest.mark.parametrize("names", (("alpha", "beta", "gamma"), ("z", "a", "m")))
def test_input_equality_orientation_cannot_invent_execution_order(names):
    a, b, c = (Atom(value=f"action:{name}") for name in names)
    source = input_field(a, Atom(value="nonce"))
    lookup = input_field(b, Atom(value="filter"))
    witness = output_field(b, Atom(value="token"))
    parameter = input_field(c, Atom(value="key"))
    graph = QdlGraph(
        facts=(
            *(entity(action.value, "Action", Context.CONTRACT) for action in (a, b, c)),
            *(
                fact("is", (field, Atom(value="InputField")))
                for field in (source, lookup, parameter)
            ),
            fact("is", (witness, Atom(value="OutputField"))),
            fact("exposes", (b, witness)),
            fact("coupled", (source, lookup, Atom(value="eq"))),
            fact("coupled", (witness, parameter, Atom(value="eq"))),
        )
    )
    plan = QdlPlanner(max_depth=3).plan(graph)
    assert [(path.actions, path.edge_effects) for path in plan.attack_paths] == [
        ((b.value, c.value), ((),))
    ]
    reversed_graph = QdlGraph(
        facts=tuple(
            fact("coupled", (lookup, source, Atom(value="eq")))
            if f.predicate.name == "coupled" and f.args[:2] == (source, lookup)
            else f
            for f in graph.facts
        )
    )
    reversed_plan = QdlPlanner(max_depth=3).plan(reversed_graph)
    assert [
        (path.actions, path.edge_effects) for path in reversed_plan.attack_paths
    ] == [(path.actions, path.edge_effects) for path in plan.attack_paths]
    assert (
        IncrementalQdlPlanner(max_depth=3).plan(graph).attack_paths == plan.attack_paths
    )
    assert _bind(plan.attack_paths[0]) is not None


def _conjunction_graph(
    names=("a", "d", "c"), *, alternative=False, context=Context.CONTRACT
):
    a, d, c = (Atom(value=f"action:{name}") for name in names)
    x, y = Atom(value="resource:x"), Atom(value="resource:y")
    first, second = changed(x, Atom(value="paid")), changed(y, Atom(value="paid"))
    facts = (
        *(entity(action.value, "Action", Context.CONTRACT) for action in (a, d, c)),
        *(entity(resource.value, "Resource", Context.CONTRACT) for resource in (x, y)),
        *(fact("is", (effect, Atom(value="Effect"))) for effect in (first, second)),
        fact("causes", (a, first)),
        fact("causes", (d, second), context),
        fact("requires", (c, first)),
        fact("requires", (c, second)),
    )
    if alternative:
        other = Atom(value="action:alternative")
        facts += (
            entity(other.value, "Action", Context.CONTRACT),
            fact("causes", (other, first)),
        )
    return QdlGraph(facts=facts), first, second


@pytest.mark.parametrize("names", (("a", "d", "c"), ("z", "a", "m")))
def test_conjunction_linearizes_sibling_producers_without_fictional_prerequisites(
    names,
):
    graph, first, second = _conjunction_graph(names)
    a, d, c = names
    path = _path(graph, (a, d, c))
    assert path.edge_effects == ((), (second,))
    assert path.supported
    assert _path(graph, (d, a, c)).edge_effects == ((), (first,))
    assert all(
        f.args[0] == Atom(value=f"action:{c}") for f in graph.facts_for("requires")
    )
    bound = _bind(path)
    assert bound is not None
    assert bound.steps[0].required_effects == ()
    assert bound.steps[1].required_effects == (second,)
    assert all(step.invariant.norm_fact is None for step in bound.steps)
    assert (
        IncrementalQdlPlanner(max_depth=3).plan(graph).attack_paths
        == QdlPlanner(max_depth=3).plan(graph).attack_paths
    )


def test_conjunction_keeps_alternative_producers_or_and_terminates_at_depth_bound():
    graph, first, second = _conjunction_graph(alternative=True)
    paths = QdlPlanner(max_depth=3).plan(graph).attack_paths
    composed = {path.actions for path in paths if len(path.actions) > 2}
    assert composed == {
        tuple(f"action:{action}" for action in names)
        for names in (
            ("a", "d", "c"),
            ("d", "a", "c"),
            ("alternative", "d", "c"),
            ("d", "alternative", "c"),
        )
    }
    assert all(path.depth <= 3 for path in paths)
    assert all(
        len(path.actions) == 2
        for path in QdlPlanner(max_depth=1).plan(graph).attack_paths
    )
    assert _path(
        graph, ("a", "d", "c"), planner=QdlPlanner(max_depth=2)
    ).edge_effects == ((), (second,))


def test_conjunction_cannot_use_another_resource_or_an_unsupported_causal_cycle():
    graph, first, second = _conjunction_graph()
    wrong = changed(Atom(value="resource:x"), Atom(value="paid"))
    missing = QdlGraph(
        facts=(
            *(
                f
                for f in graph.facts
                if not (f.predicate.name == "causes" and f.args[1] == second)
            ),
            fact("causes", (Atom(value="action:d"), wrong)),
        )
    )
    assert all(
        len(path.actions) == 2
        for path in QdlPlanner(max_depth=3).plan(missing).attack_paths
    )
    cycle = QdlGraph(
        facts=(
            *graph.facts,
            fact("requires", (Atom(value="action:a"), second)),
            fact("requires", (Atom(value="action:d"), first)),
        )
    )
    # Existing bounded walks remain diagnostic, but Clingo cannot complete a
    # supported conjunction when both producers need a future occurrence.
    planner = QdlPlanner(max_depth=3)
    assert not any(
        symbol.name == "_qdl_and_walk" for symbol in planner._solve_walk_edges(cycle)
    )
    assert all(path.depth <= 3 for path in planner.plan(cycle).attack_paths)


@pytest.mark.parametrize(
    "context", (Context.ACCEPTED, Context.PROPOSAL, Context.REPORT, Context.RUNTIME)
)
def test_conjunction_preserves_provenance_and_rejects_untrusted_supplier(context):
    graph, first, second = _conjunction_graph(context=context)
    composed = [
        path
        for path in QdlPlanner(max_depth=2).plan(graph).attack_paths
        if len(path.actions) == 3
    ]
    if context is Context.ACCEPTED:
        assert len(composed) == 2
        assert all(path.context is Context.ACCEPTED for path in composed)
        assert _path(graph, ("a", "d", "c")).edge_effects == ((), (second,))
    else:
        assert composed == []


def test_conjunction_composes_nested_prerequisites_before_a_later_consumer():
    graph, first, second = _conjunction_graph()
    middle, final = Atom(value="action:middle"), Atom(value="action:c")
    effect = allowed(middle)
    graph = QdlGraph(
        facts=(
            *(
                f.model_copy(update={"args": (middle, f.args[1])})
                if f.predicate.name == "requires"
                else f
                for f in graph.facts
            ),
            entity(middle.value, "Action", Context.CONTRACT),
            fact("is", (effect, Atom(value="Effect"))),
            fact("causes", (middle, effect)),
            fact("requires", (final, effect)),
        )
    )
    assert _path(graph, ("a", "d", "middle", "c")).edge_effects == (
        (),
        (second,),
        (effect,),
    )


def test_conjunction_does_not_grant_or_schedule_permission_requirements():
    graph, _, second = _conjunction_graph()
    permission = Atom(value="permission:operate")
    graph = QdlGraph(
        facts=(
            *graph.facts,
            entity(permission.value, "Permission", Context.CONTRACT),
            *(
                fact("requires", (Atom(value=f"action:{name}"), permission))
                for name in ("a", "d", "c")
            ),
        )
    )
    original = graph.content_hash
    path = _path(graph, ("a", "d", "c"))
    assert path.supported
    assert path.edge_effects == ((), (second,))
    assert graph.content_hash == original
    assert len([f for f in graph.facts_for("requires") if f.args[1] == permission]) == 3
    assert not graph.facts_for("has")
    assert all(f.args[1] != permission for f in graph.facts_for("causes"))


@pytest.mark.parametrize("classification", ("Effect", "Node"))
def test_missing_effect_requirement_still_prevents_conjunction_without_a_producer(
    classification,
):
    graph, _, _ = _conjunction_graph()
    effect = (
        Atom(value="effect:unavailable")
        if classification == "Effect"
        else allowed(Atom(value="action:c"))
    )
    graph = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", (effect, Atom(value=classification))),
            fact("requires", (Atom(value="action:c"), effect)),
        )
    )
    assert all(
        len(path.actions) == 2
        for path in QdlPlanner(max_depth=3).plan(graph).attack_paths
    )
    assert all(
        not path.supported for path in QdlPlanner(max_depth=3).plan(graph).attack_paths
    )


def test_nominal_support_rejects_value_dependency_suffix_and_keeps_observer_normless():
    graph = _build_graph()
    a, b = Atom(value="action:alpha"), Atom(value="action:beta")
    output = output_field(a, Atom(value="seed"))
    parameter = input_field(b, Atom(value="filter"))
    graph = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", (output, Atom(value="OutputField"))),
            fact("is", (parameter, Atom(value="InputField"))),
            fact("exposes", (a, output)),
            fact("coupled", (output, parameter, Atom(value="eq"))),
        )
    )
    complete = _path(graph, ("alpha", "beta", "gamma"))
    suffix = _path(graph, ("beta", "gamma"))
    assert complete.supported
    assert not suffix.supported
    assert complete.edge_effects == ((), ())
    assert _bind(complete).steps[1].invariant.norm_fact is None
    assert (
        QdlPlanner(max_depth=3).plan(graph).attack_paths
        == IncrementalQdlPlanner(max_depth=3).plan(graph).attack_paths
    )


def test_nominal_support_is_prospective_and_does_not_require_runtime_effect_proof():
    graph = _build_graph()
    effect = create(Atom(value="opaque"))
    graph = QdlGraph(
        facts=(*graph.facts, fact("requires", (Atom(value="action:gamma"), effect)))
    )
    path = _path(graph, ("alpha", "beta", "gamma"))
    assert path.supported
    assert path.edge_effects == ((), ())
    assert not graph.facts_for("observed_transition")
