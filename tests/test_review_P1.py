from itertools import product
from pathlib import Path

import pytest

import cloud_dast
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
    remove,
)
from cloud_dast.qdl.projection import planner_view
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.planning import (
    IncrementalQdlPlanner,
    QdlPlanner,
)


def fact(name, *args, context=Context.CONTRACT):
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


def chain(producer=Context.ACCEPTED, consumer=Context.ACCEPTED, redeclare=False):
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )
    a, b, c, resource = (
        Atom(value=value)
        for value in ("action:a", "action:b", "action:c", "resource:r")
    )
    effect = changed(resource, Atom(value="value"))
    facts = [
        *(fact("is", action, Atom(value="Action")) for action in (a, b, c)),
        fact("is", resource, Atom(value="Resource")),
        fact("is", effect, Atom(value="Effect")),
        fact("causes", a, effect, context=producer),
        fact("requires", b, effect, context=consumer),
    ]
    if redeclare:
        facts.extend(
            fact("is", action, Atom(value="Action"), context=Context.ACCEPTED)
            for action in (a, b)
        )
    return QdlGraph(facts=tuple(facts)), effect


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize("redeclare", [False, True])
def test_projection_preserves_accepted_dependencies(planner_type, redeclare):
    raw, effect = chain(redeclare=redeclare)
    view = planner_view(raw)
    raw_paths = planner_type().plan(raw).attack_paths
    paths = planner_type().plan(view).attack_paths
    expected = [(Context.ACCEPTED, ("action:a", "action:b"), ((effect,),))]
    assert [(p.context, p.actions, p.edge_effects) for p in raw_paths] == expected
    assert [(p.context, p.actions, p.edge_effects) for p in paths] == expected
    assert set(view.facts).issubset(raw.facts)
    assert {f for f in view.facts if f.predicate.name != "is"} == {
        f for f in raw.facts if f.predicate.name != "is"
    }
    assert planner_view(view) == view


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "producer,consumer",
    [
        (Context.CONTRACT, Context.ACCEPTED),
        (Context.ACCEPTED, Context.CONTRACT),
        (Context.CONTRACT, Context.CONTRACT),
    ],
)
def test_mixed_dependency_provenance(planner_type, producer, consumer):
    graph, effect = chain(producer, consumer)
    plan = planner_type().plan(planner_view(graph))
    expected_context = (
        Context.CONTRACT
        if producer == consumer == Context.CONTRACT
        else Context.ACCEPTED
    )
    assert [(p.context, p.actions, p.edge_effects) for p in plan.attack_paths] == [
        (expected_context, ("action:a", "action:b"), ((effect,),))
    ]
    assert any(
        c.context == expected_context
        and c.source == "action:a"
        and c.target == "action:b"
        for c in plan.closures
    )


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "untrusted", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT]
)
@pytest.mark.parametrize("position", ["producer", "consumer", "declaration"])
def test_untrusted_context_cannot_supply_planning_premises(
    planner_type, untrusted, position
):
    graph, _ = chain(
        producer=untrusted if position == "producer" else Context.CONTRACT,
        consumer=untrusted if position == "consumer" else Context.ACCEPTED,
    )
    if position == "declaration":
        graph = QdlGraph(
            facts=tuple(
                f.model_copy(update={"context": untrusted})
                if f.predicate.name == "is" and f.args[1] == Atom(value="Action")
                else f
                for f in graph.facts
            )
        )
    assert planner_type().plan(planner_view(graph)).attack_paths == ()


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "first_context,second_context",
    [
        (Context.CONTRACT, Context.ACCEPTED),
        (Context.ACCEPTED, Context.CONTRACT),
    ],
)
def test_walk_composes_edges_and_preserves_effects(
    planner_type, first_context, second_context
):
    base, first_effect = chain(first_context, first_context)
    second_effect = changed(Atom(value="resource:r"), Atom(value="other"))
    graph = QdlGraph(
        facts=(
            *base.facts,
            fact("is", second_effect, Atom(value="Effect")),
            fact(
                "causes", Atom(value="action:b"), second_effect, context=second_context
            ),
            fact(
                "requires",
                Atom(value="action:c"),
                second_effect,
                context=second_context,
            ),
        )
    )
    planner = planner_type()
    before = planner.plan(base)
    assert [p.actions for p in before.attack_paths] == [("action:a", "action:b")]
    plan = planner.plan(planner_view(graph))
    path = next(
        p
        for p in plan.attack_paths
        if p.actions == ("action:a", "action:b", "action:c")
    )
    assert path.context == Context.ACCEPTED
    assert path.edge_effects == ((first_effect,), (second_effect,))
    assert plan.attack_paths == planner_type().plan(graph).attack_paths
    assert plan.closures == planner_type().plan(graph).closures
    assert any(
        c.context == Context.ACCEPTED
        and c.source == "action:a"
        and c.target == "action:c"
        for c in plan.closures
    )
    bounded = planner_type(max_depth=1).plan(graph)
    assert all(len(p.actions) == 2 for p in bounded.attack_paths)
    assert {p.actions for p in bounded.attack_paths} == {
        ("action:a", "action:b"),
        ("action:b", "action:c"),
    }


def test_trusted_declarations_share_types_but_keep_smoke_scope():
    from cloud_dast.runtime.planning import declared_action_ids

    graph, effect = chain()
    graph = QdlGraph(
        facts=tuple(
            f.model_copy(update={"context": Context.ACCEPTED})
            if f.predicate.name == "is" and f.args[0] == Atom(value="action:b")
            else f
            for f in graph.facts
        )
    )
    assert declared_action_ids(graph, Context.CONTRACT) == {"action:a", "action:c"}
    assert declared_action_ids(graph, Context.ACCEPTED) == {"action:b"}
    for planner in (QdlPlanner(), IncrementalQdlPlanner()):
        assert [
            (p.actions, p.edge_effects) for p in planner.plan(graph).attack_paths
        ] == [(("action:a", "action:b"), ((effect,),))]


def test_public_binder_preserves_projected_chain(method_spec, scenario_position):
    from cloud_dast.api import LiveRequest
    from tests.workflow.execution.test_binder_graph_diet import (
        FormalRepository,
        MethodRepo,
        ScenarioRepo,
        _save,
    )

    raw, effect = chain(redeclare=True)
    final_effect = allowed(Atom(value="action:b"))
    raw = QdlGraph(
        facts=(
            *raw.facts,
            fact("is", final_effect, Atom(value="Effect")),
            fact(
                "causes", Atom(value="action:b"), final_effect, context=Context.ACCEPTED
            ),
            *(
                f
                for name, norm_effect in (
                    ("norm:edge", effect),
                    ("norm:final", final_effect),
                )
                for f in (
                    fact(
                        "is",
                        Atom(value=name),
                        Atom(value="Norm"),
                        context=Context.ACCEPTED,
                    ),
                    fact(
                        "prevents",
                        Atom(value=name),
                        norm_effect,
                        context=Context.ACCEPTED,
                    ),
                )
            ),
        )
    )
    methods = tuple(
        method_spec.model_copy(update={"method_id": name}) for name in ("a", "b", "c")
    )
    repository = FormalRepository()
    _save(repository, f"contract:{method_spec.service}", raw)
    binder = ScenarioBinder(
        MethodRepo(methods),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec.service, principal_id="attacker", resource_id="r"
        ),
        formal_proposal=False,
    )
    assert [
        (p.context, p.actions, p.edge_effects) for p in binding.plan.attack_paths
    ] == [(Context.ACCEPTED, ("action:a", "action:b"), ((effect,),))]
    assert not any(
        f.context == Context.ACCEPTED
        and f.predicate.name == "is"
        and f.args[1] == Atom(value="Action")
        for f in binding.graph.facts
    )

    assert any(
        path.kind == "attack"
        and tuple(step.method.method_id for step in path.steps) == ("a", "b")
        for path in binding.execution.paths
    )


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
def test_rule_derived_requirement_uses_shared_declarations(planner_type):
    graph, effect = chain()
    graph = QdlGraph(
        facts=tuple(f for f in graph.facts if f.predicate.name != "requires"),
        rules=(
            Rule(
                body=(
                    fact(
                        "causes",
                        Atom(value="action:a"),
                        effect,
                        context=Context.ACCEPTED,
                    ),
                ),
                head=(
                    fact(
                        "requires",
                        Atom(value="action:b"),
                        effect,
                        context=Context.ACCEPTED,
                    ),
                ),
            ),
        ),
    )
    assert [
        (p.context, p.actions) for p in planner_type().plan(graph).attack_paths
    ] == [(Context.ACCEPTED, ("action:a", "action:b"))]


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "untrusted", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT]
)
def test_whole_untrusted_chain_stays_in_its_explicit_context(planner_type, untrusted):
    graph, effect = chain(untrusted, untrusted)
    graph = QdlGraph(
        facts=tuple(f.model_copy(update={"context": untrusted}) for f in graph.facts)
    )
    assert planner_type().plan(graph).attack_paths == ()
    # Explicit diagnostic selection still works without lending declarations
    # or edges to either planning context.
    assert [
        (p.context, p.actions, p.edge_effects)
        for p in planner_type(contexts=(untrusted,)).plan(graph).attack_paths
    ] == [(untrusted, ("action:a", "action:b"), ((effect,),))]


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
def test_walk_requires_action_type_at_every_intermediate_node(planner_type):
    base, first_effect = chain()
    second_effect = changed(Atom(value="resource:r"), Atom(value="other"))
    graph = QdlGraph(
        facts=(
            *base.facts,
            fact("is", second_effect, Atom(value="Effect")),
            fact("causes", Atom(value="action:b"), second_effect),
            fact("requires", Atom(value="action:c"), second_effect),
        )
    )
    assert any(
        p.actions == ("action:a", "action:b", "action:c")
        and p.edge_effects == ((first_effect,), (second_effect,))
        for p in planner_type().plan(graph).attack_paths
    )
    untyped = QdlGraph(
        facts=tuple(
            fact("is", Atom(value="action:b"), Atom(value="Resource"))
            if f.predicate.name == "is" and f.args[0] == Atom(value="action:b")
            else f
            for f in graph.facts
        )
    )
    assert planner_type().plan(untyped).attack_paths == ()


def reveal_graph(contexts, redeclare=False):
    from tests.workflow.execution.test_qdl_planner import make_reveal_graph

    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )
    base = make_reveal_graph()
    facts = [
        f.model_copy(update={"context": contexts[f.predicate.name]})
        if f.predicate.name in contexts
        else f
        for f in base.facts
    ]
    if redeclare:
        facts.extend(
            f.model_copy(update={"context": Context.ACCEPTED})
            for f in base.facts
            if f.predicate.name == "is"
        )
    return QdlGraph(facts=tuple(facts))


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize("redeclare", [False, True])
@pytest.mark.parametrize(
    "premise_contexts", tuple(product((Context.CONTRACT, Context.ACCEPTED), repeat=4))
)
def test_reveal_preserves_every_trusted_context_combination(
    planner_type, redeclare, premise_contexts
):
    graph = reveal_graph(
        dict(zip(("causes", "exposes", "has", "refers_to"), premise_contexts)),
        redeclare,
    )
    expected_context = (
        Context.ACCEPTED if Context.ACCEPTED in premise_contexts else Context.CONTRACT
    )
    witness = graph.facts_for("exposes")[0].args[1]
    view = planner_view(graph)
    planner = planner_type()
    for source in (graph, view):
        plan = planner.plan(source)
        assert [
            (e.context, e.create_action, e.observe_action, e.resource_type, e.witness)
            for e in plan.reveal_edges
        ] == [(expected_context, "action:create", "action:read", "widget", witness)]
        assert [(p.context, p.actions, p.edge_effects) for p in plan.attack_paths] == [
            (expected_context, ("action:create", "action:read"), ((),))
        ]
    assert {f for f in view.facts if f.predicate.name != "is"} == {
        f for f in graph.facts if f.predicate.name != "is"
    }


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "untrusted", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT]
)
@pytest.mark.parametrize(
    "premise", ["causes", "exposes", "has", "refers_to", "is", "all"]
)
def test_reveal_rejects_untrusted_premises(planner_type, untrusted, premise):
    contexts = dict.fromkeys(
        ("causes", "exposes", "has", "refers_to"), Context.CONTRACT
    )
    if premise == "all":
        contexts = dict.fromkeys((*contexts, "is"), untrusted)
    else:
        contexts[premise] = untrusted
    graph = reveal_graph(contexts)
    for source in (graph, planner_view(graph)):
        plan = planner_type().plan(source)
        assert plan.attack_paths == ()
        assert plan.reveal_edges == ()
    if premise == "all":
        diagnostic = planner_type(contexts=(untrusted,)).plan(graph)
        assert len(diagnostic.reveal_edges) == 1
        assert [p.actions for p in diagnostic.attack_paths] == [
            ("action:create", "action:read")
        ]


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize("superseded", ["create", "role"])
def test_reveal_uses_current_effect_and_role(planner_type, superseded):
    graph = reveal_graph({"causes": Context.ACCEPTED, "has": Context.ACCEPTED})
    assert len(planner_type().plan(graph).reveal_edges) == 1
    if superseded == "create":
        old = graph.facts_for("causes")[0].args[1]
        new = remove(Atom(value="widget"))
    else:
        holder = graph.facts_for("has")[0].args[0]
        old = Struct(name="replacement", args=(holder, Atom(value="object_ref")))
        new = Struct(name="replacement", args=(holder, Atom(value="sensitive")))
    graph = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", new, Atom(value="Effect")),
            fact("is", old, Atom(value="Effect")),
            fact("is", Atom(value="object_ref"), Atom(value="Role")),
            fact("is", Atom(value="sensitive"), Atom(value="Role")),
            fact("supersedes", new, old, context=Context.ACCEPTED),
        )
    )
    for source in (graph, planner_view(graph)):
        # Fresh solves: incremental invalidation is owned by M1.
        plan = planner_type().plan(source)
        assert plan.reveal_edges == ()
        assert plan.attack_paths == ()


@pytest.mark.parametrize("missing", ["causes", "exposes", "has", "refers_to"])
def test_incremental_reveal_appears_when_last_trusted_premise_arrives(missing):
    graph = reveal_graph({"causes": Context.ACCEPTED, "refers_to": Context.ACCEPTED})
    partial = QdlGraph(
        facts=tuple(f for f in graph.facts if f.predicate.name != missing)
    )
    planner = IncrementalQdlPlanner()
    assert planner.plan(partial).reveal_edges == ()
    plan = planner.plan(graph)
    fresh = QdlPlanner().plan(graph)
    assert len(plan.reveal_edges) == 1
    assert plan.reveal_edges == fresh.reveal_edges
    assert plan.attack_paths == fresh.attack_paths
    assert planner.grounded_batches == 1


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize("creator", [Context.CONTRACT, Context.ACCEPTED])
def test_mixed_reveal_uses_the_common_causal_path(planner_type, creator):
    observer = Context.ACCEPTED if creator == Context.CONTRACT else Context.CONTRACT
    graph = reveal_graph(
        {
            "causes": creator,
            "exposes": observer,
            "has": observer,
            "refers_to": observer,
        },
        redeclare=True,
    )
    for source in (graph, planner_view(graph)):
        plan = planner_type().plan(source)
        assert [
            (edge.create_action, edge.observe_action) for edge in plan.reveal_edges
        ] == [
            ("action:create", "action:read"),
        ]
        assert [path.actions for path in plan.attack_paths] == [
            ("action:create", "action:read")
        ]
    for untrusted in (Context.PROPOSAL, Context.RUNTIME, Context.REPORT):
        parked = QdlGraph(
            facts=tuple(
                f.model_copy(update={"context": untrusted})
                for f in graph.facts
                if f.context != Context.ACCEPTED or f.predicate.name != "is"
            )
        )
        plan = planner_type().plan(parked)
        assert plan.reveal_edges == ()
        assert plan.attack_paths == ()


@pytest.mark.parametrize("planner_type", [QdlPlanner, IncrementalQdlPlanner])
@pytest.mark.parametrize(
    "contexts", [(Context.CONTRACT, Context.ACCEPTED), (Context.ACCEPTED,)]
)
def test_accepted_walk_preserves_contract_reveal_provenance(planner_type, contexts):
    graph = reveal_graph({})
    effect = changed(Atom(value="widget"), Atom(value="value"))
    graph = QdlGraph(
        facts=(
            *graph.facts,
            fact("is", Atom(value="action:consume"), Atom(value="Action")),
            fact("is", effect, Atom(value="Effect")),
            fact("causes", Atom(value="action:read"), effect, context=Context.ACCEPTED),
            fact(
                "requires",
                Atom(value="action:consume"),
                effect,
                context=Context.ACCEPTED,
            ),
        )
    )
    for source in (graph, planner_view(graph)):
        plan = planner_type(contexts=contexts).plan(source)
        path = next(
            p
            for p in plan.attack_paths
            if p.actions == ("action:create", "action:read", "action:consume")
        )
        assert path.context == Context.ACCEPTED
        assert path.edge_effects == ((), (effect,))
        assert all(edge.context in contexts for edge in plan.reveal_edges)
