from __future__ import annotations

import logging

import pytest

from cloud_dast.config import QDL_MAX_DEPTH
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Variable,
    allowed,
    changed,
    create,
    output_field,
    output_header,
    reached,
)
from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
    resource_state_machine_graph,
    state_machine_graph,
)
from cloud_dast.runtime.planning import (
    IncrementalQdlPlanner,
    QdlPlanner,
    QdlRevealEdge,
    QdlSubgoal,
    derivable,
    derive_requirements,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)


def test_derivable_contexts_filter_intensional_reaches_and_may() -> None:
    """Proposal-only derivations cannot satisfy a contract subgoal."""

    source = Atom(value="input:query")
    target = Atom(value="sink:sql")
    principal = Atom(value="principal:alice")
    action = Atom(value="action:read")
    resource = Atom(value="resource:orders")
    graph = QdlGraph(
        facts=(
            entity("input:query", "Field", Context.PROPOSAL),
            entity("field:normalized", "Field", Context.PROPOSAL),
            entity("sink:sql", "interpreter", Context.PROPOSAL),
            entity("principal:alice", "Principal", Context.PROPOSAL),
            entity("action:read", "Action", Context.PROPOSAL),
            entity("resource:orders", "Resource", Context.PROPOSAL),
            fact("part", (source, target), Context.PROPOSAL),
            fact("may", (principal, action, resource), Context.PROPOSAL),
        ),
        rules=(
            Rule(
                body=(
                    fact(
                        "part",
                        (Variable(name="Source"), Variable(name="Target")),
                        Context.PROPOSAL,
                    ),
                ),
                head=(
                    fact(
                        "reaches",
                        (Variable(name="Source"), Variable(name="Target")),
                        Context.PROPOSAL,
                    ),
                ),
            ),
        ),
    )

    assert not derivable(
        QdlSubgoal("reaches", (source, target)),
        graph,
        contexts=(Context.CONTRACT,),
    )
    assert derivable(
        QdlSubgoal("reaches", (source, target)),
        graph,
        contexts=(Context.PROPOSAL,),
    )
    assert not derivable(
        QdlSubgoal("may", (principal, action, resource)),
        graph,
        contexts=(Context.CONTRACT,),
    )


def fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    schema = next(
        (schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == predicate),
        None,
    )
    return Fact(
        context=context,
        predicate=Predicate.from_schema(schema)
        if schema
        else Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def entity(identifier: str, type_name: str, context: Context) -> Fact:
    return fact(
        "is",
        (Atom(value=identifier), Atom(value=type_name)),
        context,
    )


def make_attack_graph() -> QdlGraph:
    child = Atom(value="resource:child")
    parent = Atom(value="resource:parent")
    create = Atom(value="action:create")
    use = Atom(value="action:use")
    escalate = Atom(value="action:escalate")
    role_change = changed(child, Atom(value="role"))
    owner_change = changed(parent, Atom(value="owner"))

    return QdlGraph(
        facts=(
            entity("resource:child", "Resource", Context.CONTRACT),
            entity("resource:parent", "Resource", Context.CONTRACT),
            entity("action:create", "Action", Context.CONTRACT),
            entity("action:use", "Action", Context.CONTRACT),
            entity("action:escalate", "Action", Context.CONTRACT),
            fact("is", (role_change, Atom(value="Effect"))),
            fact("is", (owner_change, Atom(value="Effect"))),
            fact("causes", (create, role_change)),
            fact("requires", (use, role_change)),
            fact("causes", (use, owner_change)),
            fact("requires", (escalate, owner_change)),
        )
    )


def make_state_machine_graph() -> QdlGraph:
    return state_machine_graph(
        states=("created", "approved", "shipped"),
        actions=("approve", "ship"),
        norms=("no_ship_without_approval",),
        initial_states=("created",),
        transitions=(
            ("approve", "created", "approved"),
            ("ship", "approved", "shipped"),
        ),
        forbidden_states=(("no_ship_without_approval", "shipped"),),
    )


def make_resource_state_graph(*, with_pay_precondition: bool = True) -> QdlGraph:
    graph = resource_state_machine_graph(
        resource_states={"order": "new"},
        resource_transitions=(
            ("Create", "order", "new", "created"),
            ("Pay", "order", "created", "paid"),
        ),
    )
    if with_pay_precondition:
        return graph

    return QdlGraph(
        facts=tuple(
            fact
            for fact in graph.facts
            if not (
                fact.predicate.name == "precondition" and fact.args[0].value == "Pay"
            )
        )
    )


def make_long_state_machine_graph(edge_count: int) -> QdlGraph:
    states = tuple(f"state-{index}" for index in range(edge_count + 1))
    actions = tuple(f"advance_{index}" for index in range(edge_count))
    transitions = tuple(
        (f"advance_{index}", f"state-{index}", f"state-{index + 1}")
        for index in range(edge_count)
    )
    return state_machine_graph(
        states=states,
        actions=actions,
        norms=("forbid_final_state",),
        initial_states=("state-0",),
        transitions=transitions,
        forbidden_states=(("forbid_final_state", f"state-{edge_count}"),),
    )


def make_two_route_state_graph() -> QdlGraph:
    return state_machine_graph(
        states=("created", "left", "right", "done"),
        actions=("go_left", "go_right", "finish"),
        norms=("no_unauthorized_done",),
        initial_states=("created",),
        transitions=(
            ("go_left", "created", "left"),
            ("go_right", "created", "right"),
            ("finish", "left", "done"),
            ("finish", "right", "done"),
        ),
        forbidden_states=(("no_unauthorized_done", "done"),),
    )


def make_part_graph() -> QdlGraph:
    return QdlGraph(
        facts=(
            entity("resource:grandchild", "Resource", Context.CONTRACT),
            entity("resource:child", "Resource", Context.CONTRACT),
            entity("resource:parent", "Resource", Context.CONTRACT),
            fact(
                "part",
                (
                    Atom(value="resource:grandchild"),
                    Atom(value="resource:child"),
                ),
            ),
            fact(
                "part",
                (
                    Atom(value="resource:child"),
                    Atom(value="resource:parent"),
                ),
            ),
        )
    )


def make_reveal_graph() -> QdlGraph:
    create_action = Atom(value="action:create")
    observe_action = Atom(value="action:read")
    resource_type = Atom(value="widget")
    witness = output_field(observe_action, Atom(value="id"))
    return QdlGraph(
        facts=(
            entity("action:create", "Action", Context.CONTRACT),
            entity("action:read", "Action", Context.CONTRACT),
            entity("widget", "ResourceType", Context.CONTRACT),
            fact("is", (witness, Atom(value="OutputField"))),
            fact("causes", (create_action, create(resource_type))),
            fact("exposes", (observe_action, witness)),
            fact("has", (witness, Atom(value="object_ref"))),
            fact("refers_to", (witness, resource_type)),
        )
    )


def test_planner_derives_reveal_edge_from_qdl_facts() -> None:
    plan = QdlPlanner().plan(make_reveal_graph())

    assert plan.reveal_edges == (
        QdlRevealEdge(
            context=Context.CONTRACT,
            create_action="action:create",
            observe_action="action:read",
            resource_type="widget",
            witness=output_field(
                Atom(value="action:read"),
                Atom(value="id"),
            ),
        ),
    )
    assert ("action:create", "action:read") in {
        path.actions for path in plan.attack_paths
    }


def test_planner_derives_http_header_reveal_edge() -> None:
    action = Atom(value="action:create")
    resource_type = Atom(value="widget")
    witness = output_header(action, Atom(value="location"))
    graph = QdlGraph(
        facts=(
            entity("action:create", "Action", Context.CONTRACT),
            entity("widget", "ResourceType", Context.CONTRACT),
            fact("is", (witness, Atom(value="OutputField"))),
            fact("causes", (action, create(resource_type))),
            fact("exposes", (action, witness)),
            fact("has", (witness, Atom(value="object_ref"))),
            fact("refers_to", (witness, resource_type)),
        )
    )

    plan = QdlPlanner().plan(graph)

    assert plan.reveal_edges[0].witness == witness


def test_planner_finds_attack_chain_through_causes_and_requires() -> None:
    plan = QdlPlanner().plan(make_attack_graph())

    assert ("action:create", "action:use", "action:escalate") in {
        path.actions for path in plan.attack_paths
    }
    assert all(path.context is Context.CONTRACT for path in plan.attack_paths)


def test_planner_preserves_attack_edge_effects() -> None:
    plan = QdlPlanner().plan(make_attack_graph())
    path = next(
        path
        for path in plan.attack_paths
        if path.actions == ("action:create", "action:use", "action:escalate")
    )
    role_change = changed(
        Atom(value="resource:child"),
        Atom(value="role"),
    )
    owner_change = changed(
        Atom(value="resource:parent"),
        Atom(value="owner"),
    )

    assert path.edge_effects == ((role_change,), (owner_change,))


def test_planner_finds_state_machine_path() -> None:
    plan = QdlPlanner().plan(make_state_machine_graph())

    path = next(
        path
        for path in plan.state_paths
        if path.final_state == "shipped" and path.actions
    )
    assert path.context is Context.CONTRACT
    assert path.initial_state == "created"
    assert path.actions == ("approve", "ship")
    assert path.depth == 2


def test_planner_finds_resource_state_create_pay_chain() -> None:
    plan = QdlPlanner().plan(make_resource_state_graph())

    path = next(
        path
        for path in plan.resource_state_paths
        if path.resource == "order" and path.final_state == "paid"
    )

    assert path.actions == ("Create", "Pay")
    assert path.states == ("new", "created", "paid")
    assert path.depth == 2


def test_resource_path_selects_by_effect_and_precondition() -> None:
    graph = make_resource_state_graph()
    paths = StateMachineEngine().find_resource_paths(graph, "order", "paid")
    assert len(paths) == 1
    assert paths[0].actions == ("Create", "Pay")
    assert paths[0].states == ("new", "created", "paid")


def test_unreachable_resource_has_no_path_despite_another_resource_reaching_state() -> (
    None
):
    graph = make_resource_graph_with_reachable_invoice()
    engine = StateMachineEngine()
    solution = engine.solve_resources(graph)
    assert solution.states["order"] == ("new",)
    assert "paid" in solution.states["invoice"]
    assert engine.find_resource_paths(graph, "order", "paid") == ()


def test_resource_paths_respect_transition_preconditions() -> None:
    graph = make_resource_state_graph(with_pay_precondition=False)
    engine = StateMachineEngine()
    assert engine.solve_resources(graph).states["order"] == ("created", "new")
    assert engine.find_resource_paths(graph, "order", "paid") == ()


def make_resource_graph_with_reachable_invoice() -> QdlGraph:
    return resource_state_machine_graph(
        resource_states={"order": "new", "invoice": "issued"},
        resource_transitions=(
            ("Create", "invoice", "issued", "created"),
            ("Pay", "invoice", "created", "paid"),
        ),
    )


def test_planners_use_configured_default_depth() -> None:
    graph = make_long_state_machine_graph(QDL_MAX_DEPTH + 1)
    final_state = f"state-{QDL_MAX_DEPTH + 1}"

    one_shot = QdlPlanner().plan(graph)
    incremental = IncrementalQdlPlanner().plan(graph)

    assert one_shot == incremental
    assert all(path.depth <= QDL_MAX_DEPTH for path in one_shot.state_paths)
    assert all(
        forbidden.path.depth <= QDL_MAX_DEPTH for forbidden in one_shot.forbidden_paths
    )
    assert not any(path.final_state == final_state for path in one_shot.state_paths)
    assert not any(
        forbidden.path.final_state == final_state
        for forbidden in one_shot.forbidden_paths
    )


def test_planner_finds_forbidden_state_path() -> None:
    plan = QdlPlanner().plan(make_state_machine_graph())

    assert len(plan.forbidden_paths) == 1
    forbidden = plan.forbidden_paths[0]
    assert forbidden.norm == "no_ship_without_approval"
    assert forbidden.path.context is Context.CONTRACT
    assert forbidden.path.initial_state == "created"
    assert forbidden.path.final_state == "shipped"
    assert forbidden.path.actions == ("approve", "ship")


def test_planner_preserves_both_bounded_state_witnesses() -> None:
    plan = QdlPlanner().plan(make_two_route_state_graph())

    state_routes = {
        path.actions for path in plan.state_paths if path.final_state == "done"
    }
    forbidden_routes = {
        forbidden.path.actions
        for forbidden in plan.forbidden_paths
        if forbidden.norm == "no_unauthorized_done"
    }

    assert state_routes == {("go_left", "finish"), ("go_right", "finish")}
    assert forbidden_routes == state_routes
    assert (
        len({path.path_id for path in plan.state_paths if path.final_state == "done"})
        == 2
    )
    assert len({path.path_id for path in plan.forbidden_paths}) == 2


def test_planner_materializes_requested_closure() -> None:
    plan = QdlPlanner(closure_relations=("part_plus",)).plan(make_part_graph())

    assert (
        "resource:grandchild",
        "resource:parent",
    ) in {
        (closure.source, closure.target)
        for closure in plan.closures
        if closure.relation == "part_plus"
    }
    assert plan.attack_paths == ()


def test_planner_compiles_accepted_invariant() -> None:
    action = Atom(value="action:escalate")
    norm = Atom(value="norm:no_escalation")
    effect = allowed(action)
    graph = QdlGraph(
        facts=(
            entity("action:escalate", "Action", Context.ACCEPTED),
            entity("norm:no_escalation", "Norm", Context.ACCEPTED),
            fact(
                "prevents",
                (norm, effect),
                Context.ACCEPTED,
            ),
        )
    )

    plan = QdlPlanner().plan(graph)

    assert len(plan.invariants) == 1
    invariant = plan.invariants[0]
    assert invariant.norm == "norm:no_escalation"
    assert invariant.effect == effect
    assert invariant.primitive == "outcome"
    assert invariant.required_evidence == ("observed_outcome", "expected_outcome")
    assert invariant.verdict_policy == "deterministic"
    assert invariant.fact.context is Context.ACCEPTED


def test_planner_does_not_promote_proposal_paths() -> None:
    child = Atom(value="resource:child")
    create = Atom(value="action:create")
    use = Atom(value="action:use")
    role_change = changed(child, Atom(value="role"))
    graph = QdlGraph(
        facts=(
            entity("resource:child", "Resource", Context.PROPOSAL),
            entity("action:create", "Action", Context.PROPOSAL),
            entity("action:use", "Action", Context.PROPOSAL),
            fact("is", (role_change, Atom(value="Effect")), Context.PROPOSAL),
            fact("causes", (create, role_change), Context.PROPOSAL),
            fact("requires", (use, role_change), Context.PROPOSAL),
        )
    )

    plan = QdlPlanner().plan(graph)

    assert plan.attack_paths == ()
    assert plan.closures == ()
    assert plan.bound_paths == ()


def test_planner_does_not_promote_runtime_state_paths() -> None:
    graph = state_machine_graph(
        states=("created", "approved"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(("approve", "created", "approved"),),
        context=Context.RUNTIME,
        observed_context=Context.RUNTIME,
    )

    plan = QdlPlanner().plan(graph)

    assert plan.state_paths == ()
    assert plan.forbidden_paths == ()
    assert plan.bound_paths == ()


def test_planner_returns_no_paths_for_disconnected_actions() -> None:
    graph = QdlGraph(
        facts=(
            entity("action:first", "Action", Context.CONTRACT),
            entity("action:second", "Action", Context.CONTRACT),
        )
    )

    plan = QdlPlanner().plan(graph)

    assert plan.attack_paths == ()
    assert plan.state_paths == ()
    assert plan.forbidden_paths == ()
    assert plan.bound_paths == ()
    assert plan.closures == ()


def test_planner_rejects_invalid_depth_and_unknown_closure() -> None:
    with pytest.raises(ValueError, match="max_depth must be positive"):
        QdlPlanner(max_depth=0)
    with pytest.raises(ValueError, match="unknown closure predicate"):
        QdlPlanner(closure_relations=("path_plus",))


def test_incremental_planner_matches_one_shot_plan() -> None:
    one_shot = QdlPlanner()
    incremental = IncrementalQdlPlanner()
    graph = make_attack_graph()

    one_shot_plan = one_shot.plan(graph)
    incremental_plan = incremental.plan(graph)

    assert one_shot_plan.graph_hash == incremental_plan.graph_hash
    assert [p.path_id for p in one_shot_plan.attack_paths] == [
        p.path_id for p in incremental_plan.attack_paths
    ]
    assert [p.edge_effects for p in one_shot_plan.attack_paths] == [
        p.edge_effects for p in incremental_plan.attack_paths
    ]
    assert [i.norm for i in one_shot_plan.invariants] == [
        i.norm for i in incremental_plan.invariants
    ]
    assert [c.relation for c in one_shot_plan.closures] == [
        c.relation for c in incremental_plan.closures
    ]


def test_incremental_planner_grounds_only_new_facts() -> None:
    planner = IncrementalQdlPlanner()
    base = make_attack_graph()
    planner.plan(base)
    assert planner.grounded_batches == 0

    # Re-planning the same graph grounds nothing new.
    planner.plan(base)
    assert planner.grounded_batches == 0

    # An accepted norm arrives with the next batch.
    delete = Atom(value="action:escalate")
    norm = Atom(value="norm:no-escalation")
    extended = QdlGraph(
        facts=(
            *base.facts,
            fact("is", (norm, Atom(value="Norm"))),
            fact("prevents", (norm, allowed(delete)), Context.ACCEPTED),
        )
    )
    plan = planner.plan(extended)

    assert planner.grounded_batches == 1
    assert [invariant.norm for invariant in plan.invariants] == ["norm:no-escalation"]
    # Base facts and rules remain grounded exactly once.
    planner.plan(extended)
    assert planner.grounded_batches == 1


def test_incremental_planner_rebuilds_on_non_monotonic_rebind() -> None:
    planner = IncrementalQdlPlanner()
    base = QdlGraph(
        facts=(
            entity("action:first", "Action", Context.CONTRACT),
            entity("action:second", "Action", Context.CONTRACT),
        )
    )
    planner.plan(base)

    # A rebind drops one action (for example an accepted-batch revision
    # replaced the batch that declared it).  The planner must not abort the
    # campaign: it rebuilds over the current graph and keeps planning.
    shrink = QdlGraph(facts=(entity("action:first", "Action", Context.CONTRACT),))
    plan = planner.plan(shrink)

    assert plan.graph_hash == shrink.content_hash
    assert planner.grounded_batches == 0
    assert {invariant.norm for invariant in plan.invariants} == set()

    # The rebuilt control still accepts subsequent monotonic extensions.
    grow = QdlGraph(
        facts=(
            entity("action:first", "Action", Context.CONTRACT),
            entity("action:third", "Action", Context.CONTRACT),
        )
    )
    grown_plan = planner.plan(grow)
    assert planner.grounded_batches == 1
    assert grown_plan.graph_hash == grow.content_hash


def test_incremental_planner_keeps_append_only_diff_rebind_monotonic(
    tmp_path,
    caplog,
) -> None:
    action = Atom(value="action:get")
    old_sink = Atom(value="sink:sql")
    new_sink = Atom(value="sink:template")
    old_effect = reached(action, old_sink)
    new_effect = reached(action, new_sink)

    def reached_graph(sink: Atom, effect: Struct) -> QdlGraph:
        return QdlGraph(
            facts=(
                fact("is", (action, Atom(value="Action")), Context.RUNTIME),
                fact("is", (sink, Atom(value="Sink")), Context.RUNTIME),
                fact("is", (effect, Atom(value="Effect")), Context.RUNTIME),
            )
        )

    tombstone = QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action")), Context.RUNTIME),
            fact("is", (old_sink, Atom(value="Sink")), Context.RUNTIME),
            fact("is", (new_sink, Atom(value="Sink")), Context.RUNTIME),
            fact("is", (old_effect, Atom(value="Effect")), Context.RUNTIME),
            fact("is", (new_effect, Atom(value="Effect")), Context.RUNTIME),
            fact("supersedes", (new_effect, old_effect), Context.RUNTIME),
        )
    )
    source_id = "diff:orders:campaign:runtime"

    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        repository.save(
            source_id,
            reached_graph(old_sink, old_effect),
            provenance={"source_kind": "test", "revision": "1"},
            adapter_version="test-v1",
            mapping_report={"mapped": 3, "unmapped": 0},
        )
        planner = IncrementalQdlPlanner()
        with caplog.at_level(logging.WARNING, logger="cloud_dast.workflow.planner"):
            planner.plan(repository.load_merged("diff:orders:"))

            repository.save(
                source_id,
                reached_graph(new_sink, new_effect),
                provenance={"source_kind": "test", "revision": "2"},
                adapter_version="test-v1",
                mapping_report={"mapped": 3, "unmapped": 0},
            )
            planner.plan(repository.load_merged("diff:orders:"))

            repository.save(
                source_id,
                tombstone,
                provenance={"source_kind": "test", "revision": "3"},
                adapter_version="test-v1",
                mapping_report={"mapped": 6, "unmapped": 0},
            )
            final_plan = planner.plan(repository.load_merged("diff:orders:"))
            final_graph = repository.load_merged("diff:orders:")

    assert final_plan.graph_hash == final_graph.content_hash
    assert planner.grounded_batches == 2
    assert "qdl_planner_non_monotonic_rebuild" not in caplog.text


def test_incremental_planner_keeps_accepted_batch_revisions_monotonic(
    tmp_path,
    caplog,
) -> None:
    action = Atom(value="action:get")
    holder = output_field(action, Atom(value="token"))
    old_role = Atom(value="object_ref")
    new_role = Atom(value="identifier")
    old_node = Struct(name="replacement", args=(holder, old_role))
    new_node = Struct(name="replacement", args=(holder, new_role))

    def declarations(*roles: Atom, nodes: tuple[Struct, ...] = ()) -> tuple[Fact, ...]:
        return (
            fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
            fact("is", (holder, Atom(value="Field")), Context.ACCEPTED),
            *(
                fact("is", (role, Atom(value="Role")), Context.ACCEPTED)
                for role in roles
            ),
            *(
                fact("is", (node, Atom(value="Node")), Context.ACCEPTED)
                for node in nodes
            ),
        )

    first = QdlGraph(
        facts=(
            *declarations(old_role, nodes=(old_node,)),
            fact("has", (holder, old_role), Context.ACCEPTED),
        )
    )
    second = QdlGraph(
        facts=(
            *declarations(old_role, new_role, nodes=(old_node, new_node)),
            fact("has", (holder, new_role), Context.ACCEPTED),
            fact("supersedes", (new_node, old_node), Context.ACCEPTED),
        )
    )

    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        repository.save(
            f"accepted-batch:orders:reactive:roles:action:get:{first.content_hash}",
            first,
            provenance={"source_kind": "test"},
            adapter_version="test-v1",
            mapping_report={"mapped": len(first.facts), "unmapped": 0},
        )
        planner = IncrementalQdlPlanner()
        with caplog.at_level(logging.WARNING, logger="cloud_dast.workflow.planner"):
            planner.plan(repository.load_merged("accepted-batch:orders:"))
            repository.save(
                f"accepted-batch:orders:reactive:roles:action:get:{second.content_hash}",
                second,
                provenance={"source_kind": "test"},
                adapter_version="test-v1",
                mapping_report={"mapped": len(second.facts), "unmapped": 0},
            )
            final_graph = repository.load_merged("accepted-batch:orders:")
            final_plan = planner.plan(final_graph)

    assert final_plan.graph_hash == final_graph.content_hash
    assert planner.grounded_batches == 1
    assert "qdl_planner_non_monotonic_rebuild" not in caplog.text
    assert {
        fact.args[1].value for fact in final_graph.facts if fact.predicate.name == "has"
    } == {"object_ref", "identifier"}


def test_planner_excludes_superseded_reached_effect_edge() -> None:
    create_action = Atom(value="action:create")
    use_action = Atom(value="action:use")
    old_sink = Atom(value="sink:sql")
    new_sink = Atom(value="sink:template")
    old_effect = reached(create_action, old_sink)
    new_effect = reached(create_action, new_sink)
    graph = QdlGraph(
        facts=(
            entity("action:create", "Action", Context.ACCEPTED),
            entity("action:use", "Action", Context.ACCEPTED),
            entity("sink:sql", "Sink", Context.ACCEPTED),
            entity("sink:template", "Sink", Context.ACCEPTED),
            fact("is", (old_effect, Atom(value="Effect")), Context.ACCEPTED),
            fact("is", (new_effect, Atom(value="Effect")), Context.ACCEPTED),
            fact("causes", (create_action, old_effect), Context.ACCEPTED),
            fact("requires", (use_action, old_effect), Context.ACCEPTED),
            fact("supersedes", (new_effect, old_effect), Context.ACCEPTED),
        )
    )

    plan = QdlPlanner().plan(graph)

    assert not any(
        path.actions == ("action:create", "action:use") for path in plan.attack_paths
    )


def test_incremental_planner_preserves_existing_ids_when_new_edges_arrive() -> None:
    planner = IncrementalQdlPlanner()
    base = make_attack_graph()
    first = planner.plan(base)
    first_ids = {path.path_id for path in first.attack_paths}
    assert len(first_ids) == 3

    # A new route changes the graph snapshot and adds structural paths without
    # changing the identities of existing routes.
    create = Atom(value="action:create")
    escalate = Atom(value="action:escalate")
    shortcut = changed(Atom(value="resource:child"), Atom(value="owner"))
    extended = QdlGraph(
        facts=(
            *base.facts,
            # An LLM dataflow batch declares its own action entities and
            # edges in the accepted context.
            fact("is", (create, Atom(value="Action")), Context.ACCEPTED),
            fact("is", (escalate, Atom(value="Action")), Context.ACCEPTED),
            fact("is", (shortcut, Atom(value="Effect"))),
            fact("causes", (create, shortcut), Context.ACCEPTED),
            fact("requires", (escalate, shortcut), Context.ACCEPTED),
        )
    )
    second = planner.plan(extended)

    assert planner.grounded_batches == 1
    second_ids = {path.path_id for path in second.attack_paths}
    assert first_ids < second_ids
    assert first.graph_hash != second.graph_hash
    assert any(
        path.actions == ("action:create", "action:escalate")
        for path in second.attack_paths
    )


def test_materialized_requirements_keep_rule_proofs_and_contexts():
    action, permitted, untrusted = (
        Atom(value=value) for value in ("action:a", "permission:p", "permission:q")
    )
    expected = fact("requires", (action, permitted), Context.ACCEPTED)
    graph = QdlGraph(
        facts=(
            entity("action:a", "Action", Context.ACCEPTED),
            entity("permission:p", "Permission", Context.ACCEPTED),
            entity("permission:q", "Permission", Context.PROPOSAL),
            fact("requires", (action, untrusted), Context.PROPOSAL),
        ),
        rules=(
            Rule(
                head=(expected,), body=(entity("action:a", "Action", Context.ACCEPTED),)
            ),
        ),
    )
    assert derive_requirements(graph, contexts=(Context.ACCEPTED,)) == (expected.args,)
    assert derivable(
        QdlSubgoal("requires", (Atom(value="a"), permitted)),
        graph,
        contexts=(Context.ACCEPTED,),
    )
    assert not derivable(
        QdlSubgoal("requires", (action, untrusted)), graph, contexts=(Context.ACCEPTED,)
    )


def test_requirement_materialization_keeps_direct_proof_on_solver_failure():
    class FailedEngine:
        def solve(self, graph):
            raise RuntimeError("solver could not complete")

    action, direct, absent = (
        Atom(value=value) for value in ("action:a", "permission:p", "permission:q")
    )
    expected = fact("requires", (action, direct), Context.CONTRACT)
    graph = QdlGraph(
        facts=(
            entity("action:a", "Action", Context.CONTRACT),
            entity("permission:p", "Permission", Context.CONTRACT),
            entity("permission:q", "Permission", Context.CONTRACT),
            expected,
        )
    )
    assert derive_requirements(graph, engine=FailedEngine()) == (expected.args,)
    assert derivable(
        QdlSubgoal("requires", (action, direct)), graph, engine=FailedEngine()
    )
    assert not derivable(
        QdlSubgoal("requires", (action, absent)), graph, engine=FailedEngine()
    )


def test_requirement_query_keeps_intensional_data_literals():
    from cloud_dast.runtime.resource_projection import (
        required_states,
    )

    action, ready = Atom(value="action:a"), Atom(value="state:ready")
    value = Variable(name="Value")
    graph = QdlGraph(
        facts=(
            entity("action:a", "Action", Context.CONTRACT),
            entity("state:ready", "State", Context.CONTRACT),
            fact("has", (action, Atom(value="")), Context.CONTRACT),
            fact("requires", (action, ready), Context.CONTRACT),
        ),
        rules=(
            Rule(
                head=(fact("requires", (action, value), Context.CONTRACT),),
                body=(fact("has", (action, value), Context.CONTRACT),),
            ),
        ),
    )
    rows = derive_requirements(graph, contexts=(Context.CONTRACT,))
    assert (action, Atom(value="")) in rows
    assert derivable(QdlSubgoal("requires", (action, Atom(value=""))), graph)
    assert required_states(graph, "a", "resource", requirement_rows=rows) == (
        "state:ready",
    )


@pytest.mark.parametrize("max_depth", [1, 3])
@pytest.mark.parametrize(
    "contexts",
    [
        (Context.CONTRACT, Context.ACCEPTED),
        (Context.ACCEPTED, Context.CONTRACT),
        (Context.ACCEPTED,),
    ],
)
@pytest.mark.parametrize("closures", [("chain_plus",), ("part_plus", "chain_plus")])
def test_cached_plans_match_complete_fresh_projection_across_revisions(
    max_depth, contexts, closures
) -> None:
    options = dict(max_depth=max_depth, contexts=contexts, closure_relations=closures)
    cached = IncrementalQdlPlanner(**options)
    base = make_attack_graph()
    extended = QdlGraph(
        facts=(
            *base.facts,
            fact(
                "part",
                (Atom(value="resource:child"), Atom(value="resource:parent")),
                Context.CONTRACT,
            ),
        ),
    )
    reordered = QdlGraph(facts=tuple(reversed(extended.facts)))

    for graph in (base, extended, reordered, base, QdlGraph(), extended):
        assert cached.plan(graph) == QdlPlanner(**options).plan(graph)
