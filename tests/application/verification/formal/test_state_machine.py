from __future__ import annotations

import pytest

from cloud_dast.config import QDL_MAX_DEPTH
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.state_machine import (
    ResourceTransition,
    StateMachineEngine,
    StateMachineStatus,
    StateMachineViolation,
    StatePath,
    resource_state_machine_graph,
    state_machine_graph,
)


def make_graph():
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


def make_long_chain_graph(edge_count: int):
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


def make_ambiguous_graph():
    return state_machine_graph(
        states=("start", "left", "right", "done"),
        actions=("go_left", "go_right", "finish"),
        norms=("forbid_done",),
        initial_states=("start",),
        transitions=(
            ("go_left", "start", "left"),
            ("go_right", "start", "right"),
            ("finish", "left", "done"),
            ("finish", "right", "done"),
        ),
        forbidden_states=(("forbid_done", "done"),),
    )


def make_runtime_transition_graph(
    action: str,
    from_state: str,
    to_state: str,
) -> QdlGraph:
    """Build a runtime graph with idempotent observed_* aggregates."""

    return QdlGraph(
        facts=(
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=action), Atom(value="Action")),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=from_state), Atom(value="State")),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=to_state), Atom(value="State")),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("transition"),
                args=(
                    Atom(value=action),
                    Atom(value=from_state),
                    Atom(value=to_state),
                ),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("observed_transition"),
                args=(
                    Atom(value=action),
                    Atom(value=from_state),
                    Atom(value=to_state),
                ),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("observed_outcome"),
                args=(Atom(value=action), Atom(value="allowed")),
            ),
        )
    )


def make_resource_graph(*, with_pay_precondition: bool = True):
    transitions = (
        ("Create", "order", "new", "created"),
        ("Pay", "order", "created", "paid"),
    )
    graph = resource_state_machine_graph(
        resource_states={"order": "new"},
        resource_transitions=transitions,
    )
    if with_pay_precondition:
        return graph

    # Remove the Pay precondition without substituting another resource or
    # inventing a different transition.
    facts = tuple(
        fact
        for fact in graph.facts
        if not (fact.predicate.name == "precondition" and fact.args[0].value == "Pay")
    )
    return QdlGraph(facts=facts)


def test_state_machine_engine_finds_reachable_states() -> None:
    graph = state_machine_graph(
        states=("created", "approved", "archived"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(("approve", "created", "approved"),),
    )

    solution = StateMachineEngine().solve(graph)

    assert solution.reachable_states == ("approved", "created")
    assert "archived" not in solution.reachable_states


def test_state_machine_engine_finds_bounded_path_with_actions() -> None:
    path = StateMachineEngine().find_path(make_graph(), "shipped")

    assert path == StatePath(
        initial_state="created",
        final_state="shipped",
        actions=("approve", "ship"),
        depth=2,
    )


def test_state_machine_engine_returns_no_path_for_unreachable_state() -> None:
    graph = state_machine_graph(
        states=("created", "archived"),
        actions=(),
        initial_states=("created",),
    )

    assert StateMachineEngine().find_path(graph, "archived") is None


def test_state_machine_engine_finds_forbidden_state_reachability() -> None:
    solution = StateMachineEngine().solve(make_graph())

    assert len(solution.violations) == 1
    violation = solution.violations[0]
    assert violation.norm == "no_ship_without_approval"
    assert violation.state == "shipped"
    assert violation.path.initial_state == "created"
    assert violation.path.final_state == "shipped"
    assert violation.path.actions == ("approve", "ship")
    assert violation.path.depth == 2
    assert violation.grounded is False
    assert violation.evidence_refs == ()
    assert solution.grounded_violations == ()
    assert solution.status is StateMachineStatus.COMPLETE


def test_state_machine_engine_requires_evidence_for_grounded_violation() -> None:
    graph = state_machine_graph(
        states=("open", "archived"),
        actions=("action:orders.Close",),
        norms=("no_archive",),
        initial_states=("open",),
        forbidden_states=(("no_archive", "archived"),),
        observed_transitions=(("action:orders.Close", "unknown", "archived"),),
    )

    solution = StateMachineEngine().solve(graph)

    assert solution.grounded_violations == ()


def test_state_machine_engine_grounds_violation_from_runtime_evidence() -> None:
    specification = state_machine_graph(
        states=("open", "archived"),
        actions=("action:orders.Close",),
        norms=("no_archive",),
        initial_states=("open",),
        forbidden_states=(("no_archive", "archived"),),
    )
    runtime = make_runtime_transition_graph(
        "action:orders.Close",
        "open",
        "archived",
    )
    decoy = state_machine_graph(
        states=("open", "archived"),
        actions=("action:orders.Unrelated",),
        observed_transitions=(("action:orders.Unrelated", "open", "archived"),),
        context=Context.RUNTIME,
        observed_context=Context.RUNTIME,
    )

    solution = StateMachineEngine().solve(merge_graphs(specification, runtime, decoy))

    assert solution.grounded_violations == (
        StateMachineViolation(
            norm="no_archive",
            state="archived",
            path=StatePath(
                initial_state="open",
                final_state="archived",
                actions=("action:orders.Close",),
                depth=1,
            ),
            grounded=True,
            evidence_refs=(),
        ),
    )
    assert solution.grounded_violations[0].path.actions == ("action:orders.Close",)


def test_state_machine_engine_finds_stratified_mismatch() -> None:
    graph = state_machine_graph(
        states=("created", "approved", "shipped"),
        actions=("approve", "ship"),
        norms=(),
        initial_states=("created",),
        transitions=(
            ("approve", "created", "approved"),
            ("ship", "approved", "shipped"),
        ),
        observed_transitions=(
            ("approve", "created", "approved"),
            ("ship", "created", "shipped"),
        ),
    )

    mismatches = StateMachineEngine().mismatches(graph)

    assert len(mismatches) == 1
    assert mismatches[0].action == "ship"
    assert mismatches[0].from_state == "created"
    assert mismatches[0].to_state == "shipped"


def test_partial_transition_with_reachable_target_is_not_mismatch() -> None:
    graph = state_machine_graph(
        states=("open", "closed"),
        actions=("close",),
        norms=(),
        initial_states=("open",),
        transitions=(("close", "open", "closed"),),
        observed_transitions=(("close", "unknown", "closed"),),
    )

    assert StateMachineEngine().mismatches(graph) == ()


def test_partial_transition_with_unreachable_target_is_mismatch() -> None:
    graph = state_machine_graph(
        states=("open", "closed", "archived"),
        actions=("close",),
        norms=(),
        initial_states=("open",),
        transitions=(("close", "open", "closed"),),
        observed_transitions=(("close", "unknown", "archived"),),
    )

    mismatches = StateMachineEngine().mismatches(graph)

    assert [(item.action, item.from_state, item.to_state) for item in mismatches] == [
        ("close", "unknown", "archived")
    ]


def test_partial_transition_uses_reachability_not_action_edge() -> None:
    graph = state_machine_graph(
        states=("open", "warm", "archived"),
        actions=("close",),
        norms=(),
        initial_states=("open",),
        transitions=(("close", "warm", "archived"),),
        observed_transitions=(("close", "unknown", "archived"),),
    )

    mismatches = StateMachineEngine().mismatches(graph)

    assert [(item.action, item.from_state, item.to_state) for item in mismatches] == [
        ("close", "unknown", "archived")
    ]


def test_real_state_named_unknown_uses_exact_transition_semantics() -> None:
    graph = state_machine_graph(
        states=("unknown", "closed", "archived"),
        actions=("warm", "close"),
        norms=(),
        initial_states=("unknown",),
        transitions=(
            ("warm", "unknown", "closed"),
            ("close", "closed", "archived"),
        ),
        observed_transitions=(("close", "unknown", "archived"),),
    )

    mismatches = StateMachineEngine().mismatches(graph)

    assert [(item.action, item.from_state, item.to_state) for item in mismatches] == [
        ("close", "unknown", "archived")
    ]


def test_partial_transition_target_reachable_through_chain_is_not_mismatch() -> None:
    graph = state_machine_graph(
        states=("open", "warm", "archived"),
        actions=("warm", "close"),
        norms=(),
        initial_states=("open",),
        transitions=(
            ("warm", "open", "warm"),
            ("close", "warm", "archived"),
        ),
        observed_transitions=(("close", "unknown", "archived"),),
    )

    assert StateMachineEngine().mismatches(graph) == ()


def test_state_machine_engine_respects_max_depth() -> None:
    engine = StateMachineEngine(max_depth=1)
    graph = make_graph()

    solution = engine.solve(graph)
    path = engine.find_path(graph, "shipped")

    assert solution.reachable_states == ("approved", "created")
    assert solution.violations == ()
    assert path is None
    assert solution.status is StateMachineStatus.BOUNDED_INCOMPLETE


def test_state_machine_engine_uses_configured_default_depth() -> None:
    graph = make_long_chain_graph(QDL_MAX_DEPTH + 1)

    solution = StateMachineEngine().solve(graph)
    path = StateMachineEngine().find_path(graph, f"state-{QDL_MAX_DEPTH + 1}")

    assert solution.reachable_states == tuple(
        f"state-{index}" for index in range(QDL_MAX_DEPTH + 1)
    )
    assert solution.violations == ()
    assert path is None
    assert solution.status is StateMachineStatus.BOUNDED_INCOMPLETE


def test_state_machine_engine_reports_complete_when_bound_is_not_hit() -> None:
    graph = state_machine_graph(
        states=("created", "approved"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(("approve", "created", "approved"),),
    )

    solution = StateMachineEngine(max_depth=1).solve(graph)

    assert solution.status is StateMachineStatus.COMPLETE


def test_state_machine_engine_is_deterministic() -> None:
    engine = StateMachineEngine()
    graph = make_ambiguous_graph()

    first_paths = engine.find_paths(graph, "done")
    second_paths = engine.find_paths(graph, "done")
    first_solution = engine.solve(graph)
    second_solution = engine.solve(graph)

    assert (
        first_paths
        == second_paths
        == (
            StatePath("start", "done", ("go_left", "finish"), 2),
            StatePath("start", "done", ("go_right", "finish"), 2),
        )
    )
    assert first_solution == second_solution
    assert first_solution.violations[0].path.actions == ("go_left", "finish")


def test_state_machine_engine_rejects_invalid_depth() -> None:
    with pytest.raises(ValueError, match="max_depth must be positive"):
        StateMachineEngine(max_depth=0)


def test_resource_states_are_indexed_by_resource() -> None:
    graph = resource_state_machine_graph(
        resource_states={
            "order": "new",
            "invoice": "issued",
        },
        resource_transitions=(
            ("Create", "order", "new", "created"),
            ("Pay", "order", "created", "paid"),
            ("Settle", "invoice", "issued", "settled"),
        ),
    )

    solution = StateMachineEngine().solve_resources(graph)

    assert dict(solution.states) == {
        "order": ("created", "new", "paid"),
        "invoice": ("issued", "settled"),
    }


def test_resource_transition_requires_matching_precondition() -> None:
    graph = make_resource_graph(with_pay_precondition=False)

    solution = StateMachineEngine().solve_resources(graph)
    path = StateMachineEngine().find_resource_path(graph, "order", "paid")

    assert dict(solution.states) == {"order": ("created", "new")}
    assert solution.transitions == (
        ResourceTransition("Create", "order", "new", "created"),
    )
    assert path is None


def test_resource_state_path_preserves_create_pay_chain() -> None:
    graph = make_resource_graph()

    path = StateMachineEngine().find_resource_path(graph, "order", "paid")

    assert path is not None
    assert path.resource == "order"
    assert path.actions == ("Create", "Pay")
    assert path.states == ("new", "created", "paid")
    assert StateMachineEngine().solve_resources(graph).transitions == (
        ResourceTransition("Create", "order", "new", "created"),
        ResourceTransition("Pay", "order", "created", "paid"),
    )
