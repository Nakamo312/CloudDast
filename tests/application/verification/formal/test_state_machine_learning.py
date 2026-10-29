from __future__ import annotations

from cloud_dast.extensions import (
    LEARNED_TRANSITION_CONFLICT,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
    StateMachineLearningMismatch,
    state_machine_graph,
)


def _learned_proposal(
    *,
    action: str,
    from_state: str,
    to_state: str,
    forbidden_states: tuple[tuple[str, str], ...] = (),
) -> QdlGraph:
    return QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=action), Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=from_state), Atom(value="State")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=to_state), Atom(value="State")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("initial"),
                args=(Atom(value=from_state),),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("transition"),
                args=(
                    Atom(value=action),
                    Atom(value=from_state),
                    Atom(value=to_state),
                ),
            ),
            *(
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("is"),
                    args=(Atom(value=norm_id), Atom(value="Norm")),
                )
                for norm_id, _state in forbidden_states
            ),
            *(
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("forbidden"),
                    args=(Atom(value=norm_id), Atom(value=state)),
                )
                for norm_id, state in forbidden_states
            ),
        )
    )


def test_conflicting_transition_becomes_mismatch_not_overwrite() -> None:
    specification = state_machine_graph(
        states=("start", "declared-target"),
        actions=("a",),
        initial_states=("start",),
        transitions=(("a", "start", "declared-target"),),
    )
    learned = _learned_proposal(
        action="a",
        from_state="start",
        to_state="learned-target",
    )
    graph = merge_graphs(specification, learned)

    review = StateMachineEngine().review_learned_transitions(graph)

    assert review.mismatches == (
        StateMachineLearningMismatch(
            action="a",
            from_state="start",
            learned_to_state="learned-target",
            declared_to_state="declared-target",
        ),
    )
    assert [(fact.args[0].value, fact.args[1].value) for fact in review.deficits] == [
        ("a", LEARNED_TRANSITION_CONFLICT)
    ]
    assert {
        (fact.args[0].value, fact.args[1].value, fact.args[2].value)
        for fact in graph.facts
        if fact.predicate.name == "transition"
    } == {
        ("a", "start", "declared-target"),
        ("a", "start", "learned-target"),
    }


def test_matching_learned_transition_has_no_conflict() -> None:
    specification = state_machine_graph(
        states=("start", "target"),
        actions=("a",),
        initial_states=("start",),
        transitions=(("a", "start", "target"),),
    )
    learned = _learned_proposal(action="a", from_state="start", to_state="target")

    review = StateMachineEngine().review_learned_transitions(
        merge_graphs(specification, learned)
    )

    assert review.mismatches == ()
    assert review.deficits == ()


def test_state_machine_engine_remains_only_verifier() -> None:
    specification = state_machine_graph(
        states=("start", "forbidden-state"),
        actions=("a",),
        norms=("norm:no-forbidden-state",),
        initial_states=("start",),
        forbidden_states=(("norm:no-forbidden-state", "forbidden-state"),),
    )
    learned = _learned_proposal(
        action="a",
        from_state="start",
        to_state="forbidden-state",
        forbidden_states=(("norm:no-forbidden-state", "forbidden-state"),),
    )

    solution = StateMachineEngine().solve(
        merge_graphs(specification, learned),
        context=Context.PROPOSAL,
    )

    assert solution.reachable_states == ("forbidden-state", "start")
    assert len(solution.violations) == 1
    assert solution.violations[0].grounded is False
    assert solution.grounded_violations == ()
    assert all(fact.context is Context.PROPOSAL for fact in learned.facts)
