from __future__ import annotations

import pytest

from cloud_dast.extensions import (
    INSUFFICIENT_TRACE_EVIDENCE,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, Struct
from cloud_dast.qdl.state_machine import (
    state_machine_graph,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.verification.promotion import (
    ProposalPromotionRequest,
)
from cloud_dast_automata.learning import AALpyAutomataLearningAdapter


def _source(
    *,
    observed: tuple[tuple[str, str, str], ...],
    initial_state: str | None = "start",
    states: tuple[str, ...] = (),
    actions: tuple[str, ...] = (),
    forbidden_states: tuple[tuple[str, str], ...] = (),
) -> QdlGraph:
    observed_states = {
        state
        for action, from_state, to_state in observed
        for state in (from_state, to_state)
    }
    observed_actions = {action for action, _from_state, _to_state in observed}
    specification = state_machine_graph(
        states=(*observed_states, *states),
        actions=(*observed_actions, *actions),
        norms=(norm for norm, _state in forbidden_states),
        initial_states=() if initial_state is None else (initial_state,),
        forbidden_states=forbidden_states,
    )
    return QdlGraph(
        facts=(
            *specification.facts,
            *(
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("observed_transition"),
                    args=tuple(Atom(value=value) for value in transition),
                )
                for transition in observed
            ),
        )
    )


def _transition_facts(graph: QdlGraph, context: Context) -> list[Fact]:
    return [
        fact
        for fact in graph.facts
        if fact.context is context and fact.predicate.name == "transition"
    ]


def _transition_values(graph: QdlGraph, context: Context) -> set[tuple[str, str, str]]:
    return {
        (fact.args[0].value, fact.args[1].value, fact.args[2].value)
        for fact in _transition_facts(graph, context)
    }


@pytest.mark.parametrize("algorithm", ["rpni", "edsm"])
def test_aalpy_adapter_reads_observed_transition_facts(algorithm: str) -> None:
    source = _source(
        observed=(
            ("a", "start", "middle"),
            ("b", "middle", "end"),
            ("a", "end", "start"),
        ),
        actions=("action:name-only",),
    )

    proposal = AALpyAutomataLearningAdapter(algorithm=algorithm).learn(source)

    assert _transition_values(proposal, Context.PROPOSAL) == {
        ("a", "start", "middle"),
        ("b", "middle", "end"),
        ("a", "end", "start"),
    }
    assert ("action:name-only", "start", "middle") not in _transition_values(
        proposal, Context.PROPOSAL
    )


def test_learned_transition_is_proposal_not_accepted() -> None:
    source = _source(observed=(("a", "start", "middle"),))

    proposal = AALpyAutomataLearningAdapter().learn(source)

    assert _transition_facts(proposal, Context.PROPOSAL)
    assert not _transition_facts(proposal, Context.ACCEPTED)
    assert all(fact.context is Context.PROPOSAL for fact in proposal.facts)


def test_learned_transition_requires_observed_evidence() -> None:
    source = _source(
        observed=(
            ("a", "start", "middle"),
            ("b", "middle", "end"),
        )
    )

    proposal = AALpyAutomataLearningAdapter().learn(source)
    transitions = _transition_values(proposal, Context.PROPOSAL)
    evidence_effects: set[tuple[str, str]] = set()
    observation_ids: set[str] = set()

    for fact in proposal.facts:
        if fact.predicate.name == "is" and fact.args[1].value == "Observation":
            observation_ids.add(fact.args[0].value)
        if fact.predicate.name != "evidence" or len(fact.args) != 2:
            continue
        observation_ids.add(fact.args[0].value)
        effect = fact.args[1]
        assert isinstance(effect, Struct) and effect.name == "transition"
        evidence_effects.add((effect.args[0].value, effect.args[1].value))

    assert observation_ids
    assert evidence_effects == {
        (from_state, to_state) for _action, from_state, to_state in transitions
    }


def test_state_semantics_deficit_when_traces_insufficient() -> None:
    source = _source(
        observed=(("a", "start", "middle"),),
        initial_state=None,
    )

    proposal = AALpyAutomataLearningAdapter().learn(source)

    assert not _transition_facts(proposal, Context.PROPOSAL)
    deficits = [
        fact
        for fact in proposal.facts
        if fact.predicate.name == "state_semantics_deficit"
    ]
    assert [(fact.args[0].value, fact.args[1].value) for fact in deficits] == [
        ("a", INSUFFICIENT_TRACE_EVIDENCE)
    ]


def test_state_labels_come_from_observed_qdl_states() -> None:
    source = _source(
        observed=(
            ("a", "start", "middle"),
            ("b", "middle", "end"),
        ),
        states=("not-observed",),
    )

    proposal = AALpyAutomataLearningAdapter().learn(source)
    state_declarations = {
        fact.args[0].value
        for fact in proposal.facts
        if fact.predicate.name == "is" and fact.args[1].value == "State"
    }

    assert state_declarations == {"start", "middle", "end"}
    assert all(
        fact.args[1].value in state_declarations
        and fact.args[2].value in state_declarations
        for fact in _transition_facts(proposal, Context.PROPOSAL)
    )


def test_learned_forbidden_state_stays_a_proposal() -> None:
    source = _source(
        observed=(("a", "start", "forbidden-state"),),
        forbidden_states=(("norm:no-forbidden-state", "forbidden-state"),),
    )

    proposal = AALpyAutomataLearningAdapter().learn(source)
    forbidden = [
        fact
        for fact in proposal.facts
        if fact.context is Context.PROPOSAL and fact.predicate.name == "forbidden"
    ]

    assert [(fact.args[0].value, fact.args[1].value) for fact in forbidden] == [
        ("norm:no-forbidden-state", "forbidden-state")
    ]


def test_automata_learning_is_deterministic_under_fixed_seed() -> None:
    source = _source(
        observed=(
            ("a", "start", "middle"),
            ("b", "middle", "end"),
        )
    )
    adapter = AALpyAutomataLearningAdapter()

    first = adapter.learn(source)
    second = adapter.learn(source)

    assert first == second
    assert first.content_hash == second.content_hash


def test_promotion_goes_through_existing_deterministic_policy() -> None:
    source = _source(observed=(("a", "start", "middle"),))
    proposal = AALpyAutomataLearningAdapter().learn(source)

    request = ProposalPromotionRequest(source=source, proposal=proposal)
    disabled = PromotionPolicy(enabled=False).promote(request)
    enabled = PromotionPolicy(enabled=True).promote(request)

    assert not _transition_facts(disabled.graph, Context.ACCEPTED)
    assert _transition_values(enabled.graph, Context.ACCEPTED) == {
        ("a", "start", "middle")
    }
