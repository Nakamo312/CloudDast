"""Tests for the Layer B threat-modeling scorer."""

from __future__ import annotations

from benchmarks.nsfy_bench import (
    build_contract_graph,
    expected_grounding,
    score_grounding,
)
from benchmarks.nsfy_bench.contract import GET_USER, action_id
from benchmarks.nsfy_bench.norms import NORM_BOLA_ORDER_READ

from cloud_dast.qdl.graph import Atom, Context, QdlGraph, allowed


def _proposal_from_truth() -> QdlGraph:
    """Model the perfect threat modeler: propose exactly the answer key."""

    truth = expected_grounding()
    return QdlGraph(
        facts=tuple(
            fact.model_copy(update={"context": Context.PROPOSAL})
            for fact in truth.facts
        )
    )


def test_layer_b_input_contains_no_grounding_answers() -> None:
    """The threat modeler must not see roles, sinks, or norms."""

    contract = build_contract_graph()
    predicates = {fact.predicate.name for fact in contract.facts}

    assert "prevents" not in predicates
    assert "reaches" not in predicates
    role_facts = [
        fact
        for fact in contract.facts
        if fact.predicate.name == "has"
        and fact.args
        and getattr(fact.args[0], "name", None) == "input_field"
    ]
    assert role_facts == []


def test_ground_truth_axes_sizes() -> None:
    truth = expected_grounding()
    score = score_grounding(truth)

    # One role fact per declared field plus one extra has-fact for each
    # grounded probe field; the count tracks the declared API surface.
    from benchmarks.nsfy_bench.contract import (
        _MUTABLE_ROLES,
        _PROBE_ROLES,
        methods,
    )

    expected_roles = (
        sum(len(method.fields) for method in methods())
        + len(_PROBE_ROLES)
        + len(_MUTABLE_ROLES)
    )
    assert score.roles.expected == expected_roles
    assert score.norms.expected >= 11


def test_perfect_proposals_score_perfectly() -> None:
    score = score_grounding(_proposal_from_truth())

    assert score.roles.recall == 1.0
    assert score.roles.precision == 1.0
    assert score.norms.recall == 1.0
    assert score.norms.precision >= 0.85
    assert len(score.matched_norms) >= 11
    assert {match.truth_norm for match in score.matched_norms} == {
        match.proposal_norm for match in score.matched_norms
    }


def test_partial_proposals_report_missed_and_hallucinated() -> None:
    truth = expected_grounding()
    kept = [
        fact
        for fact in truth.facts
        if not (
            fact.predicate.name == "prevents"
            and fact.args
            and fact.args[0] == Atom(value=NORM_BOLA_ORDER_READ)
        )
    ]
    proposals = QdlGraph(
        facts=tuple(
            fact.model_copy(update={"context": Context.PROPOSAL}) for fact in kept
        )
        + (
            _bogus_norm_fact(),
            _bogus_norm_declaration(),
        )
    )

    score = score_grounding(proposals)

    assert score.norms.expected >= 11
    assert score.norms.proposed >= 11
    assert score.norms.matched == score.norms.expected - 1
    assert score.norms.recall < 1.0
    assert score.norms.precision < 1.0
    assert len(score.norms.missed) == 1
    assert len(score.norms.hallucinated) >= 1
    assert score.roles.recall == 1.0


def _bogus_norm_fact():
    from cloud_dast.qdl.graph import Fact, Predicate

    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("prevents"),
        args=(
            Atom(value="norm:proposal-hallucinated"),
            allowed(action_id(GET_USER)),
        ),
    )


def _bogus_norm_declaration():
    from cloud_dast.qdl.graph import Fact, Predicate

    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("is"),
        args=(
            Atom(value="norm:proposal-hallucinated"),
            Atom(value="Norm"),
        ),
    )


def test_allowed_covers_channel_norms_on_unprivileged_stand() -> None:
    """allowed(A) covers reached/has-channel defects of the same action."""

    from cloud_dast.qdl.graph import (
        Atom,
        Context,
        Fact,
        Predicate,
        allowed,
        reached,
    )

    truth = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:nsfy.GetDocument"), Atom(value="Action")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="../../../secret"), Atom(value="Sink")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="norm:traversal"), Atom(value="Norm")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:traversal"),
                    reached(
                        Atom(value="action:nsfy.GetDocument"),
                        Atom(value="../../../secret"),
                    ),
                ),
            ),
        )
    )
    proposals = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="norm:llm"), Atom(value="Norm")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:nsfy.GetDocument"), Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:llm"),
                    allowed(Atom(value="action:nsfy.GetDocument")),
                ),
            ),
        )
    )

    from benchmarks.nsfy_bench.threat_modeling import _score_norms

    axis, matches = _score_norms(truth, proposals)
    assert axis.matched == 1
    assert axis.recall == 1.0
    assert matches[0].truth_norm == "norm:traversal"
