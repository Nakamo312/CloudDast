from __future__ import annotations

import pytest

from cloud_dast.model import VerdictStatus
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    field,
    has,
)
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles import (
    ClassificationLeadOracle,
    evaluate_classification_leads,
)

LEAD_WITNESS = field(Atom(value="resource:user"), Atom(value="email"))


def _lead_fact(norm_id: str = "norm:lead:sensitive:0123456789ab") -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value=norm_id), has(Atom(value="principal:attacker"), LEAD_WITNESS)),
    )


def _declaration(term: object, type_name: str) -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("is"),
        args=(term, Atom(value=type_name)),  # type: ignore[arg-type]
    )


def _lead_graph(*norms: Fact) -> QdlGraph:
    return QdlGraph(
        facts=(
            _declaration(Atom(value="principal:attacker"), "Principal"),
            _declaration(Atom(value="resource:user"), "Resource"),
            _declaration(LEAD_WITNESS, "OutputField"),
            *(_declaration(norm.args[0], "Norm") for norm in norms),
            *norms,
        )
    )


def test_lead_norm_view_compiles_without_the_accepted_context() -> None:
    view = NormView.from_lead_fact(_lead_fact())

    assert view.lead is True
    assert view.compiled.primitive == "response_field"
    assert view.compiled.verdict_policy == "unscoreable"


def test_lead_norm_view_rejects_the_accepted_context() -> None:
    accepted = _lead_fact().model_copy(update={"context": Context.ACCEPTED})

    with pytest.raises(ValueError, match="proposal context"):
        NormView.from_lead_fact(accepted)


def test_lead_norm_view_requires_the_lead_prefix() -> None:
    with pytest.raises(ValueError, match="lead prefix"):
        NormView.from_lead_fact(_lead_fact(norm_id="norm:hypothesis"))


def test_classification_lead_oracle_returns_unscoreable_not_fail() -> None:
    verdict = ClassificationLeadOracle().evaluate(NormView.from_lead_fact(_lead_fact()))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert verdict.oracle_called is True
    assert "provenance" in verdict.rationale


def test_evaluate_classification_leads_scores_only_lead_norms() -> None:
    ordinary = _lead_fact(norm_id="norm:no-leak")
    graph = _lead_graph(_lead_fact(), ordinary)

    leads = evaluate_classification_leads(graph)

    assert [lead.norm_id for lead in leads] == ["norm:lead:sensitive:0123456789ab"]
    assert leads[0].role == "sensitive"
    assert leads[0].effect == "has(principal:attacker, field(resource:user, email))"
    assert leads[0].verdict.status is VerdictStatus.UNSCOREABLE
    assert leads[0].verdict_status == "unscoreable"


def test_evaluate_classification_leads_accepts_a_missing_graph() -> None:
    assert evaluate_classification_leads(None) == ()
