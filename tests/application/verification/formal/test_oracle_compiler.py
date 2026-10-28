from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, changed
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.norms import NormCompiler


def test_norm_compilation_preserves_original_fact() -> None:
    fact = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(
            Atom(value="norm:no_mass_assignment"),
            changed(Atom(value="resource:user"), Atom(value="role")),
        ),
    )

    oracle = NormCompiler().compile(fact)

    assert oracle.primitive == "marker"
    assert oracle.evidence == ("response_diff", "read_back")
    assert oracle.verdict_policy == "deterministic"
    assert oracle.norm_fact is fact
    view = NormView.from_compiled(oracle)
    assert view.effect is fact.args[1]
    assert view.resource_id == "resource:user"
    assert view.forbidden_field == "role"


def test_norm_fact_rejects_evidence_only_effect() -> None:
    from cloud_dast.qdl.graph import response_status

    with pytest.raises(Exception):
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:n"),
                response_status(Atom(value="action:a"), Atom(value="grpc.OK")),
            ),
        )


@pytest.mark.parametrize(
    "context", [Context.CONTRACT, Context.PROPOSAL, Context.RUNTIME, Context.REPORT]
)
def test_compiler_rejects_unaccepted_norms(context: Context) -> None:
    fact = Fact(
        context=context,
        predicate=Predicate.from_name("prevents"),
        args=(
            Atom(value="norm:lead:role"),
            changed(Atom(value="r"), Atom(value="role")),
        ),
    )

    with pytest.raises(ValueError, match="accepted context"):
        NormCompiler().compile(fact)
    assert fact.context is context


def test_lead_view_preserves_proposal_provenance() -> None:
    fact = Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("prevents"),
        args=(
            Atom(value="norm:lead:role"),
            changed(Atom(value="r"), Atom(value="role")),
        ),
    )

    view = NormView.from_lead_fact(fact)

    assert view.compiled.norm_fact is fact
    assert view.compiled.norm_fact.context is Context.PROPOSAL
    assert view.compiled.norm_fact.content_hash == fact.content_hash
    assert view.compiled.norm is fact.args[0]
    assert view.effect is fact.args[1]
    assert view.compiled.evidence == ("classification_provenance",)
    assert view.compiled.verdict_policy == "unscoreable"
    assert view.lead is True
    assert view.resource_id == "r"
    assert view.forbidden_field == "role"


def test_invariant_view_uses_canonical_compiler(invariant) -> None:
    view = NormView.from_invariant(invariant, compiler=NormCompiler())

    assert view is not None
    assert view.compiled.norm_fact is invariant.norm_fact
    assert view.primitive == "outcome"
    assert view.compiled.verdict_policy == "deterministic"
