from __future__ import annotations

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    field,
    has,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticNormCompiler,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.promotion import (
    ProposalPromotionRequest,
    promote_proposal,
)
from tests.grounding_owner import make_grounding


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.PROPOSAL,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _graphs(source_declares_role: bool) -> tuple[QdlGraph, QdlGraph]:
    action = Atom(value="action:get-profile")
    resource = Atom(value="resource:user")
    witness = field(resource, Atom(value="email"))
    principal = Atom(value="principal:attacker")
    norm = Atom(value="norm:no-leak")
    source_facts = [
        _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
        _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
        _fact("is", (witness, Atom(value="Field")), Context.CONTRACT),
    ]
    if source_declares_role:
        source_facts.append(
            _fact("has", (witness, Atom(value="sensitive")), Context.CONTRACT)
        )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (witness, Atom(value="Field"))),
            _fact("is", (principal, Atom(value="Principal"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("exposes", (action, witness)),
            _fact("has", (witness, Atom(value="sensitive"))),
            _fact("prevents", (norm, has(principal, witness))),
        )
    )
    return QdlGraph(facts=tuple(source_facts)), proposal


def _lead_facts(graph: QdlGraph | None) -> tuple[Fact, ...]:
    if graph is None:
        return ()
    return tuple(
        fact
        for fact in graph.facts
        if fact.predicate.name == "prevents"
        and fact.args[0].value.startswith("norm:lead:")  # type: ignore[union-attr]
    )


def test_parked_protected_role_creates_a_lead_norm() -> None:
    source, proposal = _graphs(source_declares_role=False)

    result = promote_proposal(ProposalPromotionRequest(source, proposal))

    assert result.promoted_norms == ()
    assert result.parked_classifications is not None
    lead_facts = _lead_facts(result.parked_classifications)
    assert len(lead_facts) == 1
    lead = lead_facts[0]
    assert lead.context is Context.PROPOSAL
    assert lead.args[0].value.startswith("norm:lead:sensitive:")  # type: ignore[union-attr]
    assert lead.args[1] == has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:user"), Atom(value="email")),
    )
    assert all(
        fact.context is Context.PROPOSAL for fact in result.parked_classifications.facts
    )
    assert QdlPlanner().plan(result.parked_classifications).invariants == ()
    assert SemanticNormCompiler().compile(result.parked_classifications) == ()


def test_parked_lead_norm_reaches_the_persisted_proposal_source() -> None:
    source, proposal = _graphs(source_declares_role=False)

    class _Repository:
        def __init__(self) -> None:
            self.saved: list[tuple[str, QdlGraph]] = []

        def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
            self.saved.append((source_id, graph))

    repository = _Repository()
    make_grounding(
        repository,  # type: ignore[arg-type]
        promotion_policy=PromotionPolicy(enabled=True),
    ).promotion.promote(
        ProposalPromotionRequest(source, proposal, evidence_fields=frozenset()),
        proposal_source_id="proposal:test:roles:b0",
    )

    assert repository.saved[0][0] == (
        f"proposal:test:roles:b0:{repository.saved[0][1].content_hash}"
    )
    assert len(_lead_facts(repository.saved[0][1])) == 1
    assert all(
        fact.context is Context.PROPOSAL for fact in repository.saved[0][1].facts
    )


def test_source_provenance_creates_no_lead_norm() -> None:
    source, proposal = _graphs(source_declares_role=True)

    result = promote_proposal(ProposalPromotionRequest(source, proposal))

    assert result.promoted_norms == ("norm:no-leak",)
    assert result.parked_classifications is None
    assert _lead_facts(result.parked_classifications) == ()


def test_observed_evidence_creates_no_lead_norm() -> None:
    source, proposal = _graphs(source_declares_role=False)

    result = promote_proposal(
        ProposalPromotionRequest(source, proposal, evidence_fields=frozenset({"email"}))
    )

    assert result.promoted_norms == ("norm:no-leak",)
    assert result.parked_classifications is None


def test_disabled_policy_parks_the_classification_with_its_lead_norm() -> None:
    source, proposal = _graphs(source_declares_role=False)
    policy = PromotionPolicy(enabled=False)

    result = policy.promote(ProposalPromotionRequest(source=source, proposal=proposal))

    assert result.parked_semantics is not None
    assert result.parked_classifications is not None
    assert len(_lead_facts(result.parked_classifications)) == 1
    assert all(
        fact.context is Context.PROPOSAL for fact in result.parked_classifications.facts
    )


def test_unexposed_classification_parks_without_a_lead_norm() -> None:
    source, proposal = _graphs(source_declares_role=False)
    unexposed = QdlGraph(
        facts=tuple(fact for fact in proposal.facts if fact.predicate.name != "exposes")
    )

    result = promote_proposal(ProposalPromotionRequest(source, unexposed))

    assert result.parked_classifications is not None
    assert _lead_facts(result.parked_classifications) == ()
