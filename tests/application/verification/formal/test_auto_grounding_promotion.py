"""Trust-boundary tests for automatic proposal promotion."""

from __future__ import annotations

import pytest

from cloud_dast.config import MAX_SEMANTIC_FACTS
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.proposals import (
    ClassificationPromotionContext,
    ProposalPromotionRequest,
)
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    canonical_json,
    create,
    field,
    input_field,
    output_field,
    reached,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import runtime as grounding_runtime
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.evidence import (
    build_evidence_view,
    evidence_response_fields,
)
from cloud_dast.verification.promotion import (
    PromotionPolicy,
)
from cloud_dast.verification.slices import SiblingAction, SiblingActionSlice
from tests.grounding_owner import commit_reactive, make_grounding


class _Repository:
    def __init__(self) -> None:
        self.saved: list[tuple[str, QdlGraph]] = []

    def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
        self.saved.append((source_id, graph))


class _Store:
    def __init__(self, graphs: dict[str, QdlGraph] | None = None) -> None:
        self.graphs = graphs or {}
        self.saved: list[tuple[str, QdlGraph]] = []

    def load(self, source_id: str) -> QdlGraph:
        return self.graphs.get(source_id, QdlGraph())

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return merge_graphs(
            *(
                graph
                for source_id, graph in self.saved
                if source_id.startswith(source_prefix)
            )
        )

    def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
        self.saved.append((source_id, graph))


class _StaticAxisGrounding:
    def __init__(self, proposal: QdlGraph) -> None:
        self.proposal = proposal

    def ground_reactive(self, axis, action_ids, source, **_kwargs):
        observation = _kwargs.get("observation")
        return AxisResult(
            axis,
            self.proposal,
            0,
            0,
            observation_ids=(
                (observation.observation_id,) if observation is not None else ()
            ),
        )


class _StaticStartupAxisGrounding:
    def __init__(self, proposal: QdlGraph) -> None:
        self.proposal = proposal

    def ground_stream(self, source, *, cache_source=None):
        yield "roles", "b0", self.proposal


class _RevisionAxisGrounding:
    def __init__(self, proposals: list[QdlGraph]) -> None:
        self.proposals = proposals

    def ground_reactive(self, axis, action_ids, source, **_kwargs):
        return AxisResult(axis, self.proposals.pop(0), 0, 0)


def _promote(source: QdlGraph, proposal: QdlGraph, **kwargs: object):
    max_semantic_facts = kwargs.pop("max_semantic_facts", MAX_SEMANTIC_FACTS)
    policy = PromotionPolicy(
        enabled=True,
        max_semantic_facts=int(max_semantic_facts),  # type: ignore[arg-type]
    )
    evidence = kwargs.pop("evidence", None)
    return make_grounding(
        _Repository(),
        promotion_policy=policy,
    ).promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_fields=frozenset(evidence_response_fields(evidence)),
            **kwargs,
        )
    )


def _fact(
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
        predicate=(
            Predicate.from_schema(schema) if schema else Predicate.from_name(predicate)
        ),
        args=args,  # type: ignore[arg-type]
    )


def test_startup_roles_cannot_promote_hallucinated_output_field() -> None:
    action = Atom(value="action:get")
    visible = output_field(action, Atom(value="visible"))
    hallucinated = output_field(action, Atom(value="hallucinated_secret"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (visible, Atom(value="OutputField"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (hallucinated, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (hallucinated, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )

    promoted = _promote(source, proposal)

    assert promoted is None or not any(
        fact.predicate.name == "has"
        and fact.args[0].args[1].value == "hallucinated_secret"
        for fact in promoted.facts
    )
    assert promoted is None or not any(
        fact.predicate.name == "is"
        and isinstance(fact.args[0], Struct)
        and fact.args[0].name == "output_field"
        and fact.args[0].args[1].value == "hallucinated_secret"
        for fact in promoted.facts
    )


def test_startup_exposures_cannot_promote_hallucinated_field() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:user")
    visible = field(resource, Atom(value="visible"))
    hallucinated = field(resource, Atom(value="hallucinated_secret"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("targets", (action, resource)),
            _fact("is", (visible, Atom(value="OutputField"))),
            _fact("exposes", (action, visible)),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (hallucinated, Atom(value="Witness")), Context.PROPOSAL),
            _fact("exposes", (action, hallucinated), Context.PROPOSAL),
            _fact("has", (hallucinated, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )

    promoted = _promote(source, proposal)

    assert promoted is None or not any(
        fact.predicate.name == "exposes"
        and fact.args[1].args[1].value == "hallucinated_secret"
        for fact in promoted.facts
    )
    assert promoted is None or not any(
        fact.predicate.name == "has"
        and fact.args[0].name == "field"
        and fact.args[0].args[1].value == "hallucinated_secret"
        for fact in promoted.facts
    )


def test_model_cannot_promote_invented_may_permission() -> None:
    action = Atom(value="action:get")
    principal = Atom(value="principal:attacker")
    resource = Atom(value="resource:invented")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (principal, Atom(value="Principal"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (principal, Atom(value="Principal")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("may", (principal, action, resource), Context.PROPOSAL),
        )
    )

    promoted = _promote(source, proposal)

    assert promoted is None or not any(
        fact.predicate.name == "may" for fact in promoted.facts
    )


def test_model_rules_never_become_executable_or_accepted() -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="query"))
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    action_declaration = _fact("is", (action, Atom(value="Action")), Context.PROPOSAL)
    field_declaration = _fact(
        "is", (request_field, Atom(value="InputField")), Context.PROPOSAL
    )
    classification = _fact(
        "has", (request_field, Atom(value="object_ref")), Context.PROPOSAL
    )
    proposal = QdlGraph(
        facts=(action_declaration, field_declaration),
        rules=(
            Rule(body=(action_declaration, field_declaration), head=(classification,)),
        ),
    )

    promoted = _promote(source, proposal)

    assert promoted is None


def test_extra_semantics_predicates_are_parked_not_promoted() -> None:
    action = Atom(value="action:get")
    permission = Atom(value="permission:admin")
    witness = Atom(value="witness:token")
    principal = Atom(value="principal:attacker")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (permission, Atom(value="Permission"))),
            _fact("is", (witness, Atom(value="Witness"))),
            _fact("is", (principal, Atom(value="Principal"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (permission, Atom(value="Permission")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Witness")), Context.PROPOSAL),
            _fact("is", (principal, Atom(value="Principal")), Context.PROPOSAL),
            _fact("requires", (action, permission), Context.PROPOSAL),
            _fact("accepts", (action, witness, principal), Context.PROPOSAL),
            _fact("binds", (witness, principal), Context.PROPOSAL),
        )
    )
    repository = _Repository()

    promoted = make_grounding(
        repository,
        promotion_policy=PromotionPolicy(enabled=True),
    ).promotion.promote(
        ProposalPromotionRequest(source, proposal, evidence_fields=frozenset()),
        proposal_source_id="proposal:test:extra-semantics",
    )

    # Every term is source-declared, so the legacy policy would have
    # auto-promoted all three relations into the accepted context.
    assert promoted is None
    assert len(repository.saved) == 1
    (parked_source_id, parked) = repository.saved[0]
    assert parked_source_id == (f"proposal:test:extra-semantics:{parked.content_hash}")
    assert {
        fact.predicate.name
        for fact in parked.facts
        if fact.predicate.name in {"requires", "accepts", "binds"}
    } == {"requires", "accepts", "binds"}
    assert all(fact.context is Context.PROPOSAL for fact in parked.facts)


def test_extra_fact_cannot_introduce_hallucinated_output_declaration() -> None:
    action = Atom(value="action:get")
    hallucinated = output_field(action, Atom(value="hallucinated_secret"))
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (hallucinated, Atom(value="Field")), Context.PROPOSAL),
            _fact("requires", (action, hallucinated), Context.PROPOSAL),
        )
    )

    promoted = _promote(source, proposal)

    assert promoted is None or not any(
        fact.predicate.name in {"requires", "is"}
        and any(
            isinstance(term, Struct)
            and term.name == "output_field"
            and term.args[1].value == "hallucinated_secret"
            for term in fact.args
        )
        for fact in promoted.facts
    )

    second_proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (hallucinated, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (hallucinated, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )
    second = _promote(source, second_proposal)

    assert second is None or not any(
        fact.predicate.name == "has"
        and fact.args[0].args[1].value == "hallucinated_secret"
        for fact in second.facts
    )


def test_source_declared_input_role_remains_promotable() -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="query"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (request_field, Atom(value="InputField"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (request_field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )

    promoted = _promote(source, proposal)

    assert promoted is not None
    assert any(
        fact.predicate.name == "has" and fact.args[0].args[1].value == "query"
        for fact in promoted.facts
    )


def test_batch_promotion_is_bounded_by_semantic_cap() -> None:
    action = Atom(value="action:get")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            *(
                _fact(
                    "is",
                    (
                        input_field(action, Atom(value=f"field:{index}")),
                        Atom(value="InputField"),
                    ),
                )
                for index in range(10)
            ),
        )
    )
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
    ]
    for index in range(10):
        request_field = input_field(action, Atom(value=f"field:{index}"))
        facts.extend(
            (
                _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
                _fact(
                    "has", (request_field, Atom(value="object_ref")), Context.PROPOSAL
                ),
            )
        )

    promoted = _promote(
        source,
        QdlGraph(facts=tuple(facts)),
        max_semantic_facts=3,
    )

    assert promoted is not None
    assert len(promoted.facts) <= 3


def test_evidence_field_role_cannot_follow_rejected_related_exposure() -> None:
    blocked = Atom(value="action:blocked")
    related = Atom(value="action:related")
    resource = Atom(value="resource:user")
    witness = field(resource, Atom(value="email"))
    source = QdlGraph(
        facts=(
            _fact("is", (blocked, Atom(value="Action"))),
            _fact("is", (related, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("targets", (blocked, resource)),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (related, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Witness")), Context.PROPOSAL),
            _fact("exposes", (related, witness), Context.PROPOSAL),
            _fact("has", (witness, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )
    evidence = build_evidence_view(
        observation=Observation(
            check_id="check",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="ok",
            response_tree=(("email", "bob@example.com"),),
        )
    )

    promoted = _promote(
        source,
        proposal,
        evidence=evidence,
        action_ids=("action:blocked",),
    )

    assert promoted is None or not any(
        (
            fact.predicate.name == "exposes"
            and fact.args[1].name == "field"
            and fact.args[1].args[1].value == "email"
        )
        or (
            fact.predicate.name == "has"
            and fact.args[0].name == "field"
            and fact.args[0].args[1].value == "email"
        )
        for fact in promoted.facts
    )


def test_disabled_policy_parks_proposals_without_promotion() -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="query"))
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (request_field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )
    repository = _Repository()
    grounding = make_grounding(
        repository,
        promotion_policy=PromotionPolicy(enabled=False),
    )

    promoted = grounding.promotion.promote(
        ProposalPromotionRequest(source, proposal, evidence_fields=frozenset()),
        proposal_source_id="proposal:test:disabled",
    )

    assert promoted is None
    assert len(repository.saved) == 1
    source_id, parked = repository.saved[0]
    assert source_id == f"proposal:test:disabled:{parked.content_hash}"
    assert all(fact.context is Context.PROPOSAL for fact in parked.facts)
    assert not any(fact.context is Context.ACCEPTED for fact in parked.facts)


def test_parked_proposal_revisions_use_content_addressed_sources(tmp_path) -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="token"))

    def proposal(role: str) -> QdlGraph:
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
                _fact("has", (request_field, Atom(value=role)), Context.PROPOSAL),
            )
        )

    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        grounding = make_grounding(
            repository, promotion_policy=PromotionPolicy(enabled=False)
        )
        assert (
            grounding.promotion.promote(
                ProposalPromotionRequest(
                    source, proposal("object_ref"), evidence_fields=frozenset()
                ),
                proposal_source_id="proposal:orders:roles:b0",
            )
            is None
        )
        assert (
            grounding.promotion.promote(
                ProposalPromotionRequest(
                    source, proposal("identifier"), evidence_fields=frozenset()
                ),
                proposal_source_id="proposal:orders:roles:b0",
            )
            is None
        )

        with repository._connection:
            source_ids = [
                row["source_id"]
                for row in repository._connection.execute(
                    """
                    SELECT source_id
                    FROM qdl_projection
                    WHERE source_id LIKE 'proposal:orders:roles:b0:%'
                    ORDER BY rowid
                    """
                ).fetchall()
            ]

        assert len(source_ids) == 2
        assert len(set(source_ids)) == 2
        merged = repository.load_merged("proposal:orders:")
        assert {
            fact.args[1].value for fact in merged.facts if fact.predicate.name == "has"
        } == {"object_ref", "identifier"}


def test_action_scope_blocks_cross_action_semantics() -> None:
    blocked = Atom(value="action:blocked")
    related = Atom(value="action:related")
    related_field = input_field(related, Atom(value="related_query"))
    source = QdlGraph(
        facts=(
            _fact("is", (blocked, Atom(value="Action"))),
            _fact("is", (related, Atom(value="Action"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (related, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (related_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (related_field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )

    promoted = _promote(
        source,
        proposal,
        action_ids=("action:blocked",),
    )

    assert promoted is None or not any(
        fact.predicate.name == "has" and fact.args[0].args[0].value == "action:related"
        for fact in promoted.facts
    )


def test_semantic_cap_is_global_across_batches() -> None:
    action = Atom(value="action:get")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            *(
                _fact(
                    "is",
                    (input_field(action, Atom(value=name)), Atom(value="InputField")),
                )
                for name in ("first", "second")
            ),
        )
    )
    policy = PromotionPolicy(enabled=True, max_semantic_facts=3)
    repository = _Repository()
    grounding = make_grounding(repository, promotion_policy=policy)

    def proposal(field_name: str) -> QdlGraph:
        field_term = input_field(action, Atom(value=field_name))
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (field_term, Atom(value="Field")), Context.PROPOSAL),
                _fact("has", (field_term, Atom(value="object_ref")), Context.PROPOSAL),
            )
        )

    first = grounding.promotion.promote(
        ProposalPromotionRequest(
            source, proposal("first"), evidence_fields=frozenset()
        ),
    )
    second = grounding.promotion.promote(
        ProposalPromotionRequest(
            source, proposal("second"), evidence_fields=frozenset()
        ),
    )

    assert first is not None
    assert second is None
    assert policy.promoted_semantic_facts == 3


def test_parked_leads_dedupe_and_count_new_observations() -> None:
    action = Atom(value="action:get")
    field_term = input_field(action, Atom(value="secret_id"))
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field_term, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (field_term, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )
    grounding = make_grounding(
        _Repository(),
        promotion_policy=PromotionPolicy(enabled=True),
    )

    grounding.promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:first"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:first",
    )
    grounding.promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:first"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:repeat",
    )
    grounding.promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:second"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:second",
    )

    leads = grounding.promotion.parked_lead_states()

    assert len(leads) == 1
    assert leads[0].evidence_refs == frozenset(
        {"observation:first", "observation:second"}
    )
    assert leads[0].confirmations == 2


def test_reactive_batch_keeps_action_scope() -> None:
    blocked = Atom(value="action:blocked")
    related = Atom(value="action:related")
    related_field = input_field(related, Atom(value="related_query"))
    source = QdlGraph(
        facts=(
            _fact("is", (blocked, Atom(value="Action"))),
            _fact("is", (related, Atom(value="Action"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (related, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (related_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (related_field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )
    store = _Store({"contract:orders": source})
    grounding_component_1 = _StaticAxisGrounding(proposal)
    grounding = make_grounding(
        store,
        startup=grounding_component_1,
        reactive=grounding_component_1,
        promotion_policy=PromotionPolicy(enabled=True),
    )

    promoted = commit_reactive(
        grounding,
        "orders",
        "roles",
        ("action:blocked",),
    )

    assert promoted is None
    assert not any(
        source_id.startswith("accepted-batch:orders:")
        for source_id, _build_graph in store.saved
    )


def test_fixture_typing_promotes_bounded_missing_fact_alphabet() -> None:
    consumer = Atom(value="action:svc.submit")
    producer = Atom(value="action:svc.prepare")
    order = Atom(value="resource:order")
    order_field = input_field(consumer, Atom(value="order_id"))
    source = QdlGraph(
        facts=(
            _fact("is", (consumer, Atom(value="Action"))),
            _fact("is", (producer, Atom(value="Action"))),
            _fact("is", (order_field, Atom(value="Field"))),
            _fact("is", (order, Atom(value="ResourceType"))),
            _fact("has", (order_field, Atom(value="object_ref"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (consumer, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (producer, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (order_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (order, Atom(value="ResourceType")), Context.PROPOSAL),
            _fact(
                "refers_to",
                (order_field, order),
                Context.PROPOSAL,
            ),
            _fact("targets", (consumer, order), Context.PROPOSAL),
            _fact(
                "causes",
                (producer, create(order)),
                Context.PROPOSAL,
            ),
        )
    )
    store = _Store({"contract:orders": source})
    grounding_component_2 = _StaticAxisGrounding(proposal)
    grounding = make_grounding(
        store,
        startup=grounding_component_2,
        reactive=grounding_component_2,
        promotion_policy=PromotionPolicy(enabled=True),
    )

    promoted = commit_reactive(
        grounding,
        "orders",
        "fixture",
        ("action:svc.submit",),
        context={
            "unprovable_subgoal": 'refers_to(input_field("action:svc.submit", "order_id"), AnyTarget)'
        },
        observation=Observation(
            check_id="check:fixture",
            scenario_id="scenario:fixture",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="order created",
        ),
    )

    assert promoted is not None
    assert any(
        fact.predicate.name == "refers_to"
        and fact.args == (order_field, order)
        and fact.context is Context.ACCEPTED
        for fact in promoted.facts
    )
    assert any(
        fact.predicate.name == "targets"
        and fact.args == (consumer, order)
        and fact.context is Context.ACCEPTED
        for fact in promoted.facts
    )
    assert any(
        fact.predicate.name == "causes"
        and fact.args == (producer, create(order))
        and fact.context is Context.ACCEPTED
        for fact in promoted.facts
    )


def test_reactive_role_revisions_are_append_only_and_superseded(
    tmp_path,
) -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="token"))
    old_role = Atom(value="setup_value")
    new_role = Atom(value="setup_skip")

    def proposal(role: Atom) -> QdlGraph:
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
                _fact("has", (request_field, role), Context.PROPOSAL),
            )
        )

    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (request_field, Atom(value="InputField"))),
        )
    )
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        repository.save(
            "contract:orders",
            source,
            provenance={"source_kind": "test"},
            adapter_version="test-v1",
            mapping_report={"mapped": len(source.facts), "unmapped": 0},
        )
        grounding_component_4 = _RevisionAxisGrounding(
            [proposal(old_role), proposal(new_role), proposal(new_role)]
        )
        grounding = make_grounding(
            repository,
            startup=grounding_component_4,
            reactive=grounding_component_4,
            promotion_policy=PromotionPolicy(enabled=True),
        )

        assert (
            commit_reactive(grounding, "orders", "roles", ("action:get",)) is not None
        )
        assert (
            commit_reactive(grounding, "orders", "roles", ("action:get",)) is not None
        )
        assert (
            commit_reactive(grounding, "orders", "roles", ("action:get",)) is not None
        )

        with repository._connection:
            rows = repository._connection.execute(
                """
                SELECT source_id, COUNT(*) AS projection_count
                FROM qdl_projection
                WHERE source_id LIKE 'accepted-batch:orders:reactive:roles:action:get:%'
                GROUP BY source_id
                ORDER BY source_id
                """
            ).fetchall()

        assert len(rows) == 2
        assert all(row["projection_count"] == 1 for row in rows)

        merged = repository.load_merged("accepted-batch:orders:")
        assert any(
            fact.predicate.name == "has" and fact.args == (request_field, old_role)
            for fact in merged.facts
        )
        assert any(
            fact.predicate.name == "has" and fact.args == (request_field, new_role)
            for fact in merged.facts
        )
        assert any(
            fact.predicate.name == "supersedes"
            and isinstance(fact.args[0], Struct)
            and fact.args[0].name == "replacement"
            and fact.args[0].args == (request_field, new_role)
            and isinstance(fact.args[1], Struct)
            and fact.args[1].args == (request_field, old_role)
            for fact in merged.facts
        )

        solution = ClingoEngine().solve(merged, closures={"current_has"})[0]
        assert solution.contains(
            'current_has("accepted",input_field("action:get","token"),"setup_skip")'
        )
        assert not solution.contains(
            'current_has("accepted",input_field("action:get","token"),"setup_value")'
        )


def test_reactive_reached_revisions_emit_supersedes(tmp_path) -> None:
    action = Atom(value="action:get")
    old_sink = Atom(value="sink:sql")
    new_sink = Atom(value="sink:template")
    old_effect = reached(action, old_sink)
    new_effect = reached(action, new_sink)

    def proposal(effect: Struct, sink: Atom) -> QdlGraph:
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (sink, Atom(value="Sink")), Context.PROPOSAL),
                _fact("is", (effect, Atom(value="Effect")), Context.PROPOSAL),
                _fact("causes", (action, effect), Context.PROPOSAL),
            )
        )

    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        repository.save(
            "contract:orders",
            source,
            provenance={"source_kind": "test"},
            adapter_version="test-v1",
            mapping_report={"mapped": len(source.facts), "unmapped": 0},
        )
        grounding_component_5 = _RevisionAxisGrounding(
            [
                proposal(old_effect, old_sink),
                proposal(new_effect, new_sink),
                proposal(new_effect, new_sink),
            ]
        )
        grounding = make_grounding(
            repository,
            startup=grounding_component_5,
            reactive=grounding_component_5,
            promotion_policy=PromotionPolicy(enabled=True),
        )

        for _ in range(3):
            assert (
                commit_reactive(grounding, "orders", "dataflows", ("action:get",))
                is not None
            )

        with repository._connection:
            projection_count = repository._connection.execute(
                """
                SELECT COUNT(*)
                FROM qdl_projection
                WHERE source_id LIKE 'accepted-batch:orders:reactive:dataflows:%'
                """
            ).fetchone()[0]

        merged = repository.load_merged("accepted-batch:orders:")
        assert projection_count == 2
        assert any(
            fact.predicate.name == "causes" and fact.args == (action, old_effect)
            for fact in merged.facts
        )
        assert any(
            fact.predicate.name == "causes" and fact.args == (action, new_effect)
            for fact in merged.facts
        )
        assert any(
            fact.predicate.name == "supersedes"
            and fact.args == (new_effect, old_effect)
            for fact in merged.facts
        )

        solution = ClingoEngine().solve(
            merged,
            closures={"current_reached"},
        )[0]
        assert solution.contains(
            'current_reached("accepted","action:get","sink:template")'
        )
        assert not solution.contains(
            'current_reached("accepted","action:get","sink:sql")'
        )


def test_startup_axis_promotion_requires_enabled_policy() -> None:
    action = Atom(value="action:get")
    request_field = input_field(action, Atom(value="query"))
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (request_field, Atom(value="Field")), Context.PROPOSAL),
            _fact("has", (request_field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )
    store = _Store({"contract:orders": source})
    grounding_component_3 = _StaticStartupAxisGrounding(proposal)
    grounding = make_grounding(
        store,
        startup=grounding_component_3,
        reactive=grounding_component_3,
        promotion_policy=PromotionPolicy(enabled=False),
    )

    handle = grounding.lifecycle.start_grounded("orders", ThreadedGroundingRunner())
    assert handle is not None
    assert handle.wait_batch(timeout=5) is None
    assert handle.error is None
    assert not any(
        source_id.startswith("accepted-batch:orders:")
        for source_id, _build_graph in store.saved
    )
    assert any(
        source_id == f"proposal:orders:roles:b0:{graph.content_hash}"
        and all(fact.context is Context.PROPOSAL for fact in graph.facts)
        for source_id, graph in store.saved
    )


@pytest.mark.parametrize(
    "axis,branch",
    [
        ("roles", False),
        ("fixture", False),
        ("alternatives", False),
        ("alternatives", True),
    ],
)
def test_admitted_batch_preserves_policy_scope_and_identity(
    axis, branch, monkeypatch, caplog
):
    raw = "blocked"
    actions = (raw,)
    pinned = SiblingActionSlice(
        "action:blocked",
        (SiblingAction("action:pinned", ("targets",), ("resource:r",)),),
    )
    source = QdlGraph(
        facts=(_fact("is", (Atom(value="action:outsider"), Atom(value="Action"))),)
    )
    holder = input_field(Atom(value="action:blocked"), Atom(value="token"))
    declarations = (
        _fact(
            "is", (Atom(value="action:blocked"), Atom(value="Action")), Context.ACCEPTED
        ),
        _fact("is", (holder, Atom(value="InputField")), Context.ACCEPTED),
    )
    previous = QdlGraph(
        facts=(
            *declarations,
            _fact("has", (holder, Atom(value="setup_value")), Context.ACCEPTED),
        )
    )
    promoted = QdlGraph(
        facts=(
            *declarations,
            _fact("has", (holder, Atom(value="setup_skip")), Context.ACCEPTED),
        )
    )
    metadata = ClassificationPromotionContext(
        "pinned-term", frozenset({"sensitive"}), "norm:pinned"
    )
    result = AxisResult(
        axis,
        promoted,
        0,
        1,
        observation_ids=("obs:z", "obs:a"),
        classification_context=metadata,
    )
    grounding = make_grounding(_Repository())
    parks, requests, saves, events = [], [], [], []

    def park(*args, **kwargs):
        parks.append((args, kwargs))

    def promote(request, **kwargs):
        requests.append((request, kwargs))
        return promoted

    def save(*args, **kwargs):
        events.append("save")
        saves.append((args, kwargs))
        return args[1], args[0]

    append = grounding_runtime.append_supersession

    def supersede(graph, old):
        events.append("supersede")
        return append(graph, old)

    monkeypatch.setattr(grounding.promotion, "park_secret_shapes", park)
    monkeypatch.setattr(grounding.promotion, "promote", promote)
    monkeypatch.setattr(grounding.promotion, "save_promoted_graph", save)
    monkeypatch.setattr(grounding_runtime, "append_supersession", supersede)
    with caplog.at_level("INFO"):
        accepted = grounding.batches.commit(
            "orders",
            source,
            axis,
            actions,
            result,
            sibling_slice=pinned if branch else None,
            previous=previous,
        )

    key = f"{axis}:{raw}"
    assert parks == [
        (
            (f"proposal:orders:reactive:{key}:secret-shapes", actions, None),
            {"evidence_refs": frozenset({"obs:a", "obs:z"})},
        )
    ]
    request, kwargs = requests[0]
    assert request.source is source and request.proposal is promoted
    assert tuple(request.action_ids) == (
        ("action:blocked", "action:pinned")
        if branch
        else (() if axis == "fixture" else actions)
    )
    assert request.classification_context is (None if branch else metadata)
    assert request.runtime_evidence_exempt_predicates == (
        frozenset({"refers_to", "targets"}) if axis == "fixture" else frozenset()
    )
    assert request.evidence_refs == frozenset({"obs:a", "obs:z"})
    assert request.evidence_fields == frozenset()
    assert kwargs["proposal_source_id"] == f"proposal:orders:reactive:{key}"
    activity = kwargs["activity"]
    deficit = f"blocked:{raw}" if branch else f"reactive:{axis}:{raw}"
    assert (activity.component, activity.invocation_id, activity.correlation_id) == (
        f"consultation:{axis}",
        f"consultation:{deficit}:0",
        deficit,
    )
    kind = "branch" if branch else "reactive"
    assert saves == [
        (
            (
                f"accepted-batch:orders:reactive:{key}",
                promoted if branch else append(promoted, previous),
            ),
            {
                "provenance": {
                    "source_kind": f"{kind}-grounding",
                    **(
                        {"action": raw}
                        if branch
                        else {"axis": axis, "actions": list(actions)}
                    ),
                    "evidence_refs": ["obs:a", "obs:z"],
                },
                "adapter_version": f"{kind}-grounding-v1",
                "previous": previous if branch else None,
            },
        )
    ]
    assert events == (["save", "supersede"] if branch else ["supersede", "save"])
    assert accepted is not None
    assert {f.predicate.name for f in accepted.facts} == {"is", "has", "supersedes"}
    expected_log = (
        f"branch_grounding_promoted service=orders action={raw} facts=3"
        if branch
        else f"reactive_grounding_promoted service=orders axis={axis} actions=1 facts=3"
    )
    assert expected_log in caplog.messages


@pytest.mark.parametrize("branch", [False, True])
@pytest.mark.parametrize("graph", [None, QdlGraph()])
def test_empty_admitted_batch_still_parks_secret_shapes(branch, graph, monkeypatch):
    repository = _Repository()
    grounding = make_grounding(repository)
    evidence = build_evidence_view(
        observation=Observation(
            check_id="check",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="ok",
            response_tree=(("token", "$argon2id$test"),),
        )
    )
    result = AxisResult("alternatives", graph, 0, 1, observation_ids=("obs:secret",))

    def unexpected(*args, **kwargs):
        pytest.fail("empty proposal must stop after parking")

    monkeypatch.setattr(grounding.promotion, "promote", unexpected)
    monkeypatch.setattr(grounding.promotion, "save_promoted_graph", unexpected)
    accepted = grounding.batches.commit(
        "orders",
        QdlGraph(),
        "alternatives",
        ("blocked",),
        result,
        sibling_slice=SiblingActionSlice("action:pinned") if branch else None,
        evidence=evidence,
    )
    assert accepted is None
    assert len(repository.saved) == 1
    source_id, parked = repository.saved[0]
    assert (
        source_id
        == f"proposal:orders:reactive:alternatives:blocked:secret-shapes:{parked.content_hash}"
    )
    assert all(f.context is Context.PROPOSAL for f in parked.facts)
    assert (
        _fact(
            "has",
            (
                output_field(Atom(value="action:blocked"), Atom(value="token")),
                Atom(value="credential"),
            ),
            Context.PROPOSAL,
        )
        in parked.facts
    )
    assert grounding.promotion.parked_lead_states()[0].evidence_refs == frozenset(
        {"obs:secret"}
    )


@pytest.mark.parametrize(
    "axis,actions",
    [
        ("roles", ("blocked",)),
        ("fixture", ("blocked",)),
        ("alternatives", ()),
        ("alternatives", ("blocked", "extra")),
    ],
)
def test_malformed_branch_batch_has_no_effects(axis, actions, monkeypatch):
    repository = _Repository()
    grounding = make_grounding(repository)

    def unexpected(*args, **kwargs):
        pytest.fail("malformed branch must fail before any promotion effect")

    for method in ("park_secret_shapes", "promote", "save_promoted_graph"):
        monkeypatch.setattr(grounding.promotion, method, unexpected)
    with pytest.raises(ValueError):
        grounding.batches.commit(
            "orders",
            QdlGraph(),
            axis,
            actions,
            AxisResult(axis, QdlGraph(), 0, 0),
            sibling_slice=SiblingActionSlice("action:blocked"),
        )
    assert repository.saved == []
    assert grounding.promotion.parked_lead_states() == ()


@pytest.mark.parametrize("mode", ["fallback", "provided", "missing", "invalid"])
@pytest.mark.parametrize("axis", ["classification", "roles"])
def test_prepare_freezes_classification_before_grounding(mode, axis, monkeypatch):
    action = Atom(value="action:get")
    holder = output_field(action, Atom(value="token"))
    outside = output_field(action, Atom(value="other"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (holder, Atom(value="OutputField"))),
            _fact("is", (outside, Atom(value="OutputField"))),
            *(
                [
                    _fact("has", (holder, Atom(value="sensitive"))),
                    _fact("has", (holder, Atom(value="credential"))),
                    _fact("has", (outside, Atom(value="sensitive"))),
                ]
                if mode in {"fallback", "provided"}
                else []
            ),
        )
    )
    proposal = QdlGraph(
        facts=tuple(
            f.model_copy(update={"context": Context.PROPOSAL})
            for f in source.facts
            if f.predicate.name == "is"
        )
        + (
            _fact("has", (holder, Atom(value="sensitive")), Context.PROPOSAL),
            _fact("has", (holder, Atom(value="credential")), Context.PROPOSAL),
            _fact("has", (outside, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )
    values = ["sensitive"]
    refs = ["obs:request"]
    context = {
        "classification_term": canonical_json(holder),
        "allowed_values": values,
        "invariant_id": "norm:original",
        "evidence_refs": refs,
    }
    if mode == "missing":
        context = None
    elif mode == "invalid":
        context.pop("invariant_id")
    provided = (
        ClassificationPromotionContext(
            canonical_json(holder),
            frozenset({"sensitive"}),
            "norm:provided",
            frozenset({"obs:provided"}),
        )
        if mode == "provided"
        else None
    )
    original = AxisResult(
        axis,
        proposal,
        0,
        1,
        observation_ids=("obs:result",),
        classification_context=provided,
    )
    axis_grounding = _StaticAxisGrounding(proposal)

    def ground(*args, **kwargs):
        assert kwargs["context_extra"] is context
        values[:] = ["interpreter"]
        refs.append("obs:mutated")
        if context is not None:
            context["invariant_id"] = "norm:mutated"
            context["classification_term"] = canonical_json(action)
        return original

    monkeypatch.setattr(axis_grounding, "ground_reactive", ground)
    repository = _Repository()
    grounding = make_grounding(
        repository,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    result = grounding.batches.prepare_reactive(
        source, axis, ("action:get",), context=context
    )
    assert result is not None
    if mode == "fallback" and axis == "classification":
        assert original.classification_context is None
        assert result is not original
        assert result.classification_context == ClassificationPromotionContext(
            canonical_json(holder),
            frozenset({"sensitive"}),
            "norm:original",
            frozenset({"obs:request", "obs:result"}),
        )
    else:
        assert result is original
        assert result.classification_context is provided
    accepted = grounding.batches.commit("orders", source, axis, ("action:get",), result)
    if mode in {"fallback", "provided"}:
        assert accepted is not None
        assert (
            _fact("has", (holder, Atom(value="sensitive")), Context.ACCEPTED)
            in accepted.facts
        )
        other_term = _fact("has", (outside, Atom(value="sensitive")), Context.ACCEPTED)
        other_role = _fact("has", (holder, Atom(value="credential")), Context.ACCEPTED)
        if axis == "classification" or provided is not None:
            assert other_term not in accepted.facts
            assert other_role not in accepted.facts
        else:
            assert other_term in accepted.facts
            assert other_role in accepted.facts
        assert any(
            key.startswith("accepted-batch:orders:") for key, _ in repository.saved
        )
    else:
        assert accepted is None or not any(
            f.predicate.name == "has" for f in accepted.facts
        )
        assert any(key.startswith("proposal:orders:") for key, _ in repository.saved)
        assert grounding.promotion.parked_lead_states()


def _revision_graphs():
    action = Atom(value="action:get")
    holder = input_field(action, Atom(value="token"))
    declarations = (
        _fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
        _fact("is", (holder, Atom(value="InputField")), Context.ACCEPTED),
    )
    return tuple(
        QdlGraph(
            facts=(
                *declarations,
                _fact("has", (holder, Atom(value=role)), Context.ACCEPTED),
            )
        )
        for role in ("setup_value", "setup_skip")
    )


@pytest.mark.parametrize("revision_addressed", [False, True])
def test_promoter_returns_exact_saved_revision(revision_addressed, monkeypatch):
    previous, promoted = _revision_graphs()
    repository = _Repository()
    grounding = make_grounding(repository)
    writes = []
    monkeypatch.setattr(
        repository, "save", lambda *args, **kwargs: writes.append((args, kwargs))
    )
    provenance = {"source_kind": "test", "evidence_refs": ["obs:a"]}
    saved, source_id = grounding.promotion.save_promoted_graph(
        "accepted-batch:orders:test",
        promoted,
        previous=previous,
        provenance=provenance,
        adapter_version="test-v1",
        revision_addressed=revision_addressed,
    )
    assert writes == [
        (
            (source_id, saved),
            {
                "provenance": provenance,
                "adapter_version": "test-v1",
                "mapping_report": {"mapped": len(saved.facts), "unmapped": 0},
            },
        )
    ]
    assert writes[0][0][1] is saved
    assert any(f.predicate.name == "supersedes" for f in saved.facts)
    assert source_id == "accepted-batch:orders:test" + (
        f":{saved.content_hash}" if revision_addressed else ""
    )
    assert len(saved.facts) > len(promoted.facts)
    assert not any(f.predicate.name == "supersedes" for f in promoted.facts)


@pytest.mark.parametrize(
    "branch,failure",
    [
        (branch, failure)
        for branch in (False, True)
        for failure in (None, "before_save", "save", "after_save")
        if branch or failure != "after_save"
    ],
)
def test_batch_revision_persistence_phases(branch, failure, monkeypatch):
    from cloud_dast.runtime.grounding import promotion as promotion_module

    previous, promoted = _revision_graphs()
    repository = _Repository()
    grounding = make_grounding(repository)
    append = grounding_runtime.append_supersession
    events, writes = [], []

    def outer_append(graph, old):
        phase = "after_save" if branch else "before_save"
        events.append(phase)
        if failure == phase:
            raise RuntimeError(phase)
        return append(graph, old)

    def inner_append(graph, old):
        events.append("prepare_save")
        assert old is (previous if branch else None)
        if branch and failure == "before_save":
            raise RuntimeError("before_save")
        result = append(graph, old)
        if not branch:
            assert result is graph  # The already prepared delta is an identity no-op.
        return result

    def save(source_id, graph, **kwargs):
        events.append("save")
        if failure == "save":
            raise RuntimeError("save")
        writes.append((source_id, graph, kwargs))

    monkeypatch.setattr(grounding_runtime, "append_supersession", outer_append)
    monkeypatch.setattr(promotion_module, "append_supersession", inner_append)
    monkeypatch.setattr(repository, "save", save)

    def commit():
        return grounding.batches._save(
            "orders",
            "roles",
            ("action:get",),
            "roles:action:get",
            promoted,
            evidence_refs=frozenset({"obs:z", "obs:a"}),
            previous=previous,
            branch=branch,
        )

    if failure:
        with pytest.raises(RuntimeError, match=failure):
            commit()
    else:
        returned = commit()
        assert returned == writes[0][1]
        if not branch:
            assert returned is writes[0][1]
        assert any(f.predicate.name == "supersedes" for f in returned.facts)
    expected = (
        ["prepare_save", "save", "after_save"]
        if branch
        else ["before_save", "prepare_save", "save"]
    )
    if failure == "before_save":
        expected = expected[:1]
    elif failure == "save":
        expected = expected[: expected.index("save") + 1]
    assert events == expected
    assert len(writes) == (1 if failure in {None, "after_save"} else 0)
    if writes:
        source_id, saved, metadata = writes[0]
        assert (
            source_id
            == f"accepted-batch:orders:reactive:roles:action:get:{saved.content_hash}"
        )
        assert metadata == {
            "provenance": {
                **(
                    {"source_kind": "branch-grounding", "action": "action:get"}
                    if branch
                    else {
                        "source_kind": "reactive-grounding",
                        "axis": "roles",
                        "actions": ["action:get"],
                    }
                ),
                "evidence_refs": ["obs:a", "obs:z"],
            },
            "adapter_version": "branch-grounding-v1"
            if branch
            else "reactive-grounding-v1",
            "mapping_report": {"mapped": len(saved.facts), "unmapped": 0},
        }
