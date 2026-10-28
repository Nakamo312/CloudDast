"""Trust-boundary tests for automatic proposal promotion."""

from __future__ import annotations

from cloud_dast.config import MAX_SEMANTIC_FACTS
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    create,
    field,
    input_field,
    output_field,
    reached,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import AutoGroundingService
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
from tests.grounding_owner import commit_reactive


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

    def ground_staged_stream(self, source, *, cache_source=None):
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
    return AutoGroundingService(
        _Repository(),
        promotion_policy=policy,
    )._promotion.promote(
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

    promoted = AutoGroundingService(
        repository,
        promotion_policy=PromotionPolicy(enabled=True),
    )._promotion.promote(
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
    grounding = AutoGroundingService(
        repository,
        promotion_policy=PromotionPolicy(enabled=False),
    )

    promoted = grounding._promotion.promote(
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
        grounding = AutoGroundingService(
            repository, promotion_policy=PromotionPolicy(enabled=False)
        )
        assert (
            grounding._promotion.promote(
                ProposalPromotionRequest(
                    source, proposal("object_ref"), evidence_fields=frozenset()
                ),
                proposal_source_id="proposal:orders:roles:b0",
            )
            is None
        )
        assert (
            grounding._promotion.promote(
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
    grounding = AutoGroundingService(repository, promotion_policy=policy)

    def proposal(field_name: str) -> QdlGraph:
        field_term = input_field(action, Atom(value=field_name))
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (field_term, Atom(value="Field")), Context.PROPOSAL),
                _fact("has", (field_term, Atom(value="object_ref")), Context.PROPOSAL),
            )
        )

    first = grounding._promotion.promote(
        ProposalPromotionRequest(
            source, proposal("first"), evidence_fields=frozenset()
        ),
    )
    second = grounding._promotion.promote(
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
    grounding = AutoGroundingService(
        _Repository(),
        promotion_policy=PromotionPolicy(enabled=True),
    )

    grounding._promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:first"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:first",
    )
    grounding._promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:first"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:repeat",
    )
    grounding._promotion.promote(
        ProposalPromotionRequest(
            source,
            proposal,
            evidence_refs=frozenset({"observation:second"}),
            evidence_fields=frozenset(),
        ),
        proposal_source_id="proposal:test:lead:second",
    )

    leads = grounding.parked_lead_states()

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
    grounding = AutoGroundingService(
        store,
        axis_grounding=_StaticAxisGrounding(proposal),
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
    grounding = AutoGroundingService(
        store,
        axis_grounding=_StaticAxisGrounding(proposal),
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
        grounding = AutoGroundingService(
            repository,
            axis_grounding=_RevisionAxisGrounding(
                [proposal(old_role), proposal(new_role), proposal(new_role)]
            ),
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
        grounding = AutoGroundingService(
            repository,
            axis_grounding=_RevisionAxisGrounding(
                [
                    proposal(old_effect, old_sink),
                    proposal(new_effect, new_sink),
                    proposal(new_effect, new_sink),
                ]
            ),
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
    grounding = AutoGroundingService(
        store,
        axis_grounding=_StaticStartupAxisGrounding(proposal),
        promotion_policy=PromotionPolicy(enabled=False),
    )

    handle = grounding.start_grounded("orders", ThreadedGroundingRunner())
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
