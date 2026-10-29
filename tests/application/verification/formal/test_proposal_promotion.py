from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import sleep

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    allowed,
    canonical_json,
    changed,
    create,
    duration,
    field,
    has,
    input_field,
    output_field,
    reached,
    remove,
    transition,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.semantic_norm_compiler import (
    sensitive_exposure_effects,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.promotion import (
    ClassificationPromotionContext,
    ProposalPromotionRequest,
    promote_payload_corpus_proposal,
    promote_proposal,
)
from cloud_dast_fuzzing.corpus import (
    PayloadCorpusDelta,
    PayloadSlotAlternative,
    load_payload_corpus,
)
from tests.grounding_owner import make_grounding


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _source() -> QdlGraph:
    action = Atom(value="action:get-secret")
    resource = Atom(value="resource:secret")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
        )
    )


def test_campaign_cap_is_atomic(monkeypatch) -> None:
    import importlib

    owner = importlib.import_module(PromotionPolicy.__module__)
    original = owner.promote_proposal
    start = Barrier(8)

    def delayed(*args, **kwargs):
        sleep(0.01)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, "promote_proposal", delayed)
    policy = PromotionPolicy(enabled=True, max_norms=1)

    def promote(index):
        start.wait(timeout=5)
        return policy.promote(
            ProposalPromotionRequest(
                source=_source(),
                proposal=_proposal(
                    (
                        Atom(value=f"norm:concurrent-{index}"),
                        allowed(Atom(value="action:get-secret")),
                    )
                ),
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(promote, range(8)))

    assert sum(len(result.promoted_norms) for result in results) == 1
    assert policy.promoted_norms == 1
    assert policy.exhausted
    assert sum(result.parked_semantics is not None for result in results) == 7


def test_failed_admission_does_not_spend_campaign_cap(monkeypatch) -> None:
    import importlib

    owner = importlib.import_module(PromotionPolicy.__module__)
    policy = PromotionPolicy(enabled=True, max_norms=1)
    request = ProposalPromotionRequest(
        source=_source(),
        proposal=_proposal(
            (Atom(value="norm:retry"), allowed(Atom(value="action:get-secret")))
        ),
    )

    def fail(*args, **kwargs):
        raise RuntimeError("admission interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(owner, "promote_proposal", fail)
        with pytest.raises(RuntimeError, match="admission interrupted"):
            policy.promote(request)

    assert policy.promoted_norms == policy.promoted_semantic_facts == 0
    assert policy.promote(request).promoted_norms == ("norm:retry",)


def _proposal(*effects: tuple[Atom, object]) -> QdlGraph:
    action = Atom(value="action:get-secret")
    resource = Atom(value="resource:secret")
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
        _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
    ]
    for norm, effect in effects:
        for argument in effect.args:
            if (
                isinstance(argument, Atom)
                and isinstance(argument.value, str)
                and argument.value.startswith("action:")
            ):
                facts.append(
                    _fact("is", (argument, Atom(value="Action")), Context.PROPOSAL)
                )
        facts.extend(
            (
                _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
                _fact("prevents", (norm, effect), Context.PROPOSAL),
            )
        )
    unique = {canonical_json(fact): fact for fact in facts}
    return QdlGraph(facts=tuple(unique.values()))


def _payload_source() -> QdlGraph:
    action = Atom(value="action:get")
    field_term = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:interpreter")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (field_term, Atom(value="InputField")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT),
            _fact("reaches", (field_term, sink), Context.CONTRACT),
            _fact("dialect", (sink, Atom(value="ansi")), Context.CONTRACT),
        )
    )


def _payload_delta() -> PayloadCorpusDelta:
    return PayloadCorpusDelta(
        slot_alternatives=(
            PayloadSlotAlternative(
                production_id="sql-ansi",
                slot_name="terminator",
                alternatives=("\n",),
            ),
        )
    )


def _new_production_delta() -> PayloadCorpusDelta:
    production = next(
        item
        for item in load_payload_corpus().productions
        if item.production_id == "sql-ansi"
    ).model_copy(update={"production_id": "sql-enriched", "default": False})
    return PayloadCorpusDelta(productions=(production,))


def test_promotes_graph_grounded_action_bound_norm() -> None:
    source = _source()
    proposal = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get-secret"))),
        (Atom(value="norm:no-write"), allowed(Atom(value="action:unknown"))),
        (
            Atom(value="norm:no-change"),
            changed(Atom(value="resource:secret"), Atom(value="payload")),
        ),
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ("norm:no-read",)
    assert set(result.rejected_norms) == {"norm:no-write", "norm:no-change"}
    assert any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "prevents"
        for fact in result.graph.facts
    )
    assert all(fact.context is Context.ACCEPTED for fact in result.graph.facts)
    assert QdlPlanner().plan(result.graph).invariants


def test_intersected_promotion_accepts_only_the_common_grounded_norm() -> None:
    """A single proposal is enough; intersection is not a vote threshold."""

    source = _source()
    common = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get-secret")))
    )
    first = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get-secret"))),
        (Atom(value="norm:no-write"), allowed(Atom(value="action:unknown"))),
    )
    policy = PromotionPolicy(enabled=True, max_norms=None)

    singleton = policy.promote_intersected_proposals(source, (common,))
    intersected = policy.promote_intersected_proposals(source, (first, common))

    assert singleton.promoted_norms == ("norm:no-read",)
    assert intersected.promoted_norms == ("norm:no-read",)
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "prevents"
        for fact in intersected.graph.facts
        if fact.args[0].value == "norm:no-write"
    )


def test_promotion_request_freezes_duration_thresholds() -> None:
    thresholds = {"read": 150}
    request = ProposalPromotionRequest(
        source=QdlGraph(),
        proposal=QdlGraph(),
        duration_thresholds=thresholds,
    )

    thresholds["write"] = 300

    assert dict(request.duration_thresholds or {}) == {"read": 150}


def test_intersected_promotion_with_empty_intersection_accepts_nothing() -> None:
    source = _source()
    first = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get-secret")))
    )
    second = _proposal(
        (Atom(value="norm:no-write"), allowed(Atom(value="action:get-secret")))
    )
    result = PromotionPolicy(
        enabled=True, max_norms=None
    ).promote_intersected_proposals(
        source,
        (first, second),
    )

    assert not result.promoted
    assert result.graph.facts == ()


def test_intersected_promotion_cannot_bypass_classification_provenance() -> None:
    action = Atom(value="action:create-order")
    field_term = input_field(action, Atom(value="gift_card_id"))
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field_term, Atom(value="InputField")), Context.PROPOSAL),
            _fact("has", (field_term, Atom(value="credential")), Context.PROPOSAL),
        )
    )

    result = PromotionPolicy(
        enabled=True, max_norms=None
    ).promote_intersected_proposals(
        source,
        (proposal, proposal),
    )

    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "has"
        for fact in result.graph.facts
    )
    assert result.parked_classifications is not None
    assert any(
        fact.predicate.name == "has"
        and fact.args == (field_term, Atom(value="credential"))
        for fact in result.parked_classifications.facts
    )


def test_promotion_limit_is_applied() -> None:
    source = _source()
    proposal = _proposal(
        (Atom(value="norm:first"), allowed(Atom(value="action:get-secret"))),
        (Atom(value="norm:second"), allowed(Atom(value="action:get-secret"))),
    )

    result = promote_proposal(source, proposal, max_norms=1)

    assert result.promoted_norms == ("norm:first",)
    assert len(QdlPlanner().plan(result.graph).invariants) == 1


def _authorized_policy_source(action: Atom) -> QdlGraph:
    attacker = Atom(value="principal:attacker")
    resource = Atom(value="resource:target")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (attacker, Atom(value="Subject")), Context.CONTRACT),
            _fact("attacker", (attacker,), Context.CONTRACT),
            _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
            _fact("may", (attacker, action, resource), Context.CONTRACT),
        )
    )


def test_model_norm_contradicting_policy_is_parked_as_a_lead() -> None:
    action = Atom(value="action:get")
    source = _authorized_policy_source(action)
    proposal = _proposal(
        (Atom(value="norm:no-allowed"), allowed(Atom(value="action:get")))
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ()
    assert result.parked_norms is not None
    assert all(fact.context is Context.PROPOSAL for fact in result.parked_norms.facts)
    original_norms = {
        fact.args[0].value
        for fact in result.parked_norms.facts
        if fact.predicate.name == "prevents" and fact.args[0].value == "norm:no-allowed"
    }
    lead_norms = {
        fact.args[0].value
        for fact in result.parked_norms.facts
        if fact.predicate.name == "prevents"
        and isinstance(fact.args[0].value, str)
        and fact.args[0].value.startswith("norm:lead:policy:")
    }
    assert original_norms == {"norm:no-allowed"}
    assert len(lead_norms) == 1
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "prevents"
        for fact in result.graph.facts
    )
    assert QdlPlanner().plan(result.parked_norms).invariants == ()


def test_parked_policy_norm_reaches_the_persisted_proposal_source() -> None:
    action = Atom(value="action:get")
    source = _authorized_policy_source(action)
    proposal = _proposal(
        (Atom(value="norm:no-allowed"), allowed(Atom(value="action:get")))
    )

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
        proposal_source_id="proposal:test:norms:b0",
    )

    assert repository.saved[0][0] == (
        f"proposal:test:norms:b0:{repository.saved[0][1].content_hash}"
    )
    assert any(
        fact.predicate.name == "prevents"
        and isinstance(fact.args[0].value, str)
        and fact.args[0].value.startswith("norm:lead:policy:")
        for fact in repository.saved[0][1].facts
    )


@pytest.mark.parametrize("method_id", ["CreateApiKey", "ImportPickle"])
def test_a25_unexpected_authorized_actions_do_not_promote(method_id: str) -> None:
    action = Atom(value=f"action:{method_id}")
    source = _authorized_policy_source(action)
    proposal = _proposal((Atom(value=f"norm:{method_id.lower()}"), allowed(action)))

    result = PromotionPolicy(enabled=True).promote(
        ProposalPromotionRequest(source=source, proposal=proposal)
    )

    assert result.promoted_norms == ()
    assert result.rejected_norms == ()
    assert result.parked_norms is not None
    assert any(
        fact.predicate.name == "prevents"
        and isinstance(fact.args[0].value, str)
        and fact.args[0].value.startswith("norm:lead:policy:")
        for fact in result.parked_norms.facts
    )


def test_promotion_rejects_invalid_limit() -> None:
    with pytest.raises(ValueError, match="max_norms"):
        promote_proposal(_source(), _proposal(), max_norms=0)


def test_promotion_keeps_semantic_facts_with_declarations() -> None:
    action = Atom(value="action:get")
    field_term = input_field(action, Atom(value="secret_id"))
    contract = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            _fact("is", (field_term, Atom(value="Field")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(field_term, Atom(value="Field")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(field_term, Atom(value="object_ref")),
            ),
        )
    )

    result = promote_proposal(contract, proposal)

    assert result.promoted_semantic_facts >= 1
    facts = {(f.predicate.name, f.context) for f in result.graph.facts}
    assert ("has", Context.ACCEPTED) in facts
    # The supporting declaration is promoted alongside the role.
    assert any(
        f.predicate.name == "is"
        and f.context is Context.ACCEPTED
        and f.args == (field_term, Atom(value="Field"))
        for f in result.graph.facts
    )


def test_semantic_promotion_cap_reports_overflow() -> None:
    action = Atom(value="action:get")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            *(
                _fact(
                    "is",
                    (
                        input_field(action, Atom(value=f"field:{index}")),
                        Atom(value="Field"),
                    ),
                    Context.CONTRACT,
                )
                for index in range(2)
            ),
        )
    )
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
    ]
    for index in range(2):
        field_term = input_field(action, Atom(value=f"field:{index}"))
        facts.extend(
            (
                _fact("is", (field_term, Atom(value="Field")), Context.PROPOSAL),
                _fact("has", (field_term, Atom(value="object_ref")), Context.PROPOSAL),
            )
        )

    result = promote_proposal(
        source,
        QdlGraph(facts=tuple(facts)),
        max_semantic_facts=3,
    )

    assert result.promoted_semantic_facts == 3
    assert result.rejected_semantic_facts == 1
    assert len(result.graph.facts) == 3


def test_semantic_promotion_rejects_invalid_cap() -> None:
    with pytest.raises(ValueError, match="max_semantic_facts"):
        promote_proposal(_source(), _proposal(), max_semantic_facts=0)


@pytest.mark.parametrize("source_declares_role", [False, True])
def test_sensitive_field_role_requires_source_provenance(
    source_declares_role: bool,
) -> None:
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
    source = QdlGraph(facts=tuple(source_facts))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (principal, Atom(value="Principal")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("exposes", (action, witness), Context.PROPOSAL),
            _fact("has", (witness, Atom(value="sensitive")), Context.PROPOSAL),
            _fact("prevents", (norm, has(principal, witness)), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)
    effects = sensitive_exposure_effects(result.graph)

    assert bool(effects) is source_declares_role
    assert result.promoted_norms == (("norm:no-leak",) if source_declares_role else ())
    assert (result.parked_classifications is not None) is not source_declares_role
    assert (
        any(
            fact.context is Context.ACCEPTED
            and fact.predicate.name == "has"
            and fact.args == (witness, Atom(value="sensitive"))
            for fact in result.graph.facts
        )
        is source_declares_role
    )


def test_unproven_classification_promotes_from_observed_evidence() -> None:
    action = Atom(value="action:get-profile")
    resource = Atom(value="resource:user")
    witness = field(resource, Atom(value="email"))
    principal = Atom(value="principal:attacker")
    norm = Atom(value="norm:no-leak")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
            _fact("is", (witness, Atom(value="Field")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (principal, Atom(value="Principal")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("exposes", (action, witness), Context.PROPOSAL),
            _fact("has", (witness, Atom(value="sensitive")), Context.PROPOSAL),
            _fact("prevents", (norm, has(principal, witness)), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        evidence_fields=frozenset({"email"}),
    )

    assert "norm:no-leak" in result.promoted_norms
    assert result.parked_classifications is None
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (witness, Atom(value="sensitive"))
        for fact in result.graph.facts
    )


def test_evidence_grounds_new_field_only_on_target_resource() -> None:
    action = Atom(value="action:get-profile")
    resource = Atom(value="resource:user")
    witness = field(resource, Atom(value="email"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
            _fact("targets", (action, resource), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Field")), Context.PROPOSAL),
            _fact("exposes", (action, witness), Context.PROPOSAL),
            _fact("has", (witness, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        evidence_fields=frozenset({"email"}),
    )

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "exposes"
        and fact.args == (action, witness)
        for fact in result.graph.facts
    )
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (witness, Atom(value="sensitive"))
        for fact in result.graph.facts
    )


def _semantic_proposal(
    effect_kind: str,
    *,
    bound: bool,
) -> tuple[QdlGraph, QdlGraph, object]:
    action = Atom(value="action:update")
    resource = Atom(value="resource:order")
    norm = Atom(value="norm:semantic")
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
        _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
    ]

    if effect_kind == "has":
        witness = field(resource, Atom(value="email"))
        effect = has(Atom(value="principal:attacker"), witness)
        facts.extend(
            (
                _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
                _fact("is", (witness, Atom(value="Field")), Context.PROPOSAL),
                _fact(
                    "is",
                    (Atom(value="principal:attacker"), Atom(value="Principal")),
                    Context.PROPOSAL,
                ),
                _fact("has", (witness, Atom(value="sensitive")), Context.PROPOSAL),
            )
        )
        if bound:
            facts.append(_fact("exposes", (action, witness), Context.PROPOSAL))
    elif effect_kind == "changed":
        effect = changed(resource, Atom(value="role"))
        facts.append(_fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL))
        if bound:
            facts.append(_fact("causes", (action, effect), Context.PROPOSAL))
    elif effect_kind == "transition":
        from_state = Atom(value="created")
        to_state = Atom(value="approved")
        effect = transition(from_state, to_state)
        facts.extend(
            (
                _fact("is", (from_state, Atom(value="State")), Context.PROPOSAL),
                _fact("is", (to_state, Atom(value="State")), Context.PROPOSAL),
            )
        )
        if bound:
            facts.append(
                _fact("transition", (action, from_state, to_state), Context.PROPOSAL)
            )
    else:  # pragma: no cover - guarded by parametrization
        raise AssertionError(f"unknown effect kind: {effect_kind}")

    facts.append(_fact("prevents", (norm, effect), Context.PROPOSAL))
    source_facts = [_fact("is", (action, Atom(value="Action")), Context.CONTRACT)]
    if effect_kind == "has":
        source_facts.extend(
            (
                _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
                _fact("is", (witness, Atom(value="Field")), Context.CONTRACT),
                _fact("has", (witness, Atom(value="sensitive")), Context.CONTRACT),
            )
        )
    source = QdlGraph(facts=tuple(source_facts))
    return source, QdlGraph(facts=tuple(facts)), effect


@pytest.mark.parametrize("effect_kind", ["has", "changed", "transition"])
def test_promotes_action_bound_semantic_effect(effect_kind: str) -> None:
    source, proposal, effect = _semantic_proposal(effect_kind, bound=True)

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ("norm:semantic",)
    assert result.rejected_norms == ()
    assert all(fact.context is Context.ACCEPTED for fact in result.graph.facts)
    invariants = QdlPlanner().plan(result.graph).invariants
    assert len(invariants) == 1
    assert invariants[0].effect == effect


def test_rejects_duration_proposal_without_runtime_baseline() -> None:
    source = _source()
    proposal = _proposal(
        (
            Atom(value="norm:latency"),
            duration(Atom(value="action:get-secret"), Atom(value=5000)),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:latency",)


def test_calibrates_duration_proposal_from_runtime_baseline() -> None:
    action = Atom(value="action:get-secret")
    observations = tuple(Atom(value=f"observation:{index}") for index in range(3))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            *(
                _fact(
                    "is",
                    (observation, Atom(value="Observation")),
                    Context.RUNTIME,
                )
                for observation in observations
            ),
            *(
                _fact(
                    "evidence",
                    (
                        observation,
                        duration(action, Atom(value=value)),
                    ),
                    Context.RUNTIME,
                )
                for observation, value in zip(
                    observations,
                    (100, 102, 104),
                    strict=True,
                )
            ),
        )
    )
    proposal = _proposal(
        (
            Atom(value="norm:latency"),
            duration(Atom(value="action:get-secret"), Atom(value=5000)),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ("norm:latency",)
    invariants = QdlPlanner().plan(result.graph).invariants
    assert len(invariants) == 1
    assert invariants[0].effect == duration(action, Atom(value=113))


@pytest.mark.parametrize("effect_kind", ["has", "changed", "transition"])
def test_rejects_semantic_effect_without_an_action_binding(effect_kind: str) -> None:
    source, proposal, _effect = _semantic_proposal(effect_kind, bound=False)

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:semantic",)
    assert not QdlPlanner().plan(result.graph).invariants


def test_promotes_changed_effect_from_privileged_target_semantics() -> None:
    action = Atom(value="action:order.update")
    resource = Atom(value="resource:order")
    role = input_field(action, Atom(value="role"))
    norm = Atom(value="norm:no-role-change")
    effect = changed(resource, Atom(value="role"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (resource, Atom(value="Resource")), Context.CONTRACT),
            _fact("is", (role, Atom(value="Field")), Context.CONTRACT),
            _fact("has", (role, Atom(value="privileged")), Context.CONTRACT),
            _fact("targets", (action, resource), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (role, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("has", (role, Atom(value="privileged")), Context.PROPOSAL),
            _fact("prevents", (norm, effect), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ("norm:no-role-change",)
    assert result.rejected_norms == ()
    assert QdlPlanner().plan(result.graph).invariants


def test_promotes_filesystem_reach_semantics() -> None:
    action = Atom(value="action:import")
    path = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:file")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (path, Atom(value="Field")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="filesystem")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (path, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="filesystem")), Context.PROPOSAL),
            _fact("reaches", (path, sink), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_semantic_facts >= 1
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "reaches"
        and fact.args == (path, sink)
        for fact in result.graph.facts
    )


def test_promotes_business_flow_reach_semantics() -> None:
    action = Atom(value="action:ship")
    order_id = input_field(action, Atom(value="order_id"))
    sink = Atom(value="sink:business-rule")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (order_id, Atom(value="InputField")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="business_flow")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (order_id, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="business_flow")), Context.PROPOSAL),
            _fact("reaches", (order_id, sink), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_semantic_facts >= 1
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "reaches"
        and fact.args == (order_id, sink)
        for fact in result.graph.facts
    )


def test_reach_rejects_proposal_declared_sink_type() -> None:
    action = Atom(value="action:import")
    path = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:file")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (path, Atom(value="Field")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (path, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="filesystem")), Context.PROPOSAL),
            _fact("reaches", (path, sink), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_semantic_facts == 0
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "reaches"
        for fact in result.graph.facts
    )
    assert result.parked_classifications is not None
    assert any(
        fact.predicate.name == "is" and fact.args == (sink, Atom(value="filesystem"))
        for fact in result.parked_classifications.facts
    )


def test_promotes_graph_grounded_grammar_facts() -> None:
    action = Atom(value="action:import")
    path = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:file")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (path, Atom(value="Field")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="filesystem")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (path, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="filesystem")), Context.PROPOSAL),
            _fact("reaches", (path, sink), Context.PROPOSAL),
            _fact("format", (path, Atom(value="path")), Context.PROPOSAL),
            _fact(
                "constraint",
                (path, Atom(value="ne"), Atom(value="seed")),
                Context.PROPOSAL,
            ),
            _fact("dialect", (sink, Atom(value="posix")), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    promoted = {
        fact.predicate.name
        for fact in result.graph.facts
        if fact.context is Context.ACCEPTED
    }
    assert {"reaches", "format", "constraint", "dialect"} <= promoted
    assert result.parked_classifications is None


@pytest.mark.parametrize(
    "type_order", [("Sink", "interpreter"), ("interpreter", "Sink")]
)
@pytest.mark.parametrize("source_context", [Context.CONTRACT, Context.ACCEPTED])
@pytest.mark.parametrize("anchored", [False, True])
def test_sink_type_relation_is_independent_of_declaration_order(
    type_order: tuple[str, str],
    source_context: Context,
    anchored: bool,
) -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    norm = Atom(value="norm:no-injection")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (query, Atom(value="InputField")), Context.CONTRACT),
            *(
                _fact("is", (sink, Atom(value=kind)), source_context)
                for kind in type_order
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (query, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("reaches", (query, sink), Context.PROPOSAL),
            _fact("dialect", (sink, Atom(value="ansi")), Context.PROPOSAL),
            _fact("prevents", (norm, reached(action, sink)), Context.PROPOSAL),
        )
    )
    context = (
        ClassificationPromotionContext(
            term=canonical_json(sink),
            allowed_values=frozenset({"interpreter"}),
            invariant_id="inv:no-injection",
        )
        if anchored
        else None
    )

    result = promote_proposal(source, proposal, classification_context=context)

    assert result.promoted_norms == ("norm:no-injection",)
    assert result.rejected_norms == ()
    assert result.parked_classifications is None
    for predicate, args in (
        ("reaches", (query, sink)),
        ("dialect", (sink, Atom(value="ansi"))),
    ):
        assert any(
            fact.context is Context.ACCEPTED
            and fact.predicate.name == predicate
            and fact.args == args
            for fact in result.graph.facts
        )


@pytest.mark.parametrize("untrusted_context", [None, Context.PROPOSAL, Context.RUNTIME])
def test_sink_type_relation_excludes_model_only_and_untrusted_source_types(
    untrusted_context: Context | None,
) -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    norm = Atom(value="norm:no-injection")
    source_facts = [
        _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
        _fact("is", (query, Atom(value="InputField")), Context.CONTRACT),
        _fact("is", (sink, Atom(value="Sink")), Context.CONTRACT),
        _fact(
            "is",
            (Atom(value="sink:other"), Atom(value="interpreter")),
            Context.ACCEPTED,
        ),
    ]
    if untrusted_context is not None:
        source_facts.append(
            _fact("is", (sink, Atom(value="interpreter")), untrusted_context)
        )
    source = QdlGraph(facts=tuple(source_facts))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (query, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("reaches", (query, sink), Context.PROPOSAL),
            _fact("dialect", (sink, Atom(value="ansi")), Context.PROPOSAL),
            _fact("prevents", (norm, reached(action, sink)), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(sink),
            allowed_values=frozenset({"interpreter"}),
            invariant_id="inv:no-injection",
        ),
    )

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:no-injection",)
    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name in {"reaches", "dialect"}
        for fact in result.graph.facts
    )
    assert result.parked_classifications is not None
    assert any(
        fact.predicate.name == "is" and fact.args == (sink, Atom(value="interpreter"))
        for fact in result.parked_classifications.facts
    )


@pytest.mark.parametrize("holder", [input_field, output_field])
@pytest.mark.parametrize(
    "declaration_type", [None, "Field", "InputField", "OutputField", "Resource"]
)
@pytest.mark.parametrize(
    "source_context",
    [Context.CONTRACT, Context.ACCEPTED, Context.PROPOSAL, Context.RUNTIME],
)
def test_reach_requires_exact_source_field_declaration(
    holder,
    declaration_type: str | None,
    source_context: Context,
) -> None:
    action = Atom(value="action:search")
    carrier = holder(action, Atom(value="ghost"))
    sink = Atom(value="sink:sql")
    norm = Atom(value="norm:no-injection")
    field_type = "InputField" if holder is input_field else "OutputField"
    source_facts = [
        _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
        _fact(
            "is", (Atom(value="action:other"), Atom(value="Action")), Context.CONTRACT
        ),
        _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT),
        _fact(
            "is",
            (holder(action, Atom(value="existing")), Atom(value=field_type)),
            Context.CONTRACT,
        ),
        _fact(
            "is",
            (
                holder(Atom(value="action:other"), Atom(value="ghost")),
                Atom(value=field_type),
            ),
            Context.CONTRACT,
        ),
    ]
    if declaration_type is not None:
        source_facts.append(
            _fact("is", (carrier, Atom(value=declaration_type)), source_context)
        )
    source = QdlGraph(facts=tuple(source_facts))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (carrier, Atom(value=field_type)), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("reaches", (carrier, sink), Context.PROPOSAL),
            _fact("prevents", (norm, reached(action, sink)), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    expected = source_context in {Context.CONTRACT, Context.ACCEPTED} and (
        declaration_type in {"Field", field_type}
    )
    promoted_reach = any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "reaches"
        and fact.args == (carrier, sink)
        for fact in result.graph.facts
    )
    assert promoted_reach is expected
    # A rejected carrier must not support a norm through _supported_facts either.
    # The existing compiler derives reached norms only from input carriers.
    supports_norm = expected and holder is input_field
    assert result.promoted_norms == (("norm:no-injection",) if supports_norm else ())
    assert result.rejected_norms == (() if supports_norm else ("norm:no-injection",))


@pytest.mark.parametrize("dependency", ["sink", "input"])
@pytest.mark.parametrize("source_declared", [False, True])
def test_dependency_closure_cannot_launder_schema_or_sink_types_across_promotions(
    dependency: str,
    source_declared: bool,
) -> None:
    action = Atom(value="action:search")
    carrier = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    if dependency == "input":
        carrier = input_field(action, Atom(value="ghost"))
    else:
        sink = Atom(value="sink:invented")
    subject = carrier if dependency == "input" else sink
    kind = Atom(value="InputField" if dependency == "input" else "interpreter")
    declaration = _fact("is", (subject, kind), Context.PROPOSAL)
    source_facts = [_fact("is", (action, Atom(value="Action")), Context.CONTRACT)]
    if dependency == "input" or source_declared:
        source_facts.append(
            _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT)
        )
    if dependency == "sink" or source_declared:
        source_facts.append(
            _fact("is", (carrier, Atom(value="InputField")), Context.CONTRACT)
        )
    source = QdlGraph(facts=tuple(source_facts))
    support = (
        _fact("has", (carrier, Atom(value="attacker_controlled")), Context.PROPOSAL)
        if dependency == "input"
        else _fact("causes", (action, reached(action, sink)), Context.PROPOSAL)
    )
    first_proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            declaration,
            support,
        )
    )

    first = promote_proposal(source, first_proposal)

    copied_declaration = any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "is"
        and fact.args == declaration.args
        for fact in first.graph.facts
    )
    assert copied_declaration is source_declared
    if not source_declared:
        assert first.graph.facts == ()
        assert first.promoted_semantic_facts == 0
        assert not first.promoted
        assert any(issue.code == "closure" for issue in first.issues)
        if dependency == "sink":
            assert first.parked_classifications is not None
    norm = Atom(value="norm:no-injection")
    second_proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (carrier, Atom(value="InputField")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("reaches", (carrier, sink), Context.PROPOSAL),
            _fact("prevents", (norm, reached(action, sink)), Context.PROPOSAL),
        )
    )

    second = promote_proposal(merge_graphs(source, first.graph), second_proposal)

    promoted_reach = any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "reaches"
        for fact in second.graph.facts
    )
    assert promoted_reach is source_declared
    assert second.promoted_norms == (("norm:no-injection",) if source_declared else ())


def test_invalid_dependency_closure_does_not_consume_semantic_quota() -> None:
    action = Atom(value="action:get")
    actual = input_field(action, Atom(value="query"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (actual, Atom(value="InputField")), Context.CONTRACT),
        )
    )

    def proposal(field_name: str) -> QdlGraph:
        holder = input_field(action, Atom(value=field_name))
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact("is", (holder, Atom(value="InputField")), Context.PROPOSAL),
                _fact("has", (holder, Atom(value="object_ref")), Context.PROPOSAL),
            )
        )

    policy = PromotionPolicy(enabled=True, max_semantic_facts=3)

    rejected = policy.promote(
        ProposalPromotionRequest(source=source, proposal=proposal("ghost"))
    )

    assert not rejected.promoted
    assert rejected.graph.facts == ()
    assert policy.promoted_semantic_facts == 0

    accepted = policy.promote(
        ProposalPromotionRequest(source=source, proposal=proposal("query"))
    )

    assert accepted.promoted
    assert policy.promoted_semantic_facts == 3
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (actual, Atom(value="object_ref"))
        for fact in accepted.graph.facts
    )


@pytest.mark.parametrize("has_reach", [True, False])
def test_reached_norm_requires_graph_reach(has_reach: bool) -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    norm = Atom(value="norm:no-injection")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (query, Atom(value="Field")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT),
        )
    )
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
        _fact("is", (query, Atom(value="Field")), Context.PROPOSAL),
        _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
        _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
        _fact("prevents", (norm, reached(action, sink)), Context.PROPOSAL),
    ]
    if has_reach:
        facts.append(_fact("reaches", (query, sink), Context.PROPOSAL))
    proposal = QdlGraph(facts=tuple(facts))

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == (("norm:no-injection",) if has_reach else ())
    assert result.rejected_norms == (() if has_reach else ("norm:no-injection",))


def test_has_norm_requires_sensitive_exposure_role() -> None:
    action = Atom(value="action:get-profile")
    resource = Atom(value="resource:user")
    witness = field(resource, Atom(value="email"))
    principal = Atom(value="principal:attacker")
    norm = Atom(value="norm:no-leak")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (witness, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (principal, Atom(value="Principal")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("exposes", (action, witness), Context.PROPOSAL),
            _fact("has", (witness, Atom(value="verbose")), Context.PROPOSAL),
            _fact("prevents", (norm, has(principal, witness)), Context.PROPOSAL),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:no-leak",)


@pytest.mark.parametrize("effect_kind", ["create", "remove"])
def test_promotes_registry_causal_semantics(effect_kind: str) -> None:
    action = Atom(value="action:registry")
    reference = Atom(value="resource:temporary")
    if effect_kind == "create":
        effect: Struct = create(reference)
        declaration_type = Atom(value="ResourceType")
    else:
        effect = remove(reference)
        declaration_type = Atom(value="Resource")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (reference, declaration_type), Context.PROPOSAL),
            _fact("causes", (action, effect), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        evidence_refs=frozenset({"observation:live-ownership"}),
    )

    assert result.promoted_norms == ()
    assert result.promoted_semantic_facts >= 1
    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and fact.args == (action, effect)
        for fact in result.graph.facts
    )


@pytest.mark.parametrize("effect_kind", ["create", "remove"])
def test_ownership_effects_require_evidence(effect_kind: str) -> None:
    """Create/remove decide setup ownership; without evidence they park."""

    action = Atom(value="action:svc.ApplyCoupon")
    reference = Atom(value="resource:order")
    if effect_kind == "create":
        effect: Struct = create(reference)
        declaration_type = Atom(value="ResourceType")
    else:
        effect = remove(reference)
        declaration_type = Atom(value="Resource")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (reference, declaration_type), Context.PROPOSAL),
            _fact("causes", (action, effect), Context.PROPOSAL),
        )
    )

    rejected = promote_proposal(source, proposal)

    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and fact.args == (action, effect)
        for fact in rejected.graph.facts
    )


def test_alternatives_create_is_rejected_without_evidence() -> None:
    """An alternatives batch cannot mint a setup provider from an action name.

    The action is source-declared and the batch is narrowed to it, so action
    binding alone would pass; only the ownership evidence gate rejects the
    create effect.
    """

    action = Atom(value="action:svc.ApplyCoupon")
    resource_type = Atom(value="resource:order")
    effect = create(resource_type)
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (resource_type, Atom(value="ResourceType")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource_type, Atom(value="ResourceType")), Context.PROPOSAL),
            _fact("causes", (action, effect), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        action_ids=frozenset({"action:svc.ApplyCoupon"}),
    )

    assert result.promoted_semantic_facts == 0
    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and fact.args == (action, effect)
        for fact in result.graph.facts
    )


def test_consultation_package_promotes_causes_and_parks_classification() -> None:
    action = Atom(value="action:create-order")
    field_term = input_field(action, Atom(value="gift_card_id"))
    resource_type = Atom(value="resource_type:gift-card")
    effect = create(resource_type)
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field_term, Atom(value="InputField")), Context.PROPOSAL),
            _fact(
                "is",
                (resource_type, Atom(value="ResourceType")),
                Context.PROPOSAL,
            ),
            _fact("causes", (action, effect), Context.PROPOSAL),
            _fact("has", (field_term, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        evidence_refs=frozenset({"observation:live-create"}),
    )

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "causes"
        and fact.args == (action, effect)
        for fact in result.graph.facts
    )
    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (field_term, Atom(value="sensitive"))
        for fact in result.graph.facts
    )
    assert result.parked_classifications is not None
    assert any(
        fact.predicate.name == "has"
        and fact.args == (field_term, Atom(value="sensitive"))
        for fact in result.parked_classifications.facts
    )


def test_runtime_dependency_fact_requires_observation_evidence() -> None:
    action = Atom(value="action:read-report")
    permission = Atom(value="permission:report.read")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (permission, Atom(value="Permission")), Context.PROPOSAL),
            _fact("requires", (action, permission), Context.PROPOSAL),
        )
    )

    without_evidence = promote_proposal(source, proposal)
    with_evidence = promote_proposal(
        source,
        proposal,
        evidence_refs=frozenset({"observation:live-read"}),
    )

    assert without_evidence.promoted_semantic_facts == 0
    assert any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "requires"
        for fact in with_evidence.graph.facts
    )
    assert with_evidence.parked_semantics is None


def test_promotion_ignores_runtime_action_declarations() -> None:
    action = Atom(value="action:get-secret")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.RUNTIME),)
    )
    proposal = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get-secret")))
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:no-read",)


def test_promotion_rejects_an_unknown_primitive() -> None:
    source = _source()
    proposal = _proposal(
        (
            Atom(value="norm:no-create"),
            create(Atom(value="resource:secret")),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:no-create",)


def test_promotion_limit_still_classifies_later_candidates() -> None:
    source = _source()
    proposal = _proposal(
        (Atom(value="norm:a-valid"), allowed(Atom(value="action:get-secret"))),
        (Atom(value="norm:b-valid"), allowed(Atom(value="action:get-secret"))),
        (Atom(value="norm:c-invalid"), allowed(Atom(value="action:unknown"))),
    )

    result = promote_proposal(source, proposal, max_norms=1)

    assert result.promoted_norms == ("norm:a-valid",)
    assert set(result.rejected_norms) == {"norm:b-valid", "norm:c-invalid"}
    assert len(QdlPlanner().plan(result.graph).invariants) == 1


def test_promotion_requires_self_contained_accepted_references() -> None:
    action = Atom(value="action:get-secret")
    sink = Atom(value="sink:sql")
    norm = Atom(value="norm:no-injection")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="Sink")), Context.RUNTIME),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact(
                "prevents",
                (norm, reached(action, sink)),
                Context.PROPOSAL,
            ),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()
    assert result.rejected_norms == ("norm:no-injection",)


def test_proposal_targets_cannot_bind_changed_norm() -> None:
    action = Atom(value="action:update")
    resource = Atom(value="resource:order")
    field_term = input_field(action, Atom(value="role"))
    norm = Atom(value="norm:no-role-change")
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (field_term, Atom(value="Field")), Context.CONTRACT),
            _fact("has", (field_term, Atom(value="privileged")), Context.CONTRACT),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (resource, Atom(value="Resource")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("targets", (action, resource), Context.PROPOSAL),
            _fact(
                "prevents",
                (norm, changed(resource, Atom(value="role"))),
                Context.PROPOSAL,
            ),
        )
    )

    result = promote_proposal(source, proposal)

    assert result.promoted_norms == ()


def _measured_reach_proposal() -> QdlGraph:
    action = Atom(value="action:get")
    field_term = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:canary-echo:query")
    norm = Atom(value="norm:measured-echo")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field_term, Atom(value="Field")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("reaches", (field_term, sink), Context.PROPOSAL),
            _fact(
                "prevents",
                (norm, reached(action, sink)),
                Context.PROPOSAL,
            ),
        )
    )


def test_measured_evidence_cannot_bypass_sink_witness_policy() -> None:
    action = Atom(value="action:get")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = _measured_reach_proposal()

    result = promote_proposal(
        source,
        proposal,
        action_ids=("action:get",),
    )

    assert result.promoted_norms == ()
    assert result.promoted_semantic_facts == 0
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "reaches"
        for fact in result.graph.facts
    )


def test_disabled_promotion_policy_parks_the_whole_proposal() -> None:
    action = Atom(value="action:get")
    source = QdlGraph(
        facts=(_fact("is", (action, Atom(value="Action")), Context.CONTRACT),)
    )
    proposal = _proposal(
        (Atom(value="norm:no-read"), allowed(Atom(value="action:get")))
    )
    policy = PromotionPolicy(enabled=False)

    result = policy.promote(ProposalPromotionRequest(source=source, proposal=proposal))

    assert result.promoted_norms == ()
    assert result.promoted_semantic_facts == 0
    assert result.graph.facts == ()
    assert result.parked_semantics is not None
    assert all(
        fact.context is Context.PROPOSAL for fact in result.parked_semantics.facts
    )


def test_payload_delta_promotion_requires_source_declared_grammar() -> None:
    result = promote_payload_corpus_proposal(
        _payload_source(),
        _payload_delta(),
        action_id="action:get",
        base_corpus=load_payload_corpus(),
    )

    assert result.promoted
    assert result.promoted_slot_alternatives == ("sql-ansi.terminator",)
    assert result.promoted_items == 1


def test_payload_delta_can_promote_a_new_non_default_production() -> None:
    result = promote_payload_corpus_proposal(
        _payload_source(),
        _new_production_delta(),
        action_id="action:get",
        base_corpus=load_payload_corpus(),
    )

    assert result.promoted
    assert result.promoted_productions == ("sql-enriched",)
    assert result.promoted_items == 1


def test_payload_delta_rejects_source_undeclared_sink_type() -> None:
    source = _payload_source()
    delta = PayloadCorpusDelta(
        slot_alternatives=(
            PayloadSlotAlternative(
                production_id="command-posix",
                slot_name="metachar",
                alternatives=("\n",),
            ),
        )
    )

    result = promote_payload_corpus_proposal(
        source,
        delta,
        action_id="action:get",
        base_corpus=load_payload_corpus(),
    )

    assert not result.promoted
    assert "slot target has source-undeclared grammar: command-posix.metachar" in (
        result.reasons
    )


def test_payload_promotion_policy_is_explicit_and_budgeted() -> None:
    policy = PromotionPolicy(enabled=True, max_payload_delta_items=1)

    first = policy.promote_payload_corpus(
        _payload_source(),
        _payload_delta(),
        action_id="action:get",
        base_corpus=load_payload_corpus(),
    )
    second = policy.promote_payload_corpus(
        _payload_source(),
        _payload_delta(),
        action_id="action:get",
        base_corpus=load_payload_corpus(),
    )

    assert first.promoted
    assert policy.promoted_payload_delta_items == 1
    assert not second.promoted
    assert second.status == "parked"
