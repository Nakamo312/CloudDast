from __future__ import annotations

import pytest

from cloud_dast.consultation import (
    CONSULTATION_INSTRUCTIONS,
    ConsultationBudget,
)
from cloud_dast.contracts.execution import ScenarioBinding
from cloud_dast.contracts.plan import InvariantProjection, QdlExecutionView
from cloud_dast.model import (
    AccessOutcome,
    Check,
    Observation,
    PolicyVerdict,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    changed,
    field,
    has,
    input_field,
    output_field,
    reached,
)
from cloud_dast.qdl.reasoning import QdlPlan, QdlSubgoal
from cloud_dast.runtime.deficits import (
    axis_for_subgoal,
    consultation_request,
    grounding_result_closes_deficit,
)
from cloud_dast.runtime.deficits import (
    gap_for_invariant as classification_deficit,
)
from cloud_dast.runtime.deficits import (
    gaps_for_observations as classification_deficits,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.verification.promotion import (
    ClassificationPromotionContext,
    promote_proposal,
)
from cloud_dast.verification.taxonomy import ClassificationFacts


def _invariant(effect, invariant_id: str = "inv-1") -> InvariantProjection:
    return InvariantProjection(
        invariant_id=invariant_id,
        norm_id=f"norm:{invariant_id}",
        statement="test classification",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=f"norm:{invariant_id}"), effect),
        ),
    )


def _check(method_id: str = "get") -> Check:
    return Check(
        invariant_id="inv-1",
        method_id=method_id,
        scenario_id="scenario-1",
        request=(("resource_id", "target"),),
        identities=("principal:attacker",),
    )


def _observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="grounded failure",
    )


def _binding(graph: QdlGraph, invariant: InvariantProjection) -> ScenarioBinding:
    graph_hash = graph.content_hash
    return ScenarioBinding(
        scenario=None,  # type: ignore[arg-type]
        graph=graph,
        plan=QdlPlan(graph_hash=graph_hash, invariants=()),
        execution=QdlExecutionView(
            graph_hash=graph_hash,
            paths=(),
            invariants={invariant.invariant_id: invariant},
        ),
        invariants={invariant.invariant_id: invariant},
        methods=(),
    )


def _verdict(status: VerdictStatus = VerdictStatus.FAIL) -> PolicyVerdict:
    return PolicyVerdict(
        status=status,
        confidence=1.0,
        rationale="deterministic oracle",
        model_id="test-oracle",
        negative_scope=("response",) if status is VerdictStatus.PASS else (),
        deterministic=True,
        grounded=True,
    )


def test_missing_input_role_becomes_a_classification_work_item() -> None:
    invariant = _invariant(changed(Atom(value="resource:order"), Atom(value="total")))

    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:update",
    )

    assert deficit is not None
    assert deficit.axis == "classification"
    assert deficit.predicate_class == "has"
    assert deficit.subgoal.predicate == "has"
    assert deficit.subgoal.args[0] == input_field(
        Atom(value="action:update"), Atom(value="total")
    )
    context = dict(deficit.context)
    assert context["classification_reason"] == "missing_input_role"
    assert "privileged" in context["allowed_values"].split(",")


def test_missing_witness_role_becomes_a_classification_work_item() -> None:
    witness = field(Atom(value="resource:user"), Atom(value="email"))
    invariant = _invariant(has(Atom(value="principal:attacker"), witness))

    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:get",
    )

    assert deficit is not None
    assert deficit.axis == "classification"
    assert deficit.subgoal.args[0] == witness
    context = dict(deficit.context)
    assert context["classification_reason"] == "missing_witness_role"
    assert {"credential", "privileged", "sensitive"} <= set(
        context["allowed_values"].split(",")
    )


def test_missing_sink_type_becomes_a_classification_work_item() -> None:
    invariant = _invariant(
        reached(Atom(value="action:ship"), Atom(value="sink:business-rule"))
    )

    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:ship",
    )

    assert deficit is not None
    assert deficit.axis == "classification"
    assert deficit.predicate_class == "is"
    assert deficit.subgoal.args[0] == Atom(value="sink:business-rule")
    context = dict(deficit.context)
    assert context["classification_reason"] == "missing_sink_type"
    assert "business_flow" in context["allowed_values"].split(",")


@pytest.mark.parametrize(
    ("predicate", "expected_axis"),
    [("has", "classification"), ("is", "classification")],
)
def test_classification_evidence_channel_selects_one_axis(
    predicate: str,
    expected_axis: str,
) -> None:
    subgoal = QdlSubgoal(predicate, (Atom(value="term"), Atom(value="value")))

    assert axis_for_subgoal(subgoal, classification=True) == expected_axis


def test_classification_request_carries_closed_value_context() -> None:
    invariant = _invariant(
        reached(Atom(value="action:ship"), Atom(value="sink:business-rule"))
    )
    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:ship",
    )
    assert deficit is not None

    request = consultation_request(
        deficit,
        graph=QdlGraph(),
        budget=ConsultationBudget(),
    )

    assert request is not None
    assert request.kind == "classification"
    assert request.context["classification_term"] == canonical_json(
        Atom(value="sink:business-rule")
    )
    assert "business_flow" in request.context["allowed_values"]
    assert request.context["unprovable_subgoal"] == (
        'is("sink:business-rule", AnyType)'
    )


def test_classification_deficit_is_dispatchable_as_one_work_item() -> None:
    invariant = _invariant(
        reached(Atom(value="action:ship"), Atom(value="sink:business-rule"))
    )
    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:ship",
    )
    assert deficit is not None
    queue = DeficitQueue(max_tasks=1)

    assert queue.add((deficit,)) == 1
    work_item = queue.pop_wave()[0]

    assert work_item is not None
    assert work_item.consultation_kind == "classification"
    assert work_item.requires_model is True


def test_classification_deficit_closes_on_promoted_qdl_fact() -> None:
    invariant = _invariant(
        reached(Atom(value="action:ship"), Atom(value="sink:business-rule"))
    )
    deficit = classification_deficit(
        invariant,
        ClassificationFacts(),
        action_id="action:ship",
    )
    assert deficit is not None
    promoted = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="sink:business-rule"), Atom(value="business_flow")),
            ),
        )
    )

    assert grounding_result_closes_deficit(deficit, promoted)


def test_classification_axis_has_no_benchmark_or_voting_dictionary() -> None:
    instruction = CONSULTATION_INSTRUCTIONS["classification"]

    assert not any(
        name in instruction
        for name in ("GetUser", "ShipOrder", "unpaid_shipment", "email")
    )
    assert "majority" not in instruction


def test_generic_sink_type_does_not_discharge_catalog_obligation() -> None:
    sink = Atom(value="sink:rule")
    invariant = _invariant(reached(Atom(value="action:execute"), sink))
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(sink, Atom(value="Sink")),
            ),
        )
    )
    deficit = classification_deficit(
        invariant, ClassificationFacts.from_graph(source), action_id="execute"
    )
    assert deficit is not None
    assert dict(deficit.context)["classification_reason"] == "missing_sink_type"
    assert not grounding_result_closes_deficit(deficit, source)
    queue = DeficitQueue(max_tasks=None)
    queue.add((deficit,))
    item = queue.pop_wave()[0]
    result = queue.record_work_item_result(item, source)
    assert not result.closed_deficit_ids


def test_failed_observation_projects_into_classification_work() -> None:
    invariant = _invariant(changed(Atom(value="resource:order"), Atom(value="total")))
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(
                    Atom(value="action:update"),
                    Atom(value="Action"),
                ),
            ),
        )
    )
    check = _check("update")
    observation = _observation(check)

    deficits = classification_deficits(
        _binding(graph, invariant),
        checks={check.check_id: check},
        observations=(observation,),
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): _verdict()
        },
    )

    assert len(deficits) == 1
    assert deficits[0].axis == "classification"
    assert dict(deficits[0].context)["observation_id"] == observation.observation_id


def test_non_fail_verdicts_do_not_request_classification() -> None:
    invariant = _invariant(changed(Atom(value="resource:order"), Atom(value="total")))
    check = _check("update")
    observation = _observation(check)

    deficits = classification_deficits(
        _binding(QdlGraph(), invariant),
        checks={check.check_id: check},
        observations=(observation,),
        policy_verdicts={
            (observation.observation_id, invariant.invariant_id): _verdict(
                VerdictStatus.PASS
            )
        },
    )

    assert deficits == ()


def test_classification_promotion_accepts_only_the_anchored_value() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:user")
    witness = field(Atom(value="resource:user"), Atom(value="email"))
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(witness, Atom(value="Witness")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("exposes"),
                args=(action, witness),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("has"),
                args=(witness, Atom(value="sensitive")),
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(witness, Atom(value="Witness")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(witness, Atom(value="sensitive")),
            ),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(witness),
            allowed_values=frozenset({"sensitive"}),
            invariant_id="inv-1",
        ),
    )
    untrusted = promote_proposal(
        QdlGraph(
            facts=tuple(
                fact
                for fact in source.facts
                if fact.predicate.name not in {"exposes", "has"}
            )
        ),
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(witness),
            allowed_values=frozenset({"sensitive"}),
            invariant_id="inv-1",
        ),
    )
    rejected = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(
                field(Atom(value="resource:user"), Atom(value="other"))
            ),
            allowed_values=frozenset({"sensitive"}),
            invariant_id="inv-1",
        ),
    )
    outside_alphabet = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(witness),
            allowed_values=frozenset({"credential"}),
            invariant_id="inv-1",
        ),
    )

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (witness, Atom(value="sensitive"))
        for fact in result.graph.facts
    )
    assert not any(fact.context is Context.ACCEPTED for fact in untrusted.graph.facts)
    assert untrusted.parked_classifications is not None
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "has"
        for fact in rejected.graph.facts
    )
    assert not any(
        fact.context is Context.ACCEPTED and fact.predicate.name == "has"
        for fact in outside_alphabet.graph.facts
    )


def test_classification_promotion_parks_an_anchored_sink_type_without_provenance() -> (
    None
):
    action = Atom(value="action:ship")
    sink = Atom(value="sink:business-rule")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(sink, Atom(value="Sink")),
            ),
        )
    )
    proposal = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(sink, Atom(value="business_flow")),
            ),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(sink),
            allowed_values=frozenset({"business_flow"}),
            invariant_id="inv-1",
        ),
    )
    rejected = promote_proposal(
        source,
        proposal,
        classification_context=ClassificationPromotionContext(
            term=canonical_json(sink),
            allowed_values=frozenset({"interpreter"}),
            invariant_id="inv-1",
        ),
    )

    assert not any(fact.context is Context.ACCEPTED for fact in result.graph.facts)
    assert result.parked_classifications is not None
    assert any(
        fact.args == (sink, Atom(value="business_flow"))
        for fact in result.parked_classifications.facts
    )
    assert not any(fact.context is Context.ACCEPTED for fact in rejected.graph.facts)


def test_classification_promotion_accepts_trusted_observed_output_role() -> None:
    action = Atom(value="action:get")
    witness = output_field(action, Atom(value="token"))
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(witness, Atom(value="OutputField")),
            ),
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
                args=(witness, Atom(value="OutputField")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(witness, Atom(value="sensitive")),
            ),
        )
    )

    result = promote_proposal(
        source,
        proposal,
        evidence_fields=frozenset({"token"}),
        classification_context=ClassificationPromotionContext(
            term=canonical_json(witness),
            allowed_values=frozenset({"sensitive"}),
            invariant_id="inv-1",
        ),
    )

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and fact.args == (witness, Atom(value="sensitive"))
        for fact in result.graph.facts
    )


def test_classification_promotion_context_roundtrips_provenance() -> None:
    context = ClassificationPromotionContext(
        term='{"kind":"atom","value":"sink:business-rule"}',
        allowed_values=frozenset({"business_flow", "interpreter"}),
        invariant_id="inv-42",
        evidence_refs=frozenset({"obs-1", "obs-2"}),
    )

    restored = ClassificationPromotionContext.from_mapping(context.to_mapping())

    assert restored == context
    assert restored is not context
