"""Mutable state claims expire independently of stable resource identities."""

import pytest

from cloud_dast.model import AccessOutcome, Check, ExecutionTrace, TraceStep
from cloud_dast.qdl.graph import Atom, Context, QdlGraph, Struct
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.verification.projection import (
    ObservationProjector,
    read_observed_effects,
    read_observed_references,
)
from tests.application.verification.formal.test_observation_effects import (
    E,
    observation,
)
from tests.application.verification.formal.test_observation_evidence import (
    IDENTITIES,
    SCOPE,
    consume,
    destructive_source,
    effects,
    outputs,
    project,
)
from tests.application.verification.formal.test_observed_values import payment_graph

PAID = Struct(name="transition", args=(Atom(value="open"), Atom(value="paid")))


def paid_observation(value, *, obs_id="paid-other", identities=IDENTITIES):
    check = Check(
        check_id=f"check-{obs_id}",
        invariant_id="ordinary",
        method_id="svc.Pay",
        scenario_id="scenario-1",
        identities=identities,
        request=(("id", value),),
    )
    obs = observation(None, obs_id=obs_id).model_copy(
        update={
            "check_id": check.check_id,
            "trace": ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id=obs_id,
                        step_id=check.check_id,
                        scenario_id=check.scenario_id,
                        method_id=check.method_id,
                        status=AccessOutcome.ALLOWED,
                        resource_state_before=(("state", "open"),),
                        resource_state_after=(("state", "paid"),),
                    ),
                )
            ),
        }
    )
    return check, obs


def project_payment(
    graph,
    value="widget-Y",
    *,
    obs_id="paid-other",
    identities=IDENTITIES,
    observed_at=1000.0,
):
    check, obs = paid_observation(value, obs_id=obs_id, identities=identities)
    return ObservationProjector().project(
        obs,
        check.method_id,
        graph=graph,
        check=check,
        identities=identities,
        scope=SCOPE,
        observed_at=observed_at,
    )


def resource_history(kind):
    mutations, _ = destructive_source(kind)
    paid, _ = payment_graph(values=("widget-X",), paid=True)
    graph = merge_graphs(mutations, paid)
    return merge_graphs(
        graph,
        project(
            observation("widget-X", obs_id="create-X"), source=graph, observed_at=999.0
        ),
        project(
            observation("widget-Y", obs_id="create-Y"), source=graph, observed_at=999.0
        ),
        project_payment(graph),
    )


def claims(graph):
    return {(fact.args[0].value, fact.args[1]) for fact, _, _ in effects(graph)}


@pytest.mark.parametrize("outcome", [AccessOutcome.ALLOWED, AccessOutcome.ERROR])
def test_transition_expires_only_prior_target_state_claims(outcome):
    graph = resource_history("transition")
    current, invalidation = consume(graph, value="widget-X", outcome=outcome)
    assert set(outputs(current)) == set(outputs(graph))
    assert ("create-X", E) in claims(current)
    assert ("create-Y", E) in claims(current)
    assert ("obs-1", PAID) not in claims(current)
    assert ("paid-other", PAID) in claims(current)
    assert {
        f.args[1] for f in invalidation.facts if f.predicate.name == "supersedes"
    } == {
        Struct(name="replacement", args=(Atom(value="obs-1"), PAID)),
    }
    assert set(
        read_observed_references(current, scope=SCOPE, identities=IDENTITIES)
    ) == set(read_observed_references(graph, scope=SCOPE, identities=IDENTITIES)) | {
        row
        for row in read_observed_references(current, scope=SCOPE, identities=IDENTITIES)
        if row[0] == Atom(value="delete-observation")
    }


@pytest.mark.parametrize("outcome", [AccessOutcome.ALLOWED, AccessOutcome.ERROR])
def test_removal_expires_target_identity_creation_and_state_claims(outcome):
    graph = resource_history("remove")
    current, invalidation = consume(graph, value="widget-X", outcome=outcome)
    assert {row[1].value for row in outputs(current)} == {"widget-Y"}
    assert ("create-X", E) not in claims(current)
    assert ("obs-1", PAID) not in claims(current)
    assert ("create-Y", E) in claims(current)
    assert ("paid-other", PAID) in claims(current)
    assert any(
        f.predicate.name == "supersedes"
        and f.args[1] == Struct(name="replacement", args=(Atom(value="obs-1"), PAID))
        for f in invalidation.facts
    )


def test_effect_revocation_is_observation_specific_and_survives_roundtrip():
    graph = resource_history("transition")
    current, invalidation = consume(graph, value="widget-Y")
    current = QdlGraph.model_validate_json(current.model_dump_json())
    assert ("obs-1", PAID) in claims(current)
    assert ("paid-other", PAID) not in claims(current)
    assert any(f.predicate.name == "supersedes" for f in invalidation.facts)
    _, obs = paid_observation("widget-Y")
    assert ObservationProjector().verified_effects(obs, "svc.Pay", current) == ()
    assert outputs(current)


@pytest.mark.parametrize("kind", ["remove", "transition"])
def test_mutation_cannot_expire_foreign_identity_state_or_future_claims(kind):
    mutations, _ = destructive_source(kind)
    paid, _ = payment_graph(typed=True, paid=True)
    source = QdlGraph(
        facts=tuple(f for f in paid.facts if f.context is not Context.RUNTIME)
    )
    source = merge_graphs(source, mutations)
    foreign = project_payment(source, "widget-X", identities=("other-actor",))
    future = project_payment(source, "widget-X", obs_id="future", observed_at=1002.0)
    graph = merge_graphs(source, foreign, future)
    current, invalidation = consume(graph, value="widget-X")
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert ("future", PAID) in claims(current)
    assert any(
        fact.args[1] == PAID
        for fact, _, _ in read_observed_effects(
            current, scope=SCOPE, identities=("other-actor",)
        )
    )
