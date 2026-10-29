"""Bounded evidence controls: no status-only or proposal-only causal proof."""

from __future__ import annotations

import pytest

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    GrpcStatus,
    Observation,
    ResponseData,
    TraceStep,
)
from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    create,
    input_field,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.verification.projection import (
    ObservationProjector,
)

A = Atom(value="action:svc.Create")
T = Atom(value="resource:widget")
W = output_field(A, Atom(value="id"))
E = create(T)


def fact(name, *args, context=Context.ACCEPTED):
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    return Fact(
        context=context,
        predicate=Predicate.from_schema(schema)
        if schema
        else Predicate.from_name(name),
        args=args,
    )


def declarations(*, coupled=False):
    facts = [
        fact("is", A, Atom(value="Action")),
        fact("is", T, Atom(value="ResourceType")),
        fact("is", E, Atom(value="Effect")),
        fact("is", W, Atom(value="OutputField")),
        fact("causes", A, E),
        fact("has", W, Atom(value="object_ref")),
    ]
    if coupled:
        other = Atom(value="action:svc.Use")
        witness = input_field(other, Atom(value="widget_id"))
        facts.extend(
            (
                fact("is", other, Atom(value="Action")),
                fact("is", witness, Atom(value="InputField")),
                fact("coupled", W, witness, Atom(value="eq")),
                fact("refers_to", witness, T),
            )
        )
    else:
        facts.append(fact("refers_to", W, T))
    return QdlGraph(facts=tuple(facts))


def observation(value="widget-1", *, obs_id="obs-1", scenario="scenario-1"):
    return Observation(
        observation_id=obs_id,
        check_id="check-1",
        scenario_id=scenario,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="grpc:OK",
        transport_status=GrpcStatus(code="OK"),
        output=ResponseData(fields=(("id", value),)),
    )


def instances(graph):
    return {
        f.args[0] for f in graph.facts if f.predicate.name == "is" and f.args[1] == T
    }


@pytest.mark.parametrize("coupled", [False, True])
def test_create_keeps_typed_value_and_observation_provenance(coupled):
    projector = ObservationProjector()
    obs = observation()
    graph = projector.project(obs, "svc.Create", graph=declarations(coupled=coupled))
    assert projector.verified_effects(
        obs, "svc.Create", declarations(coupled=coupled)
    ) == (E,)
    (instance,) = instances(graph)
    assert any(
        f.predicate.name == "has" and f.args == (instance, Atom(value="widget-1"))
        for f in graph.facts
    )
    assert any(
        f.predicate.name == "evidence" and f.args == (Atom(value=obs.observation_id), E)
        for f in graph.facts
    )
    assert all(f.context is Context.RUNTIME for f in graph.facts)
    assert not any(f.predicate.name == "causes" for f in graph.facts)
    assert graph == QdlGraph.model_validate_json(graph.model_dump_json())


def test_distinct_ids_survive_merge_and_same_id_is_idempotent():
    projector = ObservationProjector()
    trusted = declarations()
    one = projector.project(observation(), "svc.Create", graph=trusted)
    same = projector.project(observation(), "svc.Create", graph=trusted)
    two = projector.project(
        observation("widget-2", obs_id="obs-2"), "svc.Create", graph=trusted
    )
    assert one == same
    assert len(instances(merge_graphs(one, same))) == 1
    assert len(instances(merge_graphs(one, two))) == 2
    replay = projector.project(
        observation(obs_id="obs-replay"), "svc.Create", graph=trusted
    )
    assert instances(one) == instances(replay)
    foreign = projector.project(
        observation(scenario="foreign"), "svc.Create", graph=trusted
    )
    assert not instances(one) & instances(foreign)


@pytest.mark.parametrize("missing", ["causes", "has", "refers_to"])
def test_incomplete_declarations_do_not_prove_create(missing):
    source = declarations()
    graph = QdlGraph(
        facts=tuple(f for f in source.facts if f.predicate.name != missing)
    )
    assert (
        ObservationProjector().verified_effects(observation(), "svc.Create", graph)
        == ()
    )


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT])
def test_untrusted_declarations_never_prove_create(context):
    graph = QdlGraph(
        facts=tuple(
            f.model_copy(update={"context": context}) for f in declarations().facts
        )
    )
    assert (
        ObservationProjector().verified_effects(observation(), "svc.Create", graph)
        == ()
    )


@pytest.mark.parametrize("value", [None, "", 42, True, [], "[REDACTED]"])
def test_missing_or_non_id_value_never_proves_create(value):
    assert (
        ObservationProjector().verified_effects(
            observation(value), "svc.Create", declarations()
        )
        == ()
    )


def test_wrong_or_ambiguous_output_type_never_proves_create():
    other = Atom(value="resource:other")
    for replace in (True, False):
        graph = merge_graphs(
            QdlGraph(
                facts=tuple(
                    f
                    for f in declarations().facts
                    if not replace or f.predicate.name != "refers_to"
                )
            ),
            QdlGraph(
                facts=(
                    fact("is", other, Atom(value="ResourceType")),
                    fact("refers_to", W, other),
                    fact("is", W, Atom(value="OutputField")),
                    fact("is", A, Atom(value="Action")),
                )
            ),
        )
        assert (
            ObservationProjector().verified_effects(observation(), "svc.Create", graph)
            == ()
        )


def test_status_shape_and_full_response_tree_are_not_create_evidence():
    obs = observation().model_copy(
        update={
            "output": ResponseData(field_names=("id",)),
            "response_tree": (("id", "widget-1"),),
        }
    )
    assert (
        ObservationProjector().verified_effects(obs, "svc.Create", declarations()) == ()
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"auth_failed": True},
        {"observed_outcome": AccessOutcome.DENIED},
        {"error_reason": "failed"},
        {"transport_status": GrpcStatus(code="INVALID_ARGUMENT")},
    ],
)
def test_error_response_with_id_never_proves_create(updates):
    obs = observation().model_copy(update=updates)
    assert (
        ObservationProjector().verified_effects(obs, "svc.Create", declarations()) == ()
    )


def test_superseded_provider_role_observation_and_instance_are_not_current():
    projector = ObservationProjector()
    obs = observation()
    projected = projector.project(obs, "svc.Create", graph=declarations())
    (instance,) = instances(projected)
    for old in (
        E,
        Struct(name="replacement", args=(W, Atom(value="object_ref"))),
        Atom(value=obs.observation_id),
        instance,
    ):
        extra = QdlGraph(
            facts=(
                fact("is", old, Atom(value="Node")),
                fact("is", Atom(value="object_ref"), Atom(value="Node")),
                fact("is", Atom(value="revoked"), Atom(value="Node")),
                fact("is", A, Atom(value="Action")),
                fact("is", W, Atom(value="OutputField")),
                fact("is", T, Atom(value="ResourceType")),
                fact("supersedes", Atom(value="revoked"), old),
            )
        )
        graph = merge_graphs(declarations(), extra)
        assert projector.verified_effects(obs, "svc.Create", graph) == ()


@pytest.mark.parametrize(
    "outcome,name",
    [
        (AccessOutcome.ALLOWED, "allowed"),
        (AccessOutcome.DENIED, "denied"),
        (AccessOutcome.UNKNOWN, None),
    ],
)
def test_explicit_action_outcomes_only_verify_declared_effects(outcome, name):
    effects = tuple(Struct(name=n, args=(A,)) for n in ("allowed", "denied"))
    graph = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", A, Atom(value="Action")),
                *(fact("causes", A, e) for e in effects),
            )
        ),
    )
    obs = observation().model_copy(update={"output": None, "observed_outcome": outcome})
    assert ObservationProjector().verified_effects(obs, "svc.Create", graph) == (
        () if name is None else (Struct(name=name, args=(A,)),)
    )


def test_transition_requires_matching_explicit_trace_and_source_action():
    before, after = Atom(value="open"), Atom(value="closed")
    effect = Struct(name="transition", args=(before, after))
    graph = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", A, Atom(value="Action")),
                fact("is", before, Atom(value="State")),
                fact("is", after, Atom(value="State")),
                fact("causes", A, effect),
            )
        ),
    )
    obs = observation().model_copy(update={"output": None})
    step = TraceStep(
        observation_id=obs.observation_id,
        step_id=obs.check_id,
        scenario_id=obs.scenario_id,
        method_id="svc.Create",
        status=AccessOutcome.ALLOWED,
        resource_state_before=(("state", "open"),),
        resource_state_after=(("state", "closed"),),
    )
    obs = obs.model_copy(update={"trace": ExecutionTrace(steps=(step,))})
    assert ObservationProjector().verified_effects(obs, "svc.Create", graph) == (
        effect,
    )
    assert ObservationProjector().project(obs, "svc.Create", graph=graph)
    for updates in (
        {"method_id": "svc.Other"},
        {"scenario_id": "foreign"},
        {"observation_id": "foreign"},
        {"resource_state_after": ()},
    ):
        changed = obs.model_copy(
            update={"trace": ExecutionTrace(steps=(step.model_copy(update=updates),))}
        )
        assert (
            ObservationProjector().verified_effects(changed, "svc.Create", graph) == ()
        )


@pytest.mark.parametrize("context", [Context.CONTRACT, Context.ACCEPTED])
@pytest.mark.parametrize("derived", ["causes", "refers_to"])
def test_trusted_rules_supply_provider_and_output_reference(context, derived):
    from cloud_dast.qdl.graph import Rule

    trusted = declarations()
    facts = tuple(
        f.model_copy(update={"context": context})
        for f in trusted.facts
        if f.predicate.name != derived
    )
    if derived == "causes":
        body = (fact("is", E, Atom(value="Effect"), context=context),)
        head = fact("causes", A, E, context=context)
    else:
        body = (fact("part", W, T, context=context),)
        facts += body
        head = fact("refers_to", W, T, context=context)
    graph = QdlGraph(facts=facts, rules=(Rule(body=body, head=(head,)),))
    projector = ObservationProjector()
    assert projector.verified_effects(observation(), "svc.Create", graph) == (E,)
    assert instances(projector.project(observation(), "svc.Create", graph=graph))
    for untrusted in (Context.PROPOSAL, Context.RUNTIME):
        rule = Rule(
            body=tuple(f.model_copy(update={"context": untrusted}) for f in body),
            head=(head.model_copy(update={"context": untrusted}),),
        )
        assert (
            projector.verified_effects(
                observation(), "svc.Create", QdlGraph(facts=facts, rules=(rule,))
            )
            == ()
        )


def test_typed_instances_survive_durable_repository_roundtrip(tmp_path):
    from cloud_dast.infrastructure.sqlite.formal_repository import (
        SqliteFormalRepository,
    )

    repo = SqliteFormalRepository(tmp_path / "formal.sqlite")
    projector = ObservationProjector()
    for number in (1, 2):
        obs = observation(f"widget-{number}", obs_id=f"obs-{number}")
        graph = projector.project(obs, "svc.Create", graph=declarations())
        repo.save(
            f"observation:{obs.observation_id}",
            graph,
            provenance={"check_id": obs.check_id, "scenario_id": obs.scenario_id},
            adapter_version="test",
            mapping_report={},
        )
    durable = repo.load_merged("observation:")
    assert len(instances(durable)) == 2
    assert {
        f.args[1].value
        for f in durable.facts
        if f.predicate.name == "has" and f.args[0] in instances(durable)
    } == {"widget-1", "widget-2"}
    repo.close()


def test_sensitive_output_role_conflict_prevents_id_proof():
    graph = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", A, Atom(value="Action")),
                fact("is", W, Atom(value="OutputField")),
                fact("has", W, Atom(value="sensitive")),
            )
        ),
    )
    assert (
        ObservationProjector().verified_effects(observation(), "svc.Create", graph)
        == ()
    )


def test_role_classification_is_distinct_from_revoked_binding_evidence():
    from cloud_dast.qdl.field_roles import resolve_field_roles
    from cloud_dast.qdl.graph_ops import current_facts

    revoked = Struct(name="replacement", args=(W, Atom(value="object_ref")))
    graph = QdlGraph(
        facts=(
            *declarations().facts,
            fact("is", revoked, Atom(value="Node")),
            fact("is", Atom(value="object_ref"), Atom(value="Node")),
            fact("is", Atom(value="revoked"), Atom(value="Node")),
            fact("supersedes", Atom(value="revoked"), revoked),
        )
    )
    assert fact("has", W, Atom(value="object_ref")) in current_facts(graph)
    assert resolve_field_roles(graph).roles(
        A.value, "id", direction="output"
    ) == frozenset({"object_ref"})
    projector = ObservationProjector()
    assert projector.verified_effects(observation(), "svc.Create", graph) == ()
    assert (
        instances(projector.project(observation(), "svc.Create", graph=graph)) == set()
    )
