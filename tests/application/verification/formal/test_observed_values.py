"""Observed references remain independent of causal attribution."""

import pytest

from cloud_dast.model import AccessOutcome, Check, GrpcStatus
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    allowed,
    input_field,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.verification.projection import (
    ObservationProjector,
    read_observed_effects,
)
from tests.application.verification.formal.test_observation_effects import (
    E,
    T,
    declarations,
    fact,
    observation,
)
from tests.application.verification.formal.test_observation_evidence import (
    IDENTITIES,
    SCOPE,
    effects,
    outputs,
    project,
)

OBSERVER = Atom(value="action:svc.Inspect")
FIELD = output_field(OBSERVER, Atom(value="id"))
CONSUMER_ACTION = Atom(value="action:svc.Use")
CONSUMER = input_field(CONSUMER_ACTION, Atom(value="target"))


def observer_source():
    return merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", OBSERVER, Atom(value="Action")),
                fact("is", FIELD, Atom(value="OutputField")),
                fact("is", T, Atom(value="ResourceType")),
                fact("has", FIELD, Atom(value="object_ref")),
                fact("refers_to", FIELD, T),
            )
        ),
    )


def record(source, obs=None):
    return ObservationProjector().project(
        obs or observation(),
        "svc.Inspect",
        graph=source,
        identities=IDENTITIES,
        scope=SCOPE,
        observed_at=1000.0,
    )


def test_ordinary_observer_retains_durable_value_without_causal_proof(tmp_path):
    from cloud_dast.infrastructure.sqlite.formal_repository import (
        SqliteFormalRepository,
    )

    source = observer_source()
    source = QdlGraph(
        facts=tuple(f for f in source.facts if f.predicate.name != "causes")
    )
    projected = record(source)
    assert projected == record(source)
    repo = SqliteFormalRepository(tmp_path / "formal.sqlite")
    repo.save(
        "observation:obs-1",
        projected,
        provenance={},
        adapter_version="test",
        mapping_report={},
    )
    durable = merge_graphs(source, repo.load_merged("observation:"))
    repo.close()
    assert outputs(durable, FIELD) == (
        (
            Atom(value="obs-1"),
            Atom(value="widget-1"),
            Atom(value="check-1"),
            Atom(value="1000.0"),
        ),
    )
    assert not effects(durable)
    assert (
        ObservationProjector().verified_effects(observation(), "svc.Inspect", source)
        == ()
    )


def test_observed_id_never_completes_an_outputless_create():
    source = observer_source()
    create_obs = observation(None, obs_id="create-observation")
    created = ObservationProjector().project(
        create_obs,
        "svc.Create",
        graph=source,
        identities=IDENTITIES,
        scope=SCOPE,
        observed_at=999.0,
    )
    graph = merge_graphs(source, created, record(source))
    assert outputs(graph, FIELD)
    assert not outputs(graph)
    assert not effects(graph)
    assert not any(
        f.predicate.name == "evidence" and f.args[1] == E for f in graph.facts
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"observed_outcome": AccessOutcome.DENIED},
        {"observed_outcome": AccessOutcome.ERROR},
        {"observed_outcome": AccessOutcome.UNKNOWN},
        {"auth_failed": True},
        {"error_reason": "failed"},
        {"transport_status": GrpcStatus(code="INVALID_ARGUMENT")},
    ],
)
def test_unsuccessful_observer_cannot_supply_a_reference(updates):
    source = observer_source()
    projected = record(source, observation().model_copy(update=updates))
    assert not outputs(merge_graphs(source, projected), FIELD)


@pytest.mark.parametrize("value", [None, "", 42, True, [], "[REDACTED]", "bad\0id"])
def test_ordinary_observer_requires_a_safe_retained_reference(value):
    source = observer_source()
    assert not outputs(merge_graphs(source, record(source, observation(value))), FIELD)


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT])
def test_untrusted_observer_typing_cannot_supply_values(context):
    source = QdlGraph(
        facts=tuple(
            f.model_copy(update={"context": context}) for f in observer_source().facts
        )
    )
    assert not outputs(merge_graphs(source, record(source)), FIELD)


@pytest.mark.parametrize("conflict", ["sensitive", "credential", "type"])
@pytest.mark.parametrize("historical", [False, True])
def test_conflicting_current_observer_declarations_block_values(conflict, historical):
    source = observer_source()
    projected = record(source)
    other = Atom(value="resource:other")
    additions = (
        (fact("is", other, Atom(value="ResourceType")), fact("refers_to", FIELD, other))
        if conflict == "type"
        else (fact("has", FIELD, Atom(value=conflict)),)
    )
    changed = QdlGraph(facts=source.facts + additions)
    graph = merge_graphs(changed, projected if historical else record(changed))
    assert not outputs(graph, FIELD)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scope": "foreign"},
        {"identities": ("foreign",)},
    ],
)
def test_ordinary_outputs_require_actual_scope_and_identity(kwargs):
    source = observer_source()
    assert not outputs(merge_graphs(source, record(source)), FIELD, **kwargs)


def revoke(graph, old):
    return QdlGraph(
        facts=graph.facts
        + (
            fact("is", Atom(value="revoker"), Atom(value="Node")),
            fact("is", Atom(value="object_ref"), Atom(value="Node")),
            fact("is", old, Atom(value="Node")),
            fact("supersedes", Atom(value="revoker"), old),
        )
    )


@pytest.mark.parametrize(
    "target",
    [
        "observation",
        "check",
        "action",
        "field",
        "type",
        "value",
        "role",
        "reference",
        "instance",
        "link",
    ],
)
def test_ordinary_output_revocation_closes_historical_values(target):
    source = observer_source()
    graph = merge_graphs(source, record(source))
    instance = next(
        f.args[0]
        for f in graph.facts
        if f.context is Context.RUNTIME and f.predicate.name == "is" and f.args[1] == T
    )
    old = {
        "observation": Atom(value="obs-1"),
        "check": Atom(value="check-1"),
        "action": OBSERVER,
        "field": FIELD,
        "type": T,
        "value": Atom(value="widget-1"),
        "instance": instance,
        "role": Struct(name="replacement", args=(FIELD, Atom(value="object_ref"))),
        "reference": Struct(name="replacement", args=(FIELD, T)),
        "link": Struct(name="replacement", args=(Atom(value="obs-1"), instance)),
    }[target]
    assert not outputs(revoke(graph, old), FIELD)


def payment_graph(*, values=("widget-X", "widget-Y"), typed=True, paid=False):
    action = Atom(value="action:svc.Pay")
    before, after = Atom(value="open"), Atom(value="paid")
    effect = (
        Struct(name="transition", args=(before, after)) if paid else allowed(action)
    )
    fields = tuple(input_field(action, Atom(value=name)) for name in ("id", "peer_id"))
    source = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", T, Atom(value="ResourceType")),
            fact("is", before, Atom(value="State")),
            fact("is", after, Atom(value="State")),
            fact("causes", action, effect),
            *(fact("is", w, Atom(value="InputField")) for w in fields),
            *(fact("has", w, Atom(value="object_ref")) for w in fields),
            *((fact("refers_to", w, T) for w in fields) if typed else ()),
        )
    )
    actual = Check(
        check_id="payment-check",
        invariant_id="ordinary",
        method_id="svc.Pay",
        scenario_id="scenario-1",
        identities=IDENTITIES,
        request=tuple(zip(("id", "peer_id"), values)),
    )
    obs = observation(None).model_copy(update={"check_id": actual.check_id})
    if paid:
        from cloud_dast.model import ExecutionTrace, TraceStep

        obs = obs.model_copy(
            update={
                "trace": ExecutionTrace(
                    steps=(
                        TraceStep(
                            observation_id=obs.observation_id,
                            step_id=actual.check_id,
                            scenario_id=actual.scenario_id,
                            method_id=actual.method_id,
                            status=AccessOutcome.ALLOWED,
                            resource_state_before=(("state", "open"),),
                            resource_state_after=(("state", "paid"),),
                        ),
                    )
                )
            }
        )
    projected = ObservationProjector().project(
        obs,
        actual.method_id,
        graph=source,
        check=actual,
        identities=IDENTITIES,
        scope=SCOPE,
        observed_at=1000.0,
    )
    return merge_graphs(source, projected), fields


def with_consumer(graph):
    return QdlGraph(
        facts=graph.facts
        + (
            fact("is", CONSUMER_ACTION, Atom(value="Action")),
            fact("is", CONSUMER, Atom(value="InputField")),
            fact("has", CONSUMER, Atom(value="object_ref")),
            fact("refers_to", CONSUMER, T),
        )
    )


def proofs(graph, references=(), **kwargs):
    return read_observed_effects(
        with_consumer(graph),
        scope=SCOPE,
        identities=IDENTITIES,
        references=references,
        **kwargs,
    )


def test_reference_filter_accepts_current_output_without_changing_default_reader():
    graph = merge_graphs(declarations(), project())
    assert proofs(graph, ((CONSUMER, Atom(value="widget-1")),)) == effects(graph)
    assert not proofs(graph, ((CONSUMER, Atom(value="widget-other")),))
    assert not proofs(graph, ((Atom(value="resource:wrong"), Atom(value="widget-1")),))


def test_reference_filter_requires_every_value_and_preserves_exact_field_binding():
    graph, (field, peer) = payment_graph()
    x, y = Atom(value="widget-X"), Atom(value="widget-Y")
    assert proofs(graph, ((CONSUMER, x), (CONSUMER, y))) == effects(graph)
    assert not proofs(graph, ((CONSUMER, x), (CONSUMER, Atom(value="missing"))))
    assert proofs(graph, ((CONSUMER, y),), bindings=((field, x), (peer, y)))
    assert not proofs(graph, ((CONSUMER, x),), bindings=((field, y),))
    assert proofs(graph, bindings=((field, x),))
    assert not proofs(graph, bindings=((field, y),))


def test_untyped_request_values_never_qualify_as_required_references():
    graph, _ = payment_graph(typed=False)
    expected = input_field(Atom(value="action:svc.Pay"), Atom(value="expected"))
    graph = QdlGraph(
        facts=graph.facts
        + (
            fact("is", expected, Atom(value="InputField")),
            fact("has", expected, Atom(value="object_ref")),
            fact("refers_to", expected, T),
        )
    )
    assert effects(graph)
    assert not proofs(graph, ((CONSUMER, Atom(value="widget-X")),))


def test_pay_x_transition_cannot_authorize_pay_y_by_type_alone():
    graph, (field, _) = payment_graph(values=("widget-X",), paid=True)
    x, y = Atom(value="widget-X"), Atom(value="widget-Y")
    (row,) = proofs(graph, ((CONSUMER, x),), bindings=((field, x),))
    assert row[0].args[1] == Struct(
        name="transition", args=(Atom(value="open"), Atom(value="paid"))
    )
    assert not proofs(graph, ((CONSUMER, y),))
    assert not proofs(graph, bindings=((field, y),))


def test_references_cannot_join_different_proof_observations():
    one = project(observation("widget-X", obs_id="one"))
    two = project(observation("widget-Y", obs_id="two"))
    graph = merge_graphs(declarations(), one, two)
    assert proofs(graph, ((CONSUMER, Atom(value="widget-X")),))
    assert proofs(graph, ((CONSUMER, Atom(value="widget-Y")),))
    assert not proofs(
        graph, ((CONSUMER, Atom(value="widget-X")), (CONSUMER, Atom(value="widget-Y")))
    )


@pytest.mark.parametrize(
    "target",
    [
        "link",
        "instance",
        "role",
        "reference",
        "type",
        "value",
        "field",
        "binding",
        "observation",
        "check",
        "action",
    ],
)
def test_required_input_reference_must_remain_current(target):
    graph, (field, _) = payment_graph()
    instance = next(
        f.args[1]
        for f in graph.facts
        if f.context is Context.RUNTIME
        and f.predicate.name == "has"
        and f.args[0] == field
    )
    value = Atom(value="widget-X")
    old = {
        "link": Struct(name="replacement", args=(Atom(value="obs-1"), instance)),
        "instance": instance,
        "type": T,
        "value": value,
        "field": field,
        "binding": Struct(name="replacement", args=(field, instance)),
        "role": Struct(name="replacement", args=(field, Atom(value="object_ref"))),
        "reference": Struct(name="replacement", args=(field, T)),
        "observation": Atom(value="obs-1"),
        "check": Atom(value="payment-check"),
        "action": Atom(value="action:svc.Pay"),
    }[target]
    assert proofs(graph, ((CONSUMER, value),))
    assert not proofs(revoke(graph, old), ((CONSUMER, value),))


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "ambiguous",
        "sensitive",
        "credential",
        "no_role",
        "role",
        "reference",
        "field",
    ],
)
def test_consumer_reference_typing_and_role_must_be_current_and_unambiguous(change):
    graph, _ = payment_graph()
    graph = with_consumer(graph)
    if change in {"unknown", "no_role"}:
        graph = QdlGraph(
            facts=tuple(
                f
                for f in graph.facts
                if not (
                    f.args[0] == CONSUMER
                    and f.predicate.name
                    == ("refers_to" if change == "unknown" else "has")
                )
            )
        )
    elif change == "ambiguous":
        other = Atom(value="resource:other")
        graph = QdlGraph(
            facts=graph.facts
            + (
                fact("is", other, Atom(value="ResourceType")),
                fact("refers_to", CONSUMER, other),
            )
        )
    elif change in {"sensitive", "credential"}:
        graph = QdlGraph(
            facts=graph.facts + (fact("has", CONSUMER, Atom(value=change)),)
        )
    else:
        old = {
            "role": Struct(
                name="replacement", args=(CONSUMER, Atom(value="object_ref"))
            ),
            "reference": Struct(name="replacement", args=(CONSUMER, T)),
            "field": CONSUMER,
        }[change]
        graph = revoke(graph, old)
    assert effects(graph)
    assert not read_observed_effects(
        graph,
        scope=SCOPE,
        identities=IDENTITIES,
        references=((CONSUMER, Atom(value="widget-X")),),
    )


def test_reference_filter_joins_input_and_output_of_the_same_proof():
    from cloud_dast.model import ResponseData

    source = observer_source()
    target = input_field(OBSERVER, Atom(value="target"))
    source = QdlGraph(
        facts=source.facts
        + (
            fact("is", target, Atom(value="InputField")),
            fact("has", target, Atom(value="object_ref")),
            fact("refers_to", target, T),
            fact("causes", OBSERVER, allowed(OBSERVER)),
        )
    )
    actual = Check(
        check_id="check-1",
        invariant_id="ordinary",
        method_id="svc.Inspect",
        scenario_id="scenario-1",
        identities=IDENTITIES,
        request=(("target", "input-id"),),
    )
    obs = observation().model_copy(
        update={"output": ResponseData(fields=(("id", "output-id"),))}
    )
    projected = ObservationProjector().project(
        obs,
        actual.method_id,
        graph=source,
        check=actual,
        identities=IDENTITIES,
        scope=SCOPE,
        observed_at=1000.0,
    )
    graph = merge_graphs(source, projected)
    assert proofs(
        graph, ((CONSUMER, Atom(value="input-id")), (CONSUMER, Atom(value="output-id")))
    )
    for kwargs in ({"scope": "foreign"}, {"identities": ("foreign",)}):
        options = {"scope": SCOPE, "identities": IDENTITIES, **kwargs}
        assert not read_observed_effects(
            with_consumer(graph),
            **options,
            references=((CONSUMER, Atom(value="input-id")),),
        )


PART = Atom(value="resource:part")
PART_CONSUMER = input_field(CONSUMER_ACTION, Atom(value="part"))
PART_ACTION = Atom(value="action:svc.MakePart")


def independent_resources():
    from cloud_dast.qdl.graph import create

    source = with_consumer(declarations())
    field = output_field(PART_ACTION, Atom(value="id"))
    source = QdlGraph(
        facts=source.facts
        + (
            fact("is", PART_ACTION, Atom(value="Action")),
            fact("is", PART, Atom(value="ResourceType")),
            fact("is", field, Atom(value="OutputField")),
            fact("has", field, Atom(value="object_ref")),
            fact("refers_to", field, PART),
            fact("causes", PART_ACTION, create(PART)),
            fact("is", PART_CONSUMER, Atom(value="InputField")),
            fact("has", PART_CONSUMER, Atom(value="object_ref")),
            fact("refers_to", PART_CONSUMER, PART),
        )
    )
    part = ObservationProjector().project(
        observation("part-1", obs_id="part-observation"),
        "svc.MakePart",
        graph=source,
        scope=SCOPE,
        identities=IDENTITIES,
        observed_at=1001.0,
    )
    return merge_graphs(source, project(source=source), part)


def independent_proofs(graph, *, widget="widget-1", part="part-1"):
    return read_observed_effects(
        graph,
        scope=SCOPE,
        identities=IDENTITIES,
        references=((CONSUMER, Atom(value=widget)), (PART_CONSUMER, Atom(value=part))),
    )


def test_independent_resource_proofs_require_only_their_declared_types():
    graph = independent_resources()
    assert {row[0].args[0].value for row in independent_proofs(graph)} == {
        "obs-1",
        "part-observation",
    }
    assert {
        row[0].args[0].value for row in independent_proofs(graph, part="wrong")
    } == {"obs-1"}
    assert {
        row[0].args[0].value for row in independent_proofs(graph, widget="wrong")
    } == {"part-observation"}


@pytest.mark.parametrize("direction", ["input", "output"])
def test_missing_declared_source_reference_cannot_disappear_from_relevance(direction):
    graph = independent_resources()
    witness = Struct(
        name=f"{direction}_field", args=(PART_ACTION, Atom(value="expected"))
    )
    graph = QdlGraph(
        facts=graph.facts
        + (
            fact("is", witness, Atom(value=f"{direction.title()}Field")),
            fact("has", witness, Atom(value="object_ref")),
            fact("refers_to", witness, T),
        )
    )
    assert {row[0].args[0].value for row in independent_proofs(graph)} == {"obs-1"}


@pytest.mark.parametrize("change", ["unknown", "ambiguous"])
def test_invalid_consumer_type_blocks_even_unrelated_resource_proofs(change):
    graph = independent_resources()
    if change == "unknown":
        graph = QdlGraph(
            facts=tuple(
                f
                for f in graph.facts
                if not (f.predicate.name == "refers_to" and f.args[0] == PART_CONSUMER)
            )
        )
    else:
        graph = QdlGraph(facts=graph.facts + (fact("refers_to", PART_CONSUMER, T),))
    assert not independent_proofs(graph)


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize("instance", [False, True])
@pytest.mark.parametrize("kind", ["remove", "changed"])
def test_core_resource_arguments_require_typed_values_even_without_source_fields(
    kind, instance, typed
):
    graph, _ = payment_graph(typed=typed)
    action = Atom(value="action:svc.Pay")
    resource = Atom(value="resource:target") if instance else T
    effect = Struct(
        name=kind,
        args=(resource,) if kind == "remove" else (resource, Atom(value="status")),
    )
    additions = (
        fact("is", effect, Atom(value="Effect")),
        fact("causes", action, effect),
        fact("evidence", Atom(value="obs-1"), effect, context=Context.RUNTIME),
    )
    if instance:
        additions += (
            fact("is", resource, Atom(value="Resource")),
            fact("is", resource, T),
        )
    graph = QdlGraph(facts=graph.facts + additions)
    # Seed canonical causal evidence to exercise the reader for core effects
    # that the response-only projector deliberately does not assert.
    assert effect in {row[0].args[1] for row in effects(graph)}
    current = {
        row[0].args[1] for row in proofs(graph, ((CONSUMER, Atom(value="widget-X")),))
    }
    assert (effect in current) is typed
    assert effect not in {
        row[0].args[1] for row in proofs(graph, ((CONSUMER, Atom(value="widget-Z")),))
    }


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT])
def test_untrusted_source_typing_does_not_create_reference_relevance(context):
    graph = independent_resources()
    witness = input_field(PART_ACTION, Atom(value="untrusted"))
    graph = QdlGraph(
        facts=graph.facts
        + (
            fact("is", witness, Atom(value="InputField"), context=context),
            fact("has", witness, Atom(value="object_ref"), context=context),
            fact("refers_to", witness, T, context=context),
        )
    )
    assert {
        row[0].args[0].value for row in independent_proofs(graph, widget="irrelevant")
    } == {"part-observation"}


@pytest.mark.parametrize("role", ["sensitive", "credential"])
def test_source_redaction_cannot_erase_target_type_relevance(role):
    graph, fields = payment_graph(values=("widget-X",), paid=True)
    graph = QdlGraph(
        facts=graph.facts
        + tuple(fact("has", field, Atom(value=role)) for field in fields)
    )
    assert effects(graph)
    assert not proofs(graph, ((CONSUMER, Atom(value="widget-X")),))
    assert not proofs(graph, ((CONSUMER, Atom(value="widget-Y")),))


def test_consumer_reference_needs_a_trusted_resource_type_declaration():
    graph, _ = payment_graph(paid=True)
    graph = QdlGraph(
        facts=tuple(
            f
            for f in graph.facts
            if not (
                f.context is Context.ACCEPTED
                and f.predicate.name == "is"
                and f.args == (T, Atom(value="ResourceType"))
            )
        )
    )
    assert effects(graph)
    assert not proofs(graph, ((CONSUMER, Atom(value="widget-X")),))
