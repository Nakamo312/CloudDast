"""Canonical reference reads preserve joint provenance and exact source fields."""

import pytest

from cloud_dast.model import Check
from cloud_dast.qdl.graph import Atom, Context, QdlGraph, Struct, input_field
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.verification.projection import (
    ObservationProjector,
    read_observed_references,
)
from tests.application.verification.formal.test_observation_effects import (
    T,
    fact,
    observation,
)
from tests.application.verification.formal.test_observation_evidence import (
    IDENTITIES,
    SCOPE,
    effects,
    outputs,
)
from tests.application.verification.formal.test_observed_values import (
    FIELD,
    OBSERVER,
    observer_source,
    payment_graph,
    revoke,
)

INPUT = input_field(OBSERVER, Atom(value="target"))


def bound_observation(
    input_value="widget-input",
    output_value="widget-output",
    *,
    obs_id="bound",
    observed_at=1000.0,
):
    source = observer_source()
    source = QdlGraph(
        facts=source.facts
        + (
            fact("is", INPUT, Atom(value="InputField")),
            fact("has", INPUT, Atom(value="object_ref")),
            fact("refers_to", INPUT, T),
        )
    )
    actual = Check(
        check_id=f"check-{obs_id}",
        invariant_id="ordinary",
        method_id="svc.Inspect",
        scenario_id="scenario-1",
        identities=IDENTITIES,
        request=(("target", input_value),),
    )
    obs = observation(output_value, obs_id=obs_id).model_copy(
        update={"check_id": actual.check_id}
    )
    projected = ObservationProjector().project(
        obs,
        actual.method_id,
        graph=source,
        check=actual,
        identities=IDENTITIES,
        scope=SCOPE,
        observed_at=observed_at,
    )
    return merge_graphs(source, projected)


def references(graph, **kwargs):
    options = {"scope": SCOPE, "identities": IDENTITIES, **kwargs}
    return read_observed_references(graph, **options)


def test_reference_rows_keep_input_output_type_and_actual_provenance():
    graph = bound_observation()
    assert set(references(graph)) == {
        (
            Atom(value="bound"),
            INPUT,
            T,
            Atom(value="widget-input"),
            Atom(value="check-bound"),
            Atom(value="1000.0"),
        ),
        (
            Atom(value="bound"),
            FIELD,
            T,
            Atom(value="widget-output"),
            Atom(value="check-bound"),
            Atom(value="1000.0"),
        ),
    }
    assert not effects(graph)  # Bindings are not a claim of causality.
    assert outputs(graph, FIELD) == (
        (
            Atom(value="bound"),
            Atom(value="widget-output"),
            Atom(value="check-bound"),
            Atom(value="1000.0"),
        ),
    )


@pytest.mark.parametrize("method_id", ["svc.Inspect", "action:svc.Inspect"])
def test_reference_method_filter_uses_the_actual_source_action(method_id):
    graph = bound_observation()
    assert references(graph, method_id=method_id) == references(graph)
    assert not references(graph, method_id="svc.Create")


@pytest.mark.parametrize(
    "options", [{"scope": "foreign"}, {"identities": ("foreign",)}]
)
def test_reference_reads_require_exact_operational_scope_and_identity(options):
    assert not references(bound_observation(), **options)


def test_reference_rows_survive_durable_graph_roundtrip(tmp_path):
    from cloud_dast.infrastructure.sqlite.formal_repository import (
        SqliteFormalRepository,
    )

    graph = bound_observation()
    repo = SqliteFormalRepository(tmp_path / "formal.sqlite")
    repo.save(
        "observation:bound",
        graph,
        provenance={},
        adapter_version="test",
        mapping_report={},
    )
    durable = repo.load_merged("observation:")
    repo.close()
    assert set(references(durable)) == set(references(graph))


def semantic_groups(graph):
    groups = {}
    for obs, witness, resource_type, value, _, _ in references(graph):
        groups.setdefault(obs, set()).add((witness, resource_type, value))
    return frozenset(frozenset(group) for group in groups.values())


def test_semantic_rows_ignore_replay_provenance_but_distinguish_actual_targets():
    first, _ = payment_graph(values=("widget-X",), paid=True)
    changed, _ = payment_graph(values=("widget-Y",), paid=True)
    assert effects(first) == effects(changed)
    assert semantic_groups(first) != semantic_groups(changed)
    original = bound_observation()
    replay = bound_observation(obs_id="replayed", observed_at=2000.0)
    assert references(original) != references(replay)
    assert semantic_groups(original) == semantic_groups(replay)


def test_partial_observations_do_not_become_one_joint_binding_tuple():
    joint = bound_observation()
    partial = merge_graphs(
        bound_observation(output_value=None, obs_id="input-only"),
        bound_observation(input_value=None, obs_id="output-only"),
    )
    assert {row[1:4] for row in references(joint)} == {
        row[1:4] for row in references(partial)
    }
    assert semantic_groups(joint) != semantic_groups(partial)


@pytest.mark.parametrize("field", [INPUT, FIELD])
@pytest.mark.parametrize(
    "target",
    [
        "observation",
        "check",
        "action",
        "type",
        "field",
        "role",
        "reference",
        "instance",
        "value",
        "observation_link",
        "field_link",
        "value_link",
    ],
)
def test_current_reference_rows_follow_canonical_revocation(field, target):
    graph = bound_observation()
    instance = next(
        f.args[1]
        for f in graph.facts
        if f.context is Context.RUNTIME
        and f.predicate.name == "has"
        and f.args[0] == field
    )
    value = Atom(value="widget-input" if field == INPUT else "widget-output")
    old = {
        "observation": Atom(value="bound"),
        "check": Atom(value="check-bound"),
        "action": OBSERVER,
        "type": T,
        "field": field,
        "role": Struct(name="replacement", args=(field, Atom(value="object_ref"))),
        "reference": Struct(name="replacement", args=(field, T)),
        "instance": instance,
        "value": value,
        "observation_link": Struct(
            name="replacement", args=(Atom(value="bound"), instance)
        ),
        "field_link": Struct(name="replacement", args=(field, instance)),
        "value_link": Struct(name="replacement", args=(instance, value)),
    }[target]
    assert not any(row[1] == field for row in references(revoke(graph, old)))


@pytest.mark.parametrize("field", [INPUT, FIELD])
@pytest.mark.parametrize("conflict", ["sensitive", "credential", "type"])
def test_reference_reader_rechecks_current_roles_and_typing(field, conflict):
    graph = bound_observation()
    other = Atom(value="resource:other")
    additions = (
        (fact("is", other, Atom(value="ResourceType")), fact("refers_to", field, other))
        if conflict == "type"
        else (fact("has", field, Atom(value=conflict)),)
    )
    graph = QdlGraph(facts=graph.facts + additions)
    assert not any(row[1] == field for row in references(graph))


def test_untyped_request_does_not_become_a_reference_row():
    graph, _ = payment_graph(typed=False, paid=True)
    assert effects(graph)
    assert not references(graph)
