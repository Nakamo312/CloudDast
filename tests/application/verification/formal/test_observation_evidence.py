"""Pure canonical evidence reads; no execution, fixture or repository owner."""

from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import Atom, Context, QdlGraph, Rule, Struct
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.verification.projection import (
    ObservationProjector,
    read_observed_effects,
    read_observed_outputs,
)
from tests.application.verification.formal.test_observation_effects import (
    A,
    E,
    T,
    W,
    declarations,
    fact,
    instances,
    observation,
)

SCOPE = 'binding:TYPE_SCOPE_IDENTITY:"scope"'
IDENTITIES = ("actual:IDENTITY_SCOPE",)


def project(
    obs=None, *, source=None, identities=IDENTITIES, scope=SCOPE, observed_at=1000.0
):
    obs = obs or observation()
    return ObservationProjector().project(
        obs,
        "svc.Create",
        graph=source or declarations(),
        identities=identities,
        scope=scope,
        observed_at=observed_at,
    )


def effects(graph, **kwargs):
    return read_observed_effects(
        graph,
        scope=kwargs.get("scope", SCOPE),
        identities=kwargs.get("identities", IDENTITIES),
    )


def outputs(graph, witness=W, **kwargs):
    return read_observed_outputs(
        graph,
        witness,
        scope=kwargs.get("scope", SCOPE),
        identities=kwargs.get("identities", IDENTITIES),
    )


def test_core_effect_and_output_rows_keep_actual_observation_check_and_time():
    obs = observation()
    graph = merge_graphs(declarations(), project(obs))
    (row,) = effects(graph)
    evidence, check, timestamp = row
    assert evidence.predicate.name == "evidence" and evidence.context is Context.RUNTIME
    assert evidence.args == (Atom(value=obs.observation_id), E)
    assert check == Atom(value=obs.check_id) and timestamp == Atom(value="1000.0")
    assert outputs(graph) == (
        (Atom(value=obs.observation_id), Atom(value="widget-1"), check, timestamp),
    )
    assert (
        outputs(graph, Struct(name="output_field", args=(A, Atom(value="other")))) == ()
    )


def test_one_observation_graph_roundtrip_is_sufficient_for_durable_read(tmp_path):
    from cloud_dast.infrastructure.sqlite.formal_repository import (
        SqliteFormalRepository,
    )

    repo = SqliteFormalRepository(tmp_path / "formal.sqlite")
    obs = observation()
    canonical = project(obs)
    repo.save(
        f"observation:{obs.observation_id}",
        canonical,
        provenance={"check_id": obs.check_id},
        adapter_version="test-canonical",
        mapping_report={},
    )
    durable = merge_graphs(declarations(), repo.load_merged("observation:"))
    assert effects(durable) == effects(merge_graphs(declarations(), canonical))
    assert outputs(durable)[0][1] == Atom(value="widget-1")
    repo.close()


def test_two_ids_do_not_cross_observation_values_and_same_id_is_idempotent():
    first = observation("widget-1", obs_id="obs-1")
    second = observation("widget-2", obs_id="obs-2").model_copy(
        update={"check_id": "check-2"}
    )
    one = project(first)
    two = project(second, observed_at=2000.0)
    graph = merge_graphs(declarations(), one, two)
    assert len(instances(graph)) == 2
    assert set(outputs(graph)) == {
        (
            Atom(value="obs-1"),
            Atom(value="widget-1"),
            Atom(value="check-1"),
            Atom(value="1000.0"),
        ),
        (
            Atom(value="obs-2"),
            Atom(value="widget-2"),
            Atom(value="check-2"),
            Atom(value="2000.0"),
        ),
    }
    assert one == project(first)
    replay = project(
        first.model_copy(
            update={
                "observation_id": "replay",
                "scenario_id": "different-method-scenario",
            }
        )
    )
    assert instances(one) == instances(replay)
    assert len(instances(merge_graphs(one, replay))) == 1


@pytest.mark.parametrize("missing", ["identities", "scope", "observed_at"])
def test_missing_operational_provenance_cannot_authorize_reuse(missing):
    graph = merge_graphs(declarations(), project(**{missing: None}))
    assert effects(graph) == () and outputs(graph) == ()


def test_foreign_actual_identity_or_scenario_scope_does_not_match():
    graph = merge_graphs(declarations(), project())
    assert effects(graph, identities=("requested-not-executed",)) == ()
    assert outputs(graph, scope="foreign-binding") == ()
    assert effects(graph, scope="foreign-binding") == ()


@pytest.mark.parametrize("value", [None, "", 42])
def test_unconfirmed_output_never_proves_create_or_a_concrete_next_value(value):
    graph = merge_graphs(declarations(), project(observation(value)))
    assert effects(graph) == () and outputs(graph) == ()


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT])
def test_untrusted_provider_declarations_cannot_execute_recorded_evidence(context):
    # Even a real past observation does not turn runtime/proposal causes into
    # an executable source declaration.
    source = QdlGraph(
        facts=tuple(
            f.model_copy(update={"context": context}) for f in declarations().facts
        )
    )
    graph = merge_graphs(source, project())
    assert effects(graph) == () and outputs(graph) == ()


def amended(old, context=Context.ACCEPTED, *, derived=False):
    graph = merge_graphs(declarations(), project())
    replacement = Atom(value="replacement-node")
    additions = (
        fact("is", old, Atom(value="Node"), context=context),
        fact("is", replacement, Atom(value="Node"), context=context),
        fact("is", Atom(value="object_ref"), Atom(value="Node"), context=context),
    )
    supersedes = fact("supersedes", replacement, old, context=context)
    premise = fact("part", replacement, old, context=context)
    additions += (premise,) if derived else (supersedes,)
    facts = tuple({f.content_hash: f for f in (*graph.facts, *additions)}.values())
    return QdlGraph(
        facts=facts,
        rules=(Rule(body=(premise,), head=(supersedes,)),) if derived else (),
    )


@pytest.mark.parametrize(
    "context", [Context.CONTRACT, Context.ACCEPTED, Context.RUNTIME]
)
@pytest.mark.parametrize(
    "target",
    [
        "observation",
        "check",
        "action",
        "effect",
        "instance",
        "value",
        "role",
        "reference",
    ],
)
def test_current_supersession_closes_historical_effects_and_outputs(context, target):
    (instance,) = instances(project())
    old = {
        "observation": Atom(value="obs-1"),
        "check": Atom(value="check-1"),
        "action": A,
        "effect": E,
        "instance": instance,
        "value": Atom(value="widget-1"),
        "role": Struct(name="replacement", args=(W, Atom(value="object_ref"))),
        "reference": Struct(name="replacement", args=(W, T)),
    }[target]
    graph = amended(old, context)
    assert effects(graph) == ()
    if target == "effect":
        assert outputs(graph)  # Revoking causality does not erase an observed value.
    else:
        assert outputs(graph) == ()


def test_trusted_rules_derive_provider_reference_and_revocation():
    base = declarations()
    provider = next(f for f in base.facts if f.predicate.name == "causes")
    ref = next(f for f in base.facts if f.predicate.name == "refers_to")
    premise = fact("part", W, T)
    effect_decl = fact("is", E, Atom(value="Effect"))
    source = QdlGraph(
        facts=tuple(f for f in base.facts if f not in (provider, ref)) + (premise,),
        rules=(
            Rule(body=(effect_decl,), head=(provider,)),
            Rule(body=(premise,), head=(ref,)),
        ),
    )
    graph = merge_graphs(source, project(source=source))
    assert effects(graph) and outputs(graph)
    assert effects(amended(E, derived=True)) == ()
    assert outputs(amended(E, derived=True))
    assert effects(amended(E, Context.PROPOSAL, derived=True))
    assert effects(amended(E, Context.PROPOSAL))


@pytest.mark.parametrize("time", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_time_does_not_make_durable_proof(time):
    graph = merge_graphs(declarations(), project(observed_at=time))
    assert effects(graph) == () and outputs(graph) == ()


@pytest.mark.parametrize("role", ["sensitive", "credential"])
def test_current_forced_redaction_role_blocks_historical_output(role):
    graph = merge_graphs(declarations(), project())
    changed = QdlGraph(facts=(*graph.facts, fact("has", W, Atom(value=role))))
    assert effects(changed) == () and outputs(changed) == ()


def test_effect_source_filter_does_not_replace_another_producers_binding():
    from cloud_dast.qdl.graph import output_field

    other = Atom(value="action:svc.OtherMake")
    other_witness = output_field(other, Atom(value="id"))
    source = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", other, Atom(value="Action")),
                fact("is", T, Atom(value="ResourceType")),
                fact("is", other_witness, Atom(value="OutputField")),
                fact("has", other_witness, Atom(value="object_ref")),
                fact("refers_to", other_witness, T),
                fact("causes", other, E),
            )
        ),
    )
    obs = observation(obs_id="other-observation").model_copy(
        update={"check_id": "other-check"}
    )
    recorded = ObservationProjector().project(
        obs,
        "svc.OtherMake",
        graph=source,
        scope=SCOPE,
        identities=IDENTITIES,
        observed_at=1000.0,
    )
    graph = merge_graphs(source, recorded)
    assert read_observed_effects(graph, scope=SCOPE, identities=IDENTITIES)
    assert (
        read_observed_effects(
            graph, scope=SCOPE, identities=IDENTITIES, method_id="svc.Create"
        )
        == ()
    )
    rows = read_observed_effects(
        graph, scope=SCOPE, identities=IDENTITIES, method_id="svc.OtherMake"
    )
    assert rows and rows[0][0].args == (Atom(value="other-observation"), E)
    assert outputs(graph) == ()  # The Make witness is absent, despite equal effects.
    assert outputs(graph, other_witness)[0][1] == Atom(value="widget-1")


def destructive_source(kind="remove", *, cause_context=Context.ACCEPTED):
    from cloud_dast.qdl.graph import input_field

    action = Atom(value="action:svc.Delete")
    parameter = input_field(action, Atom(value="widget_id"))
    before, after = Atom(value="ready"), Atom(value="changed-state")
    effect = Struct(name=kind, args=(T,) if kind == "remove" else (before, after))
    source = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", action, Atom(value="Action")),
                fact("is", T, Atom(value="ResourceType")),
                fact("is", parameter, Atom(value="InputField")),
                fact("is", before, Atom(value="State")),
                fact("is", after, Atom(value="State")),
                fact("is", effect, Atom(value="Effect")),
                fact("has", parameter, Atom(value="object_ref")),
                fact("refers_to", parameter, T),
                fact("causes", action, effect, context=cause_context),
            )
        ),
    )
    return source, parameter


def consume(graph, *, scope=SCOPE, value="widget-1", outcome=None, check_updates=None):
    from cloud_dast.model import AccessOutcome, Check

    actual = Check(
        check_id="delete-check",
        invariant_id="ordinary",
        method_id="svc.Delete",
        scenario_id="delete-scenario",
        request=(("widget_id", value),),
        identities=IDENTITIES,
    )
    obs = observation(
        None, obs_id="delete-observation", scenario="delete-scenario"
    ).model_copy(
        update={
            "check_id": actual.check_id,
            "observed_outcome": outcome or AccessOutcome.ALLOWED,
        }
    )
    if check_updates:
        actual = actual.model_copy(update=check_updates)
    projected = ObservationProjector().project(
        obs,
        "svc.Delete",
        graph=graph,
        check=actual,
        identities=IDENTITIES,
        scope=scope,
        observed_at=1001.0,
    )
    return merge_graphs(graph, projected), projected


@pytest.mark.parametrize("kind", ["remove", "transition"])
def test_declared_mutation_invalidates_only_actual_typed_target(kind):
    source, _ = destructive_source(kind)
    graph = merge_graphs(
        source,
        project(source=source),
        project(observation("widget-2", obs_id="untouched"), source=source),
    )
    merged, invalidation = consume(graph)
    if kind == "remove":
        assert any(f.predicate.name == "supersedes" for f in invalidation.facts)
        assert {row[1].value for row in outputs(merged)} == {"widget-2"}
        assert {row[0].args[0].value for row in effects(merged)} == {"untouched"}
    else:
        # Changing mutable state does not revoke stable identity or creation.
        # There is no earlier transition claim in this graph to expire.
        assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
        assert set(outputs(merged)) == set(outputs(graph))
        assert set(effects(merged)) == set(effects(graph))
    assert not any(
        f.predicate.name == "evidence" and f.args[1].name in {"remove", "transition"}
        for f in invalidation.facts
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"check_id": "other-check"},
        {"method_id": "svc.Read"},
        {"scenario_id": "other-scenario"},
        {"identities": ("other-actor",)},
    ],
)
def test_unmatched_executed_check_never_invalidates_another_target(updates):
    source, _ = destructive_source()
    graph = merge_graphs(source, project(source=source))
    merged, invalidation = consume(graph, check_updates=updates)
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert outputs(merged)


def test_mutation_in_foreign_scope_or_with_other_id_does_not_consume_current_instance():
    source, _ = destructive_source()
    graph = merge_graphs(source, project(source=source))
    for kwargs in ({"scope": "other-scope"}, {"value": "other-id"}):
        merged, invalidation = consume(graph, **kwargs)
        assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
        assert outputs(merged)


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME, Context.REPORT])
def test_untrusted_destructive_declaration_never_invalidates(context):
    source, _ = destructive_source(cause_context=context)
    graph = merge_graphs(source, project(source=source))
    merged, invalidation = consume(graph)
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert outputs(merged)


def test_undeclared_input_semantics_never_invalidate_by_field_name_or_status():
    source, parameter = destructive_source()
    source = QdlGraph(
        facts=tuple(
            f
            for f in source.facts
            if not (f.predicate.name == "has" and f.args[0] == parameter)
        )
    )
    graph = merge_graphs(source, project(source=source))
    merged, invalidation = consume(graph)
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert outputs(merged)


def test_uncertain_destructive_result_invalidates_reuse_but_does_not_prove_remove():
    from cloud_dast.model import AccessOutcome

    source, _ = destructive_source()
    merged, invalidation = consume(
        merge_graphs(source, project(source=source)), outcome=AccessOutcome.ERROR
    )
    assert not outputs(merged)
    assert not any(
        f.predicate.name == "evidence" and f.args[1].name == "remove"
        for f in invalidation.facts
    )


def test_nonzero_process_with_retained_id_cannot_become_positive_create_proof():
    from cloud_dast.infrastructure.runtime.local_process import (
        JsonLocalProcessCodec,
        LocalProcessResult,
        LocalProcessTarget,
    )
    from cloud_dast.model import AccessOutcome, Check
    from cloud_dast.ports import Invocation

    class Invocations:
        def get_invocation(self, method_id):
            return Invocation(
                method_id=method_id, endpoint="unused", transport="local-process"
            )

    class Transport:
        def run(self, call):
            return LocalProcessResult(exit_code=1, stdout=b'{"id":"never-created"}')

    check = Check(
        check_id="process-check",
        invariant_id="ordinary",
        method_id="svc.Create",
        scenario_id="scenario-1",
        request=(),
        identities=IDENTITIES,
    )
    obs = LocalProcessTarget(
        Invocations(), JsonLocalProcessCodec(safe_fields=("id",)), Transport()
    )(check)
    assert (
        obs.observed_outcome is AccessOutcome.ERROR
        and obs.error_reason is None
        and obs.transport_status is None
    )
    projector = ObservationProjector()
    assert projector.verified_effects(obs, "svc.Create", declarations()) == ()
    graph = merge_graphs(
        declarations(),
        projector.project(
            obs,
            "svc.Create",
            graph=declarations(),
            check=check,
            identities=IDENTITIES,
            scope=SCOPE,
            observed_at=1000.0,
        ),
    )
    assert effects(graph) == () and outputs(graph) == ()


def test_concrete_instance_remove_revokes_its_old_proof():
    from cloud_dast.qdl.graph import remove

    source, _ = destructive_source()
    created = project(source=source)
    (instance,) = instances(created)
    action = Atom(value="action:svc.Delete")
    source = QdlGraph(
        facts=tuple(
            f
            for f in source.facts
            if not (f.predicate.name == "causes" and f.args[0] == action)
        )
        + created.facts
        + (
            fact("is", instance, Atom(value="Resource")),
            fact("causes", action, remove(instance)),
        )
    )
    merged, invalidation = consume(source)
    assert not effects(merged) and not outputs(merged)
    assert any(
        f.predicate.name == "supersedes"
        and f.args[1]
        == Struct(name="replacement", args=(Atom(value="obs-1"), instance))
        for f in invalidation.facts
    )
    assert not any(
        f.predicate.name == "supersedes" and f.args[1] == instance
        for f in invalidation.facts
    )


def test_new_creation_same_id_is_new_proof_while_old_proof_stays_closed():
    source, _ = destructive_source()
    consumed, _ = consume(merge_graphs(source, project(source=source)))
    assert not outputs(consumed)
    fresh = observation("widget-1", obs_id="new-creation").model_copy(
        update={"check_id": "new-check"}
    )
    new = project(fresh, source=consumed, observed_at=1002.0)
    current = merge_graphs(consumed, new)
    assert {row[0].args[0].value for row in effects(current)} == {"new-creation"}
    assert outputs(current) == (
        (
            Atom(value="new-creation"),
            Atom(value="widget-1"),
            Atom(value="new-check"),
            Atom(value="1002.0"),
        ),
    )
    assert new == project(fresh, source=consumed, observed_at=1002.0)
    replayed, _ = consume(current)
    assert outputs(replayed) == outputs(current)
    assert effects(replayed) == effects(current)


def test_consumption_preserves_other_instances_from_the_same_observation():
    from cloud_dast.model import ResponseData
    from cloud_dast.qdl.graph import output_field

    source, _ = destructive_source()
    sibling = output_field(A, Atom(value="sibling_id"))
    source = QdlGraph(
        facts=source.facts
        + (
            fact("is", sibling, Atom(value="OutputField")),
            fact("has", sibling, Atom(value="object_ref")),
            fact("refers_to", sibling, T),
        )
    )
    obs = observation().model_copy(
        update={
            "output": ResponseData(
                fields=(("id", "widget-1"), ("sibling_id", "widget-2")),
            )
        }
    )
    initial = merge_graphs(source, project(obs, source=source))
    assert {row[1].value for row in outputs(initial, sibling)} == {"widget-2"}
    current, _ = consume(initial, value="widget-1")
    assert not outputs(current, W)
    assert {row[1].value for row in outputs(current, sibling)} == {"widget-2"}
    assert effects(current)


def test_request_reference_cannot_become_another_observations_output():
    from cloud_dast.model import Check
    from cloud_dast.qdl.graph import input_field

    parameter = input_field(A, Atom(value="parent_id"))
    source = merge_graphs(
        declarations(),
        QdlGraph(
            facts=(
                fact("is", A, Atom(value="Action")),
                fact("is", T, Atom(value="ResourceType")),
                fact("is", parameter, Atom(value="InputField")),
                fact("has", parameter, Atom(value="object_ref")),
                fact("refers_to", parameter, T),
            )
        ),
    )
    first = project(source=source)
    obs = observation("widget-2", obs_id="second").model_copy(
        update={"check_id": "second-check"}
    )
    actual = Check(
        check_id=obs.check_id,
        invariant_id="ordinary",
        method_id="svc.Create",
        scenario_id=obs.scenario_id,
        identities=IDENTITIES,
        request=(("parent_id", "widget-1"),),
    )
    second = ObservationProjector().project(
        obs,
        actual.method_id,
        graph=merge_graphs(source, first),
        check=actual,
        identities=actual.identities,
        scope=SCOPE,
        observed_at=1002.0,
    )
    current = merge_graphs(source, first, second)
    assert {
        value.value
        for observation_id, value, _, _ in outputs(current)
        if observation_id == Atom(value="second")
    } == {"widget-2"}


def test_unrepresentable_input_reference_does_not_poison_canonical_evidence():
    from cloud_dast.qdl.engine import ClingoEngine

    source, parameter = destructive_source()
    graph = merge_graphs(source, project(source=source))
    current, invalidation = consume(graph, value="bad\0id")
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert ClingoEngine().compile(current)
    assert (
        read_observed_effects(
            current,
            scope=SCOPE,
            identities=IDENTITIES,
            method_id="svc.Delete",
            bindings=((parameter, Atom(value="bad\0id")),),
        )
        == ()
    )


def test_unrepresentable_output_reference_is_not_creation_evidence():
    from cloud_dast.qdl.engine import ClingoEngine

    obs = observation("bad\0id")
    graph = merge_graphs(declarations(), project(obs))
    assert ClingoEngine().compile(graph)
    assert not effects(graph) and not outputs(graph)


@pytest.mark.parametrize(
    ("proof_layout", "output_layout", "expected"),
    [
        ((), (), None),
        ((("old", 0, 1), ("old", 1, 1)), (), "old"),
        ((("old", 0, 1), ("new", 1, 2)), ((("old", "v"), ("new", "v")),), None),
        ((("old", 0, 1), ("old", 1, 1)), ((("new", "v"),),), None),
        ((("old", 0, 1), ("old", 1, 1)), ((("old", "v"), ("new", "other")),), None),
        (
            (
                ("old", 0, 1),
                ("old", 1, 1),
                ("new", 0, 3),
                ("new", 1, 3),
                ("partial", 0, 5),
            ),
            ((("old", "v"), ("new", "v")),),
            "new",
        ),
        (
            (("old", 0, 1), ("old", 1, 1), ("new", 0, 3), ("new", 1, 3)),
            ((("old", "v"),),),
            "old",
        ),
        ((("old", 0, 1), ("old", 1, 1)), ((),), None),
        (
            (("old", 0, 1), ("old", 1, 1), ("new", 0, 3), ("new", 1, 3)),
            ((("old", "v"),), (("new", "v"),)),
            None,
        ),
        (
            (("old", 0, 3), ("old", 1, 3), ("new", 0, 3), ("new", 1, 3)),
            ((("old", "v"), ("new", "v")),),
            "old",
        ),
    ],
)
def test_effect_witness_requires_one_complete_observation(
    proof_layout, output_layout, expected
):
    from cloud_dast.verification.projection import select_effect_witness

    required = (E, Struct(name="allowed", args=(A,)))
    proofs = tuple(
        (
            fact("evidence", Atom(value=obs), required[index], context=Context.RUNTIME),
            Atom(value=f"check:{obs}"),
            Atom(value=float(timestamp)),
        )
        for obs, index, timestamp in proof_layout
    )
    output_groups = (
        tuple(
            (
                Atom(value=obs),
                Atom(value=value),
                Atom(value=f"check:{obs}"),
                Atom(value=0.0),
            )
            for obs, value in group
        )
        for group in output_layout
    )
    selected = select_effect_witness(
        proofs, required_effects=required, outputs=output_groups
    )
    assert (selected[0].args[0].value if selected is not None else None) == expected


def test_revoked_input_role_binding_cannot_consume_existing_proof():
    source, parameter = destructive_source()
    revoked = Struct(name="replacement", args=(parameter, Atom(value="object_ref")))
    revised = QdlGraph(
        facts=(
            *source.facts,
            fact("is", revoked, Atom(value="Node")),
            fact("is", Atom(value="object_ref"), Atom(value="Node")),
            fact("is", Atom(value="revoked"), Atom(value="Node")),
            fact("supersedes", Atom(value="revoked"), revoked),
        )
    )
    graph = merge_graphs(revised, project(source=source))
    merged, invalidation = consume(graph)
    assert not any(f.predicate.name == "supersedes" for f in invalidation.facts)
    assert outputs(merged) == outputs(graph)
    assert effects(merged) == effects(graph)
