"""Observable regressions for projection I-4/I-5 and planning-4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import cloud_dast
from cloud_dast.composition.app_provider import (
    FileContractGraphRepository,
    FileInvocationRepository,
    FileMethodRepository,
    load_contract_manifest,
)
from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import Atom, input_field
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.contract_projection import (
    ContractProjector,
)
from cloud_dast_fuzzing import (
    MinimalSeedGenerator,
    TemplateGenerator,
)


def _manifest(tmp_path, method_ids, enum_values=(" admin ",)):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    path = tmp_path / "contract.json"
    path.write_text(
        json.dumps(
            {
                "service": "svc",
                "endpoints": [{"address": "offline.invalid:443"}],
                "methods": [
                    {
                        "method_id": method_id,
                        "service": "svc",
                        "name": "Update",
                        "layer": "private",
                        "input_type": "svc.UpdateRequest",
                        "fields": [
                            {
                                "name": "status",
                                "type": "string",
                                "required": True,
                                "enum_values": enum_values,
                            }
                        ],
                    }
                    for method_id in method_ids
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _project(path):
    return ContractProjector().project(
        FileContractGraphRepository(path).load_slice("svc")
    )


@pytest.mark.parametrize("literal", [" admin ", "\tadmin\n", "admin", "", "   "])
def test_enum_literal_survives_projection_and_public_generation(
    tmp_path, literal, verification_plan, invariant, scenario_position
):
    path = _manifest(tmp_path, ["grpc:svc.Update"], (literal,))
    method = FileMethodRepository(path).list_methods("svc")[0]
    assert load_contract_manifest(path).methods[0].fields[0].enum_values == (literal,)
    assert method.fields[0].enum_values == (literal,)
    projection = _project(path)
    field = input_field(
        Atom(value=canonical_action_id(method.method_id)), Atom(value="status")
    )
    values = {
        fact.args[1].value
        for fact in projection.graph.facts_for("field_enum_value")
        if fact.args[0] == field
    }
    plan = verification_plan.model_copy(update={"method_id": method.method_id})
    check = MinimalSeedGenerator(TemplateGenerator()).generate(
        plan, method, invariant, scenario_position
    )[0]
    assert dict(check.request)["status"] == literal
    assert values == {literal}
    assert projection.report.unmapped == ()


def test_enum_whitespace_changes_content_identity_without_collapsing_values(tmp_path):
    path = _manifest(tmp_path, ["grpc:svc.Update"], (" admin ",))
    padded = _project(path)
    path = _manifest(tmp_path, ["grpc:svc.Update"], ("admin",))
    plain = _project(path)
    assert padded.canonical_hash != plain.canonical_hash
    path = _manifest(tmp_path, ["grpc:svc.Update"], (" admin ", "admin"))
    combined = _project(path)
    assert {
        fact.args[1].value for fact in combined.graph.facts_for("field_enum_value")
    } == {" admin ", "admin"}


@pytest.mark.parametrize(
    ("source_id", "canonical_id", "rpc_path"),
    [
        ("svc.Update", "grpc:svc.Update", "/svc/Update"),
        ("  svc/Update  ", "grpc:svc.Update", "/svc/Update"),
        ("svc.priv.Update", "grpc-priv:svc.priv.Update", "/svc.priv/Update"),
        ("grpc:svc.Update", "grpc:svc.Update", "/svc/Update"),
    ],
)
def test_manifest_repositories_and_projection_share_canonical_identity(
    tmp_path, source_id, canonical_id, rpc_path
):
    path = _manifest(tmp_path, [source_id])
    manifest = load_contract_manifest(path)
    assert manifest.methods[0].method_id == canonical_id
    methods = FileMethodRepository(path)
    method = methods.list_methods("svc")[0]
    assert method.method_id == canonical_id
    assert methods.get_method(method.method_id) == method
    assert methods.get_method(source_id) == method
    invocation = FileInvocationRepository(path).get_invocation(method.method_id)
    assert invocation is not None
    assert invocation.method_id == canonical_id
    assert invocation.rpc_path == rpc_path
    assert any(
        fact.args
        == (Atom(value=canonical_action_id(canonical_id)), Atom(value="Action"))
        for fact in _project(path).graph.facts_for("is")
    )


@pytest.mark.parametrize(
    "ids", [("svc.Update", "grpc:svc.Update"), ("svc/Update", "svc.Update")]
)
def test_manifest_rejects_normalized_identity_collisions(tmp_path, ids):
    path = _manifest(tmp_path, ids)
    with pytest.raises(ValidationError, match="duplicate method IDs"):
        load_contract_manifest(path)


def test_manifest_rejects_whitespace_only_method_id(tmp_path):
    path = _manifest(tmp_path, ["  "])
    with pytest.raises(ValidationError, match="method ID must not be blank"):
        load_contract_manifest(path)


@pytest.mark.parametrize("effect_kind", ["changed", "has"])
@pytest.mark.parametrize(
    "resource_types", [("user", "order"), ("tenant.record", "task.record")]
)
def test_public_binder_does_not_attach_resource_norm_to_neighbor_with_same_field(
    tmp_path, scenario_position, resource_types, effect_kind
):
    from unittest.mock import Mock

    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
    from cloud_dast.model import ResourceRef
    from cloud_dast.qdl.graph import (
        Context,
        Fact,
        Predicate,
        QdlGraph,
        changed,
        field,
        has,
    )
    from cloud_dast.runtime.binding import ScenarioBinder

    path = _manifest(tmp_path, ["grpc:svc.UpdateLeft", "grpc:svc.UpdateRight"])
    manifest = json.loads(path.read_text())
    for record, resource_type in zip(manifest["methods"], resource_types, strict=True):
        record["resource_types"] = [resource_type]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    contract = _project(path).graph
    methods = FileMethodRepository(path)
    norm = Atom(value="norm:protected-status")
    principal = Atom(value="principal:attacker")
    witnesses = tuple(
        field(Atom(value=f"resource:{resource_type}"), Atom(value="status"))
        for resource_type in resource_types
    )
    effects = tuple(
        changed(witness.args[0], witness.args[1])
        if effect_kind == "changed"
        else has(principal, witness)
        for witness in witnesses
    )
    facts = [
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_name("is"),
            args=(norm, Atom(value="Norm")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(norm, effects[0]),
        ),
    ]
    if effect_kind == "has":
        facts.append(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(principal, Atom(value="Subject")),
            )
        )
        facts.extend(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(witness, Atom(value="Witness")),
            )
            for witness in witnesses
        )
    for method, effect, witness in zip(
        methods.list_methods("svc"), effects, witnesses, strict=True
    ):
        facts.append(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name(
                    "causes" if effect_kind == "changed" else "exposes"
                ),
                args=(
                    Atom(value=canonical_action_id(method.method_id)),
                    effect if effect_kind == "changed" else witness,
                ),
            )
        )
    graph = QdlGraph(facts=(*contract.facts, *facts))
    scenarios = Mock()
    stand = scenario_position.stand.model_copy(
        update={
            "resources": tuple(
                ResourceRef(resource_id=f"fixture-{i}", resource_type=t, service="svc")
                for i, t in enumerate(resource_types)
            )
        }
    )
    scenarios.get_scenario.return_value = scenario_position.model_copy(
        update={"stand": stand}
    )
    with SqliteFormalRepository(":memory:") as repository:
        repository.save(
            "contract:svc",
            graph,
            provenance={},
            adapter_version="test",
            mapping_report={},
        )
        binding = ScenarioBinder(
            methods, scenarios, repository, qdl_planner=IncrementalQdlPlanner()
        ).bind(
            LiveRequest(
                service="svc",
                method_id="grpc:svc.UpdateLeft",
                principal_id="attacker",
                resource_id="fixture-0",
            ),
            formal_proposal=False,
        )
    bound = {
        step.method.method_id
        for bound_path in binding.execution.paths
        for step in bound_path.steps
        if step.invariant.norm_id == norm.value
    }
    assert bound == {"grpc:svc.UpdateLeft"}
