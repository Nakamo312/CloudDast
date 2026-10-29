"""Resource-scoped file policy reaches scenario and deterministic oracle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.composition.run_provider import FileScenarioRepository
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    EndpointLayer,
    MethodSpec,
)

ROOT = Path(__file__).resolve().parents[1]
ACTION = "grpc:svc.Get"
METHOD = MethodSpec(
    method_id=ACTION,
    service="svc",
    name="Get",
    layer=EndpointLayer.PUBLIC,
    permissions=frozenset({"read"}),
    resource_types=frozenset({"item"}),
)
RESOURCES = [dict(resource=x, resource_type="item") for x in ("item-1", "item-2")]


def repository(tmp_path, **policy):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(ROOT)
    path = tmp_path / "stand.json"
    path.write_text(json.dumps(dict(resources=RESOURCES, **policy)))
    return FileScenarioRepository(path)


def test_direct_grant_does_not_authorize_another_resource(tmp_path):
    repo = repository(
        tmp_path, permissions=[dict(subject="alice", action=ACTION, resource="item-1")]
    )
    allowed = repo.get_scenario("alice", "item-1", METHOD)
    foreign = repo.get_scenario("alice", "item-2", METHOD)
    assert allowed.stand.effective_permissions == METHOD.permissions
    assert allowed.stand.permissions_known
    assert not foreign.stand.effective_permissions
    assert not foreign.stand.permissions_known


@pytest.mark.parametrize("ownership", [False, True])
def test_existing_policy_derives_resource_scoped_may(tmp_path, ownership):
    policy = dict(
        requirements=[dict(action=ACTION, permission="read")],
        applications=[dict(permission="read", resource_type="item")],
        targets=[dict(action=ACTION, resource_type="item")],
    )
    if ownership:
        policy["ownerships"] = [dict(subject="alice", resource="item-1")]
    else:
        policy.update(
            bindings=[dict(subject="alice", role="reader", scope="tenant")],
            grants=[dict(role="reader", permission="read")],
            containments=[dict(child="item-1", parent="tenant")],
        )
    repo = repository(tmp_path, **policy)
    allowed = repo.get_scenario("alice", "item-1", METHOD)
    foreign = repo.get_scenario("alice", "item-2", METHOD)
    assert allowed is not None
    assert allowed.stand.effective_permissions == METHOD.permissions
    assert allowed.stand.permissions_known
    assert foreign is not None
    assert not foreign.stand.effective_permissions
    assert not foreign.stand.permissions_known


def test_type_decision_is_not_an_instance_wildcard(tmp_path):
    repo = repository(
        tmp_path, permissions=[dict(subject="alice", action=ACTION, resource="item")]
    )
    typed = repo.get_scenario("alice", "item", METHOD)
    instance = repo.get_scenario("alice", "item-1", METHOD)
    assert not typed.stand.effective_permissions
    assert not typed.stand.permissions_known
    assert not typed.stand.resources
    assert not instance.stand.effective_permissions
    assert not instance.stand.permissions_known


def test_policy_lookup_preserves_principal_action_and_resource_identity(tmp_path):
    repo = repository(
        tmp_path,
        permissions=[
            dict(subject="alice", action=ACTION, resource="item-1"),
            dict(subject="bob", action="grpc:svc.Other", resource="item-1"),
        ],
    )
    exact = repo.get_scenario(
        "subject:alice", "resource:item-1", method_id=f"action:{ACTION}", method=METHOD
    )
    assert exact.stand.principals[0].principal_id == "subject:alice"
    assert exact.stand.effective_permissions == METHOD.permissions
    for principal, resource, method in (
        ("bob", "item-1", METHOD),
        ("alice", "prefix:item-1", METHOD),
        ("alice", "item-1", METHOD.model_copy(update={"method_id": "grpc:svc.Other"})),
    ):
        scenario = repo.get_scenario(principal, resource, method)
        assert not scenario.stand.effective_permissions
        assert not scenario.stand.permissions_known
    assert repo.get_scenario("missing", "item-1", METHOD) is None


def test_positive_and_unknown_policy_have_distinct_oracle_grounding(tmp_path):
    from cloud_dast.model import (
        AccessOutcome,
        Observation,
        Severity,
        VerdictStatus,
    )
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, denied
    from cloud_dast.verification.oracles import GroundedOutcomeOracle

    repo = repository(
        tmp_path, permissions=[dict(subject="alice", action=ACTION, resource="item-1")]
    )
    invariant = InvariantProjection(
        invariant_id="i",
        norm_id="norm:deny-forbidden",
        statement="allowed control",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:deny-forbidden"),
                denied(Atom(value=f"action:{ACTION}")),
            ),
        ),
    )
    oracle = GroundedOutcomeOracle()
    for resource, grounded in (("item-1", True), ("item-2", False)):
        scenario = repo.get_scenario("alice", resource, METHOD)
        observation = Observation(
            check_id="check",
            scenario_id=scenario.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
        )
        verdict = oracle.evaluate_outcome(invariant, observation, METHOD, scenario)
        assert verdict.grounded is grounded
        if grounded:
            assert verdict.status is VerdictStatus.PASS


def test_permission_completeness_is_unknown_without_a_method(tmp_path):
    repo = repository(
        tmp_path, permissions=[dict(subject="alice", action=ACTION, resource="item-1")]
    )
    scenario = repo.get_scenario("alice", "item-1", method_id=ACTION)
    assert not scenario.stand.effective_permissions
    assert not scenario.stand.permissions_known


def test_policy_solver_failure_never_becomes_known_deny(tmp_path, monkeypatch):
    from cloud_dast.qdl.engine import ClingoEngine

    repo = repository(
        tmp_path,
        bindings=[dict(subject="alice", role="reader", scope="tenant")],
        grants=[dict(role="reader", permission="read")],
        requirements=[dict(action=ACTION, permission="read")],
        applications=[dict(permission="read", resource_type="item")],
        targets=[dict(action=ACTION, resource_type="item")],
        containments=[
            dict(child="item-1", parent="folder"),
            dict(child="folder", parent="tenant"),
        ],
    )
    assert repo.get_scenario("alice", "item-1", METHOD).stand.permissions_known

    def incomplete_solve(*args, **kwargs):
        raise RuntimeError("Clingo solve limit reached before completion")

    monkeypatch.setattr(ClingoEngine, "solve", incomplete_solve)
    scenario = repo.get_scenario("alice", "item-1", METHOD)
    assert not scenario.stand.permissions_known
    assert not scenario.stand.effective_permissions


def test_complete_scope_grounds_foreign_resource_as_denied(tmp_path):
    from cloud_dast.model import (
        AccessOutcome,
        Observation,
        Severity,
        VerdictStatus,
    )
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, allowed
    from cloud_dast.verification.norm_view import NormView
    from cloud_dast.verification.oracles import GroundedOutcomeOracle

    repo = repository(
        tmp_path,
        permissions=[dict(subject="alice", action=ACTION, resource="item-1")],
        completeness=[
            dict(
                service="svc",
                subject="alice",
                action=ACTION,
                resources=["item-1", "item-2"],
            )
        ],
    )
    permitted = repo.get_scenario("alice", "item-1", METHOD)
    assert permitted.stand.effective_permissions == METHOD.permissions
    assert permitted.stand.permissions_known
    foreign = repo.get_scenario("alice", "item-2", METHOD)
    invariant = InvariantProjection(
        invariant_id="i",
        norm_id="norm:foreign",
        statement="foreign denied",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:foreign"), allowed(Atom(value=f"action:{ACTION}"))),
        ),
    )
    norm = NormView.from_invariant(invariant)
    expected, grounded, _ = GroundedOutcomeOracle._expected_outcome(
        norm, METHOD, foreign
    )
    assert expected is AccessOutcome.DENIED
    assert grounded
    observation = Observation(
        check_id="check",
        scenario_id=foreign.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
    )
    verdict = GroundedOutcomeOracle().evaluate_outcome(
        invariant, observation, METHOD, foreign
    )
    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded
    assert verdict.deterministic


@pytest.mark.parametrize(
    "scope_change",
    [
        {"service": "another-service"},
        {"subject": "bob"},
        {"subject": "subject:alice"},
        {"action": "grpc:svc.Other"},
        {"action": f"action:{ACTION}"},
        {"resources": ["item-1"]},
    ],
)
def test_completeness_does_not_escape_its_scope(tmp_path, scope_change):
    scope = dict(
        service="svc", subject="alice", action=ACTION, resources=["item-1", "item-2"]
    )
    scope.update(scope_change)
    repo = repository(
        tmp_path,
        permissions=[dict(subject="alice", action=ACTION, resource="item-1")],
        completeness=[scope],
    )
    foreign = repo.get_scenario("alice", "item-2", METHOD)
    assert not foreign.stand.effective_permissions
    assert not foreign.stand.permissions_known


@pytest.mark.parametrize(
    "scope_change",
    [
        {"resources": ["missing"]},
        {"resources": []},
        {"service": " "},
        {"subject": ""},
        {"action": ""},
    ],
)
def test_invalid_complete_scope_is_rejected_at_file_boundary(tmp_path, scope_change):
    scope = dict(service="svc", subject="alice", action=ACTION, resources=["item-2"])
    scope.update(scope_change)
    with pytest.raises(ValueError):
        repository(tmp_path, completeness=[scope])


def test_complete_scope_cannot_claim_another_services_resource(tmp_path):
    from cloud_dast.infrastructure.stand.file import FileStandSource

    path = tmp_path / "stand.json"
    path.write_text(
        json.dumps(
            dict(
                resources=[
                    dict(resource="item-2", resource_type="item", service="foreign")
                ],
                completeness=[
                    dict(
                        service="svc",
                        subject="alice",
                        action=ACTION,
                        resources=["item-2"],
                    )
                ],
            )
        )
    )
    with pytest.raises(ValueError, match="another service"):
        FileStandSource(path).snapshot("svc")


def test_core_may_query_preserves_exact_triples_and_pair_projection(tmp_path):
    from cloud_dast.infrastructure.stand.file import FileStandSource
    from cloud_dast.qdl.engine import ClingoEngine

    repository(
        tmp_path,
        permissions=[
            dict(subject="alice", action=ACTION, resource="item-1"),
            dict(subject="alice", action=ACTION, resource="item-2"),
            dict(subject="bob", action="grpc:svc.Other", resource="item-2"),
        ],
    )
    graph = FileStandSource(tmp_path / "stand.json").project("svc")
    engine = ClingoEngine()
    assert engine.derive_may_triples(graph) == (
        ("principal:alice", f"action:{ACTION}", "resource:item-1"),
        ("principal:alice", f"action:{ACTION}", "resource:item-2"),
        ("principal:bob", "action:grpc:svc.Other", "resource:item-2"),
    )
    assert engine.derive_may_pairs(graph) == (
        ("principal:alice", f"action:{ACTION}"),
        ("principal:bob", "action:grpc:svc.Other"),
    )


def test_core_may_query_reuses_transitive_rbac_derivation(tmp_path):
    from cloud_dast.infrastructure.stand.file import FileStandSource
    from cloud_dast.qdl.engine import ClingoEngine

    repository(
        tmp_path,
        bindings=[dict(subject="alice", role="reader", scope="tenant")],
        grants=[dict(role="reader", permission="read")],
        requirements=[dict(action=ACTION, permission="read")],
        applications=[dict(permission="read", resource_type="item")],
        targets=[dict(action=ACTION, resource_type="item")],
        containments=[
            dict(child="item-1", parent="folder"),
            dict(child="folder", parent="tenant"),
        ],
    )
    graph = FileStandSource(tmp_path / "stand.json").project("svc")
    assert ClingoEngine().derive_may_triples(graph) == (
        ("principal:alice", f"action:{ACTION}", "resource:item-1"),
    )


@pytest.mark.parametrize("failure", ["no_stable_model", "runtime_error"])
def test_core_query_failure_remains_unknown_even_in_complete_scope(
    tmp_path, monkeypatch, failure
):
    from cloud_dast.infrastructure.stand.file import FileStandSource
    from cloud_dast.qdl.engine import ClingoEngine

    repo = repository(
        tmp_path,
        completeness=[
            dict(service="svc", subject="alice", action=ACTION, resources=["item-2"]),
        ],
    )
    graph = FileStandSource(tmp_path / "stand.json").project("svc")
    # A completed model with no may is distinct from a failed/no-model solve.
    assert ClingoEngine().derive_may_triples(graph) == ()
    assert repo.get_scenario("alice", "item-2", METHOD).stand.permissions_known

    def fail_solve(*args, **kwargs):
        if failure == "no_stable_model":
            return ()
        raise RuntimeError("Clingo solve limit reached before completion")

    monkeypatch.setattr(ClingoEngine, "solve", fail_solve)
    for query in (ClingoEngine().derive_may_triples, ClingoEngine().derive_may_pairs):
        with pytest.raises(RuntimeError):
            query(graph)
    scenario = repo.get_scenario("alice", "item-2", METHOD)
    assert not scenario.stand.permissions_known
    assert not scenario.stand.effective_permissions
