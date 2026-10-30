"""A scenario's policy proof must concern the resource its check addresses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.candidates import TemplateGenerator
from cloud_dast.composition.run_provider import FileScenarioRepository
from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, allowed
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.verification.oracles import primitive_router

ACTION = "grpc:svc.Get"
METHOD = MethodSpec(
    method_id=ACTION,
    service="svc",
    name="Get",
    layer=EndpointLayer.PUBLIC,
    permissions=frozenset({"read"}),
    resource_types=frozenset({"item"}),
    fields=(FieldSpec(name="item_id", type="string", required=True),),
)
NORM = InvariantProjection(
    invariant_id="i",
    norm_id="n",
    statement="foreign access forbidden",
    severity=Severity.HIGH,
    norm_fact=Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="n"), allowed(Atom(value=f"action:{ACTION}"))),
    ),
)


class EventLog:
    def __init__(self):
        self.events = []
        self.cursors = {}

    def publish(self, event):
        self.events.append(event)

    def read_new(self, key):
        start = self.cursors.get(key, 0)
        self.cursors[key] = len(self.events)
        return tuple(self.events[start:])


@pytest.mark.parametrize(
    "requested,complete,bound_expected,known,findings",
    [
        ("folder-1", True, False, False, 0),
        ("item-1", True, True, True, 0),
        ("item-2", True, True, True, 1),
        ("item-2", False, True, False, 0),
        ("missing", True, False, False, 0),
    ],
)
def test_actual_resource_binding_preserves_scoped_policy(
    tmp_path,
    requested,
    complete,
    bound_expected,
    known,
    findings,
):
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )
    path = tmp_path / "stand.json"
    path.write_text(
        json.dumps(
            dict(
                resources=[
                    dict(resource="item-1", resource_type="item"),
                    dict(resource="item-2", resource_type="item"),
                    dict(resource="folder-1", resource_type="folder"),
                ],
                permissions=[dict(subject="alice", action=ACTION, resource="item-1")],
                completeness=(
                    [
                        dict(
                            service="svc",
                            subject="alice",
                            action=ACTION,
                            resources=["folder-1", "item-1", "item-2"],
                        )
                    ]
                    if complete
                    else []
                ),
            )
        )
    )
    repo = FileScenarioRepository(path)
    scenario = repo.get_scenario(
        "alice",
        requested,
        method=METHOD,
    )
    bound = bool(scenario.stand.resources)
    assert bound is bound_expected
    assert scenario == repo.get_scenario("alice", requested, METHOD)
    assert scenario.stand.effective_permissions == (
        METHOD.permissions if requested == "item-1" else frozenset()
    )
    assert scenario.stand.permissions_known is known
    if bound:
        assert tuple(r.resource_id for r in scenario.stand.resources) == (requested,)
    else:
        assert not scenario.stand.resources
    plan = VerificationPlan(
        plan_id="p",
        method_id=ACTION,
        scenario_id=scenario.scenario_id,
        invariant_id=NORM.invariant_id,
        resource_types=(("item_id", "item"),),
    )
    check = TemplateGenerator().generate(plan, METHOD, NORM, scenario)[0]
    assert dict(check.request)["item_id"] == (requested if bound else None)
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
    )
    verdict = primitive_router.Oracle().evaluate_policy(
        NORM, (observation,), method=METHOD, scenario=scenario
    )
    assert verdict.grounded is bool(findings)
    if findings:
        assert verdict.status is VerdictStatus.FAIL
    log = EventLog()
    execution = ExecutionResult(
        observations=(observation,),
        checks=(check,),
        provenance={
            (observation.observation_id, NORM.invariant_id): ObservationProvenance(
                None, "path", "step", NORM.invariant_id
            )
        },
        policy_verdicts={(observation.observation_id, NORM.invariant_id): verdict},
    )
    result = FindingEvaluator(EventProjection(log, log)).evaluate(
        execution, {NORM.invariant_id: NORM}
    )
    assert len(result.findings) == findings


def test_actual_resource_binding_cannot_inherit_another_resources_deny(tmp_path):
    path = tmp_path / "stand.json"
    path.write_text(
        json.dumps(
            dict(
                resources=[
                    dict(resource="folder-1", resource_type="folder"),
                    dict(resource="item-1", resource_type="item"),
                ],
                completeness=[
                    dict(
                        service="svc",
                        subject="alice",
                        action=ACTION,
                        resources=["folder-1"],
                    )
                ],
            )
        )
    )
    repository = FileScenarioRepository(path)
    # The complete denial for a container never becomes proof for an item.
    container = repository.get_scenario("alice", "folder-1", method=METHOD)
    assert not container.stand.resources
    assert not container.stand.permissions_known
    assert not container.stand.effective_permissions

    scenario = repository.get_scenario("alice", "item-1", method=METHOD)
    assert tuple(r.resource_id for r in scenario.stand.resources) == ("item-1",)
    assert scenario.stand.resources[0].resource_type == "item"
    assert not scenario.stand.permissions_known
    assert not scenario.stand.effective_permissions
    plan = VerificationPlan(
        plan_id="p:item",
        method_id=ACTION,
        scenario_id=scenario.scenario_id,
        invariant_id=NORM.invariant_id,
        resource_types=(("item_id", "item"),),
    )
    check = TemplateGenerator().generate(plan, METHOD, NORM, scenario)[0]
    assert dict(check.request)["item_id"] == "item-1"
    observation = Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
    )
    verdict = primitive_router.Oracle().evaluate_policy(
        NORM,
        (observation,),
        method=METHOD,
        scenario=scenario,
    )
    assert not verdict.grounded
    log = EventLog()
    result = FindingEvaluator(EventProjection(log, log)).evaluate(
        ExecutionResult(
            observations=(observation,),
            checks=(check,),
            provenance={
                (observation.observation_id, NORM.invariant_id): ObservationProvenance(
                    None, "path", "step", NORM.invariant_id
                )
            },
            policy_verdicts={(observation.observation_id, NORM.invariant_id): verdict},
        ),
        {NORM.invariant_id: NORM},
    )
    assert result.findings == ()
