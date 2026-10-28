"""Ordinary QDL create/pay/ship execution and state-evidence controls."""

from __future__ import annotations

from dataclasses import replace

import pytest

from cloud_dast.api import LiveRequest
from cloud_dast.binding import scenario_scope
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    ExecutionTrace,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    PrincipalRef,
    ResponseData,
    StandState,
    TraceStep,
)
from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    allowed,
    create,
    input_field,
    output_field,
    transition,
)
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.projection import (
    ObservationProjector,
    read_observed_effects,
)
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


def fact(name, *args, context=Context.ACCEPTED):
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    return Fact(
        context=context,
        predicate=Predicate.from_schema(schema)
        if schema
        else Predicate.from_name(name),
        args=args,
    )


def case(scenario_position, *, pay=True, missing_pay_method=False, transform=None):
    actions = {name: Atom(value=f"action:{name}") for name in ("Create", "Pay", "Ship")}
    resource = Atom(value="resource:order")
    output = output_field(actions["Create"], Atom(value="id"))
    created = create(resource)
    paid = transition(Atom(value="created"), Atom(value="paid"))
    goal = allowed(actions["Ship"])
    facts = [
        fact("is", term, Atom(value=kind))
        for term, kind in (
            *((action, "Action") for action in actions.values()),
            (resource, "ResourceType"),
            (Atom(value="principal:actor"), "Subject"),
            (output, "OutputField"),
            (created, "Effect"),
            (paid, "Effect"),
            (Atom(value="created"), "State"),
            (Atom(value="paid"), "State"),
            (goal, "Effect"),
            (Atom(value="norm:ship"), "Norm"),
        )
    ]
    facts.extend(
        (
            fact("attacker", Atom(value="principal:actor")),
            fact("has", output, Atom(value="object_ref")),
            fact("refers_to", output, resource),
            fact("causes", actions["Create"], created),
            fact("requires", actions["Pay"], created),
            fact("requires", actions["Ship"], paid),
            fact("causes", actions["Ship"], goal),
            fact("prevents", Atom(value="norm:ship"), goal),
        )
    )
    if pay:
        facts.append(fact("causes", actions["Pay"], paid))
    for name in ("Pay", "Ship"):
        parameter = input_field(actions[name], Atom(value="ref"))
        facts.extend(
            (
                fact("is", parameter, Atom(value="InputField")),
                fact("has", parameter, Atom(value="object_ref")),
                fact("refers_to", parameter, resource),
                fact("coupled", output, parameter, Atom(value="eq")),
            )
        )
    graph = QdlGraph(facts=tuple(facts))
    if transform:
        graph = transform(graph)
    methods = tuple(
        MethodSpec(
            method_id=name,
            service="orders",
            name=name,
            layer=EndpointLayer.PRIVATE,
            fields=(FieldSpec(name="tag", type="string"),)
            if name == "Create"
            else (FieldSpec(name="ref", type="string", required=True),),
        )
        for name in ("Create", "Pay", "Ship")
        if not (missing_pay_method and name == "Pay")
    )
    scenario = scenario_position.model_copy(
        update={
            "stand": StandState(
                principals=(PrincipalRef(principal_id="actor", principal_type="user"),),
                permissions_known=True,
            )
        }
    )
    plan = QdlPlanner().plan(graph)
    view = build(
        plan,
        graph,
        methods=methods,
        scenarios_by_method={m.method_id: scenario for m in methods},
    )
    paths = tuple(
        path
        for path in view.paths
        if tuple(s.method.method_id for s in path.steps) == ("Create", "Pay", "Ship")
    )
    return graph, plan, replace(view, paths=paths)


class EventLog:
    def __init__(self):
        self.events = []
        self.cursors = {}

    def publish(self, event):
        self.events.append(event)

    def append(self, event):
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id):
        start = self.cursors.get(consumer_id, 0)
        self.cursors[consumer_id] = len(self.events)
        return tuple(self.events[start:])


class ChainRuntime:
    def __init__(self, mode="valid"):
        self.mode = mode
        self.actions = []
        self.checks = []
        self.state = "new"
        self.created = 0

    def __call__(self, check):
        self.actions.append(check.method_id)
        self.checks.append(check)
        before = self.state
        if check.method_id == "Create":
            self.created += 1
            self.state = "created"
        else:
            assert dict(check.request)["ref"] == f"made-order-{self.created}"
            if check.method_id == "Pay":
                assert self.state == "created"
                self.state = "paid"
            if check.method_id == "Ship":
                assert self.state == "paid"
                self.state = "shipped"
        observation = Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("id", f"made-order-{self.created}"),)),
        )
        trace = TraceStep(
            observation_id=observation.observation_id,
            step_id=check.check_id,
            method_id=check.method_id,
            scenario_id=check.scenario_id,
            status=AccessOutcome.ALLOWED,
            resource_state_before=(("control", before),),
            resource_state_after=(("control", self.state),),
        )
        if check.method_id == "Pay":
            changes = {
                "no_state": {"resource_state_before": (), "resource_state_after": ()},
                "wrong_before": {"resource_state_before": (("control", "new"),)},
                "wrong_after": {"resource_state_after": (("control", "created"),)},
                "partial_state": {"resource_state_after": ()},
                "wrong_method": {"method_id": "Other"},
                "wrong_trace_scenario": {"scenario_id": "other"},
                "wrong_observation": {"observation_id": "other"},
            }
            trace = trace.model_copy(update=changes.get(self.mode, {}))
            if self.mode == "wrong_check":
                observation = observation.model_copy(update={"check_id": "other"})
            if self.mode == "wrong_scenario":
                observation = observation.model_copy(update={"scenario_id": "other"})
            if self.mode == "denied":
                observation = observation.model_copy(
                    update={"observed_outcome": AccessOutcome.DENIED}
                )
            if self.mode == "transport":
                observation = observation.model_copy(
                    update={"transport_status": HttpStatus(code=503)}
                )
        traces = (
            (
                trace,
                trace.model_copy(
                    update={"resource_state_after": (("control", "created"),)}
                ),
            )
            if check.method_id == "Pay" and self.mode == "conflicting_trace"
            else (trace,)
        )
        return observation.model_copy(update={"trace": ExecutionTrace(steps=traces)})


def execute(
    scenario,
    *,
    mode="valid",
    max_checks=3,
    pay=True,
    missing_pay_method=False,
    transform=None,
    generator=None,
):
    graph, plan, view = case(
        scenario, pay=pay, missing_pay_method=missing_pay_method, transform=transform
    )
    target, events = ChainRuntime(mode), EventLog()
    service = Checker(
        target, generator or TemplateGenerator(), AllowAllGuardrail(), events
    )
    runner = BoundPathRunner(service, events, events)
    result = runner.execute_plan(
        LiveRequest(
            service="orders",
            principal_id="actor",
            resource_id="order",
            max_checks=max_checks,
        ),
        plan,
        view,
    )
    return result, target, events, view, graph


def test_ordinary_plan_proves_create_pay_before_ship(scenario_position):
    _, _, view = case(scenario_position)
    (path,) = view.paths
    assert [step.method.method_id for step in path.steps] == ["Create", "Pay", "Ship"]
    assert path.steps[0].invariant.norm_fact is None
    assert path.steps[1].invariant.norm_fact is None
    assert path.steps[0].required_effects[0].name == "create"
    assert path.steps[1].required_effects == (
        transition(Atom(value="created"), Atom(value="paid")),
    )


def test_ordinary_execution_establishes_paid_before_ship(scenario_position):
    result, target, _, _, _ = execute(scenario_position)
    assert target.actions == ["Create", "Pay", "Ship"]
    assert target.state == "shipped"
    assert len(result.checks) == len(result.observations) == 3
    assert all(
        dict(check.request).get("ref") == "made-order-1" for check in result.checks[1:]
    )


@pytest.mark.parametrize(
    "mode",
    [
        "no_state",
        "wrong_before",
        "wrong_after",
        "partial_state",
        "wrong_method",
        "wrong_trace_scenario",
        "wrong_observation",
        "conflicting_trace",
        "denied",
        "transport",
    ],
)
def test_unproved_transition_blocks_ship(scenario_position, mode):
    result, target, _, _, _ = execute(scenario_position, mode=mode)
    assert target.actions == ["Create", "Pay"]
    assert len(result.checks) == 2
    assert not any(
        v.grounded and v.status.value == "fail" for v in result.policy_verdicts.values()
    )


@pytest.mark.parametrize("mode", ["wrong_check", "wrong_scenario"])
def test_foreign_transition_observation_is_rejected(scenario_position, mode):
    with pytest.raises(ValueError, match="another check|another scenario"):
        execute(scenario_position, mode=mode)


@pytest.mark.parametrize("missing", ["transition", "method"])
def test_missing_causal_provider_cannot_execute_ship(scenario_position, missing):
    result, target, _, view, _ = execute(
        scenario_position,
        pay=missing != "transition",
        missing_pay_method=missing == "method",
    )
    assert view.paths == ()
    assert result.checks == ()
    assert target.actions == []


@pytest.mark.parametrize("state", ["existing", "created", "updated", "deleted"])
def test_profile_state_never_substitutes_for_transition_evidence(
    scenario_position, state
):
    position = scenario_position.model_copy(
        update={
            "profile": scenario_position.profile.model_copy(
                update={"resource_state": state}
            )
        }
    )
    _, target, _, _, _ = execute(position, mode="no_state")
    assert target.actions == ["Create", "Pay"]


def test_request_budget_counts_ordinary_prefix_calls(scenario_position):
    result, target, _, _, _ = execute(scenario_position, max_checks=2)
    assert target.actions == ["Create", "Pay"]
    assert len(result.checks) == 2
    assert target.state == "paid"


def test_mutated_create_is_not_replaced_by_prior_resource(scenario_position):
    class CandidateGenerator(TemplateGenerator):
        def generate(self, plan, method, invariant, scenario, **kwargs):
            checks = super().generate(plan, method, invariant, scenario, **kwargs)
            if method.method_id == "Create":
                return (
                    checks[0].model_copy(
                        update={
                            "request": (("tag", "mutation"),),
                            "check_id": "candidate:create",
                        }
                    ),
                )
            return checks

    result, target, _, _, _ = execute(scenario_position, generator=CandidateGenerator())
    assert target.actions == ["Create", "Pay", "Ship"]
    assert result.checks[0].check_id == "candidate:create"
    assert result.checks[0].request == (("tag", "mutation"),)


def test_superseded_create_cannot_supply_causal_path(scenario_position):
    def supersede(graph):
        effect = create(Atom(value="resource:order"))
        replacement = allowed(Atom(value="action:Create"))
        return QdlGraph(
            facts=graph.facts
            + (
                fact("is", replacement, Atom(value="Effect")),
                fact("supersedes", replacement, effect),
            )
        )

    result, target, _, view, _ = execute(scenario_position, transform=supersede)
    assert view.paths == () and result.checks == () and target.actions == []


def test_rule_derived_create_uses_the_same_ordinary_path(scenario_position):
    def derive(graph):
        provider = next(
            f
            for f in graph.facts_for("causes")
            if f.args[0] == Atom(value="action:Create")
        )
        witness = next(
            f
            for f in graph.facts_for("has")
            if f.args[0] == output_field(Atom(value="action:Create"), Atom(value="id"))
        )
        return QdlGraph(
            facts=tuple(f for f in graph.facts if f != provider),
            rules=(
                Rule(
                    body=(
                        witness,
                        next(
                            f
                            for f in graph.facts_for("is")
                            if f.args == (provider.args[1], Atom(value="Effect"))
                        ),
                    ),
                    head=(provider,),
                ),
            ),
        )

    _, target, _, _, _ = execute(scenario_position, transform=derive)
    assert target.actions == ["Create", "Pay", "Ship"]


def test_supersession_closes_a_previously_proved_paid_transition(scenario_position):
    result, target, events, view, graph = execute(scenario_position)
    step = view.paths[0].steps[1]
    observation = result.observations[1]
    occurred_at = next(
        event.occurred_at.timestamp()
        for event in events.events
        if getattr(event, "observation", None) == observation
    )
    projected = ObservationProjector().project(
        observation,
        step.method.method_id,
        graph=graph,
        scope=scenario_scope(step.scenario),
        identities=result.checks[1].identities,
        observed_at=occurred_at,
    )
    from cloud_dast.qdl.graph_ops import merge_graphs

    merged = merge_graphs(graph, projected)
    effect = transition(Atom(value="created"), Atom(value="paid"))
    assert any(
        row[0].args[1] == effect
        for row in read_observed_effects(
            merged,
            scope=scenario_scope(step.scenario),
            identities=result.checks[1].identities,
        )
    )
    replacement = Atom(value="superseded-transition")
    revoked = QdlGraph(
        facts=merged.facts
        + (
            fact("is", replacement, Atom(value="Node")),
            fact("supersedes", replacement, effect),
        )
    )
    assert not read_observed_effects(
        revoked,
        scope=scenario_scope(step.scenario),
        identities=result.checks[1].identities,
    )


def test_historical_transition_cannot_discharge_another_resources_step(
    tmp_path, scenario_position
):
    from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
    from tests.workflow.execution.test_causal_execution import _events

    _, plan, view = case(scenario_position)
    repository = SqliteFormalRepository(tmp_path / "formal.sqlite")
    target = ChainRuntime()
    request = LiveRequest(
        service="orders", principal_id="actor", resource_id="order", max_checks=3
    )
    for index in range(2):
        bus, journal = _events(tmp_path / f"events-{index}.jsonl")
        runner = BoundPathRunner(
            Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
            bus,
            journal,
            formal_repository=repository,
        )
        result = runner.execute_plan(request, plan, view)
        assert len(result.checks) == len(result.observations) == 3
    assert target.actions == ["Create", "Pay", "Ship"] * 2
    first_id = dict(target.checks[1].request)["ref"]
    second_id = dict(target.checks[4].request)["ref"]
    assert first_id != second_id
    assert dict(target.checks[5].request)["ref"] == second_id
    assert target.state == "shipped"
