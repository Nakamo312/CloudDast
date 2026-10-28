"""Causal prerequisites use observed QDL effects, independently of violations."""

from dataclasses import replace

import pytest

from cloud_dast.api import LiveRequest
from cloud_dast.extensions import DefaultGeneratorPolicy
from cloud_dast.infrastructure.events import EventBus, JsonlEventStore
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
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
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import DomainEvent, QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    allowed,
    create,
    input_field,
    output_field,
    remove,
)
from cloud_dast.qdl.graph_ops import merge_facts, merge_graphs
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.projection import ObservationProjector
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_fuzzing.plugin import build_fuzz_session
from tests.support.guardrails import AllowAllGuardrail


def _events(path):
    bus, journal = EventBus(), JsonlEventStore(path)
    for event_type in DomainEvent.__subclasses__():
        bus.subscribe(event_type, journal.append)
    return bus, journal


def _binding(*, security_make=False, make_fields=()):
    make, use = Atom(value="action:widgets.Make"), Atom(value="action:widgets.Use")
    resource, subject = Atom(value="resource:widget"), Atom(value="principal:actor")
    witness, parameter = (
        output_field(make, Atom(value="id")),
        input_field(use, Atom(value="widget_id")),
    )
    effect, goal, norm = create(resource), allowed(use), Atom(value="norm:deny-use")
    schemas = {schema.name: schema for schema in EXTENSION_PREDICATE_SCHEMAS}

    def f(name, *args, context=Context.CONTRACT):
        predicate = (
            Predicate.from_schema(schemas[name])
            if name in schemas
            else Predicate.from_name(name)
        )
        return Fact(context=context, predicate=predicate, args=args)

    facts = [
        f("is", term, Atom(value=kind))
        for term, kind in (
            (make, "Action"),
            (use, "Action"),
            (resource, "ResourceType"),
            (subject, "Subject"),
            (witness, "OutputField"),
            (parameter, "InputField"),
            (effect, "Effect"),
            (goal, "Effect"),
            (norm, "Norm"),
        )
    ]
    facts.extend(
        (
            f("attacker", subject),
            f("causes", make, effect),
            f("requires", use, effect),
            f("causes", use, goal),
            f("exposes", make, witness),
            f("has", witness, Atom(value="object_ref")),
            f("refers_to", witness, resource),
            f("has", parameter, Atom(value="object_ref")),
            f("refers_to", parameter, resource),
            f("coupled", witness, parameter, Atom(value="eq")),
            f("prevents", norm, goal, context=Context.ACCEPTED),
        )
    )
    if security_make:
        make_goal = allowed(make)
        make_norm = Atom(value="norm:deny-make")
        facts.extend(
            (
                f("is", make_goal, Atom(value="Effect")),
                f("is", make_norm, Atom(value="Norm")),
                f("causes", make, make_goal),
                f("requires", use, make_goal),
                f("prevents", make_norm, make_goal, context=Context.ACCEPTED),
            )
        )
    graph = QdlGraph(facts=tuple(facts))
    methods = (
        MethodSpec(
            method_id="widgets.Make",
            service="widgets",
            name="Make",
            permissions=frozenset({"widget.make"}),
            layer=EndpointLayer.PRIVATE,
            resource_types=frozenset({"widget"}),
            fields=make_fields,
        ),
        MethodSpec(
            method_id="widgets.Use",
            service="widgets",
            name="Use",
            layer=EndpointLayer.PRIVATE,
            resource_types=frozenset({"widget"}),
            permissions=frozenset({"widget.use"}),
            fields=(FieldSpec(name="widget_id", type="string", required=True),),
        ),
    )
    profile = ScenarioProfile(
        scope_relation=ScopeRelation.SAME_FOLDER,
        binding_level="resource",
        endpoint_layer=EndpointLayer.PRIVATE,
        resource_state="existing",
        identity_class="attacker",
        addressing_mode="direct",
    )
    scenarios = {
        m.method_id: ScenarioPosition(
            scenario_id="scenario:" + m.method_id,
            profile=profile,
            stand=StandState(
                principals=(PrincipalRef(principal_id="actor", principal_type="user"),),
                permissions_known=True,
            ),
        )
        for m in methods
    }
    plan = QdlPlanner().plan(graph)
    view = build(plan, graph, methods=methods, scenarios_by_method=scenarios)
    chain = next(p for p in view.paths if len(p.steps) == 2)
    return graph, plan, replace(view, paths=(chain,))


@pytest.mark.parametrize(
    "witness,persist,security_make,adaptive",
    [
        (True, True, False, False),
        (False, True, False, False),
        (True, False, False, False),
        (False, True, True, False),
        (True, True, False, True),
    ],
)
def test_ordinary_create_supplies_renamed_input_without_a_security_norm(
    tmp_path, witness, persist, security_make, adaptive
):
    graph, plan, view = _binding(security_make=security_make)
    events, journal = _events(tmp_path / "events.jsonl")
    calls = []

    def target(check):
        calls.append(check)
        if check.method_id == "widgets.Use":
            assert dict(check.request)["widget_id"] == "widget-observed"
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="OK",
            output=ResponseData(fields=(("id", "widget-observed"),))
            if witness and check.method_id == "widgets.Make"
            else None,
        )

    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    service = checker

    repository = SqliteFormalRepository(tmp_path / "formal.sqlite") if persist else None
    sessions = {}

    def session_factory(request):
        session = build_fuzz_session(
            request,
            generators={"template": TemplateGenerator()},
            policy=DefaultGeneratorPolicy(),
            guardrail=AllowAllGuardrail(),
            max_checks=4,
        )
        sessions[request.method.method_id] = session
        return session

    runner = BoundPathRunner(
        service,
        events,
        journal,
        formal_repository=repository,
        fuzz_session_factory=session_factory if adaptive else None,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="launch-context",
            max_checks=2,
        ),
        plan,
        view,
    )
    assert [c.method_id for c in calls] == (
        ["widgets.Make", "widgets.Use"] if witness else ["widgets.Make"]
    )
    first = next(e for e in journal.read() if isinstance(e, QdlStepEvaluated))
    assert (first.norm_fact is not None) is security_make
    assert (first.verdict is VerdictStatus.FAIL) is security_make
    assert bool(first.completed_steps) is witness
    outcomes = [e for e in journal.read() if isinstance(e, QdlPathEvaluated)]
    assert outcomes[-1].outcome == ("completed" if witness else "blocked")
    if witness:
        assert len(result.observations) == 2
        if adaptive:
            assert sessions["widgets.Make"].state.emitted == 1
            assert not sessions["widgets.Make"].stopped
        if repository is not None:
            assert repository.load(
                "observation:" + result.observations[0].observation_id
            ).facts
            calls.clear()
            fresh_events, fresh_journal = _events(tmp_path / "replay.jsonl")
            fresh_runner = BoundPathRunner(
                Checker(
                    target,
                    TemplateGenerator(),
                    AllowAllGuardrail(),
                    fresh_events,
                ),
                fresh_events,
                fresh_journal,
                formal_repository=repository,
            )
            replay = fresh_runner.execute_plan(
                LiveRequest(
                    service="widgets",
                    principal_id="actor",
                    resource_id="launch-context",
                    max_checks=1,
                ),
                plan,
                view,
            )
            assert [check.method_id for check in calls] == ["widgets.Use"]
            assert len(replay.checks) == len(replay.observations) == 1
            reused = next(
                event
                for event in fresh_journal.read()
                if isinstance(event, QdlStepEvaluated)
            )
            assert reused.completed_steps == (view.paths[0].steps[0].step_id,)
            assert reused.verdict is VerdictStatus.UNSCOREABLE


@pytest.mark.parametrize(
    "max_checks,denied,expected",
    [
        (0, None, []),
        (1, None, ["widgets.Make"]),
        (2, "widgets.Make", []),
        (2, "widgets.Use", ["widgets.Make"]),
        (2, None, ["widgets.Make", "widgets.Use"]),
    ],
)
def test_ordinary_prerequisites_share_request_budget_and_guardrail(
    tmp_path, max_checks, denied, expected
):
    _, plan, view = _binding()
    bus, journal = _events(tmp_path / "events.jsonl")
    calls = []

    class Guardrail:
        def allows(self, check):
            if check.method_id == "widgets.Use":
                assert dict(check.request)["widget_id"] == "created-id"
            return check.method_id != denied

    def target(check):
        calls.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=ResponseData(fields=(("id", "created-id"),))
            if check.method_id == "widgets.Make"
            else None,
        )

    runner = BoundPathRunner(
        Checker(target, TemplateGenerator(), Guardrail(), bus),
        bus,
        journal,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="launch-context",
            max_checks=max_checks,
        ),
        plan,
        view,
    )
    assert [check.method_id for check in calls] == expected
    assert len(result.checks) == len(result.observations) == len(expected)


@pytest.mark.parametrize("persist", [False, True])
def test_two_planned_paths_reuse_accumulated_observation(tmp_path, persist):
    graph, _, original = _binding()
    make_step, use_step = original.paths[0].steps
    aliases = {
        Atom(value="action:widgets.Use"): Atom(value="action:widgets.UseOther"),
        Atom(value="norm:deny-use"): Atom(value="norm:deny-other"),
    }

    def retarget(term):
        if isinstance(term, Atom):
            return aliases.get(term, term)
        if isinstance(term, Struct):
            return term.model_copy(
                update={"args": tuple(retarget(a) for a in term.args)}
            )
        return term

    graph = merge_graphs(
        graph,
        QdlGraph(
            facts=tuple(
                fact.model_copy(
                    update={"args": tuple(retarget(arg) for arg in fact.args)}
                )
                for fact in graph.facts
            )
        ),
    )
    other_method = use_step.method.model_copy(
        update={"method_id": "widgets.UseOther", "name": "UseOther"}
    )
    other_scenario = use_step.scenario.model_copy(
        update={"scenario_id": "scenario:widgets.UseOther"}
    )
    plan = QdlPlanner().plan(graph)
    view = build(
        plan,
        graph,
        methods=(make_step.method, use_step.method, other_method),
        scenarios_by_method={
            make_step.method.method_id: make_step.scenario,
            use_step.method.method_id: use_step.scenario,
            other_method.method_id: other_scenario,
        },
    )
    chains = tuple(path for path in view.paths if len(path.steps) == 2)
    assert len(chains) == 2
    view = replace(view, paths=chains)
    calls = []

    def target(check):
        calls.append(check)
        if check.method_id != "widgets.Make":
            assert dict(check.request)["widget_id"] == "reusable"
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=ResponseData(fields=(("id", "reusable"),))
            if check.method_id == "widgets.Make"
            else None,
        )

    bus, journal = _events(tmp_path / "events.jsonl")
    runner = BoundPathRunner(
        Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
        bus,
        journal,
        formal_repository=SqliteFormalRepository(tmp_path / "formal.sqlite")
        if persist
        else None,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets", principal_id="actor", resource_id="context", max_checks=3
        ),
        plan,
        view,
    )
    assert [check.method_id for check in calls].count("widgets.Make") == 1
    assert {check.method_id for check in calls} == {
        "widgets.Make",
        "widgets.Use",
        "widgets.UseOther",
    }
    assert len(result.checks) == len(result.observations) == 3


def test_consumed_instance_is_not_reused_by_a_fresh_runner(tmp_path):
    graph, _, original = _binding()
    removed = remove(Atom(value="resource:widget"))
    graph = merge_facts(
        graph,
        (
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(removed, Atom(value="Effect")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("causes"),
                args=(Atom(value="action:widgets.Use"), removed),
            ),
        ),
    )
    steps = original.paths[0].steps
    plan = QdlPlanner().plan(graph)
    view = build(
        plan,
        graph,
        methods=tuple(step.method for step in steps),
        scenarios_by_method={step.method.method_id: step.scenario for step in steps},
    )
    view = replace(
        view, paths=tuple(path for path in view.paths if len(path.steps) == 2)
    )
    repository = SqliteFormalRepository(tmp_path / "formal.sqlite")
    live, calls = set(), []

    def target(check):
        calls.append(check)
        output = None
        if check.method_id == "widgets.Make":
            value = f"created-{len(calls)}"
            live.add(value)
            output = ResponseData(fields=(("id", value),))
        else:
            value = dict(check.request)["widget_id"]
            assert value in live, "A consumed ID must not be sent again"
            live.remove(value)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=output,
        )

    for index in range(2):
        bus, journal = _events(tmp_path / f"events-{index}.jsonl")
        runner = BoundPathRunner(
            Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
            bus,
            journal,
            formal_repository=repository,
        )
        result = runner.execute_plan(
            LiveRequest(
                service="widgets",
                principal_id="actor",
                resource_id="context",
                max_checks=2,
            ),
            plan,
            view,
        )
        assert len(result.checks) == len(result.observations) == 2
        assert not live
    assert [check.method_id for check in calls] == ["widgets.Make", "widgets.Use"] * 2
    assert dict(calls[1].request)["widget_id"] != dict(calls[3].request)["widget_id"]


@pytest.mark.parametrize("conflicting", [False, True])
def test_trace_evidence_is_idempotent_and_rejects_conflicts(conflicting):
    graph, _, view = _binding()
    step = view.paths[0].steps[0]
    observation = Observation(
        check_id="check",
        scenario_id=step.scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        output=ResponseData(fields=(("id", "created"),)),
    )
    record = TraceStep(
        observation_id=observation.observation_id,
        step_id="check",
        method_id=step.method.method_id,
        scenario_id=step.scenario.scenario_id,
        status=AccessOutcome.ALLOWED,
        response=observation.output,
    )
    other = (
        record.model_copy(update={"status": AccessOutcome.DENIED})
        if conflicting
        else record
    )
    observation = observation.model_copy(
        update={"trace": ExecutionTrace(steps=(record, other))}
    )
    proved = ObservationProjector().verified_effects(
        observation, step.method.method_id, graph
    )
    assert (step.required_effects[0] in proved) is not conflicting


@pytest.mark.parametrize(
    "max_checks,deny_use,expected",
    [
        (1, False, ["widgets.Make"]),
        (2, False, ["widgets.Make", "widgets.Make"]),
        (3, False, ["widgets.Make", "widgets.Make", "widgets.Use"]),
        (3, True, ["widgets.Make", "widgets.Make"]),
    ],
)
def test_adaptive_prerequisite_retries_share_budget_and_guardrail(
    tmp_path, max_checks, deny_use, expected
):
    _, plan, view = _binding(make_fields=(FieldSpec(name="tag", type="string"),))
    bus, journal = _events(tmp_path / "events.jsonl")
    calls = []

    class Guardrail:
        def allows(self, check):
            if check.method_id == "widgets.Use":
                value = dict(check.request)["widget_id"]
                if value is not None:
                    assert value == "created"
            return not (deny_use and check.method_id == "widgets.Use")

    class Generator:
        def __init__(self):
            self.emitted = 0

        def generate(self, plan, method, invariant, scenario, **kwargs):
            checks = TemplateGenerator().generate(
                plan, method, invariant, scenario, **kwargs
            )
            if method.method_id != "widgets.Make":
                return checks
            self.emitted += 1
            return tuple(
                check.model_copy(
                    update={"request": (("tag", f"{self.emitted}:{index}"),)}
                )
                for check in checks
                for index in range(4)
            )

    def target(check):
        calls.append(check)
        make_count = sum(call.method_id == "widgets.Make" for call in calls)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=ResponseData(fields=(("id", "created"),))
            if check.method_id == "widgets.Make" and make_count >= 2
            else None,
        )

    guardrail, generator = Guardrail(), Generator()
    runner = BoundPathRunner(
        Checker(target, generator, guardrail, bus),
        bus,
        journal,
        fuzz_session_factory=lambda request: build_fuzz_session(
            request,
            generators={"template": generator},
            policy=DefaultGeneratorPolicy(),
            guardrail=guardrail,
            max_checks=4,
        ),
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="context",
            max_checks=max_checks,
        ),
        plan,
        view,
    )
    assert [check.method_id for check in calls] == expected
    assert len(result.checks) == len(result.observations) == len(expected)
