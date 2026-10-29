"""Ordinary QDL requests acquire values without manufacturing causal proof."""

from dataclasses import replace
from uuid import uuid4

import pytest

from cloud_dast.binding import scenario_scope
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    FieldSpec,
    HttpStatus,
    Observation,
    ResponseData,
)
from cloud_dast.model.events import QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    input_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.projection import (
    read_observed_effects,
    read_observed_outputs,
)
from cloud_dast_fuzzing import (
    GeneratorSelector,
    MinimalSeedGenerator,
    TemplateGenerator,
)
from tests.support.guardrails import AllowAllGuardrail
from tests.workflow.execution.test_causal_execution import _binding, _events


def _chain(*, require_creation=False):
    graph, _, original = _binding(
        make_fields=(
            FieldSpec(
                name="nonce",
                type="string",
                required=True,
                enum_values=("declared-input",),
            ),
        )
    )
    first, last = original.paths[0].steps
    a, b, c = (
        Atom(value="action:" + n)
        for n in ("widgets.Make", "opaque.Observe", "widgets.Use")
    )

    def move(term):
        if isinstance(term, Struct):
            args = tuple(move(x) for x in term.args)
            if term.name == "output_field" and args[0] == a:
                args = (b, *args[1:])
            return term.model_copy(update={"args": args})
        return term

    facts = [
        f.model_copy(update={"args": tuple(move(t) for t in f.args)})
        for f in graph.facts
        if require_creation or f.predicate.name != "requires"
    ]
    facts = [
        fact.model_copy(update={"args": (b, fact.args[1])})
        if fact.predicate.name == "exposes"
        else fact
        for fact in facts
    ]

    def f(name, *args):
        return Fact(
            context=Context.CONTRACT, predicate=Predicate.from_name(name), args=args
        )

    token, lookup = (
        input_field(a, Atom(value="nonce")),
        input_field(b, Atom(value="filter")),
    )
    facts.extend(
        (
            f("is", b, Atom(value="Action")),
            f("is", token, Atom(value="InputField")),
            f("is", lookup, Atom(value="InputField")),
            f("coupled", token, lookup, Atom(value="eq")),
        )
    )
    graph = QdlGraph(facts=tuple(facts))
    observer = first.method.model_copy(
        update={
            "method_id": "opaque.Observe",
            "name": "Observe",
            "fields": (FieldSpec(name="filter", type="string", required=True),),
        }
    )
    methods = (first.method, observer, last.method)
    scenarios = {
        m.method_id: first.scenario.model_copy(
            update={"scenario_id": "scenario:" + m.method_id}
        )
        for m in methods
    }
    plan = QdlPlanner().plan(graph)
    view = build(plan, graph, methods=methods, scenarios_by_method=scenarios)
    return graph, plan, view


@pytest.mark.parametrize("persist", [False, True])
@pytest.mark.parametrize("require_creation", [False, True])
@pytest.mark.parametrize("limit", [0, 1, 2, 3])
def test_outputless_action_observer_consumer_is_an_ordinary_qdl_chain(
    tmp_path, persist, require_creation, limit
):
    graph, plan, view = _chain(require_creation=require_creation)
    paths = [
        p
        for p in view.paths
        if tuple(s.method.method_id for s in p.steps)
        == ("widgets.Make", "opaque.Observe", "widgets.Use")
    ]
    assert paths, (
        "QDL dependencies must retain the ordinary observer without a security norm"
    )
    path = paths[0]
    first = path.steps[0]
    path = replace(
        path,
        steps=(
            replace(first, plan=first.plan.model_copy(update={"generator": "seed"})),
            *path.steps[1:],
        ),
    )
    view = replace(view, paths=(path,))
    bus, journal = _events(tmp_path / "events.jsonl")
    resources, calls = {}, []

    def target(check):
        calls.append(check)
        request = dict(check.request)
        output = None
        if check.method_id == "widgets.Make":
            assert not resources
            resources[request["nonce"]] = "runtime-" + uuid4().hex
        elif check.method_id == "opaque.Observe":
            output = ResponseData(fields=(("id", resources[request["filter"]]),))
        else:
            assert request["widget_id"] in resources.values()
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="OK",
            output=output,
        )

    repo = SqliteFormalRepository(tmp_path / "formal.sqlite") if persist else None
    generators = GeneratorSelector(
        {
            "template": TemplateGenerator(),
            "seed": MinimalSeedGenerator(TemplateGenerator()),
        }
    )
    runner = assemble_runner(
        Checker(target, generators, AllowAllGuardrail(), bus),
        bus,
        journal,
        formal_repository=repo,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="NOT-AN-ID",
            max_checks=limit,
        ),
        plan,
        view,
    )
    expected = ["widgets.Make", "opaque.Observe", "widgets.Use"]
    if require_creation:
        expected.pop()
    expected = expected[:limit]
    assert [c.method_id for c in calls] == expected
    assert len(result.observations) == len(result.checks) == len(expected)
    ordinary = [
        e
        for e in journal.read()
        if isinstance(e, QdlStepEvaluated) and e.action_id != "widgets.Use"
    ]
    assert all(e.norm_fact is None and not e.completed_steps for e in ordinary)
    if repo and len(calls) >= 2:
        combined = merge_graphs(graph, repo.load_merged("observation:"))
        scope = scenario_scope(view.paths[0].steps[0].scenario)
        proofs = read_observed_effects(
            combined,
            scope=scope,
            identities=calls[0].identities,
            method_id="widgets.Make",
        )
        assert not proofs, "A later observed ID must not manufacture creation causality"
        witness = Struct(
            name="output_field",
            args=(Atom(value="action:opaque.Observe"), Atom(value="id")),
        )
        assert read_observed_outputs(
            combined, witness, scope=scope, identities=calls[1].identities
        )
    outcomes = [e for e in journal.read() if isinstance(e, QdlPathEvaluated)]
    assert outcomes[-1].outcome == (
        "completed" if limit == 3 and not require_creation else "blocked"
    )


def test_repeated_observer_occurrences_supply_latest_actual_values(tmp_path):
    graph, _, view = _chain()
    methods = {s.method.method_id: s.method for p in view.paths for s in p.steps}
    scenarios = {s.method.method_id: s.scenario for p in view.paths for s in p.steps}
    a, b = Atom(value="action:widgets.Make"), Atom(value="action:opaque.Observe")
    from cloud_dast.qdl.graph import allowed

    prerequisite = allowed(b)

    def correlation(term):
        return isinstance(term, Struct) and (
            term.name == "input_field"
            and term.args[1] in (Atom(value="nonce"), Atom(value="filter"))
            or any(correlation(arg) for arg in term.args)
        )

    facts = tuple(f for f in graph.facts if not any(correlation(arg) for arg in f.args))

    def f(name, *args):
        return Fact(
            context=Context.CONTRACT, predicate=Predicate.from_name(name), args=args
        )

    graph = QdlGraph(
        facts=(
            *facts,
            f("is", prerequisite, Atom(value="Effect")),
            f("causes", b, prerequisite),
            f("requires", a, prerequisite),
        )
    )
    methods["widgets.Make"] = methods["widgets.Make"].model_copy(update={"fields": ()})
    methods["opaque.Observe"] = methods["opaque.Observe"].model_copy(
        update={"fields": ()}
    )
    plan = QdlPlanner(max_depth=3).plan(graph)
    view = build(
        plan, graph, methods=tuple(methods.values()), scenarios_by_method=scenarios
    )
    path = next(
        p
        for p in view.paths
        if tuple(s.method.method_id for s in p.steps)
        == ("opaque.Observe", "widgets.Make", "opaque.Observe", "widgets.Use")
    )
    assert path.steps[0].step_id != path.steps[2].step_id
    bus, journal = _events(tmp_path / "events.jsonl")
    calls, ids = [], []

    def target(check):
        calls.append(check)
        output = None
        if check.method_id == "widgets.Make":
            ids.append("observed-" + uuid4().hex)
        elif check.method_id == "opaque.Observe" and ids:
            output = ResponseData(fields=(("id", ids[-1]),))
        elif check.method_id == "widgets.Use":
            assert dict(check.request)["widget_id"] == ids[-1]
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="OK",
            output=output,
        )

    runner = assemble_runner(
        Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
        bus,
        journal,
        formal_repository=SqliteFormalRepository(tmp_path / "formal.sqlite"),
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="NOT-AN-ID",
            max_checks=4,
        ),
        plan,
        replace(view, paths=(path,)),
    )
    assert [c.method_id for c in calls] == [
        "opaque.Observe",
        "widgets.Make",
        "opaque.Observe",
        "widgets.Use",
    ]
    assert len(result.checks) == len(result.observations) == 4
    assert [e for e in journal.read() if isinstance(e, QdlPathEvaluated)][
        -1
    ].outcome == "completed"


def test_independent_qdl_prerequisites_form_one_conjunctive_chain(tmp_path):
    from cloud_dast.qdl.graph import create
    from tests.workflow.execution.test_setup_requirements import _multiple_resource_path

    _, previous, _ = _multiple_resource_path(2)
    old = previous.paths[0]
    graph = old.steps[0].evidence_graph
    assert graph is not None
    first_effect = create(Atom(value="resource:widget"))
    graph = QdlGraph(
        facts=(
            *(
                f
                for f in graph.facts
                if not (
                    f.predicate.name == "requires"
                    and f.args == (Atom(value="action:widgets.Make2"), first_effect)
                )
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(Atom(value="action:widgets.Use"), first_effect),
            ),
        )
    )
    methods = tuple(s.method for s in old.steps)
    scenarios = {s.method.method_id: s.scenario for s in old.steps}
    plan = QdlPlanner(max_depth=3).plan(graph)
    view = build(plan, graph, methods=methods, scenarios_by_method=scenarios)
    path = next(
        p
        for p in view.paths
        if len(p.steps) == 3
        and p.steps[-1].method.method_id == "widgets.Use"
        and {s.method.method_id for s in p.steps[:-1]}
        == {"widgets.Make", "widgets.Make2"}
    )
    bus, journal = _events(tmp_path / "events.jsonl")
    calls = []

    def target(check):
        calls.append(check)
        output = None
        if check.method_id == "widgets.Use":
            assert dict(check.request) == {"widget_id": "made-X", "part2_id": "made-Y"}
        else:
            value = "made-X" if check.method_id == "widgets.Make" else "made-Y"
            output = ResponseData(fields=(("id", value),))
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="OK",
            output=output,
        )

    runner = assemble_runner(
        Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
        bus,
        journal,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="widgets",
            principal_id="actor",
            resource_id="NOT-AN-ID",
            max_checks=3,
        ),
        plan,
        replace(view, paths=(path,)),
    )
    assert len(result.checks) == len(result.observations) == 3
    assert calls[-1].method_id == "widgets.Use"


@pytest.mark.parametrize("require_creation", [False, True])
@pytest.mark.parametrize("persist", [False, True])
def test_new_observation_resumes_chain_without_repeating_mutation(
    tmp_path, require_creation, persist
):
    from cloud_dast.model.events import EventScope
    from cloud_dast.runtime.budget import CallLimits
    from cloud_dast.runtime.execution.projection import contract_smoke_path
    from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

    graph, _, original = _chain(require_creation=require_creation)

    def carries_input(term):
        return isinstance(term, Struct) and (
            term.name == "input_field"
            and term.args[1] in (Atom(value="nonce"), Atom(value="filter"))
            or any(carries_input(arg) for arg in term.args)
        )

    graph = QdlGraph(
        facts=tuple(
            f for f in graph.facts if not any(carries_input(arg) for arg in f.args)
        )
    )
    by_method = {s.method.method_id: s for p in original.paths for s in p.steps}
    methods = tuple(
        s.method.model_copy(update={"fields": ()}) if m != "widgets.Use" else s.method
        for m, s in by_method.items()
    )
    scenarios = {m: s.scenario for m, s in by_method.items()}
    plan = QdlPlanner(max_depth=3).plan(graph)
    view = build(plan, graph, methods=methods, scenarios_by_method=scenarios)
    path = next(
        p
        for p in view.paths
        if tuple(s.method.method_id for s in p.steps)
        == ("widgets.Make", "opaque.Observe", "widgets.Use")
    )
    bus, journal = _events(tmp_path / "events.jsonl")
    calls, resources, readiness = [], [], []

    def target(check):
        calls.append(check)
        output = None
        if check.method_id == "widgets.Make":
            resources.append("generated-" + uuid4().hex)
        elif check.method_id == "opaque.Observe" and readiness:
            output = ResponseData(fields=(("id", resources[0]),))
        elif check.method_id == "widgets.Use":
            assert dict(check.request)["widget_id"] == resources[0]
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="OK",
            output=output,
        )

    repo = SqliteFormalRepository(tmp_path / "formal.sqlite") if persist else None
    runner = assemble_runner(
        Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus),
        bus,
        journal,
        formal_repository=repo,
    )
    scope = EventScope(campaign_id="offline-observation", run_id="offline-run")
    request = LiveRequest(
        service="widgets", principal_id="actor", resource_id="NOT-AN-ID"
    )
    budget = CallLimits(4)
    first = runner.execute_round(
        request, CoverageDrivenScheduler((path,)), budget=budget, scope=scope
    )
    assert len(first.checks) == 2
    unchanged = runner.execute_round(
        request, CoverageDrivenScheduler((path,)), budget=budget, scope=scope
    )
    assert not unchanged.checks
    readiness.append(True)
    observer = path.steps[1]
    smoke = contract_smoke_path(
        "action:opaque.Observe", method=observer.method, scenario=observer.scenario
    )
    smoke = replace(smoke, steps=(replace(smoke.steps[0], evidence_graph=graph),))
    measured = runner.execute_round(
        request, CoverageDrivenScheduler((smoke,)), budget=budget, scope=scope
    )
    assert len(measured.checks) == 1
    resumed = runner.execute_round(
        request, CoverageDrivenScheduler((path,)), budget=budget, scope=scope
    )
    assert [c.method_id for c in calls] == [
        "widgets.Make",
        "opaque.Observe",
        "opaque.Observe",
    ] + ([] if require_creation else ["widgets.Use"])
    assert len(resources) == 1
    assert len(resumed.checks) == (0 if require_creation else 1)
