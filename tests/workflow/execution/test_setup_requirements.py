"""Ordinary causal paths retain typed references and mutating-effect metadata."""

from __future__ import annotations

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    create,
    remove,
)
from cloud_dast.runtime.execution.metadata import (
    irreversible_actions as _irreversible_actions,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)


def _fact(predicate: str, args: tuple[object, ...], *, context: Context) -> Fact:
    predicate_object = (
        Predicate.from_schema(
            next(
                schema
                for schema in EXTENSION_PREDICATE_SCHEMAS
                if schema.name == predicate
            )
        )
        if predicate == "refers_to"
        else Predicate.from_name(predicate)
    )
    return Fact(
        context=context,
        predicate=predicate_object,
        args=args,  # type: ignore[arg-type]
    )


def test_irreversibility_projection_separates_readers_and_mutators() -> None:
    create_order = Atom(value="action:svc.create_order")
    upsert_order = Atom(value="action:svc.upsert_order")
    update_order = Atom(value="action:svc.update_order")
    delete_order = Atom(value="action:svc.delete_order")
    order = Atom(value="resource:order")
    order_id = Atom(value="order_id")
    graph = QdlGraph(
        facts=(
            _fact("is", (create_order, Atom(value="Action")), context=Context.CONTRACT),
            _fact("is", (upsert_order, Atom(value="Action")), context=Context.CONTRACT),
            _fact("is", (update_order, Atom(value="Action")), context=Context.CONTRACT),
            _fact("is", (delete_order, Atom(value="Action")), context=Context.CONTRACT),
            _fact("is", (order, Atom(value="ResourceType")), context=Context.ACCEPTED),
            _fact(
                "is",
                (create(order), Atom(value="Effect")),
                context=Context.ACCEPTED,
            ),
            _fact(
                "is",
                (changed(order, order_id), Atom(value="Effect")),
                context=Context.ACCEPTED,
            ),
            _fact(
                "is",
                (remove(order), Atom(value="Effect")),
                context=Context.ACCEPTED,
            ),
            _fact("causes", (create_order, create(order)), context=Context.ACCEPTED),
            _fact(
                "causes",
                (upsert_order, create(order)),
                context=Context.ACCEPTED,
            ),
            _fact(
                "causes",
                (upsert_order, changed(order, order_id)),
                context=Context.ACCEPTED,
            ),
            _fact(
                "causes",
                (update_order, changed(order, order_id)),
                context=Context.ACCEPTED,
            ),
            _fact("causes", (delete_order, remove(order)), context=Context.ACCEPTED),
        )
    )

    projection = _irreversible_actions(graph)
    assert projection["svc.create_order"] is False
    assert projection["svc.upsert_order"] is False
    assert projection["svc.update_order"] is True
    assert projection["svc.delete_order"] is True
    assert "svc.get" not in projection


def _multiple_resource_path(producer_count):
    from dataclasses import replace

    from cloud_dast.model import FieldSpec
    from cloud_dast.qdl.graph import input_field, output_field
    from cloud_dast.runtime.execution.view import build
    from cloud_dast.runtime.planning import QdlPlanner
    from tests.workflow.execution.test_causal_execution import _binding

    graph, _, view = _binding()
    initial, consumer = view.paths[0].steps
    methods = [initial.method]
    scenarios = {initial.method.method_id: initial.scenario}
    facts = list(graph.facts)
    fields = list(consumer.method.fields)
    previous = create(Atom(value="resource:widget"))
    use = Atom(value="action:" + consumer.method.method_id)
    expected = {"widget_id": "value-1"}

    def f(name, *args):
        schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
        predicate = (
            Predicate.from_schema(schema) if schema else Predicate.from_name(name)
        )
        return Fact(context=Context.CONTRACT, predicate=predicate, args=args)

    for number in range(2, producer_count + 1):
        method_id = f"widgets.Make{number}"
        action = Atom(value="action:" + method_id)
        resource = Atom(value=f"resource:part{number}")
        effect = create(resource)
        output = output_field(action, Atom(value="id"))
        field = f"part{number}_id"
        parameter = input_field(use, Atom(value=field))
        for term, kind in [
            (action, "Action"),
            (resource, "ResourceType"),
            (effect, "Effect"),
            (output, "OutputField"),
            (parameter, "InputField"),
        ]:
            facts.append(f("is", term, Atom(value=kind)))
        # Keep the dependency chain explicit: only the last predecessor
        # enables Use; earlier outputs still feed their declared input fields.
        facts = [
            fact
            for fact in facts
            if not (fact.predicate.name == "requires" and fact.args == (use, previous))
        ]
        facts.extend(
            (
                f("requires", action, previous),
                f("causes", action, effect),
                f("requires", use, effect),
                f("exposes", action, output),
                f("has", output, Atom(value="object_ref")),
                f("refers_to", output, resource),
                f("has", parameter, Atom(value="object_ref")),
                f("refers_to", parameter, resource),
                f("coupled", output, parameter, Atom(value="eq")),
            )
        )
        method = initial.method.model_copy(
            update={
                "method_id": method_id,
                "name": f"Make{number}",
                "resource_types": frozenset({f"part{number}"}),
            }
        )
        methods.append(method)
        scenarios[method_id] = initial.scenario.model_copy(
            update={"scenario_id": f"scenario:{method_id}"}
        )
        fields.append(FieldSpec(name=field, type="string", required=True))
        expected[field] = f"value-{number}"
        previous = effect
    methods.append(consumer.method.model_copy(update={"fields": tuple(fields)}))
    scenarios[consumer.method.method_id] = consumer.scenario
    graph = QdlGraph(facts=tuple(facts))
    plan = QdlPlanner().plan(graph)
    execution = build(
        plan, graph, methods=tuple(methods), scenarios_by_method=scenarios
    )
    path = next(p for p in execution.paths if len(p.steps) == producer_count + 1)
    return plan, replace(execution, paths=(path,)), expected


import pytest


@pytest.mark.parametrize("producer_count,limit", [(2, 3), (3, 4), (2, 2)])
def test_multiple_object_refs_use_ordinary_qdl_steps_and_shared_budget(
    producer_count, limit
):
    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.model import AccessOutcome, HttpStatus, Observation, ResponseData
    from cloud_dast.runtime.budget import CallLimits
    from cloud_dast.runtime.execution.scenarios import Checker
    from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
    from cloud_dast_fuzzing import TemplateGenerator
    from tests.support.guardrails import AllowAllGuardrail
    from tests.workflow.execution.test_step_setup import EventLog

    plan, view, expected = _multiple_resource_path(producer_count)
    calls = []
    events = EventLog()

    def target(check):
        calls.append(check)
        if check.method_id == "widgets.Use":
            assert dict(check.request) == expected
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="ordinary request",
            output=ResponseData(fields=(("id", f"value-{len(calls)}"),)),
        )

    service = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    runner = assemble_runner(service, events, events)
    budget = CallLimits(limit)
    result = runner.execute_round(
        LiveRequest(service="widgets", principal_id="actor", resource_id="context"),
        CoverageDrivenScheduler(view.paths),
        budget=budget,
    )
    assert len(result.checks) == len(result.observations) == len(calls) == limit
    assert budget.live_calls == limit
    assert [check.method_id for check in calls] == [
        step.method.method_id for step in view.paths[0].steps
    ][:limit]
    assert (calls[-1].method_id == "widgets.Use") is (limit == producer_count + 1)
