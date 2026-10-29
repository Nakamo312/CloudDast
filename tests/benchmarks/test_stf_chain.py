"""The STF chain: multi-step unpaid-shipment proof through the real engine."""

from __future__ import annotations

from dataclasses import replace

import pytest
from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import (
    CREATE_ORDER,
    SERVICE,
    SHIP_ORDER,
    methods,
    structural_facts,
)
from benchmarks.nsfy_bench.graph import build_graph
from benchmarks.nsfy_bench.norms import NORM_SHIP_UNPAID_ORDER, state_machine_facts

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.model import (
    EndpointLayer,
    ExecutionTrace,
    PrincipalRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
    TraceStep,
)
from cloud_dast.model.events import DomainEvent
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_fuzzing.strategies.goal_payload import (
    GoalPayloadGenerator,
)
from cloud_dast_fuzzing.strategies.selector import GeneratorSelector
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class FormalRepository:
    def __init__(self) -> None:
        self.saved = []

    def save(
        self,
        source_id,
        graph,
        *,
        provenance,
        adapter_version,
        mapping_report,
    ):
        self.saved.append((source_id, graph))

    def load(self, source_id):
        from cloud_dast.qdl.graph import QdlGraph

        return next(
            (
                graph
                for saved_id, graph in reversed(self.saved)
                if saved_id == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix):
        from cloud_dast.qdl.graph import QdlGraph

        merged = QdlGraph()
        for saved_id, graph in self.saved:
            if saved_id.startswith(source_prefix):
                from cloud_dast.qdl.graph_ops import merge_graphs

                merged = merge_graphs(merged, graph)
        return merged


class MethodRepo:
    def list_methods(self, service):
        return methods()


class ScenarioRepo:
    def __init__(self, scenario) -> None:
        self.scenario = scenario

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        return self.scenario


def build_state_machine_graph():
    from cloud_dast.qdl.graph import QdlGraph

    return QdlGraph(facts=(*structural_facts(), *state_machine_facts()))


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="stf-unpaid-shipment",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(),
            principals=(PrincipalRef(principal_id="attacker", principal_type="user"),),
            permissions_known=True,
        ),
    )


@pytest.mark.parametrize("instrumented", [False, True])
def test_stf_chain_executes_ordinary_create_before_unpaid_shipment(
    instrumented,
) -> None:
    repository = FormalRepository()
    from cloud_dast.qdl.graph import (
        Atom,
        Context,
        Fact,
        Predicate,
        QdlGraph,
        input_field,
        output_field,
    )
    from cloud_dast.qdl.graph_ops import merge_graphs

    output = output_field(Atom(value=f"action:{CREATE_ORDER}"), Atom(value="order_id"))
    parameter = input_field(Atom(value=f"action:{SHIP_ORDER}"), Atom(value="order_id"))
    answer_key = merge_graphs(
        build_graph(),
        QdlGraph(
            facts=(
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(output, Atom(value="OutputField")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(parameter, Atom(value="InputField")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(output.args[0], Atom(value="Action")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("is"),
                    args=(parameter.args[0], Atom(value="Action")),
                ),
                Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("coupled"),
                    args=(output, parameter, Atom(value="eq")),
                ),
            )
        ),
    )
    repository.save(
        f"contract:{SERVICE}",
        answer_key,
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    repository.save(
        f"accepted:{SERVICE}",
        answer_key,
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    repository.save(
        f"state-machine:{SERVICE}",
        build_state_machine_graph(),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )

    events = EventLog()
    bus = EventBus()
    for event_type in DomainEvent.__subclasses__():
        bus.subscribe(event_type, events.append)
    service = BenchService(BenchState.seed())
    plain_target = BenchTarget(service)
    sink = next(
        fact.args[1].args[1].value
        for fact in answer_key.facts_for("prevents")
        if fact.args[0].value == NORM_SHIP_UNPAID_ORDER
    )

    def target(check):
        before_orders = {
            key: dict(value) for key, value in service._state.orders.items()
        }
        observation = plain_target(check)
        output = dict(observation.output.fields) if observation.output else {}
        order_id = output.get("order_id") or dict(check.request).get("order_id")
        before = before_orders.get(order_id, {}).get("state")
        after = service._state.orders.get(order_id, {}).get("state")
        if (
            check.method_id == CREATE_ORDER
            and order_id not in before_orders
            and after == "created"
        ):
            before = "new"
        # Both cases measure actual causal state transitions. Only the positive
        # case additionally observes the source-declared security sink.
        sinks = (
            (sink,)
            if instrumented
            and check.method_id == SHIP_ORDER
            and before == "created"
            and after == "shipped"
            else ()
        )
        return observation.model_copy(
            update={
                "trace": ExecutionTrace(
                    steps=(
                        TraceStep(
                            observation_id=observation.observation_id,
                            step_id=check.check_id,
                            method_id=check.method_id,
                            scenario_id=check.scenario_id,
                            status=observation.observed_outcome,
                            request_fields=tuple(name for name, _ in check.request),
                            sinks_reached=sinks,
                            resource_state_before=(("control", before),)
                            if before
                            else (),
                            resource_state_after=(("control", after),) if after else (),
                        ),
                    )
                )
            }
        )

    generator = GoalPayloadGenerator(
        GeneratorSelector({"template": TemplateGenerator()})
    )
    checker = Checker(target, generator, AllowAllGuardrail(), bus)
    service_workflow = checker
    runner = assemble_runner(
        service_workflow,
        bus,
        events,
        grounded_oracle=GroundedOutcomeOracle(),
        primitive_oracle=PrimitiveOracleRouter(),
        formal_repository=repository,
    )
    binder = ScenarioBinder(
        MethodRepo(),
        ScenarioRepo(_scenario()),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binding = binder.bind(
        LiveRequest(
            service=SERVICE,
            principal_id="attacker",
            resource_id="fixture:order",
            method_id=SHIP_ORDER,
        )
    )

    # The DAG contains the STF chains from the grounded create effect.
    chain_actions = {path.actions for path in binding.plan.attack_paths}
    assert (
        "action:grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "action:grpc:nsfy.shop.v1.OrderService.PayOrder",
    ) in chain_actions
    assert (
        "action:grpc:nsfy.shop.v1.OrderService.CreateOrder",
        "action:grpc:nsfy.shop.v1.OrderService.ShipOrder",
    ) in chain_actions

    causal_paths = [
        path
        for path in binding.execution.paths
        if path.steps[-1].method.method_id == SHIP_ORDER
        and path.steps[0].method.method_id == CREATE_ORDER
    ]
    assert causal_paths
    assert causal_paths[0].steps[0].required_effects

    # The marker rides the grounded note probe field.
    ship_steps = [
        step
        for path in binding.execution.paths
        for step in path.steps
        if step.method.method_id == SHIP_ORDER
    ]
    assert ship_steps
    assert any(step.plan.probe_fields == ("note",) for step in ship_steps)
    execution = runner.execute_plan(
        LiveRequest(
            service=SERVICE,
            principal_id="attacker",
            resource_id="fixture:order",
            method_id=SHIP_ORDER,
        ),
        binding.plan,
        replace(
            binding.execution,
            paths=tuple(
                path
                for path in binding.execution.paths
                if path.steps[-1].invariant.norm_id == NORM_SHIP_UNPAID_ORDER
            )[:1],
        ),
    )
    executed_methods = [check.method_id for check in execution.checks]
    # The multi-step trace: legitimate create first, then the ship probe.
    assert CREATE_ORDER in executed_methods
    assert SHIP_ORDER in executed_methods
    assert executed_methods.index(CREATE_ORDER) < executed_methods.index(SHIP_ORDER)

    ship_checks = [check for check in execution.checks if check.method_id == SHIP_ORDER]
    assert ship_checks
    # This measurement selects the source-declared reached norm. Unrelated
    # outcome probes are separate experiments and may mutate their fixture.
    ship_check = next(check for check in ship_checks if check.probe_marker is not None)
    assert ship_check.probe_marker is not None
    assert ship_check.probe_marker in dict(ship_check.request).get("note", "")

    # The multi-step effect: the freshly created attacker-owned (unpaid)
    # order was shipped — exactly the STF divergence.
    shipped_ids = {dict(check.request).get("order_id") for check in ship_checks}
    shipped_attacker_orders = [
        order_id
        for order_id in shipped_ids
        if order_id in service._state.orders
        and service._state.orders[order_id]["owner"] == "attacker"
        and service._state.orders[order_id]["state"] == "shipped"
    ]
    assert shipped_attacker_orders

    from cloud_dast.verification.finding_evaluator import FindingEvaluator

    evaluation = FindingEvaluator(bus, events).evaluate(
        execution, binding.execution.invariants
    )
    ship_findings = [
        finding
        for finding in evaluation.findings
        if NORM_SHIP_UNPAID_ORDER in finding.invariant_id
    ]
    if instrumented:
        assert ship_findings
        assert any("unpaid" in finding.title.lower() for finding in ship_findings)
    else:
        assert not ship_findings
        # Actual bad state above is known to the test, but no sink observation
        # was supplied to the engine. It must preserve this evidence deficit.
        assert any(
            verdict.status.value == "unscoreable" and not verdict.grounded
            for verdict in execution.policy_verdicts.values()
        )
