from __future__ import annotations

from collections.abc import Iterable
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_dast.candidates import TemplateGenerator
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model import (
    AccessOutcome,
    MethodSpec,
    Observation,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.model.events import CoverageUpdated, DomainEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    create,
    reached,
)
from cloud_dast.qdl.reasoning import QdlInvariant, QdlPlan
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import IncrementalQdlPlanner, declared_action_ids
from tests.support.guardrails import AllowAllGuardrail


class FormalRepository:
    def __init__(self, graph: QdlGraph) -> None:
        self.graph = graph

    def load(self, source_id: str) -> QdlGraph:
        return self.graph if source_id.startswith("contract:") else QdlGraph()

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return QdlGraph()

    def save(self, *args: object, **kwargs: object) -> None:
        return None


class MethodRepository:
    def __init__(self, methods: tuple[MethodSpec, ...]) -> None:
        self.methods = methods

    def list_methods(self, service: str) -> tuple[MethodSpec, ...]:
        return self.methods


class ScenarioRepository:
    def __init__(
        self,
        scenario: ScenarioPosition,
        *,
        missing_methods: frozenset[str] = frozenset(),
    ) -> None:
        self.scenario = scenario
        self.missing_methods = missing_methods

    def get_scenario(
        self,
        principal_id: str,
        resource_id: str,
        method: MethodSpec | None = None,
        **kwargs: object,
    ) -> ScenarioPosition | None:
        if method is None or method.method_id in self.missing_methods:
            return None
        return self.scenario


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self) -> Iterable[DomainEvent]:
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class RecordingTarget:
    def __init__(self) -> None:
        self.checks = []

    def __call__(self, check):
        self.checks.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
        )


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def _build_graph(*actions: str) -> QdlGraph:
    return QdlGraph(
        facts=(
            _fact("is", (Atom(value="service:orders"), Atom(value="Service"))),
            *(
                _fact("is", (Atom(value=action), Atom(value="Action")))
                for action in actions
            ),
        )
    )


def test_declared_action_universe_uses_only_is_declarations() -> None:
    declared = Atom(value="action:declared")
    inferred = Atom(value="action:inferred")
    graph = QdlGraph(
        facts=(
            _fact("is", (declared, Atom(value="Action"))),
            _fact("is", (inferred, Atom(value="ResourceType"))),
            _fact("is", (Atom(value="resource:thing"), Atom(value="ResourceType"))),
            _fact("causes", (inferred, create(Atom(value="resource:thing")))),
        )
    )

    assert declared_action_ids(graph, Context.CONTRACT) == frozenset(
        {"action:declared"}
    )


def test_contract_smoke_path_binds_orphan_declared_action(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    action = f"action:{method_spec.method_id}"
    graph = _build_graph(action)
    view = build(
        QdlPlan(graph_hash=graph.content_hash),
        graph,
        methods=(method_spec,),
        scenarios_by_method={method_spec.method_id: scenario_position},
    )

    assert len(view.paths) == 1
    path = view.paths[0]
    assert path.kind == "smoke"
    assert path.steps[0].method is method_spec
    assert path.steps[0].invariant.norm_fact is None


def test_missing_contract_method_and_scenario_become_explicit_deficits(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    bound_method = method_spec
    missing_method = method_spec.model_copy(
        update={"method_id": "grpc:orders.MissingScenario"}
    )
    graph = _build_graph(
        f"action:{bound_method.method_id}",
        "action:grpc:orders.MissingMethod",
        f"action:{missing_method.method_id}",
    )
    repository = FormalRepository(graph)
    binder = ScenarioBinder(
        MethodRepository((bound_method, missing_method)),
        ScenarioRepository(
            scenario_position,
            missing_methods=frozenset({missing_method.method_id}),
        ),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binding = binder.bind(
        LiveRequest(
            service=bound_method.service,
            principal_id="attacker",
            resource_id="resource-victim",
        ),
        formal_proposal=False,
    )

    assert {
        (deficit.action, deficit.reason)
        for deficit in binding.deficits
        if deficit.reason in {"contract_method_missing", "contract_scenario_missing"}
    } == {
        ("action:grpc:orders.MissingMethod", "contract_method_missing"),
        ("action:grpc:orders.MissingScenario", "contract_scenario_missing"),
    }


def test_contract_smoke_path_executes_but_stays_unscoreable(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    graph = _build_graph(f"action:{method_spec.method_id}")
    plan = QdlPlan(graph_hash=graph.content_hash)
    view = build(
        plan,
        graph,
        methods=(method_spec,),
        scenarios_by_method={method_spec.method_id: scenario_position},
    )
    events = EventLog()
    target = RecordingTarget()
    checker = Checker(
        target,
        TemplateGenerator(),
        AllowAllGuardrail(),
        events,
    )
    runner = assemble_runner(
        checker,
        events,
        events,
    )

    result = runner.execute_plan(
        LiveRequest(
            service=method_spec.service,
            principal_id="attacker",
            resource_id="secret-victim",
        ),
        plan,
        view,
    )

    assert len(result.observations) == 1
    verdict = next(iter(result.policy_verdicts.values()))
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.rationale == "QDL invariant has no executable norm fact"
    assert any(
        isinstance(event, CoverageUpdated) and event.method_id == method_spec.method_id
        for event in events.events
    )
    assert result.observations[0].trace is not None
    assert result.observations[0].trace.steps[0].request_fields == ("secret_id",)


@pytest.mark.parametrize("missing", [False, True])
def test_duplicate_norms_preserve_scenario_lookup_order(
    method_spec, scenario_position, missing
) -> None:
    first = method_spec.model_copy(update={"method_id": "first"})
    second = method_spec.model_copy(update={"method_id": "second"})
    graph = QdlGraph()
    effects = tuple(
        reached(Atom(value=f"action:{name}"), Atom(value="sink:sql"))
        for name in ("second", "first", "second")
    )
    norms = tuple(
        QdlInvariant(
            norm=f"norm:{number}",
            effect=effect,
            primitive="marker",
            required_evidence=("trace", "sink_evidence"),
            verdict_policy="deterministic",
            fact=_fact(
                "prevents", (Atom(value=f"norm:{number}"), effect), Context.ACCEPTED
            ),
        )
        for number, effect in enumerate(effects)
    )
    plan = QdlPlan(graph_hash=graph.content_hash, invariants=norms)
    scenarios = Mock(
        wraps=ScenarioRepository(
            scenario_position,
            missing_methods=frozenset({"second"}) if missing else frozenset(),
        )
    )
    binder = ScenarioBinder(
        MethodRepository((first, second)),
        scenarios,
        FormalRepository(graph),
        SimpleNamespace(plan=lambda graph: plan),
    )
    request = LiveRequest(
        service=first.service, principal_id="attacker", resource_id="r"
    )
    previous = None
    for _ in range(2):
        scenarios.reset_mock()
        binding = binder.bind(request, formal_proposal=False)
        calls = [
            call.kwargs["method"].method_id
            for call in scenarios.get_scenario.call_args_list
        ]
        assert calls == (
            ["first", "second", "second"] if missing else ["first", "second"]
        )
        assert len(binding.invariants) == 2
        if previous is not None:
            assert binding == previous
        previous = binding


@pytest.mark.parametrize("caused", [False, True])
def test_changed_norm_keeps_unbound_resource_diagnostic(
    method_spec, scenario_position, caused
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    resource = Atom(value="resource:order")
    effect = changed(resource, Atom(value="total"))
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (effect, Atom(value="Effect"))),
            _fact("is", (Atom(value="norm:first"), Atom(value="Norm"))),
            _fact("is", (Atom(value="norm:second"), Atom(value="Norm"))),
            _fact("targets", (action, resource)),
            _fact("prevents", (Atom(value="norm:first"), effect), Context.ACCEPTED),
            _fact("prevents", (Atom(value="norm:second"), effect), Context.ACCEPTED),
            *((_fact("causes", (action, effect)),) if caused else ()),
        )
    )
    binder = ScenarioBinder(
        MethodRepository((method_spec,)),
        ScenarioRepository(scenario_position),
        FormalRepository(graph),
        IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec.service, principal_id="attacker", resource_id="r"
        ),
        formal_proposal=False,
    )
    missing = [d for d in binding.deficits if d.reason == "missing_causal_effect"]
    assert [d.action for d in missing] == ([] if caused else [method_spec.method_id])
    assert len(binding.invariants) == 1
