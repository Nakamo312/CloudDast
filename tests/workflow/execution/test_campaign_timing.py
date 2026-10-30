from __future__ import annotations

from datetime import timedelta

import pytest

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
)
from cloud_dast.model.events import DomainEvent, PhaseChanged
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, allowed
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign import (
    FindingEvaluator,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.oracles import (
    GroundedOutcomeOracle,
    PrimitiveOracleRouter,
)
from cloud_dast_fuzzing import TemplateGenerator
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
        self._cursors[consumer_id] = len(events) + cursor
        return events


class ScenarioRepo:
    def __init__(self, scenario) -> None:
        self.scenario = scenario

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        return self.scenario


class MethodRepo:
    def __init__(self, methods) -> None:
        self.methods = methods

    def list_methods(self, service):
        return self.methods


class FormalRepository:
    def __init__(self) -> None:
        self.saved = []

    def save(self, source_id, graph, *, provenance, adapter_version, mapping_report):
        self.saved.append((source_id, graph))

    def load(self, source_id):
        return next(
            (
                graph
                for saved_id, graph in reversed(self.saved)
                if saved_id == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix):
        merged = QdlGraph()
        for saved_id, graph in self.saved:
            if saved_id.startswith(source_prefix):
                merged = merge_graphs(merged, graph)
        return merged


def _fact(predicate: str, args: tuple[object, ...], context=Context.ACCEPTED) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _accepted_norm_graph(method) -> QdlGraph:
    action = Atom(value=f"action:{method.method_id}")
    norm = Atom(value="norm:foreign-secret-read")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, allowed(action))),
        )
    )


def _allowed_target(check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


def test_live_workflow_records_all_campaign_phases(
    method_spec,
    scenario_position,
) -> None:
    repository = FormalRepository()
    repository.save(
        f"contract:{method_spec.service}",
        _accepted_norm_graph(method_spec),
        provenance={"source_kind": "test"},
        adapter_version="contract-projection-v1",
        mapping_report={"mapped": 3, "unmapped": ()},
    )
    events = EventLog()
    bus = EventBus()
    bus.subscribe(PhaseChanged, events.append)
    service = Checker(_allowed_target, TemplateGenerator(), AllowAllGuardrail(), bus)
    metrics = CampaignMetrics()
    event_projection = EventProjection(bus, events)
    workflow = assemble_workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            event_projection,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(event_projection),
        options=LiveWorkflowOptions(event_bus=bus, metrics=metrics),
    )

    workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert [
        event.phase for event in events.events if isinstance(event, PhaseChanged)
    ] == ["qdl_planning", "executing", "evaluating", "finished"]
    timing = metrics.snapshot().timing
    assert timing.wall_time >= timedelta()
    assert set(timing.phase_elapsed) == {
        "qdl_planning",
        "executing",
        "evaluating",
        "finished",
    }


@pytest.mark.parametrize(
    "failure", [None, "snapshot", "publish", "start", "bind", "campaign"]
)
def test_startup_preserves_order_snapshot_and_exact_failure(
    scenario_position,
    monkeypatch,
    failure,
):
    from types import SimpleNamespace

    from cloud_dast.contracts.execution import ExecutionResult, ScenarioBinding
    from cloud_dast.contracts.plan import QdlExecutionView
    from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
    from cloud_dast.runtime.differential.executor import ProbeExecutor

    order = []
    error = RuntimeError(f"startup {failure}")
    baseline = PhaseChanged(phase="finished")
    history = [baseline]
    graph = QdlGraph()
    binding = ScenarioBinding(
        scenario=scenario_position,
        graph=graph,
        plan=SimpleNamespace(
            graph_hash=graph.content_hash,
            attack_paths=(),
            forbidden_paths=(),
            invariants=(),
        ),
        execution=QdlExecutionView(graph.content_hash, (), {}),
        methods=(),
        invariants={},
    )

    def checkpoint(name):
        order.append(name)
        if failure == name:
            raise error

    class Evaluator:
        @property
        def events(self):
            if not order:
                checkpoint("snapshot")
            return tuple(history)

    class Bus:
        def publish(self, event):
            if event.phase == "qdl_planning":
                checkpoint("publish")
                history.append(event)

    handle = None

    def start_grounded(service, runner):
        assert service == "orders"
        checkpoint("start")
        return handle

    def bind(request, *, formal_proposal):
        assert formal_proposal is False
        checkpoint("bind")
        return binding

    runner = SimpleNamespace(
        differential=ProbeExecutor(None, None),
        reconsider_paths=lambda *a, **kw: None,
        execute_round=lambda *a, **kw: ExecutionResult((), (), {}, {}),
    )
    workflow = assemble_workflow(
        SimpleNamespace(bind=bind),
        runner,
        Evaluator(),
        lifecycle=SimpleNamespace(start_grounded=start_grounded),
        options=LiveWorkflowOptions(
            event_bus=Bus(), grounding_runner=ThreadedGroundingRunner()
        ),
    )
    construct = workflow._initializer.prepare_campaign

    def prepare_campaign(request, initial_binding, scope, *, handle):
        checkpoint("campaign")
        assert initial_binding is binding
        assert scope.baseline_event_ids == frozenset({baseline.event_id})
        return construct(request, initial_binding, scope, handle=handle)

    monkeypatch.setattr(workflow._initializer, "prepare_campaign", prepare_campaign)
    monkeypatch.setattr(workflow, "_finish_campaign", lambda campaign: campaign)
    request = LiveRequest(
        service="orders", principal_id="attacker", resource_id="victim"
    )
    expected = ["snapshot", "publish", "start", "bind", "campaign"]
    if failure is None:
        campaign = workflow.execute(request)
        assert campaign.binding is binding
        assert campaign.request is request
        assert order == expected
    else:
        with pytest.raises(RuntimeError) as caught:
            workflow.execute(request)
        assert caught.value is error
        assert order == expected[: expected.index(failure) + 1]
