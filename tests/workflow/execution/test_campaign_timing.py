from __future__ import annotations

from datetime import timedelta

from cloud_dast.api import LiveRequest
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
    BoundPathRunner,
    FindingEvaluator,
    LiveWorkflow,
)
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
    workflow = LiveWorkflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        BoundPathRunner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        event_bus=bus,
        metrics=metrics,
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
