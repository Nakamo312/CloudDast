from __future__ import annotations

import asyncio
import json
import logging
import threading
from unittest.mock import Mock

import pytest

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest, ObservationProvenance
from cloud_dast.contracts.plan import QdlExecutionStep, VerificationPlan
from cloud_dast.contracts.proposals import FormalModelOutput
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.infrastructure.runtime import (
    MemoryEvidenceChannel,
    ThreadedGroundingRunner,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    ExecutionTrace,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    PrincipalRef,
    ResponseData,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DiffPairComputed,
    DomainEvent,
    DownstreamDecision,
    EvidenceRecorded,
    FactVerified,
    FindingRaised,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.ports import EvidenceEvent, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
    allowed,
    canonical_json,
    changed,
    create,
    denied,
    differs,
    external_call,
    input_field,
    output_field,
    transition,
)
from cloud_dast.qdl.graph import field as resource_field
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.graph_slice import slice_graph_by_actions
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.qdl.state_machine import (
    state_machine_graph,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign import (
    BoundPathRunner,
    FindingEvaluator,
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.consultation.calls import Invoker
from cloud_dast.runtime.deficits import (
    Deficit,
    consultation_context,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.evidence_gate import Gate
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.runtime.planning import IncrementalQdlPlanner, QdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.evidence_facts import verified_fact_id
from cloud_dast.verification.oracles import (
    GroundedOutcomeOracle,
    OobOracle,
    PrimitiveOracleRouter,
)
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
    TemplateGenerator,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from cloud_dast_llm.threat_model import FormalThreatModeler
from cloud_dast_reporting import (
    CoverageSnapshot,
    PhaseChanged,
    PlanReady,
)
from tests.grounding_owner import make_grounding
from tests.support.guardrails import AllowAllGuardrail


def _workflow(
    scenario_binder,
    path_runner,
    finding_evaluator,
    grounding=None,
    *,
    lifecycle=None,
    source=None,
    variance=None,
    options=None,
) -> LiveWorkflow:
    return assemble_workflow(
        scenario_binder,
        path_runner,
        finding_evaluator,
        grounding,
        lifecycle=lifecycle,
        source=source,
        variance=variance,
        options=options
        or LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    )


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


class ScenarioRepo:
    def __init__(self, scenario) -> None:
        self.scenario = scenario
        self.calls = []

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        self.calls.append((principal_id, resource_id, method))
        return self.scenario


class MethodRepo:
    def __init__(self, methods) -> None:
        self.methods = methods

    def list_methods(self, service):
        return self.methods


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
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id):
        return next(
            (
                item["graph"]
                for item in reversed(self.saved)
                if item["source_id"] == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix):
        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


class FakeModelClient:
    def __init__(self, *responses: ModelResponse) -> None:
        self.responses = responses
        self.requests: list[tuple[object, object]] = []

    def complete(self, request, *, response_type=None) -> ModelResponse:
        self.requests.append((request, response_type))
        if len(self.requests) > len(self.responses):
            raise AssertionError("model client was called more times than expected")
        return self.responses[len(self.requests) - 1]


class RecordingQdlPlanner(QdlPlanner):
    def __init__(self) -> None:
        super().__init__()
        self.graphs: list[QdlGraph] = []

    def plan(self, graph):
        self.graphs.append(graph)
        return super().plan(graph)


def _event_bus(events: EventLog) -> EventBus:
    bus = EventBus()
    for event_type in (
        CoverageSnapshot,
        PhaseChanged,
        PlanReady,
        CheckCompleted,
        CoverageUpdated,
        EvidenceRecorded,
        FactVerified,
        FindingRaised,
    ):
        bus.subscribe(event_type, events.append)
    return bus


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
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


def _execution_step(
    method: MethodSpec,
    scenario,
    invariant,
    *,
    resource_params: tuple[str, ...] = (),
) -> QdlExecutionStep:
    plan = VerificationPlan(
        plan_id=f"plan:{method.method_id}",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        resource_params=resource_params,
    )
    return QdlExecutionStep(
        step_id=f"step:{method.method_id}",
        goal_id=f"goal:{method.method_id}",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
    )


def _accepted_norm_graph(method: MethodSpec) -> QdlGraph:
    action = Atom(value=f"action:{method.method_id}")
    norm = Atom(value="norm:foreign-secret-read")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, allowed(action))),
        )
    )


def _oob_norm_graph(method: MethodSpec) -> QdlGraph:
    action = Atom(value=f"action:{method.method_id}")
    norm = Atom(value="norm:no-external-call")
    callback = input_field(action, Atom(value="callback_url"))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("is", (callback, Atom(value="InputField"))),
            _fact("part", (callback, action), Context.CONTRACT),
            _fact("has", (callback, Atom(value="oob_target"))),
            _fact("prevents", (norm, external_call(action, Atom(value="oob-marker")))),
        )
    )


def _state_machine(methods: tuple[MethodSpec, ...]) -> QdlGraph:
    approve, ship = methods
    return state_machine_graph(
        states=("created", "approved", "shipped"),
        actions=(approve.method_id, ship.method_id),
        norms=("no_ship_without_approval",),
        initial_states=("created",),
        transitions=(
            (approve.method_id, "created", "approved"),
            (ship.method_id, "approved", "shipped"),
        ),
        forbidden_states=(("no_ship_without_approval", "shipped"),),
    )


def _changed_norm_graph(method: MethodSpec) -> QdlGraph:
    action = Atom(value=f"action:{method.method_id}")
    resource = Atom(value="resource:order")
    total = Atom(value="total")
    norm = Atom(value="norm:immutable-total")
    request_field = input_field(action, total)
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="ResourceType"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("is", (request_field, Atom(value="InputField"))),
            _fact("part", (request_field, action), Context.CONTRACT),
            _fact("prevents", (norm, changed(resource, total))),
            _fact("causes", (action, changed(resource, total)), Context.CONTRACT),
        )
    )


def _readback_contract_graph(write: MethodSpec, read: MethodSpec) -> QdlGraph:
    write_action = Atom(value=f"action:{write.method_id}")
    read_action = Atom(value=f"action:{read.method_id}")
    resource = Atom(value="resource:order")
    write_field = input_field(write_action, Atom(value="order_id"))
    read_field = input_field(read_action, Atom(value="order_id"))
    write_payload = input_field(write_action, Atom(value="note"))
    return QdlGraph(
        facts=(
            _fact("is", (write_action, Atom(value="Action"))),
            _fact("is", (read_action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="ResourceType"))),
            _fact("is", (write_field, Atom(value="InputField"))),
            _fact("is", (read_field, Atom(value="InputField"))),
            _fact("is", (write_payload, Atom(value="InputField"))),
            _fact("targets", (write_action, resource), Context.CONTRACT),
            _fact("targets", (read_action, resource), Context.CONTRACT),
            _fact("has", (write_field, Atom(value="object_ref"))),
            _fact("has", (read_field, Atom(value="object_ref"))),
            _fact("has", (write_payload, Atom(value="payload"))),
            _fact("refers_to", (write_field, resource), Context.CONTRACT),
            _fact("refers_to", (read_field, resource), Context.CONTRACT),
            _fact("has", (read_action, Atom(value="readback"))),
            _fact("causes", (write_action, changed(resource, Atom(value="note")))),
        )
    )


def _save_graph(
    repository: FormalRepository,
    source_id: str,
    graph: QdlGraph,
    *,
    adapter_version: str,
) -> None:
    repository.save(
        source_id,
        graph,
        provenance={"source_kind": "test"},
        adapter_version=adapter_version,
        mapping_report={"mapped": len(graph.facts), "unmapped": ()},
    )


def _service(methods, target, bus):
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), bus)
    return checker


def _allowed_target(check):
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


class _RecordingOobTarget:
    """Capture the generated OOB marker while returning a normal observation."""

    def __init__(self) -> None:
        self.marker: str | None = None

    def __call__(self, check) -> Observation:
        self.marker = check.probe_marker
        return _allowed_target(check)


class _StaticOobUrls:
    def url_for(self, marker: str) -> str:
        return f"https://collaborator.test/{marker}"


class _LateOobRunner(BoundPathRunner):
    """Deliver one late OOB callback at the campaign-final sweep boundary."""

    def __init__(
        self,
        service_workflow,
        event_bus,
        event_store,
        *,
        oob_events,
        target,
        **kwargs,
    ) -> None:
        assembled = assemble_runner(service_workflow, event_bus, event_store, **kwargs)
        super().__init__(**vars(assembled))
        self.target = target
        self.oob_events = oob_events

    def reevaluate_oob_pending(self, *, timeout=None):
        marker = self.target.marker
        if marker is None:
            return {}
        self.oob_events.record(
            EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
        )
        return super().reevaluate_oob_pending(timeout=0.0)


class StateTransitionTarget:
    """Return complete before/after state evidence for each executed call."""

    def __init__(self, transitions: tuple[tuple[str, str], ...]) -> None:
        self.transitions = iter(transitions)

    def __call__(self, check) -> Observation:
        before, after = next(self.transitions)
        observation_id = f"observation:{check.check_id}"
        return Observation(
            observation_id=observation_id,
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id=observation_id,
                        step_id=check.check_id,
                        method_id=check.method_id,
                        scenario_id=check.scenario_id,
                        status=AccessOutcome.ALLOWED,
                        resource_state_before=(("state", before),),
                        resource_state_after=(("state", after),),
                    ),
                )
            ),
        )


class ReadBackStateTarget:
    """Serve a read/write/read-back sequence over one order state."""

    def __init__(self, ship_method_id: str) -> None:
        self.ship_method_id = ship_method_id
        self.state = "paid"
        self.calls: list[str] = []

    def __call__(self, check) -> Observation:
        self.calls.append(check.method_id)
        state_before = self.state
        if check.method_id == self.ship_method_id:
            self.state = "shipped"
        observation_id = f"observation:{check.check_id}"
        return Observation(
            observation_id=observation_id,
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("state", self.state),)),
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id=observation_id,
                        step_id=check.check_id,
                        method_id=check.method_id,
                        scenario_id=check.scenario_id,
                        status=AccessOutcome.ALLOWED,
                        resource_state_before=(("state", state_before),),
                        resource_state_after=(("state", self.state),),
                    ),
                )
            ),
        )


def test_live_workflow_executes_accepted_qdl_norm(
    method_spec,
    scenario_position,
) -> None:
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _accepted_norm_graph(method_spec),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    service = _service((method_spec,), _allowed_target, bus)
    scenario_repo = ScenarioRepo(scenario_position)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            scenario_repo,
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert scenario_repo.calls[0][2] == method_spec
    assert result.qdl_graph is not None
    assert result.qdl_plan is not None
    assert result.qdl_plan.invariants[0].norm == "norm:foreign-secret-read"
    assert len(result.observations) == 1
    assert len(result.findings) == 1
    assert result.findings[0].invariant_id.startswith("invariant:qdl:")
    assert result.findings[0].path_id.startswith("qdl-invariant-")
    assert result.replayed_observations == result.observations
    assert result.replayed_findings == result.findings
    assert result.coverage is not None
    assert not hasattr(result, "threat_graph")
    assert repository.saved[-1]["source_id"].startswith("observation:")


def test_live_workflow_final_sweep_reevaluates_late_oob_callback(
    method_spec,
    scenario_position,
) -> None:
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="callback_url", type="url", required=True),)}
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method.service}",
        _oob_norm_graph(method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    oob_events = MemoryEvidenceChannel()
    oob_events.set_ready(True)
    target = _RecordingOobTarget()

    checker = Checker(
        target,
        GoalPayloadGenerator(
            TemplateGenerator(),
            oob_urls=_StaticOobUrls(),
        ),
        AllowAllGuardrail(),
        bus,
    )
    runner = _LateOobRunner(
        checker,
        bus,
        events,
        primitive_oracle=PrimitiveOracleRouter(
            oob_oracle=OobOracle(oob_events, wait_seconds=0.0)
        ),
        formal_repository=repository,
        target=target,
        oob_events=oob_events,
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((method,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        runner,
        FindingEvaluator(bus, events),
    )

    result = workflow.execute(
        LiveRequest(
            service=method.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert target.marker is not None
    assert len(result.observations) == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.evidence_refs[-1] in {
        event.event_id
        for event in oob_events.events
        if event.correlation_id == target.marker
    }


def test_concurrency_mode_saves_evidence_for_changed_norms(
    method_spec,
    scenario_position,
) -> None:
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _changed_norm_graph(method_spec),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    service = _service((method_spec,), _allowed_target, bus)
    runner = assemble_runner(
        service,
        bus,
        events,
        grounded_oracle=GroundedOutcomeOracle(),
        primitive_oracle=PrimitiveOracleRouter(),
        formal_repository=repository,
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        runner,
        FindingEvaluator(bus, events),
        options=LiveWorkflowOptions(
            diff_mode=True,
            diff_modes=frozenset({"concurrency"}),
            event_bus=bus,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
            method_id=method_spec.method_id,
        )
    )

    assert len(result.observations) == 5
    assert [
        event.mode for event in events.events if isinstance(event, DiffPairComputed)
    ] == ["concurrency"]


def test_live_workflow_execution_does_not_imply_oracle_coverage(
    method_spec,
    scenario_position,
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    resource = Atom(value="resource:order")
    status = Atom(value="status")
    norm = Atom(value="norm:immutable-status")
    effect = changed(resource, status)
    target_field = resource_field(resource, status)
    request_field = input_field(action, status)
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="ResourceType"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("is", (target_field, Atom(value="Field"))),
            _fact("is", (request_field, Atom(value="InputField"))),
            _fact("part", (request_field, action), Context.CONTRACT),
            _fact("prevents", (norm, effect)),
            _fact("causes", (action, effect), Context.CONTRACT),
            _fact("refers_to", (request_field, resource), Context.CONTRACT),
        )
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        graph,
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service((method_spec,), _allowed_target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert result.observations
    assert result.coverage is not None
    assert result.coverage.field_summary.total == 2
    assert result.coverage.field_summary.covered == 0
    unresolved = next(
        cell for cell in result.coverage.fields if cell.field_kind == "resource"
    )
    assert unresolved.semantic_role == "state_transition"
    assert unresolved.primitive == "marker"
    assert unresolved.status == "unresolved"
    assert unresolved.deficit == "evidence_blind"
    unclassified = next(
        cell for cell in result.coverage.fields if cell.field_kind == "input"
    )
    assert unclassified.deficit == "capability_blind"


def test_scenario_binder_builds_runtime_view_from_state_machine(
    method_spec,
    scenario_position,
) -> None:
    ship_method = method_spec.model_copy(
        update={"method_id": "grpc:ship", "name": "Ship"}
    )
    methods = (method_spec, ship_method)
    repository = FormalRepository()
    state_machine = _state_machine(methods)
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )

    binder = ScenarioBinder(
        MethodRepo(methods),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    # The binding graph contains the state machine, the attacker hypothesis,
    # and universal exposes facts for every declared action.
    assert binding.graph is not None
    assert binding.plan.graph_hash == binding.graph.content_hash

    # State machine facts are all present.
    sm_facts = {canonical_json(f) for f in state_machine.facts}
    graph_facts = {canonical_json(f) for f in binding.graph.facts}
    assert sm_facts <= graph_facts

    # Attacker hypothesis is present.
    assert any(
        f.predicate.name == "attacker"
        and f.args[0].value == "principal:principal-attacker"
        for f in binding.graph.facts
    )

    # Universal exposes are present for every declared action.
    actions = {
        f.args[0].value
        for f in binding.graph.facts
        if f.predicate.name == "is" and len(f.args) == 2 and f.args[1].value == "Action"
    }
    exposes_actions = {
        f.args[0].value for f in binding.graph.facts if f.predicate.name == "exposes"
    }
    assert actions <= exposes_actions
    assert len(binding.plan.forbidden_paths) == 1
    forbidden = next(
        path for path in binding.execution.paths if path.kind == "forbidden"
    )
    assert [step.method.method_id for step in forbidden.steps] == [
        method_spec.method_id,
        ship_method.method_id,
    ]
    assert [
        (step.invariant.norm_fact.args[1].name, step.invariant.norm_fact.args[1].args)
        for step in forbidden.steps
    ] == [
        ("transition", (Atom(value="created"), Atom(value="approved"))),
        ("transition", (Atom(value="approved"), Atom(value="shipped"))),
    ]
    assert any(
        item.invariant_id.startswith("invariant:qdl:forbidden:")
        for item in binding.invariants.values()
    )
    assert len(repository.saved) == 1


def test_scenario_binder_keeps_repository_context_without_matching_live_resource(
    method_spec,
    scenario_position,
) -> None:
    wrong_resource_method = method_spec.model_copy(
        update={"resource_types": frozenset({"other.thing"})}
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _accepted_norm_graph(wrong_resource_method),
        adapter_version="contract-projection-v1",
    )
    binder = ScenarioBinder(
        MethodRepo((wrong_resource_method,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    # The repository supplies context; QDL producers supply dynamic values.
    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(step.scenario == scenario_position for step in steps)
    assert all(step.method == wrong_resource_method for step in steps)
    assert all(step.plan.resource_types == () for step in steps)


def test_scenario_binder_does_not_require_service_part_to_bind_ordinary_action(
    method_spec,
    scenario_position,
) -> None:
    wrong_resource_method = method_spec.model_copy(
        update={"resource_types": frozenset({"other.thing"})}
    )
    action = Atom(value=f"action:{wrong_resource_method.method_id}")
    resource = Atom(value="resource:other.thing")
    graph = QdlGraph(
        facts=(
            *_accepted_norm_graph(wrong_resource_method).facts,
            _fact("is", (resource, Atom(value="ResourceType"))),
            _fact("targets", (action, resource), Context.CONTRACT),
        )
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        graph,
        adapter_version="contract-projection-v1",
    )
    binder = ScenarioBinder(
        MethodRepo((wrong_resource_method,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(step.scenario.stand == scenario_position.stand for step in steps)
    assert all(step.plan.resource_types == () for step in steps)


def test_scenario_binder_does_not_synthesize_resources_from_service_part(
    method_spec,
    scenario_position,
) -> None:
    wrong_resource_method = method_spec.model_copy(
        update={"resource_types": frozenset({"other.thing"})}
    )
    action = Atom(value=f"action:{wrong_resource_method.method_id}")
    resource = Atom(value="resource:other.thing")
    service = Atom(value="service:explicit-service")
    graph = QdlGraph(
        facts=(
            *_accepted_norm_graph(wrong_resource_method).facts,
            _fact("is", (resource, Atom(value="ResourceType"))),
            _fact("is", (service, Atom(value="Service"))),
            _fact("targets", (action, resource), Context.CONTRACT),
            _fact("part", (resource, service), Context.CONTRACT),
        )
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        graph,
        adapter_version="contract-projection-v1",
    )
    binder = ScenarioBinder(
        MethodRepo((wrong_resource_method,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(step.scenario.stand == scenario_position.stand for step in steps)
    assert all(
        resource.resource_type != "other.thing"
        for step in steps
        for resource in step.scenario.stand.resources
    )
    assert any(fact.predicate.name == "part" for fact in binding.graph.facts)


def test_owner_fact_controls_differential_control_position(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    from cloud_dast.runtime.differential.specs import SpecResolver

    workflow = SpecResolver.__new__(SpecResolver)
    workflow._scenario_repository = _diff_scenario_repo(scenario_position)
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    step = _execution_step(method_spec, scenario_position, invariant)
    resource = Atom(value="resource:secret-victim")
    owner = Atom(value="subject:owner")
    owner_graph = QdlGraph(
        facts=(
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (owner, Atom(value="Subject"))),
            _fact("owner", (resource, owner)),
        )
    )

    assert (
        workflow.differential_spec(
            request,
            step,
            owner_graph,
            DeficitQueue(),
        )
        is not None
    )

    deficits = DeficitQueue()
    assert (
        workflow.differential_spec(
            request,
            step,
            QdlGraph(facts=()),
            deficits,
        )
        is None
    )
    deficit = deficits.pop_next()
    assert deficit is not None
    assert deficit.predicate_class == "has"
    assert deficit.action == method_spec.method_id
    assert dict(deficit.context)["coverage"] == "owner"


def test_readback_requires_object_ref_and_readback_facts(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    from cloud_dast.runtime.differential.specs import SpecResolver

    workflow = SpecResolver.__new__(SpecResolver)
    write = method_spec.model_copy(
        update={
            "method_id": "grpc:write-order",
            "name": "WriteOrder",
            "resource_types": frozenset({"order"}),
            "fields": (
                FieldSpec(name="order_id", type="string", required=True),
                FieldSpec(name="note", type="string"),
            ),
        }
    )
    read = method_spec.model_copy(
        update={
            "method_id": "grpc:read-order",
            "name": "ReadOrder",
            "resource_types": frozenset({"order"}),
            "fields": (FieldSpec(name="order_id", type="string", required=True),),
        }
    )
    graph = _readback_contract_graph(write, read)
    method_pool = {read.method_id: read}

    object_ref_deficits = DeficitQueue()
    assert (
        workflow.readback_spec(
            _execution_step(write, scenario_position, invariant),
            graph,
            method_pool,
            object_ref_deficits,
        )
        is None
    )
    object_ref_deficit = object_ref_deficits.pop_next()
    assert object_ref_deficit is not None
    assert object_ref_deficit.predicate_class == "has"
    assert dict(object_ref_deficit.context)["coverage"] == "object_ref"

    graph_without_readback = QdlGraph(
        facts=tuple(
            fact
            for fact in graph.facts
            if not (
                fact.predicate.name == "has"
                and isinstance(fact.args[0], Atom)
                and fact.args[0].value == f"action:{read.method_id}"
                and fact.args[1].value == "readback"
            )
        )
    )
    readback_deficits = DeficitQueue()
    assert (
        workflow.readback_spec(
            _execution_step(
                write, scenario_position, invariant, resource_params=("order_id",)
            ),
            graph_without_readback,
            method_pool,
            readback_deficits,
        )
        is None
    )
    readback_deficit = readback_deficits.pop_next()
    assert readback_deficit is not None
    assert readback_deficit.predicate_class == "has"
    assert dict(readback_deficit.context)["coverage"] == "readback"


def _proposal_atom(value: str) -> dict[str, object]:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _proposal_struct(name: str, *args: dict[str, object]) -> dict[str, object]:
    return {"kind": "struct", "name": name, "args": list(args)}


def _proposal_fact(predicate: str, *args: dict[str, object]) -> dict[str, object]:
    return {
        "context": "proposal",
        "predicate": predicate,
        "args": list(args),
    }


def _formal_proposal_response() -> ModelResponse:
    changed = _proposal_struct(
        "changed",
        _proposal_atom("resource:secret"),
        _proposal_atom("resourceType"),
    )
    payload = {
        "context": "proposal",
        "facts": (
            _proposal_fact(
                "is",
                _proposal_atom("resource:secret"),
                _proposal_atom("Resource"),
            ),
            _proposal_fact(
                "is",
                _proposal_atom("threat:mass-assignment"),
                _proposal_atom("Threat"),
            ),
            _proposal_fact(
                "is",
                _proposal_atom("norm:no-mass-assignment"),
                _proposal_atom("Norm"),
            ),
            _proposal_fact("is", changed, _proposal_atom("Effect")),
            _proposal_fact(
                "causes",
                _proposal_atom("threat:mass-assignment"),
                changed,
            ),
            _proposal_fact(
                "prevents",
                _proposal_atom("norm:no-mass-assignment"),
                changed,
            ),
        ),
        "rules": (),
    }
    return ModelResponse(
        structured=payload,
        content=json.dumps(payload),
        model_id="fake-model",
    )


def _formal_allowed_proposal_response(action_value: str) -> ModelResponse:
    action = _proposal_atom(action_value)
    norm = _proposal_atom("norm:no-unauthorized-read")
    effect = _proposal_struct("allowed", action)
    payload = {
        "context": "proposal",
        "facts": (
            _proposal_fact("is", action, _proposal_atom("Action")),
            _proposal_fact("is", norm, _proposal_atom("Norm")),
            _proposal_fact("prevents", norm, effect),
        ),
        "rules": (),
    }
    return ModelResponse(
        structured=payload,
        content=json.dumps(payload),
        model_id="fake-model",
    )


def test_scenario_binder_can_promote_formal_proposal_explicitly(
    method_spec,
    scenario_position,
) -> None:
    action = Atom(value=f"action:{method_spec.method_id}")
    contract = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        contract,
        adapter_version="contract-projection-v1",
    )
    client = FakeModelClient(
        _formal_allowed_proposal_response(f"action:{method_spec.method_id}")
    )
    planner = RecordingQdlPlanner()
    binder = ScenarioBinder(
        MethodRepo((method_spec,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=planner,
        formal_threat_modeler=FormalThreatModeler(client),
        promote_formal_proposals=True,
    )

    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert planner.graphs
    accepted = tuple(
        fact
        for fact in planner.graphs[0].facts
        if fact.context is Context.ACCEPTED and fact.predicate.name == "prevents"
    )
    assert len(accepted) == 1
    assert binding.plan.invariants
    assert binding.execution.paths


def test_scenario_binder_passes_llm_proposal_to_planner_without_accepting(
    method_spec,
    scenario_position,
) -> None:
    ship_method = method_spec.model_copy(
        update={"method_id": "grpc:ship", "name": "Ship"}
    )
    methods = (method_spec, ship_method)
    contract = _accepted_norm_graph(method_spec)
    state_machine = _state_machine(methods)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        contract,
        adapter_version="contract-projection-v1",
    )
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )

    client = FakeModelClient(_formal_proposal_response())
    planner = RecordingQdlPlanner()
    binder = ScenarioBinder(
        MethodRepo(methods),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=planner,
        formal_threat_modeler=FormalThreatModeler(client),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert len(client.requests) == 1
    request, response_type = client.requests[0]
    assert request.task == "formal_threat_modeling"
    assert response_type is FormalModelOutput
    source = merge_graphs(contract, state_machine)
    expected_slice = slice_graph_by_actions(source)
    assert request.context["graph"] == expected_slice.model_dump(mode="json")

    assert len(planner.graphs) == 1
    planning_graph = planner.graphs[0]
    assert all(fact in planning_graph.facts for fact in state_machine.facts)
    proposal_facts = tuple(
        fact for fact in planning_graph.facts if fact.context is Context.PROPOSAL
    )
    assert any(fact.predicate.name == "prevents" for fact in proposal_facts)
    assert all(fact.context is not Context.ACCEPTED for fact in proposal_facts)

    assert len(repository.saved) == 2
    assert binding.plan.invariants
    assert all(
        "no-mass-assignment" not in item.norm for item in binding.plan.invariants
    )
    assert any(path.kind == "forbidden" for path in binding.execution.paths)


def test_scenario_binder_continues_without_valid_formal_proposal(
    method_spec,
    scenario_position,
) -> None:
    ship_method = method_spec.model_copy(
        update={"method_id": "grpc:ship", "name": "Ship"}
    )
    methods = (method_spec, ship_method)
    state_machine = _state_machine(methods)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )
    client = FakeModelClient(
        ModelResponse(content="I cannot produce formal artefacts.", model_id="fake"),
        ModelResponse(content="Still prose.", model_id="fake"),
    )
    planner = RecordingQdlPlanner()
    binder = ScenarioBinder(
        MethodRepo(methods),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=planner,
        formal_threat_modeler=FormalThreatModeler(client),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
        )
    )

    assert len(client.requests) == 2
    assert len(planner.graphs) == 1
    assert all(fact.context is not Context.PROPOSAL for fact in planner.graphs[0].facts)
    assert len(repository.saved) == 1
    assert any(path.kind == "forbidden" for path in binding.execution.paths)


def test_forbidden_state_path_without_state_evidence_is_unscoreable(
    method_spec,
    scenario_position,
) -> None:
    ship_method = method_spec.model_copy(
        update={"method_id": "grpc:ship", "name": "Ship"}
    )
    methods = (method_spec, ship_method)
    state_machine = _state_machine(methods)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlPathEvaluated, QdlStepEvaluated):
        bus.subscribe(event_type, events.append)
    service = _service(methods, _allowed_target, bus)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
            max_checks=2,
        )
    )

    assert result.observations
    assert result.findings == ()
    step_events = [
        event
        for event in events.events
        if isinstance(event, QdlStepEvaluated)
        and event.path_id.startswith("qdl-forbidden-")
    ]
    assert len(step_events) == 1
    assert step_events[0].verdict is VerdictStatus.UNSCOREABLE
    assert step_events[0].phase == "unscoreable"
    assert "no complete before/after state evidence" in step_events[0].reason
    path_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated)
        and event.path_id.startswith("qdl-forbidden-")
    ]
    assert len(path_events) == 1
    assert path_events[0].outcome == "blocked"
    assert path_events[0].attempted_steps == 1
    assert not [event for event in events.events if isinstance(event, FactVerified)]
    assert result.qdl_graph is not None
    sm_facts = {canonical_json(f) for f in state_machine.facts}
    graph_facts = {canonical_json(f) for f in result.qdl_graph.facts}
    assert sm_facts <= graph_facts
    assert result.qdl_plan is not None
    assert len(result.qdl_plan.forbidden_paths) == 1
    assert result.norm_coverage is not None
    coverage = result.norm_coverage[0]
    assert coverage.verdict == VerdictStatus.UNSCOREABLE.value
    assert coverage.blocked_reason == (
        "transition QDL norm has no complete before/after state evidence"
    )


def test_readback_transition_does_not_prove_the_following_write(
    method_spec,
    scenario_position,
    invariant,
) -> None:
    get_method = method_spec.model_copy(
        update={
            "method_id": "grpc:get-order",
            "name": "GetOrder",
            "resource_types": frozenset({"order"}),
            "fields": (FieldSpec(name="order_id", type="string", required=True),),
        }
    )
    ship_method = method_spec.model_copy(
        update={
            "method_id": "grpc:ship-order",
            "name": "ShipOrder",
            "resource_types": frozenset({"order"}),
            "fields": (
                FieldSpec(name="order_id", type="string", required=True),
                FieldSpec(name="note", type="string"),
            ),
        }
    )
    methods = (get_method, ship_method)
    order_scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "resources": (
                        scenario_position.stand.resources[0].model_copy(
                            update={"resource_type": "order"}
                        ),
                        *scenario_position.stand.resources[1:],
                    )
                }
            )
        }
    )
    state_machine = state_machine_graph(
        states=("paid", "shipped"),
        actions=(get_method.method_id, ship_method.method_id),
        norms=("no_unapproved_shipment",),
        initial_states=("paid",),
        transitions=((ship_method.method_id, "paid", "shipped"),),
        forbidden_states=(("no_unapproved_shipment", "shipped"),),
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _readback_contract_graph(ship_method, get_method),
        adapter_version="contract-projection-v1",
    )
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    target = ReadBackStateTarget(ship_method.method_id)
    service = _service(methods, target, bus)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(order_scenario),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        options=LiveWorkflowOptions(
            diff_mode=True,
            diff_modes=frozenset({"readback"}),
            event_bus=bus,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
            max_checks=6,
        )
    )

    assert target.calls == [
        get_method.method_id,
        ship_method.method_id,
        get_method.method_id,
        ship_method.method_id,
        # The final read-only call is the contract smoke path for an action
        # that the runtime adds as a readback leg rather than a bound QDL step.
        get_method.method_id,
    ]
    assert len(result.observations) == 5
    assert len(result.findings) == 1
    assert result.findings[0].observation_id == result.observations[1].observation_id
    assert result.findings[0].evidence_refs == tuple(
        o.observation_id for o in result.observations[:3]
    )
    assert result.findings[0].observation_id != result.observations[3].observation_id
    measured_write = result.observations[1]
    fresh_write = result.observations[3]
    assert measured_write.check_id != fresh_write.check_id
    assert fresh_write.trace.steps[0].resource_state_before == (("state", "shipped"),)
    assert fresh_write.trace.steps[0].resource_state_after == (("state", "shipped"),)
    transition_norm = invariant.model_copy(
        update={
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:no_unapproved_shipment"),
                    transition(Atom(value="paid"), Atom(value="shipped")),
                ),
            )
        }
    )
    measured_verdict = PrimitiveOracleRouter().evaluate_policy(
        transition_norm,
        result.observations[:3],
        method=ship_method,
        scenario=order_scenario,
    )
    assert measured_verdict.status is VerdictStatus.FAIL
    assert measured_verdict.grounded and measured_verdict.deterministic
    assert (
        measured_verdict.rationale == "forbidden transition completed: paid -> shipped"
    )
    assert measured_verdict.evidence_refs == tuple(
        observation.observation_id for observation in result.observations[:3]
    )
    assert [
        event.mode for event in events.events if isinstance(event, DiffPairComputed)
    ] == ["readback"]


def test_forbidden_state_transition_with_state_evidence_fails(
    method_spec,
    scenario_position,
) -> None:
    ship_method = method_spec.model_copy(
        update={"method_id": "grpc:ship", "name": "Ship"}
    )
    methods = (method_spec, ship_method)
    state_machine = _state_machine(methods)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"state-machine:{method_spec.service}",
        state_machine,
        adapter_version="state-machine-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlPathEvaluated, QdlStepEvaluated):
        bus.subscribe(event_type, events.append)
    service = _service(
        methods,
        StateTransitionTarget((("created", "approved"), ("approved", "shipped"))),
        bus,
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id=scenario_position.stand.resources[0].resource_id,
            max_checks=2,
        )
    )

    assert len(result.observations) == 2
    assert [finding.method_id for finding in result.findings] == [
        method_spec.method_id,
        ship_method.method_id,
    ]
    assert all(
        finding.path_id.startswith("qdl-forbidden-") for finding in result.findings
    )
    assert [finding.rationale for finding in result.findings] == [
        "forbidden transition completed: created -> approved",
        "forbidden transition completed: approved -> shipped",
    ]
    assert "business state 'shipped'" in result.findings[-1].description
    path_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated)
        and event.path_id.startswith("qdl-forbidden-")
    ]
    assert len(path_events) == 1
    assert path_events[0].outcome == "completed"
    verified = {
        fact_id
        for event in events.events
        if isinstance(event, FactVerified)
        and (fact_id := verified_fact_id(event.fact)) is not None
    }
    assert any(fact_id.startswith("fact:state:approved:") for fact_id in verified)
    assert any(fact_id.startswith("fact:state:shipped:") for fact_id in verified)
    assert result.qdl_graph is not None
    sm_facts = {canonical_json(f) for f in state_machine.facts}
    graph_facts = {canonical_json(f) for f in result.qdl_graph.facts}
    assert sm_facts <= graph_facts
    assert result.qdl_plan is not None
    assert len(result.qdl_plan.forbidden_paths) == 1


def test_scenario_binder_attaches_value_couplings_to_plans(
    method_spec_with_ids,
    scenario_position,
) -> None:
    repository = FormalRepository()
    action = Atom(value=f"action:{method_spec_with_ids.method_id}")
    left = input_field(action, Atom(value="secret_id"))
    right = input_field(action, Atom(value="folder_id"))
    graph = QdlGraph(
        facts=(
            *_accepted_norm_graph(method_spec_with_ids).facts,
            _fact("is", (left, Atom(value="Field"))),
            _fact("is", (right, Atom(value="Field"))),
            _fact("coupled", (left, right, Atom(value="ne"))),
        )
    )
    _save_graph(
        repository,
        f"contract:{method_spec_with_ids.service}",
        graph,
        adapter_version="contract-projection-v1",
    )

    binder = ScenarioBinder(
        MethodRepo((method_spec_with_ids,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec_with_ids.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(
        step.plan.couplings
        == (
            (
                input_field(
                    Atom(value=f"action:{method_spec_with_ids.method_id}"),
                    Atom(value="secret_id"),
                ),
                input_field(
                    Atom(value=f"action:{method_spec_with_ids.method_id}"),
                    Atom(value="folder_id"),
                ),
                "ne",
            ),
        )
        for step in steps
    )


def test_scenario_binder_attaches_probe_fields_to_plans(
    method_spec_with_ids,
    scenario_position,
) -> None:
    repository = FormalRepository()
    action = Atom(value=f"action:{method_spec_with_ids.method_id}")
    probe_field = input_field(action, Atom(value="folder_id"))
    graph = QdlGraph(
        facts=(
            *_accepted_norm_graph(method_spec_with_ids).facts,
            _fact("is", (probe_field, Atom(value="Field"))),
            _fact("has", (probe_field, Atom(value="probe_target"))),
        )
    )
    _save_graph(
        repository,
        f"contract:{method_spec_with_ids.service}",
        graph,
        adapter_version="contract-projection-v1",
    )

    binder = ScenarioBinder(
        MethodRepo((method_spec_with_ids,)),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=method_spec_with_ids.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(step.plan.probe_fields == ("folder_id",) for step in steps)


class StaggeredAxisGrounding:
    """Fake model grounding whose later batches wait for live execution.

    The gate proves the event loop runs paths before all model tasks
    finish: the probe-role batch is only produced after the first live
    check has executed, so a blocking workflow would deadlock here and
    the re-versioned path assertions would fail.
    """

    def __init__(self, batches, execution_started, gate_index=1):
        self._batches = batches
        self._execution_started = execution_started
        self._gate_index = gate_index
        self.stream_finished = threading.Event()
        self.reactive_calls = []

    def ground_stream(self, source, *, cache_source=None):
        for index, (axis, key, graph) in enumerate(self._batches):
            if index == self._gate_index:
                if not self._execution_started.wait(timeout=10):
                    raise AssertionError(
                        "live execution never started while grounding ran"
                    )
            yield axis, key, graph
        self.stream_finished.set()

    def ground_reactive(
        self,
        axis,
        action_ids,
        graph,
        *,
        observation=None,
        **kwargs,
    ):
        from cloud_dast.runtime.grounding.results import AxisResult

        self.reactive_calls.append((axis, tuple(action_ids), observation))
        return AxisResult(axis, None, 0, len(action_ids))

    def ground_alternatives(self, graph, action, **kwargs):
        from cloud_dast.runtime.grounding.results import AxisResult

        self.reactive_calls.append(("alternatives", (action,), kwargs))
        return AxisResult("alternatives", None, 0, 1)


def _two_action_contract(get_method, delete_method) -> QdlGraph:
    get_action = Atom(value=f"action:{get_method.method_id}")
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    norm = Atom(value="norm:initial-get-denied")
    return QdlGraph(
        facts=(
            _fact("is", (get_action, Atom(value="Action"))),
            _fact("is", (delete_action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, allowed(get_action))),
        )
    )


def test_live_workflow_executes_paths_while_grounding_is_running(
    method_spec,
    scenario_position,
) -> None:
    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    get_action = Atom(value=f"action:{method_spec.method_id}")
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    llm_norm = Atom(value="norm:llm-delete-denied")
    probe_term = input_field(get_action, Atom(value="secret_id"))
    sensitive_term = input_field(delete_action, Atom(value="secret_id"))
    sink = Atom(value="sink:delete-secret")

    batches = (
        (
            "dataflows",
            "b0",
            QdlGraph(
                facts=(
                    _fact("is", (delete_action, Atom(value="Action"))),
                    _fact("is", (sensitive_term, Atom(value="Field"))),
                    _fact("is", (sink, Atom(value="interpreter"))),
                    _fact("reaches", (sensitive_term, sink)),
                )
            ),
        ),
        (
            "norms",
            "b1",
            QdlGraph(
                facts=(
                    _fact("is", (delete_action, Atom(value="Action"))),
                    _fact("is", (llm_norm, Atom(value="Norm"))),
                    _fact(
                        "prevents",
                        (llm_norm, allowed(delete_action)),
                        Context.PROPOSAL,
                    ),
                )
            ),
        ),
        (
            "roles",
            "b2",
            QdlGraph(
                facts=(
                    _fact("is", (get_action, Atom(value="Action"))),
                    _fact("is", (probe_term, Atom(value="Field"))),
                    _fact("has", (probe_term, Atom(value="probe_target"))),
                )
            ),
        ),
        (
            "roles",
            "b3",
            QdlGraph(
                facts=(
                    _fact("is", (delete_action, Atom(value="Action"))),
                    _fact("is", (sensitive_term, Atom(value="Field"))),
                    _fact("has", (sensitive_term, Atom(value="sensitive"))),
                )
            ),
        ),
    )

    repository = FormalRepository()
    contract = _two_action_contract(method_spec, delete_method)
    contract = contract.model_copy(
        update={
            "facts": (
                *contract.facts,
                _fact("is", (sink, Atom(value="interpreter"))),
                # The contract owns the input schema. A grounding batch may
                # supply a missing flow, but cannot introduce its own field.
                _fact("is", (probe_term, Atom(value="InputField"))),
                _fact("is", (sensitive_term, Atom(value="InputField"))),
            )
        }
    )
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        contract,
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    execution_started = threading.Event()
    executed_checks = []

    def target(check):
        executed_checks.append(check)
        execution_started.set()
        return _allowed_target(check)

    service = _service(methods, target, bus)
    axis_grounding = StaggeredAxisGrounding(batches, execution_started)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    assert execution_started.is_set()
    assert axis_grounding.stream_finished.is_set()
    assert len(executed_checks) == 4
    path_ids = {
        event.path_id for event in events.events if isinstance(event, QdlPathEvaluated)
    }
    invariant_bases = {path_id.split(":pv")[0] for path_id in path_ids}
    # The specific reached path executes while grounding is still running;
    # generic permission-gap paths are released only after grounding finishes.
    assert len(path_ids) == 4
    assert len(invariant_bases) == 3
    assert any(":pv" in path_id for path_id in path_ids)
    # Counting argument: the initial get-norm path exists in two versions
    # (before and after the probe role), while the reached path and LLM
    # Delete norm each exist in one version.
    base_counts: dict[str, int] = {}
    for path_id in path_ids:
        base = path_id.split(":pv")[0]
        base_counts[base] = base_counts.get(base, 0) + 1
    assert sorted(base_counts.values()) == [1, 1, 2]
    assert result.findings
    assert any(
        item["source_id"].startswith("accepted-batch:") for item in repository.saved
    )


def test_generic_allowed_path_executes_before_grounding_completion(
    method_spec,
    scenario_position,
) -> None:
    """Generic permission-gap paths must not wait for global grounding."""

    get_user = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.GetUser",
            "name": "GetUser",
        }
    )
    action = Atom(value=f"action:{get_user.method_id}")
    probe_term = input_field(action, Atom(value="user_id"))
    batches = (
        (
            "roles",
            "b0",
            QdlGraph(
                facts=(
                    _fact("is", (action, Atom(value="Action"))),
                    _fact("is", (probe_term, Atom(value="Field"))),
                    _fact("has", (probe_term, Atom(value="probe_target"))),
                )
            ),
        ),
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{get_user.service}",
        _accepted_norm_graph(get_user),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    get_user_executed = threading.Event()
    executed_methods = []

    def target(check):
        executed_methods.append(check.method_id)
        if check.method_id == get_user.method_id:
            get_user_executed.set()
        return _allowed_target(check)

    service = _service((get_user,), target, bus)
    axis_grounding = StaggeredAxisGrounding(
        batches,
        get_user_executed,
        gate_index=0,
    )
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((get_user,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
    )

    result = workflow.execute(
        LiveRequest(
            service=get_user.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    assert get_user_executed.is_set()
    assert axis_grounding.stream_finished.is_set()
    assert get_user.method_id in executed_methods
    assert result.observations


def test_live_workflow_rounds_are_idempotent_for_unchanged_paths(
    method_spec,
    scenario_position,
) -> None:
    """A batch that changes no executable path triggers no re-execution."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    get_action = Atom(value=f"action:{method_spec.method_id}")
    role_term = input_field(get_action, Atom(value="secret_id"))
    batches = (
        (
            "roles",
            "b1",
            QdlGraph(
                facts=(
                    _fact("is", (get_action, Atom(value="Action"))),
                    _fact("is", (role_term, Atom(value="Field"))),
                    _fact("has", (role_term, Atom(value="sensitive"))),
                )
            ),
        ),
    )

    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _two_action_contract(method_spec, delete_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)
    service = _service(methods, _allowed_target, bus)
    grounding_component_1 = StaggeredAxisGrounding(
        batches, threading.Event(), gate_index=1
    )
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=grounding_component_1,
        reactive=grounding_component_1,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    assert len(result.observations) == 1


class DiffScenarioRepo:
    """Resolve both legs of a factors pair.

    The attacker position is the campaign's own binding; the control leg is
    the same stand re-bound to the resource owner, so the pair varies
    exactly one profile factor (``identity_class``).
    """

    def __init__(self, attacker, owner) -> None:
        self.attacker = attacker
        self.owner = owner
        self.calls: list[tuple[str, str, str | None]] = []

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        identity_class = kwargs.get("identity_class", "attacker")
        self.calls.append((principal_id, resource_id, identity_class))
        if identity_class == "owner":
            return self.owner
        return self.attacker


class GatedDifferentialAxisGrounding:
    """Startup grounding whose later batches wait for differential discovery.

    The first batch is promoted immediately so the campaign has a stable
    action set to execute; every later batch is held back until a
    ``DiffPairComputed`` event arrives.  ``differential_first`` records
    whether that happened before the gate timeout — a workflow that waits
    for global grounding completion deadlocks against the gate and fails
    the assertion instead.
    """

    def __init__(self, batches, differential_ran, *, gate_timeout=10.0):
        self._batches = batches
        self._differential_ran = differential_ran
        self._gate_timeout = gate_timeout
        self.differential_first: bool | None = None
        self.stream_finished = threading.Event()

    def ground_stream(self, source, *, cache_source=None):
        for index, batch in enumerate(self._batches):
            if index == 1:
                self.differential_first = self._differential_ran.wait(
                    timeout=self._gate_timeout
                )
            yield batch
        self.stream_finished.set()

    def ground_reactive(
        self,
        axis,
        action_ids,
        graph,
        *,
        observation=None,
        check=None,
        oob_events=(),
        evidence=None,
        cache_source=None,
    ):
        from cloud_dast.runtime.grounding.results import AxisResult

        return AxisResult(axis, None, 0, len(action_ids))

    def ground_alternatives(self, graph, action, **kwargs):
        from cloud_dast.runtime.grounding.results import AxisResult

        return AxisResult("alternatives", None, 0, 1)


class FailingAxisGrounding:
    """Startup grounding that aborts before promoting any batch."""

    def __init__(self) -> None:
        self.failed = threading.Event()

    def ground_stream(self, source, *, cache_source=None):
        self.failed.set()
        raise RuntimeError("axis grounding exploded")
        yield  # pragma: no cover - makes this a generator

    def ground_reactive(self, axis, action_ids, graph, *, observation=None, **kwargs):
        from cloud_dast.runtime.grounding.results import AxisResult

        return AxisResult(axis, None, 0, len(action_ids))

    def ground_alternatives(self, graph, action, **kwargs):
        from cloud_dast.runtime.grounding.results import AxisResult

        return AxisResult("alternatives", None, 0, 1)


def _diff_scenario_repo(scenario_position) -> DiffScenarioRepo:
    owner = scenario_position.model_copy(
        update={
            "scenario_id": "owner-position",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    return DiffScenarioRepo(scenario_position, owner)


def _reached_path_batches(method_spec, delete_method) -> tuple:
    """One ungated dataflows batch plus gated follow-up batches."""

    get_action = Atom(value=f"action:{method_spec.method_id}")
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    sensitive_term = input_field(delete_action, Atom(value="secret_id"))
    probe_term = input_field(get_action, Atom(value="secret_id"))
    sink = Atom(value="sink:delete-secret")
    llm_norm = Atom(value="norm:llm-delete-denied")
    return (
        (
            "dataflows",
            "b0",
            QdlGraph(
                facts=(
                    _fact("is", (delete_action, Atom(value="Action"))),
                    _fact("is", (sensitive_term, Atom(value="Field"))),
                    _fact("is", (sink, Atom(value="interpreter"))),
                    _fact("reaches", (sensitive_term, sink)),
                )
            ),
        ),
        (
            "norms",
            "b1",
            QdlGraph(
                facts=(
                    _fact("is", (delete_action, Atom(value="Action"))),
                    _fact("is", (llm_norm, Atom(value="Norm"))),
                    _fact(
                        "prevents",
                        (llm_norm, allowed(delete_action)),
                        Context.PROPOSAL,
                    ),
                )
            ),
        ),
        (
            "roles",
            "b2",
            QdlGraph(
                facts=(
                    _fact("is", (get_action, Atom(value="Action"))),
                    _fact("is", (probe_term, Atom(value="Field"))),
                    _fact("has", (probe_term, Atom(value="probe_target"))),
                )
            ),
        ),
    )


def _diff_campaign(
    method_spec,
    methods,
    scenario_repo,
    grounding,
    events,
    bus,
    *,
    repository=None,
    target=None,
):
    """Assemble a LiveWorkflow whose differential modes can run."""

    repository = repository or FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _contract_with_roles(*methods),
        adapter_version="contract-projection-v1",
    )
    service = _service(methods, target or _allowed_target, bus)
    return _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            scenario_repo,
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches if grounding is not None else None,
        lifecycle=grounding.lifecycle if grounding is not None else None,
        source=grounding.source if grounding is not None else None,
        variance=grounding.variance if grounding is not None else None,
        options=LiveWorkflowOptions(
            diff_mode=True,
            diff_modes=frozenset({"factors"}),
            scenario_repository=scenario_repo,
            formal_repository=repository,
            event_bus=bus,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )


class PartialPairTarget:
    """Complete the control leg and fail the treatment leg."""

    def __init__(self) -> None:
        self.executed: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.executed.append(check)
        if len(self.executed) == 2:
            raise RuntimeError("treatment transport failed")
        return _allowed_target(check)


def test_differential_partial_failure_preserves_executed_work_and_budget(
    method_spec,
    scenario_position,
) -> None:
    """A failed second leg keeps the first leg and both live calls visible."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    scenario_repo = _diff_scenario_repo(scenario_position)
    target = PartialPairTarget()
    workflow = _diff_campaign(
        method_spec,
        methods,
        scenario_repo,
        None,
        events,
        bus,
        target=target,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        )
    )

    completed = [event for event in events.events if isinstance(event, CheckCompleted)]
    assert len(target.executed) == 2
    assert len(result.observations) == 1
    assert result.observations[0].check_id == target.executed[0].check_id
    assert [event.observation.check_id for event in completed] == [
        target.executed[0].check_id
    ]
    assert not [event for event in events.events if isinstance(event, DiffPairComputed)]


def test_differential_runs_before_grounding_completion(
    method_spec,
    scenario_position,
) -> None:
    """Differential discovery must not wait for global grounding completion."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    events = EventLog()
    bus = _event_bus(events)
    differential_ran = threading.Event()
    bus.subscribe(DiffPairComputed, events.append)
    bus.subscribe(DiffPairComputed, lambda _event: differential_ran.set())
    axis_grounding = GatedDifferentialAxisGrounding(
        _reached_path_batches(method_spec, delete_method),
        differential_ran,
    )
    scenario_repo = _diff_scenario_repo(scenario_position)
    repository = FormalRepository()
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _diff_campaign(
        method_spec,
        methods,
        scenario_repo,
        grounding,
        events,
        bus,
        repository=repository,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    # The gate only opened because a DiffPairComputed event arrived while
    # the grounding stream was still holding later batches back.
    assert axis_grounding.differential_first is True
    assert axis_grounding.stream_finished.is_set()
    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert diff_events
    assert all(event.mode == "factors" for event in diff_events)
    assert result.observations


def test_differential_continues_after_grounding_failure(
    method_spec,
    scenario_position,
) -> None:
    """A grounding failure must not cancel differential discovery."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    axis_grounding = FailingAxisGrounding()
    repository = FormalRepository()
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    scenario_repo = _diff_scenario_repo(scenario_position)
    workflow = _diff_campaign(
        method_spec,
        methods,
        scenario_repo,
        grounding,
        events,
        bus,
        repository=repository,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    assert axis_grounding.failed.is_set()
    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    # Both planned actions were paired with the actions already available
    # from the initial binding, despite the aborted grounding campaign.
    assert {event.action_id for event in diff_events} == {
        method_spec.method_id,
        delete_method.method_id,
    }
    assert all(event.mode == "factors" for event in diff_events)
    assert result.observations


def test_differential_budget_is_reserved_against_qdl_starvation(
    method_spec,
    scenario_position,
) -> None:
    """Ordinary paths cannot consume the whole budget before differential."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    scenario_repo = _diff_scenario_repo(scenario_position)
    workflow = _diff_campaign(
        method_spec,
        methods,
        scenario_repo,
        None,
        events,
        bus,
    )

    # Two one-check ordinary paths would exhaust all three checks on their
    # own; the protected reserve must leave room for one complete pair.
    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=3,
        )
    )

    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    assert diff_events[0].mode == "factors"
    assert len(result.observations) == 3


def test_differential_legs_count_against_campaign_budget(
    method_spec,
    scenario_position,
) -> None:
    """Both legs of a differential pair consume the shared live-call budget."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    events = EventLog()
    bus = _event_bus(events)
    bus.subscribe(DiffPairComputed, events.append)
    scenario_repo = _diff_scenario_repo(scenario_position)
    executed_checks = []

    def target(check):
        executed_checks.append(check)
        return _allowed_target(check)

    workflow = _diff_campaign(
        method_spec,
        methods,
        scenario_repo,
        None,
        events,
        bus,
        target=target,
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=2,
        )
    )

    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    assert diff_events[0].mode == "factors"
    assert len(executed_checks) == 2
    assert len(result.observations) == 2


def test_formal_grounding_runs_once_and_off_the_loop(
    method_spec,
    scenario_position,
) -> None:
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _accepted_norm_graph(method_spec),
        adapter_version="contract-projection-v1",
    )
    action_payload = {
        "kind": "atom",
        "value": f"action:{method_spec.method_id}",
        "literal_type": "string",
    }
    norm_payload = {
        "kind": "atom",
        "value": "norm:threat",
        "literal_type": "string",
    }
    model_client = FakeModelClient(
        ModelResponse(
            structured={
                "context": "proposal",
                "facts": [
                    {
                        "context": "proposal",
                        "predicate": "is",
                        "args": (
                            action_payload,
                            {
                                "kind": "atom",
                                "value": "Action",
                                "literal_type": "string",
                            },
                        ),
                    },
                    {
                        "context": "proposal",
                        "predicate": "is",
                        "args": (
                            norm_payload,
                            {
                                "kind": "atom",
                                "value": "Norm",
                                "literal_type": "string",
                            },
                        ),
                    },
                    {
                        "context": "proposal",
                        "predicate": "prevents",
                        "args": (
                            norm_payload,
                            {
                                "kind": "struct",
                                "name": "allowed",
                                "args": [action_payload],
                            },
                        ),
                    },
                ],
                "rules": (),
            },
        )
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )
    binder = ScenarioBinder(
        MethodRepo((method_spec,)),
        ScenarioRepo(scenario_position),
        repository,
        formal_threat_modeler=FormalThreatModeler(model_client),
        qdl_planner=IncrementalQdlPlanner(),
    )

    # Loop binds carry no model calls at all.
    loop_binding = binder.bind(request, formal_proposal=False)
    assert model_client.requests == []
    assert loop_binding.plan.invariants

    # The background grounding task proposes exactly once.
    formal = binder.formal_grounder
    assert formal is not None
    prepared = formal.prepare(method_spec.service)
    assert prepared is not None
    assert not formal.commit(method_spec.service, prepared).promoted
    assert len(model_client.requests) == 1

    # Later binds reuse the cached proposal without a second call.
    final_binding = binder.bind(request, formal_proposal=True)
    assert len(model_client.requests) == 1
    assert final_binding.graph is not None


def _denied_target(check):
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
        transport_status=HttpStatus(code=403),
    )


def _contract_with_roles(get_method, delete_method) -> QdlGraph:
    get_action = Atom(value=f"action:{get_method.method_id}")
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    get_norm = Atom(value="norm:get-denied")
    delete_norm = Atom(value="norm:delete-denied")
    get_field = input_field(get_action, Atom(value="secret_id"))
    delete_field = input_field(delete_action, Atom(value="secret_id"))
    resource = Atom(value="resource:secret-victim")
    owner = Atom(value="subject:owner")
    return QdlGraph(
        facts=(
            _fact("is", (get_action, Atom(value="Action"))),
            _fact("is", (delete_action, Atom(value="Action"))),
            _fact("is", (get_norm, Atom(value="Norm"))),
            _fact("is", (delete_norm, Atom(value="Norm"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (owner, Atom(value="Subject"))),
            _fact("owner", (resource, owner)),
            _fact("prevents", (get_norm, allowed(get_action))),
            _fact("prevents", (delete_norm, allowed(delete_action))),
            # Grounded roles keep coverage deficits out of this test: the
            # blocked step is the only deficit source.
            _fact("is", (get_field, Atom(value="Field"))),
            _fact("has", (get_field, Atom(value="sensitive"))),
            _fact("is", (delete_field, Atom(value="Field"))),
            _fact("has", (delete_field, Atom(value="sensitive"))),
        )
    )


def _missing_irreversibility_contract(
    create_method: MethodSpec,
    update_method: MethodSpec,
) -> QdlGraph:
    create_action = Atom(value=f"action:{create_method.method_id}")
    update_action = Atom(value=f"action:{update_method.method_id}")
    resource_type = Atom(value="lockbox.secret")
    resource = Atom(value="resource:lockbox.secret")
    create_effect = create(resource_type)
    changed_effect = changed(resource, Atom(value="total"))
    norm = Atom(value="norm:immutable-total")
    resource_ref = input_field(update_action, Atom(value="secret_id"))
    total = input_field(update_action, Atom(value="total"))
    created_resource = output_field(create_action, Atom(value="secret_id"))
    return QdlGraph(
        facts=(
            _fact("is", (create_action, Atom(value="Action"))),
            _fact("is", (update_action, Atom(value="Action"))),
            _fact("is", (resource_type, Atom(value="ResourceType"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (create_effect, Atom(value="Effect"))),
            _fact("is", (changed_effect, Atom(value="Effect"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("is", (resource_ref, Atom(value="InputField"))),
            _fact("is", (total, Atom(value="InputField"))),
            _fact("is", (created_resource, Atom(value="OutputField"))),
            _fact("has", (resource_ref, Atom(value="object_ref"))),
            _fact("has", (created_resource, Atom(value="object_ref"))),
            _fact("has", (total, Atom(value="privileged"))),
            _fact("refers_to", (resource_ref, resource_type), Context.CONTRACT),
            _fact("prevents", (norm, changed_effect)),
            # Bind the action independently of the missing mutation proof.
            # A changed norm alone cannot attribute an action by field name.
            _fact("is", (Atom(value="norm:unauthorized-update"), Atom(value="Norm"))),
            _fact(
                "prevents",
                (Atom(value="norm:unauthorized-update"), allowed(update_action)),
            ),
            _fact("targets", (update_action, resource), Context.CONTRACT),
            _fact("causes", (create_action, create_effect), Context.CONTRACT),
        )
    )


def _mutation_effect_graph(update_method: MethodSpec) -> QdlGraph:
    update_action = Atom(value=f"action:{update_method.method_id}")
    effect = changed(Atom(value="resource:lockbox.secret"), Atom(value="total"))
    return QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="resource:lockbox.secret"), Atom(value="Resource")),
                Context.PROPOSAL,
            ),
            _fact("is", (update_action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact("causes", (update_action, effect), Context.PROPOSAL),
        )
    )


def _contract_with_input_role(method: MethodSpec) -> QdlGraph:
    action = Atom(value=f"action:{method.method_id}")
    norm = Atom(value="norm:action-allowed")
    request_field = input_field(action, Atom(value="user_id"))
    resource = Atom(value="resource:user")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("targets", (action, resource)),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, allowed(action))),
            _fact("is", (request_field, Atom(value="InputField"))),
            _fact("has", (request_field, Atom(value="object_ref"))),
        )
    )


def _contract_with_input_roles(methods: tuple[MethodSpec, ...]) -> QdlGraph:
    facts: list[Fact] = []
    resource = Atom(value="resource:user")
    owned_resource = Atom(value="resource:secret-victim")
    owner = Atom(value="subject:owner")
    facts.extend((_fact("is", (resource, Atom(value="Resource"))),))
    facts.extend(
        (
            _fact("is", (owned_resource, Atom(value="Resource"))),
            _fact("is", (owner, Atom(value="Subject"))),
            _fact("owner", (owned_resource, owner)),
        )
    )
    for method in methods:
        action = Atom(value=f"action:{method.method_id}")
        norm = Atom(value=f"norm:{method.method_id}")
        request_field = input_field(action, Atom(value="secret_id"))
        facts.extend(
            (
                _fact("is", (action, Atom(value="Action"))),
                _fact("targets", (action, resource)),
                _fact("is", (norm, Atom(value="Norm"))),
                _fact("prevents", (norm, allowed(action))),
                _fact("is", (request_field, Atom(value="InputField"))),
                _fact("has", (request_field, Atom(value="object_ref"))),
            )
        )
    return QdlGraph(facts=tuple(facts))


def _roles_proposal(methods: tuple[MethodSpec, ...]) -> QdlGraph:
    facts: list[Fact] = []
    for method in methods:
        action = Atom(value=f"action:{method.method_id}")
        request_field = input_field(action, Atom(value="secret_id"))
        facts.extend(
            (
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact(
                    "is",
                    (request_field, Atom(value="InputField")),
                    Context.PROPOSAL,
                ),
                _fact(
                    "has", (request_field, Atom(value="object_ref")), Context.PROPOSAL
                ),
            )
        )
    return QdlGraph(facts=tuple(facts))


def _promoted_marker() -> QdlGraph:
    return QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="resource:reactive"), Atom(value="Resource")),
                Context.PROPOSAL,
            ),
        )
    )


def _response_semantics_model_payload(action: str, field_name: str) -> dict:
    return {
        "context": "proposal",
        "facts": [
            f'is("{action}", "Action")',
            'is("resource:user", "Resource")',
            f'is(field("resource:user", "{field_name}"), "Witness")',
            f'exposes("{action}", field("resource:user", "{field_name}"))',
            f'is(output_field("{action}", "{field_name}"), "Field")',
            f'has(output_field("{action}", "{field_name}"), "sensitive")',
            'is("norm:out-of-scope", "Norm")',
            f'prevents("norm:out-of-scope", allowed("{action}"))',
        ],
        "rules": [],
    }


class ResponseShapeModelClient:
    def __init__(self, action: str, field_name: str) -> None:
        self.payload = _response_semantics_model_payload(action, field_name)
        self.requests = []

    def complete(self, request, *, response_type=None) -> ModelResponse:
        self.requests.append(request)
        payload = (
            self.payload
            if request.task == "formal_grounding_response_semantics"
            else {"context": "proposal", "facts": [], "rules": []}
        )
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="fake-model",
        )


class ResponseSemanticsTimeoutModelClient:
    """Fail the first response-semantics call, then recover on retry."""

    def __init__(self) -> None:
        self.requests = []
        self._email_timed_out = False

    def complete(self, request, *, response_type=None) -> ModelResponse:
        self.requests.append(request)
        payload = {"context": "proposal", "facts": [], "rules": []}
        if request.task == "formal_grounding_response_semantics":
            leaves = request.context["evidence"]["response"]["leaves"]
            field = leaves[0]["path"]
            if field == "email" and not self._email_timed_out:
                self._email_timed_out = True
                raise TimeoutError("model timed out " + "x" * 500)
            method_id = request.context["evidence"]["request"]["method_id"]
            payload = _response_semantics_model_payload(
                f"action:{method_id}",
                field,
            )
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="fake-model",
        )


class CancelledResponseSemanticsModelClient:
    """Propagate an asyncio cancellation from one model request."""

    def __init__(self) -> None:
        self.requests = []

    def complete(self, request, *, response_type=None) -> ModelResponse:
        self.requests.append(request)
        if request.task == "formal_grounding_response_semantics":
            raise asyncio.CancelledError()
        payload = {"context": "proposal", "facts": [], "rules": []}
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="fake-model",
        )


class ReactiveAxisGrounding:
    """Fake grounding with an empty stream and a scripted reactive answer."""

    def __init__(self, reactive_graph):
        self.reactive_graph = reactive_graph
        self.reactive_calls = []
        self.stream_finished = threading.Event()

    def ground_stream(self, source, *, cache_source=None):
        self.stream_finished.set()
        return
        yield  # pragma: no cover - empty stream

    def ground_reactive(
        self,
        axis,
        action_ids,
        graph,
        *,
        observation=None,
        **kwargs,
    ):
        from cloud_dast.runtime.grounding.results import AxisResult

        self.reactive_calls.append((axis, tuple(action_ids), observation))
        return AxisResult(
            axis,
            self.reactive_graph,
            0,
            len(action_ids),
        )

    def ground_alternatives(self, graph, action, **kwargs):
        """MazeRunner branch fake: returns the same scripted graph."""

        from cloud_dast.runtime.grounding.results import AxisResult

        self.reactive_calls.append(
            ("alternatives", (action,), kwargs.get("observation"))
        )
        return AxisResult("alternatives", self.reactive_graph, 0, 1)


class ScriptedReactiveAxisGrounding:
    """Fake grounding returning one branch proposal per call."""

    def __init__(self, graphs: tuple[QdlGraph, ...]) -> None:
        self.graphs = list(graphs)
        self.reactive_calls: list[tuple[str, Observation | None, QdlGraph]] = []
        self.stream_finished = threading.Event()

    def ground_stream(self, source, *, cache_source=None):
        self.stream_finished.set()
        return
        yield  # pragma: no cover - empty stream

    def ground_reactive(
        self,
        axis,
        action_ids,
        graph,
        *,
        observation=None,
        **kwargs,
    ):
        return AxisResult(axis, None, 0, len(action_ids))

    def ground_alternatives(self, graph, action, **kwargs):
        if not self.graphs:
            raise AssertionError("no scripted reactive graph left")
        reactive_graph = self.graphs.pop(0)
        self.reactive_calls.append((action, kwargs.get("observation"), reactive_graph))
        return AxisResult("alternatives", reactive_graph, 0, 1)


class SchedulingAxisGrounding:
    """Record startup roles work and reactive signal-class dispatch order."""

    def __init__(self, roles_graph: QdlGraph, promoted_graph: QdlGraph) -> None:
        self.roles_graph = roles_graph
        self.promoted_graph = promoted_graph
        self.events: list[str] = []
        self.reactive_calls: list[tuple[str, tuple[str, ...]]] = []
        self.variance_calls: list[str] = []

    def ground_stream(self, source, *, cache_source=None):
        self.events.append("roles-start")
        yield "roles", "roles-in-flight", self.roles_graph
        self.events.append("roles-finish")

    def ground_reactive(self, axis, action_ids, graph, **kwargs):
        self.events.append(f"reactive:{axis}")
        self.reactive_calls.append((axis, tuple(action_ids)))
        action = Atom(value=f"action:{action_ids[0]}")
        request_field = input_field(action, Atom(value="secret_id"))
        promoted_graph = QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact(
                    "is",
                    (request_field, Atom(value="Field")),
                    Context.PROPOSAL,
                ),
                _fact(
                    "has",
                    (request_field, Atom(value="object_ref")),
                    Context.PROPOSAL,
                ),
            )
        )
        return AxisResult(axis, promoted_graph, 0, len(action_ids))

    def ground_variance(self, graph, action_id, **kwargs):
        self.events.append(f"variance:{action_id}")
        self.variance_calls.append(action_id)
        return AxisResult("variance", self.promoted_graph, 0, 1)

    def ground_alternatives(self, graph, action_ids, **kwargs):
        self.events.append("reactive:alternatives")
        self.reactive_calls.append(("alternatives", tuple(action_ids)))
        return AxisResult("alternatives", self.promoted_graph, 0, len(action_ids))


class OwnerScenarioRepo:
    """Return the attacker position, except for differential owner controls."""

    def __init__(self, attacker, owner) -> None:
        self.attacker = attacker
        self.owner = owner
        self.identity_classes: list[str | None] = []

    def get_scenario(
        self,
        principal_id,
        resource_id,
        method=None,
        identity_class=None,
        **kwargs,
    ):
        self.identity_classes.append(identity_class)
        return self.owner if identity_class == "owner" else self.attacker


def _observation_gate_workflow() -> LiveWorkflow:
    grounding = make_grounding(FormalRepository())
    return assemble_workflow(
        None,
        Mock(spec=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            formal_repository=None,
            grounding_runner=ThreadedGroundingRunner(),
            batch_timeout=1,
            reactive_max_workers=2,
        ),
    )


def _evidence_gate_deficit(
    axis: str,
    context: tuple[tuple[str, str], ...],
) -> Deficit:
    """Build one algebraic deficit for the S31 evidence-gate tests."""

    action = Atom(value="svc.Get")
    if axis == "response_semantics":
        return Deficit(
            subgoal=QdlSubgoal(
                "exposes",
                (
                    action,
                    resource_field(
                        Variable(name="AnyResource"),
                        Variable(name="AnyField"),
                    ),
                ),
            ),
            predicate_class="exposes",
            axis="response_semantics",
            action="svc.Get",
            context=context,
        )
    return Deficit(
        subgoal=QdlSubgoal(
            "prevents",
            (
                Variable(name="AnyNorm"),
                differs(action, Variable(name="AnyDimension")),
            ),
        ),
        predicate_class="prevents",
        axis="variance",
        action="svc.Get",
        context=context,
    )


def _gate_observation(check_id: str) -> Observation:
    return Observation(
        check_id=check_id,
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )


@pytest.mark.parametrize("axis", ["response_semantics", "variance"])
def test_observation_required_deficits_without_observation_become_evidence_deficits(
    axis: str,
) -> None:
    """S31-v2: expected-evidence deficits never consult without evidence."""

    workflow = _observation_gate_workflow()
    context = (
        (("fields", "email"), ("observation_id", "missing-response"))
        if axis == "response_semantics"
        else (
            ("diff", "outcome"),
            ("control", "missing-control"),
            ("treatment", "missing-treatment"),
        )
    )
    deficit = _evidence_gate_deficit(axis, context)
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    work_item = deficits.pop_wave()[0]

    gated, observation, check = (
        workflow._replanning._consultation._committer.plan_observation(
            LiveRequest(
                service="svc", principal_id="principal", resource_id="resource"
            ),
            work_item,
            deficits,
            CampaignAccumulator.empty(),
        )
    )

    assert (gated, observation, check) == (True, None, None)
    assert len(workflow.evidence_deficits) == 1
    record = workflow.evidence_deficits[0]
    assert record.source_kind == deficit.predicate_class
    assert dict(record.deficit.context)["evidence_kind"] == "evidence_deficit"
    assert record.deficit.axis is None
    assert record.deficit.subgoal == deficit.subgoal
    assert deficits.pop_wave() == ()


@pytest.mark.parametrize(
    "axis",
    [
        "response_semantics",
        "variance",
    ],
)
def test_observation_required_deficits_with_observation_are_not_gated(
    axis: str,
) -> None:
    """S31-v2: live evidence keeps response semantics and variance eligible."""

    workflow = _observation_gate_workflow()
    accumulator = CampaignAccumulator.empty()
    if axis == "response_semantics":
        observation = _gate_observation("check-response")
        accumulator.observations.append(observation)
        context = (
            ("fields", "email"),
            ("observation_id", observation.observation_id),
        )
    else:
        control = _gate_observation("check-control")
        treatment = _gate_observation("check-treatment")
        accumulator.observations.extend((control, treatment))
        observation = treatment
        context = (
            ("diff", "outcome"),
            ("control", control.observation_id),
            ("treatment", treatment.observation_id),
        )
    deficit = _evidence_gate_deficit(axis, context)
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    work_item = deficits.pop_wave()[0]

    gated, resolved_observation, check = (
        workflow._replanning._consultation._committer.plan_observation(
            LiveRequest(
                service="svc", principal_id="principal", resource_id="resource"
            ),
            work_item,
            deficits,
            accumulator,
        )
    )

    assert gated is False
    assert resolved_observation is observation
    assert check is None
    assert workflow.evidence_deficits == ()


def _dataflows_gate_deficit(context: tuple[tuple[str, str], ...]) -> Deficit:
    """Build one reaches deficit routed to the dataflows consultation."""

    action = Atom(value="action:svc.Get")
    return Deficit(
        subgoal=QdlSubgoal(
            "reaches",
            (input_field(action, Variable(name="AnyField")), Variable(name="AnySink")),
        ),
        predicate_class="reaches",
        axis="dataflows",
        action="svc.Get",
        context=context,
    )


def _dataflows_sink_graph() -> QdlGraph:
    """A contract graph that already declares one typed sink reach."""

    action = Atom(value="action:svc.Get")
    field = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:svc.Get:query:interpreter")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="InputField"))),
            _fact("is", (sink, Atom(value="interpreter"))),
            _fact("reaches", (field, sink)),
        )
    )


def _dataflows_gate_workflow(repository=None) -> LiveWorkflow:
    grounding = make_grounding(repository or FormalRepository())
    return assemble_workflow(
        None,
        Mock(spec=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            formal_repository=repository,
            grounding_runner=ThreadedGroundingRunner(),
            batch_timeout=1,
            reactive_max_workers=2,
        ),
    )


def test_dataflows_deficit_without_evidence_parks_as_evidence_deficit() -> None:
    """A dataflows consultation never runs without observation or sink facts."""

    workflow = _dataflows_gate_workflow()
    deficit = _dataflows_gate_deficit((("coverage", "executable_path"),))
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    work_item = deficits.pop_wave()[0]

    gated, observation, check = (
        workflow._replanning._consultation._committer.plan_observation(
            LiveRequest(
                service="svc", principal_id="principal", resource_id="resource"
            ),
            work_item,
            deficits,
            CampaignAccumulator.empty(),
        )
    )

    assert (gated, observation, check) == (True, None, None)
    assert len(workflow.evidence_deficits) == 1
    record = workflow.evidence_deficits[0]
    assert record.source_kind == "reaches"
    assert dict(record.deficit.context)["evidence_kind"] == "evidence_deficit"
    assert record.deficit.axis is None
    assert record.deficit.subgoal == deficit.subgoal
    assert deficits.pop_wave() == ()


def test_dataflows_deficit_with_observation_dispatches() -> None:
    """A live observation keeps the dataflows consultation eligible."""

    workflow = _dataflows_gate_workflow()
    dispatched: list[tuple[str, str, Observation | None]] = []

    def record_call(request, item, **kwargs):
        dispatched.append(
            (item.work_item.axis, item.work_item.action, item.observation)
        )
        return None

    workflow._replanning._consultation._invoker.invoke = record_call  # type: ignore[method-assign]
    accumulator = CampaignAccumulator.empty()
    observation = _gate_observation("check-dataflows")
    accumulator.observations.append(observation)
    deficit = _dataflows_gate_deficit(
        (
            ("coverage", "executable_path"),
            ("observation_id", observation.observation_id),
        )
    )
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    work_item = deficits.pop_wave()[0]

    execution = workflow._replanning._consultation._run_parallel_work_items(
        LiveRequest(service="svc", principal_id="principal", resource_id="resource"),
        (work_item,),
        deficits,
        accumulator,
    )

    assert dispatched == [("dataflows", "svc.Get", observation)]
    assert execution.promoted == 0
    assert workflow.evidence_deficits == ()


def test_dataflows_deficit_with_declared_sink_dispatches() -> None:
    """A declared sink/reaches fact is graph evidence for dataflows."""

    repository = FormalRepository()
    _save_graph(
        repository,
        "contract:svc",
        _dataflows_sink_graph(),
        adapter_version="contract-projection-v1",
    )
    workflow = _dataflows_gate_workflow(repository)
    dispatched: list[tuple[str, str, Observation | None]] = []

    def record_call(request, item, **kwargs):
        dispatched.append(
            (item.work_item.axis, item.work_item.action, item.observation)
        )
        return None

    workflow._replanning._consultation._invoker.invoke = record_call  # type: ignore[method-assign]
    deficit = _dataflows_gate_deficit((("coverage", "executable_path"),))
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    work_item = deficits.pop_wave()[0]

    execution = workflow._replanning._consultation._run_parallel_work_items(
        LiveRequest(service="svc", principal_id="principal", resource_id="resource"),
        (work_item,),
        deficits,
        CampaignAccumulator.empty(),
    )

    assert dispatched == [("dataflows", "svc.Get", None)]
    assert execution.promoted == 0
    assert workflow.evidence_deficits == ()


def test_missing_irreversibility_without_observation_still_consults(
    method_spec,
    scenario_position,
) -> None:
    """S31 border fix: blocked deficits consult without observation.

    A blocked path has no observation by definition; the evidence-first
    gate must not apply to blocked_step/missing_irreversibility deficits
    (chicken-and-egg: observation only appears AFTER unblocking).
    """

    create_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Create", "name": "Create"}
    )
    update_method = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.Update",
            "name": "Update",
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="total", type="string"),
            ),
        }
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _missing_irreversibility_contract(create_method, update_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated, DownstreamDecision):
        bus.subscribe(event_type, events.append)
    executed_checks = []

    def target(check):
        executed_checks.append(check)
        return _allowed_target(check)

    service = _service((create_method, update_method), target, bus)
    axis_grounding = ReactiveAxisGrounding(_mutation_effect_graph(update_method))
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((create_method, update_method)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=1, event_bus=bus, grounding_runner=ThreadedGroundingRunner()
        ),
    )

    workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    # S31 border fix (2026-10-24): blocked-path deficits consult from
    # contract/graph context — their observation CANNOT exist yet (the path
    # has not executed), so gating them is a chicken-and-egg deadlock.
    # The model IS called and the alternatives consultation proceeds.
    assert len(axis_grounding.reactive_calls) >= 1
    assert workflow.evidence_deficits == ()


def test_evidence_deficit_carries_deterministic_sibling_actions(
    method_spec,
    scenario_position,
) -> None:
    """S31 border fix: sibling-slice recording only fires for gated kinds."""

    create_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Create", "name": "Create"}
    )
    update_method = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.Update",
            "name": "Update",
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="total", type="string"),
            ),
        }
    )
    create_action = Atom(value=f"action:{create_method.method_id}")
    shared_resource = Atom(value="resource:lockbox.secret")
    contract = QdlGraph(
        facts=(
            *_missing_irreversibility_contract(create_method, update_method).facts,
            _fact("targets", (create_action, shared_resource)),
        )
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        contract,
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)

    def target(check):
        return _allowed_target(check)

    service = _service((create_method, update_method), target, bus)
    axis_grounding = ReactiveAxisGrounding(_mutation_effect_graph(update_method))
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((create_method, update_method)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=1,
            formal_repository=repository,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )

    workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    # S31 border fix: the gate is disabled for blocked deficits, so the
    # consultation runs and no evidence_deficit is recorded.  The sibling
    # slice itself is covered by test_slices.py (deterministic, QDL-only).
    assert len(axis_grounding.reactive_calls) >= 1
    assert workflow.evidence_deficits == ()


def test_missing_irreversibility_with_observation_still_consults_model(
    method_spec,
    scenario_position,
) -> None:
    """S31 gate: with live evidence the alternatives consultation still runs."""

    create_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Create", "name": "Create"}
    )
    update_method = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.Update",
            "name": "Update",
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="total", type="string"),
            ),
        }
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _missing_irreversibility_contract(create_method, update_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    service = _service((create_method, update_method), _allowed_target, bus)
    axis_grounding = ReactiveAxisGrounding(_mutation_effect_graph(update_method))
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((create_method, update_method)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=1, grounding_runner=ThreadedGroundingRunner()
        ),
    )

    observation = Observation(
        check_id="check-update",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="updated",
    )
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(observation)
    accumulator.provenance[(observation.observation_id, "norm:update")] = (
        ObservationProvenance("check-update", "path-1", "step-1", "norm:update")
    )
    deficit = Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (Atom(value=update_method.method_id), Variable(name="AnyEffect")),
        ),
        predicate_class="causes",
        axis="alternatives",
        action=update_method.method_id,
        context=(
            ("path_id", "path-1"),
            ("step_id", "step-1"),
            ("reason", "missing_irreversibility_fact"),
            ("effect", ""),
        ),
    )
    deficits = DeficitQueue(max_tasks=1)
    deficits.add((deficit,))
    wave = deficits.pop_wave()
    assert len(wave) == 1
    work_item = wave[0]

    execution = workflow._replanning._consultation._run_parallel_work_items(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        (work_item,),
        deficits,
        accumulator,
    )

    assert execution.promoted == 1
    assert len(axis_grounding.reactive_calls) == 1
    axis, actions, observed = axis_grounding.reactive_calls[0]
    assert axis == "alternatives"
    assert actions == (update_method.method_id,)
    assert observed is observation
    assert workflow.evidence_deficits == ()
    assert any(
        item["source_id"].startswith(
            f"accepted-batch:{method_spec.service}:reactive:alternatives:"
        )
        for item in repository.saved
    )


def test_reactive_grounding_closes_deficit_and_executes_new_path(
    method_spec,
    scenario_position,
) -> None:
    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    reactive_norm = Atom(value="norm:reactive-extra")
    reactive_graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (delete_action, Atom(value="Action")),
                Context.PROPOSAL,
            ),
            _fact("is", (reactive_norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact(
                "prevents",
                (reactive_norm, denied(delete_action)),
                Context.PROPOSAL,
            ),
        )
    )

    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _contract_with_roles(method_spec, delete_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    executed_checks = []

    def target(check):
        executed_checks.append(check)
        if check.method_id == delete_method.method_id:
            return _denied_target(check)
        return _allowed_target(check)

    service = _service(methods, target, bus)
    axis_grounding = ReactiveAxisGrounding(reactive_graph)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=2, grounding_runner=ThreadedGroundingRunner()
        ),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    # Each blocked execution carries a distinct observation, so S33R admits a
    # new evidence revision while S26R still counts both calls in one class.
    assert len(axis_grounding.reactive_calls) == 2
    axis, action_ids, observation = axis_grounding.reactive_calls[0]
    assert axis == "alternatives"
    assert action_ids == (delete_method.method_id,)
    assert observation is not None
    assert observation.observed_outcome is AccessOutcome.DENIED

    # The reactive batch was promoted append-only and created new work.
    assert any(
        item["source_id"].startswith(f"accepted-batch:{method_spec.service}:reactive:")
        for item in repository.saved
    )
    path_ids = {
        event.path_id for event in events.events if isinstance(event, QdlPathEvaluated)
    }
    bases = {path_id.split(":pv")[0] for path_id in path_ids}
    # get norm + delete norm + reactive norm for delete = three paths.
    assert len(bases) == 3
    assert len(executed_checks) == 3
    assert result.observations
    assert result.findings


def test_irrelevant_promotion_does_not_buy_a_retry(
    method_spec,
    scenario_position,
) -> None:
    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    delete_action = Atom(value=f"action:{delete_method.method_id}")
    changed_resource = Atom(value="resource:order")
    changed_field = Atom(value="state")
    changed_effect = changed(changed_resource, changed_field)

    irrelevant = QdlGraph(
        facts=(
            _fact("is", (delete_action, Atom(value="Action")), Context.PROPOSAL),
            _fact(
                "is", (Atom(value="norm:changed"), Atom(value="Norm")), Context.PROPOSAL
            ),
            _fact(
                "is", (changed_resource, Atom(value="ResourceType")), Context.PROPOSAL
            ),
            _fact("is", (changed_effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact(
                "prevents",
                (Atom(value="norm:changed"), changed_effect),
                Context.PROPOSAL,
            ),
            _fact("causes", (delete_action, changed_effect), Context.PROPOSAL),
        )
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _contract_with_roles(method_spec, delete_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    def target(check):
        if check.method_id == delete_method.method_id:
            return _denied_target(check)
        return _allowed_target(check)

    axis_grounding = ScriptedReactiveAxisGrounding((irrelevant,))
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service(methods, target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=3, grounding_runner=ThreadedGroundingRunner()
        ),
    )

    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    branch_saves = [
        item
        for item in repository.saved
        if item["source_id"].startswith(
            f"accepted-batch:{method_spec.service}:reactive:alternatives:"
        )
    ]
    assert len(branch_saves) == 1
    assert len(axis_grounding.reactive_calls) == 1
    assert axis_grounding.reactive_calls[0][2] is irrelevant
    assert result.observations


def test_response_shape_grounding_promotes_and_binds_response_norm(
    method_spec,
    scenario_position,
) -> None:
    get_user = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.GetUser", "name": "GetUser"}
    )
    action = f"action:{get_user.method_id}"
    attacker_position = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "principals": (
                        PrincipalRef(principal_id="attacker", principal_type="user"),
                    )
                }
            )
        }
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{get_user.service}",
        _contract_with_input_role(get_user),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    def target(check):
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="user returned",
            transport_status=HttpStatus(code=200),
            response_tree=(("email", "response-value"),),
        )

    model_client = ResponseShapeModelClient(action, "email")
    options = GrounderOptions(
        consultation=ConsultationDispatcher(model_client),
        grounding_dispatcher=Dispatcher(model_client),
        batch_size=1,
        max_workers=1,
    )
    startup = Bootstrap(options=options)
    reactive = Followup(options=options)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=startup,
        reactive=reactive,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    binder = ScenarioBinder(
        MethodRepo((get_user,)),
        ScenarioRepo(attacker_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    workflow = _workflow(
        binder,
        assemble_runner(
            _service((get_user,), target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=2, grounding_runner=ThreadedGroundingRunner()
        ),
    )
    request = LiveRequest(
        service=get_user.service,
        principal_id="attacker",
        resource_id="secret-victim",
    )

    result = workflow.execute(request)

    reactive_requests = [
        request
        for request in model_client.requests
        if request.task == "formal_grounding_response_semantics"
    ]
    assert len(reactive_requests) == 1
    evidence_leaf = reactive_requests[0].context["evidence"]["response"]["leaves"][0]
    assert evidence_leaf["path"] == "email"
    assert evidence_leaf["value"]["evidence_encoding"] == "redacted"

    promoted = next(
        item
        for item in repository.saved
        if item["source_id"].startswith(
            f"accepted-batch:{get_user.service}:reactive:response_semantics:"
        )
    )["graph"]
    assert promoted.facts
    assert all(fact.context is Context.ACCEPTED for fact in promoted.facts)
    assert not any(fact.predicate.name == "prevents" for fact in promoted.facts)
    assert any(fact.predicate.name == "exposes" for fact in promoted.facts)
    assert any(
        fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and fact.args[1].value == "sensitive"
        for fact in promoted.facts
    )

    final_binding = binder.bind(request, formal_proposal=False)
    response_invariants = [
        invariant
        for invariant in final_binding.plan.invariants
        if invariant.primitive == "response_field"
    ]
    assert response_invariants
    response_paths = [
        path
        for path in final_binding.execution.paths
        if any(
            canonical_json(step.invariant.norm_fact)
            == canonical_json(response_invariants[0].fact)
            for step in path.steps
        )
    ]
    assert response_paths
    assert len(result.observations) == 2
    assert any(
        finding.invariant_id == response_paths[0].steps[0].invariant.invariant_id
        for finding in result.findings
    )


def test_response_semantics_timeout_is_isolated_without_retry(
    method_spec,
    scenario_position,
    caplog,
) -> None:
    """One timed-out consultation is terminal until new evidence arrives."""

    email_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.GetEmail", "name": "GetEmail"}
    )
    payment_method = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.GetPaymentToken",
            "name": "GetPaymentToken",
        }
    )
    methods = (email_method, payment_method)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{email_method.service}",
        _contract_with_input_roles(methods),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    def target(check):
        field = (
            ("email", "response-value")
            if check.method_id == email_method.method_id
            else ("payment_token", "tok_123")
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="user returned",
            transport_status=HttpStatus(code=200),
            response_tree=(field,),
        )

    model_client = ResponseSemanticsTimeoutModelClient()
    options = GrounderOptions(
        consultation=ConsultationDispatcher(model_client),
        grounding_dispatcher=Dispatcher(model_client),
        batch_size=1,
        max_workers=1,
    )
    startup = Bootstrap(options=options)
    reactive = Followup(options=options)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=startup,
        reactive=reactive,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service(methods, target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=4, grounding_runner=ThreadedGroundingRunner()
        ),
    )
    request = LiveRequest(
        service=email_method.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )

    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime.campaign"):
        result = workflow.execute(request)

    assert result.observations
    response_requests = [
        request
        for request in model_client.requests
        if request.task == "formal_grounding_response_semantics"
    ]
    requested_fields = [
        request.context["evidence"]["response"]["leaves"][0]["path"]
        for request in response_requests
    ]
    assert sorted(requested_fields) == ["email", "payment_token"]

    warnings = [
        message
        for message in caplog.messages
        if "reactive_grounding_exception" in message
    ]
    assert len(warnings) == 1
    assert "error_type=TimeoutError" in warnings[0]
    assert "x" * 241 not in warnings[0]

    promoted_fields = []
    for item in repository.saved:
        if not item["source_id"].startswith(
            f"accepted-batch:{email_method.service}:reactive:response_semantics:"
        ):
            continue
        fields = {
            fact.args[1].args[1].value
            for fact in item["graph"].facts
            if fact.predicate.name == "exposes"
        }
        if fields:
            promoted_fields.append(next(iter(fields)))
    assert promoted_fields == ["payment_token"]


def test_reactive_grounding_preserves_cancellation_signal(
    method_spec,
    scenario_position,
    caplog,
) -> None:
    """Cancellation is a control signal, not a per-deficit grounding failure."""

    get_user = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.GetUser", "name": "GetUser"}
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{get_user.service}",
        _contract_with_input_role(get_user),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    def target(check):
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="user returned",
            transport_status=HttpStatus(code=200),
            response_tree=(("email", "response-value"),),
        )

    options = GrounderOptions(
        consultation=ConsultationDispatcher(
            grounding_client := CancelledResponseSemanticsModelClient()
        ),
        grounding_dispatcher=Dispatcher(grounding_client),
        batch_size=1,
        max_workers=1,
    )
    startup = Bootstrap(options=options)
    reactive = Followup(options=options)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=startup,
        reactive=reactive,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((get_user,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service((get_user,), target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=2, grounding_runner=ThreadedGroundingRunner()
        ),
    )

    with caplog.at_level(logging.WARNING, logger="cloud_dast.runtime.campaign"):
        with pytest.raises(asyncio.CancelledError):
            workflow.execute(
                LiveRequest(
                    service=get_user.service,
                    principal_id="principal-attacker",
                    resource_id="secret-victim",
                )
            )

    assert not any(
        "reactive_grounding_exception" in message for message in caplog.messages
    )


def test_classification_deficit_context_reaches_generic_reactive_grounding() -> None:
    """Classification obligations are forwarded without workflow reformatting."""

    class RecordingGrounding:
        def __init__(self) -> None:
            self.calls = []

        def prepare_reactive(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return None

    grounding = RecordingGrounding()
    invoker = Invoker(grounding, None, None)
    deficit = Deficit(
        subgoal=QdlSubgoal(
            "has",
            (Atom(value="field:svc.Get:email"), Atom(value="classification")),
        ),
        predicate_class="has",
        axis="classification",
        action="svc.Get",
        context=(
            ("classification_term", "field:svc.Get:email"),
            ("allowed_values", "public,sensitive"),
            ("observation_id", "observation-1"),
        ),
    )

    invoker._prepare(
        LiveRequest(service="svc", principal_id="principal", resource_id="resource"),
        deficit,
        source=QdlGraph(),
        evidence=None,
        observation=None,
        check=None,
    )

    assert len(grounding.calls) == 1
    args, kwargs = grounding.calls[0]
    assert args == (QdlGraph(), "classification", ("svc.Get",))
    assert kwargs["context"] == consultation_context(deficit)


def test_fair_share_balances_deficit_classes_after_roles_work(
    method_spec,
    scenario_position,
    caplog,
) -> None:
    """Measured variance must not consume the response-semantics LLM reserve."""

    methods = tuple(
        method_spec.model_copy(
            update={
                "method_id": f"{method_spec.service}.Action{index}",
                "name": f"Action{index}",
            }
        )
        for index in range(9)
    )
    owner_position = scenario_position.model_copy(
        update={
            "scenario_id": f"{scenario_position.scenario_id}:owner",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _contract_with_input_roles(methods),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    def target(check):
        if check.scenario_id != owner_position.scenario_id:
            return Observation(
                check_id=check.check_id,
                scenario_id=check.scenario_id,
                observed_outcome=AccessOutcome.DENIED,
                response_summary="denied",
                transport_status=HttpStatus(code=403),
            )
        response_tree = (
            (("email", "response-value"),)
            if check.method_id != methods[-1].method_id
            else None
        )
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="owner read",
            transport_status=HttpStatus(code=200),
            response_tree=response_tree,
        )

    axis_grounding = SchedulingAxisGrounding(
        _roles_proposal(methods),
        _promoted_marker(),
    )
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=axis_grounding,
        reactive=axis_grounding,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    scenario_repository = OwnerScenarioRepo(scenario_position, owner_position)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            scenario_repository,
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service(methods, target, bus),
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            reactive_budget=8,
            diff_mode=True,
            diff_modes=frozenset({"factors"}),
            scenario_repository=scenario_repository,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )

    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime"):
        result = workflow.execute(
            LiveRequest(
                service=method_spec.service,
                principal_id="principal-attacker",
                resource_id="secret-victim",
            )
        )

    assert result.observations
    assert axis_grounding.events[:2] == ["roles-start", "roles-finish"]
    assert any(
        item["source_id"].startswith(f"accepted-batch:{method_spec.service}:roles:")
        for item in repository.saved
    )
    assert any(
        "class=causes" in message
        for message in caplog.messages
        if "deficit_detected" in message
    )

    # Fair-share (S26R): the numeric budget is split by max-min service over
    # QDL deficit classes, not by axis-specific reserves.  Variance, response
    # semantics, and fixture typing all receive service before the budget ends.
    assert len(axis_grounding.variance_calls) == 2
    response_calls = [
        call
        for call in axis_grounding.reactive_calls
        if call[0] == "response_semantics"
    ]
    assert len(response_calls) == 2
    alternatives_calls = [
        call for call in axis_grounding.reactive_calls if call[0] == "alternatives"
    ]
    fixture_calls = [
        call for call in axis_grounding.reactive_calls if call[0] == "fixture"
    ]
    assert len(alternatives_calls) == 2
    assert len(fixture_calls) == 2
    assert all(
        axis in {"response_semantics", "alternatives", "fixture"}
        for axis, _ in axis_grounding.reactive_calls
    )
    assert (
        len(
            [
                item
                for item in repository.saved
                if item["source_id"].startswith(
                    f"accepted-batch:{method_spec.service}:reactive:response_semantics:"
                )
            ]
        )
        == 2
    )


def test_skip_mode_terminates_with_pending_deficits(
    method_spec,
    scenario_position,
) -> None:
    """Without reactive grounding the loop must not wait for deficits."""

    delete_method = method_spec.model_copy(
        update={"method_id": f"{method_spec.service}.Delete", "name": "Delete"}
    )
    methods = (method_spec, delete_method)
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _contract_with_roles(method_spec, delete_method),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)

    executed_checks = []

    def target(check):
        executed_checks.append(check)
        if check.method_id == delete_method.method_id:
            return _denied_target(check)
        return _allowed_target(check)

    service = _service(methods, target, bus)
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=None,
        reactive=None,
        skip_llm_grounding=True,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    assert grounding.batches.reactive_capable is False
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo(methods),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
    )

    # A blocked delete path produces a dispatchable deficit; with no
    # reactive grounding the fix-point must ignore it and finish.
    result = workflow.execute(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        )
    )

    assert result.observations
    assert any(
        isinstance(event, QdlPathEvaluated) and event.outcome == "blocked"
        for event in events.events
    )


def test_rerun_into_same_event_log_is_visible_replay(
    method_spec,
    scenario_position,
) -> None:
    """A fully-deduped rerun must publish replay events, not silence."""

    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _accepted_norm_graph(method_spec),
        adapter_version="contract-projection-v1",
    )
    events = EventLog()
    bus = _event_bus(events)
    for event_type in (QdlStepEvaluated, QdlPathEvaluated):
        bus.subscribe(event_type, events.append)
    service = _service((method_spec,), _allowed_target, bus)
    workflow = _workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            service,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        ),
        FindingEvaluator(bus, events),
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="principal-attacker",
        resource_id="secret-victim",
    )

    first = workflow.execute(request)
    assert first.observations

    second = workflow.execute(request)

    # No live work is repeated: the campaign is idempotent.
    assert second.observations == ()
    # But the replay is visible: every path publishes a replay outcome
    # instead of silently rendering as "waiting" in the progress UI.
    replay_events = [
        event
        for event in events.events
        if isinstance(event, QdlPathEvaluated)
        and "cross-campaign replay" in event.reason
    ]
    assert replay_events
    assert all(event.outcome == "completed" for event in replay_events)


@pytest.mark.parametrize("context", tuple(Context))
@pytest.mark.parametrize("query_action", ["svc.Get", "action:svc.Get"])
@pytest.mark.parametrize(
    ("kind", "eligible"),
    [
        ("input_reach", True),
        ("action_reach", True),
        ("output_reach", False),
        ("sink_prefix", True),
        ("unsupported_sink", False),
        ("norm_reached", True),
        ("norm_external", True),
        ("untyped_norm", False),
        ("foreign_norm", False),
        ("unsupported_reach", True),
    ],
)
def test_dataflow_admission_requires_action_bound_executable_context(
    context, query_action, kind, eligible
) -> None:
    from cloud_dast.qdl.graph import reached

    action = Atom(value="action:svc.Get")
    foreign = Atom(value="action:svc.Other")
    field = input_field(action, Atom(value="query"))
    output = output_field(action, Atom(value="result"))
    sink = Atom(
        value=(
            "sink:svc.Get:query:interpreter"
            if kind in {"sink_prefix", "unsupported_sink"}
            else "sink:unrelated"
        )
    )
    norm = Atom(value="norm:gate")
    facts = [
        _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
        _fact("is", (foreign, Atom(value="Action")), Context.CONTRACT),
        _fact("is", (field, Atom(value="InputField")), Context.CONTRACT),
        _fact("is", (output, Atom(value="Field")), Context.CONTRACT),
        _fact("is", (sink, Atom(value="Sink")), Context.CONTRACT),
        _fact("is", (norm, Atom(value="Norm")), Context.CONTRACT),
        _fact(
            "is",
            (
                sink,
                Atom(
                    value=(
                        "sql"
                        if kind
                        in {"unsupported_sink", "untyped_norm", "unsupported_reach"}
                        else "interpreter"
                    )
                ),
            ),
            context,
        ),
    ]
    if kind in {"input_reach", "action_reach", "output_reach", "unsupported_reach"}:
        source = (
            action
            if kind == "action_reach"
            else output
            if kind == "output_reach"
            else field
        )
        facts.append(_fact("reaches", (source, sink), context))
    elif kind in {"norm_reached", "norm_external", "untyped_norm", "foreign_norm"}:
        effect = (
            external_call(action, sink)
            if kind == "norm_external"
            else reached(foreign if kind == "foreign_norm" else action, sink)
        )
        facts.append(_fact("prevents", (norm, effect), context))
    repository = FormalRepository()
    _save_graph(
        repository, "contract:svc", QdlGraph(facts=tuple(facts)), adapter_version="test"
    )
    gate = Gate(formal_repository=repository, event_bus=None)
    assert gate.allows_dataflows(
        LiveRequest(service="svc", principal_id="actor", resource_id="resource"),
        query_action,
    ) is (eligible and context in {Context.CONTRACT, Context.ACCEPTED})
