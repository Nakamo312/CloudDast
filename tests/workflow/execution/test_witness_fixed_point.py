"""A missing carrier must become graph work before spending probe calls."""

from __future__ import annotations

import json
from dataclasses import replace

from cloud_dast.api import LiveRequest
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    FieldSpec,
    Observation,
    ResponseData,
    VerdictStatus,
)
from cloud_dast.model.events import QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.ports import ModelResponse
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
    reached,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign import (
    LiveWorkflow,
)
from cloud_dast.runtime.deficits import (
    grounding_result_closes_deficit,
    witness_deficits,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.runtime.grounding.axis import Grounder
from cloud_dast.runtime.planning import IncrementalQdlPlanner, derivable
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.finding_evaluator import FindingEvaluator
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
    TemplateGenerator,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self):
        self.events = []
        self.cursors = {}

    def append(self, event):
        self.events.append(event)

    def publish(self, event):
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id):
        cursor = self.cursors.get(consumer_id, 0)
        self.cursors[consumer_id] = len(self.events)
        return tuple(self.events[cursor:])


class MethodRepo:
    def __init__(self, method):
        self.method = method

    def list_methods(self, service):
        return (self.method,)


class ScenarioRepo:
    def __init__(self, scenario):
        self.scenario = scenario

    def get_scenario(self, *args, **kwargs):
        return self.scenario


def fact(predicate, *args, context=Context.CONTRACT):
    return Fact(context=context, predicate=Predicate.from_name(predicate), args=args)


def source_graph(action):
    field = input_field(action, Atom(value="payload"))
    sink = Atom(value="sink:interpreter")
    norm = Atom(value="norm:forbidden-sink")
    return QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", field, Atom(value="InputField")),
            fact("part", field, action),
            fact("is", sink, Atom(value="Sink")),
            fact("is", sink, Atom(value="interpreter")),
            fact("is", norm, Atom(value="Norm"), context=Context.ACCEPTED),
            fact("prevents", norm, reached(action, sink), context=Context.ACCEPTED),
        )
    )


class CarrierModel:
    """Only the external model boundary is replaced in the closure test."""

    def __init__(self, action, *, supported=True):
        self.action = action
        self.supported = supported
        self.requests = []

    def complete(self, request, *, response_type=None):
        self.requests.append(request)
        graph = QdlGraph()
        if self.supported and request.task == "formal_grounding_dataflows":
            field = input_field(self.action, Atom(value="payload"))
            graph = QdlGraph(
                facts=(
                    fact(
                        "is",
                        self.action,
                        Atom(value="Action"),
                        context=Context.PROPOSAL,
                    ),
                    fact(
                        "is", field, Atom(value="InputField"), context=Context.PROPOSAL
                    ),
                    fact(
                        "is",
                        Atom(value="sink:interpreter"),
                        Atom(value="Sink"),
                        context=Context.PROPOSAL,
                    ),
                    fact(
                        "is",
                        Atom(value="sink:interpreter"),
                        Atom(value="interpreter"),
                        context=Context.PROPOSAL,
                    ),
                    fact(
                        "reaches",
                        field,
                        Atom(value="sink:interpreter"),
                        context=Context.PROPOSAL,
                    ),
                )
            )
        # FormalModelWireOutput uses predicate names, rather than schemas.
        payload = {
            "context": "proposal",
            "facts": [
                {
                    "context": "proposal",
                    "predicate": item.predicate.name,
                    "args": [term.model_dump(mode="json") for term in item.args],
                }
                for item in graph.facts
            ],
            "rules": [],
        }
        return ModelResponse(
            structured=payload, content=json.dumps(payload), model_id="carrier-test"
        )


def configure(tmp_path, method_spec, scenario_position):
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="payload", type="string", required=True),)}
    )
    action = Atom(value=f"action:{method.method_id}")
    repository = SqliteFormalRepository(tmp_path / "formal.sqlite3")
    repository.save(
        f"contract:{method.service}",
        source_graph(action),
        provenance={},
        adapter_version="test",
        mapping_report={},
    )
    binder = ScenarioBinder(
        MethodRepo(method),
        ScenarioRepo(scenario_position),
        repository,
        qdl_planner=IncrementalQdlPlanner(),
    )
    request = LiveRequest(
        service=method.service, principal_id="attacker", resource_id="secret-victim"
    )
    events = EventLog()
    bus = events
    checks = []

    def target(check):
        checks.append(check)
        values = (("rendered", check.probe_marker),) if check.probe_marker else ()
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="rendered response",
            probe_marker=check.probe_marker,
            output=ResponseData(fields=values),
            response_tree=values,
        )

    checker = Checker(
        target, GoalPayloadGenerator(TemplateGenerator()), AllowAllGuardrail(), bus
    )
    runner = BoundPathRunner(checker, bus, events)
    return repository, binder, request, runner, bus, events, checks, action


def test_missing_carrier_blocks_before_setup_and_emits_one_graph_obligation(
    tmp_path,
    method_spec,
    scenario_position,
):
    repository, binder, request, runner, _bus, events, checks, _action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        binding = binder.bind(request, formal_proposal=False)
        pending = witness_deficits(binding.execution.paths)
        assert len(pending) == 1
        assert pending[0].predicate_class == "probe_carrier"
        assert pending[0].axis == "dataflows"
        paths = tuple(path for path in binding.execution.paths if path.kind != "smoke")
        assert paths
        queue = DeficitQueue(max_tasks=None)
        budget = CallLimits.from_request(request)
        runner.execute_round(
            request,
            CoverageDrivenScheduler(paths),
            budget=budget,
            deficit_sink=lambda item: queue.add((item,)),
        )
        assert not checks
        assert budget.live_calls == 0
        assert queue.pending_count == 1
        assert any(
            isinstance(event, QdlPathEvaluated)
            and "probe_carrier" in event.reason
            and event.probe_count == 0
            for event in events.events
        )
    finally:
        repository.close()


def test_live_workflow_repairs_carrier_but_echo_does_not_prove_sink(
    tmp_path,
    monkeypatch,
    method_spec,
    scenario_position,
):
    repository, binder, request, runner, bus, events, checks, action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        initial = binder.bind(request, formal_proposal=False)
        deficit = witness_deficits(initial.execution.paths)[0]
        old_ids = {
            path.path_id for path in initial.execution.paths if path.kind != "smoke"
        }
        model = CarrierModel(action)
        grounding = AutoGroundingService(
            repository,
            axis_grounding=Grounder(
                consultation=ConsultationDispatcher(model),
                grounding_dispatcher=Dispatcher(model),
                batch_size=1,
                max_workers=1,
            ),
            promotion_policy=PromotionPolicy(enabled=True),
        )
        # Isolate reactive repair; startup proposals must not supply the carrier.
        monkeypatch.setattr(grounding, "start_grounded", lambda *args: None)
        workflow = LiveWorkflow(
            binder,
            runner,
            FindingEvaluator(bus, events),
            grounding=grounding,
            formal_repository=repository,
            event_bus=bus,
            reactive_budget=3,
            grounding_runner=ThreadedGroundingRunner(),
        )
        result = workflow.execute(request)
        rebound = binder.bind(request, formal_proposal=False)
        assert not witness_deficits(rebound.execution.paths)
        assert derivable(deficit.subgoal, rebound.graph)
        assert grounding_result_closes_deficit(deficit, rebound.graph)
        assert {
            path.path_id for path in rebound.execution.paths if path.kind != "smoke"
        } - old_ids
        assert any(check.probe_marker for check in checks)
        evaluated = [
            event for event in events.events if isinstance(event, QdlStepEvaluated)
        ]
        assert evaluated
        assert all(event.verdict is VerdictStatus.UNSCOREABLE for event in evaluated)
        # Repairing the carrier authorizes a probe, not a sink-effect proof.
        assert not result.findings
        assert any("probe_carrier" in str(item.context) for item in model.requests)
        assert not any(
            "no grounded probe fields" in str(event) for event in events.events
        )
        # Rebinding an unchanged graph is idempotent.
        again = binder.bind(request, formal_proposal=False)
        assert again.execution.paths == rebound.execution.paths
    finally:
        repository.close()


def test_proposal_role_does_not_close_carrier_obligation(
    tmp_path,
    method_spec,
    scenario_position,
):
    repository, binder, request, _runner, _bus, _events, _checks, action = configure(
        tmp_path, method_spec, scenario_position
    )
    try:
        binding = binder.bind(request, formal_proposal=False)
        deficit = witness_deficits(binding.execution.paths)[0]
        role = fact(
            "has",
            input_field(action, Atom(value="payload")),
            Atom(value="probe_target"),
            context=Context.PROPOSAL,
        )
        assert not grounding_result_closes_deficit(
            deficit, QdlGraph(facts=(*binding.graph.facts, role))
        )
    finally:
        repository.close()


def test_missing_flow_remains_deficit_without_invented_verdict(
    tmp_path,
    monkeypatch,
    method_spec,
    scenario_position,
):
    repository, binder, request, runner, bus, events, checks, action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        model = CarrierModel(action, supported=False)
        grounding = AutoGroundingService(
            repository,
            axis_grounding=Grounder(
                consultation=ConsultationDispatcher(model),
                grounding_dispatcher=Dispatcher(model),
                max_workers=1,
            ),
            promotion_policy=PromotionPolicy(enabled=True),
        )
        monkeypatch.setattr(grounding, "start_grounded", lambda *args: None)
        workflow = LiveWorkflow(
            binder,
            runner,
            FindingEvaluator(bus, events),
            grounding=grounding,
            formal_repository=repository,
            event_bus=bus,
            reactive_budget=None,
            grounding_runner=ThreadedGroundingRunner(),
        )
        result = workflow.execute(request)
        assert witness_deficits(
            binder.bind(request, formal_proposal=False).execution.paths
        )
        assert checks  # The contract smoke path supplied transport evidence.
        assert all(check.probe_marker is None for check in checks)
        assert not result.findings
        assert all(
            event.verdict is VerdictStatus.UNSCOREABLE
            for event in events.events
            if isinstance(event, QdlStepEvaluated)
        )
        assert (
            sum(item.task == "formal_grounding_dataflows" for item in model.requests)
            == 1
        )
    finally:
        repository.close()


def test_prerequisite_fanout_and_replay_preserve_repaired_path_retry_budget(
    tmp_path,
    method_spec,
    scenario_position,
):
    repository, binder, request, runner, _bus, _events, checks, action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        initial = binder.bind(request, formal_proposal=False)
        path = next(path for path in initial.execution.paths if path.kind != "smoke")
        variants = tuple(
            replace(path, path_id=f"{path.path_id}:variant{i}") for i in range(4)
        )
        scheduler = CoverageDrivenScheduler(variants)
        runner.execute_round(request, scheduler)
        assert not checks
        assert not scheduler.state.canonical_attempts
        assert not scheduler.state.attempts
        # A new scheduler replays the same prerequisite failures without
        # turning them into executed attempts either.
        replay = CoverageDrivenScheduler(variants)
        runner.execute_round(request, replay)
        assert not replay.state.canonical_attempts
        repaired = QdlGraph(
            facts=(
                *source_graph(action).facts,
                fact(
                    "reaches",
                    input_field(action, Atom(value="payload")),
                    Atom(value="sink:interpreter"),
                    context=Context.ACCEPTED,
                ),
            )
        )
        repository.save(
            f"accepted:{request.service}",
            repaired,
            provenance={},
            adapter_version="test",
            mapping_report={},
        )
        rebound = binder.bind(request, formal_proposal=False)
        ready = tuple(path for path in rebound.execution.paths if path.kind != "smoke")
        assert scheduler.add_paths(ready)
        assert scheduler.remaining
        runner.execute_round(request, scheduler)
        assert any(check.probe_marker for check in checks)
    finally:
        repository.close()


def test_witness_fanout_reuses_bound_carrier_projection(
    tmp_path,
    monkeypatch,
    method_spec,
    scenario_position,
):
    repository, binder, request, _runner, _bus, _events, _checks, _action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        binding = binder.bind(request, formal_proposal=False)
        path = next(path for path in binding.execution.paths if path.kind != "smoke")
        expanded = replace(
            binding,
            execution=replace(
                binding.execution,
                paths=tuple(
                    replace(path, path_id=f"variant:{index}") for index in range(100)
                ),
            ),
        )

        def unexpected_solve(*args, **kwargs):
            raise AssertionError("a bound snapshot must not be solved per deficit")

        monkeypatch.setattr(ClingoEngine, "solve", unexpected_solve)
        assert len(witness_deficits(expanded.execution.paths)) == 1
    finally:
        repository.close()


def test_accepted_norm_sink_admits_carrier_consultation_before_observation(
    tmp_path,
    method_spec,
    scenario_position,
):
    repository, binder, request, runner, bus, events, _checks, _action = configure(
        tmp_path,
        method_spec,
        scenario_position,
    )
    try:
        binding = binder.bind(request, formal_proposal=False)
        queue = DeficitQueue(max_tasks=None)
        queue.add(witness_deficits(binding.execution.paths))
        work_item = queue.pop_wave()[0]
        workflow = LiveWorkflow(
            binder,
            runner,
            FindingEvaluator(bus, events),
            formal_repository=repository,
            event_bus=bus,
            grounding_runner=ThreadedGroundingRunner(),
        )
        assert workflow._replanning._consultation._plan_work_item_observation(
            request,
            work_item,
            queue,
            CampaignAccumulator.empty(),
        ) == (False, None, None)
        assert not workflow.evidence_deficits
    finally:
        repository.close()
