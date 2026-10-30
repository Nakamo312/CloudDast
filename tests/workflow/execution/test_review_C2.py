"""Campaign fixed point and cooperative wave execution, entirely local."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cloud_dast
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import ExecutionResult, LiveRequest, ScenarioBinding
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
    VerificationPlan,
)
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    FieldSpec,
    HttpStatus,
    JsonValue,
    MethodSpec,
    Observation,
    ScenarioPosition,
    Severity,
    TraceStep,
    TransportStatus,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DomainEvent,
    EvidenceRecorded,
    FactVerified,
    FindingRaised,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
    allowed,
    duration,
    input_field,
)
from cloud_dast.qdl.graph_ops import merge_facts, merge_graphs
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign import (
    FindingEvaluator,
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.consultation.context import WaveExecution
from cloud_dast.runtime.deficits import Deficit
from cloud_dast.runtime.deficits.collection import ClassificationState
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.execution.runner import EventProjection, build_event_scope
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.runtime.recovery import Coordinator as RecoveryCoordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.oracles import PrimitiveOracleRouter
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.oracles.witness import WitnessSignalOracle
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_reporting import CoverageSnapshot, PhaseChanged, PlanReady
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


class MethodRepo:
    def __init__(self, methods) -> None:
        self.methods = methods

    def list_methods(self, service):
        return self.methods


class ScenarioRepo:
    def __init__(self, scenario) -> None:
        self.scenario = scenario
        self.calls = []

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        self.calls.append((principal_id, resource_id, method))
        return self.scenario


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


def _allowed_target(check):
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


def _baseline_deficit() -> Deficit:
    action = Atom(value="action:orders.Get")
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (action, duration(action, Variable(name="AnyMilliseconds"))),
        ),
        predicate_class="causes",
        axis="availability",
        action="action:orders.Get",
    )


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


def _latency_execution_path(
    method_spec: MethodSpec,
    verification_plan: VerificationPlan,
    scenario_position: ScenarioPosition,
    *,
    path_id: str = "path:latency",
) -> QdlExecutionPath:
    latency_invariant = _latency_invariant(method_spec.method_id)
    latency_plan = verification_plan.model_copy(
        update={"invariant_id": latency_invariant.invariant_id}
    )
    step = QdlExecutionStep(
        step_id="step:latency",
        goal_id="goal:latency",
        plan=latency_plan,
        method=method_spec,
        scenario=scenario_position,
        invariant=latency_invariant,
    )
    return QdlExecutionPath(
        path_id=path_id,
        goal_id="goal:latency",
        kind="invariant",
        description="latency path",
        steps=(step,),
    )


def _latency_invariant(method_id: str = "orders.Get") -> InvariantProjection:
    effect = duration(Atom(value=f"action:{method_id}"), Atom(value=110))
    return InvariantProjection(
        invariant_id="invariant:latency",
        norm_id="norm:latency",
        statement="latency must stay bounded",
        severity=Severity.LOW,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:latency"), effect),
        ),
    )


def _observation(
    index: int,
    duration_ms: float,
    *,
    method_id: str = "orders.Get",
    observed_outcome: AccessOutcome = AccessOutcome.ALLOWED,
    transport_status: TransportStatus | None = HttpStatus(code=200),
    error_reason: str | None = None,
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    observation_id = f"observation-{index}"
    return Observation(
        check_id=f"check-{index}",
        scenario_id="scenario",
        observed_outcome=observed_outcome,
        response_summary="allowed",
        transport_status=transport_status,
        duration_ms=duration_ms,
        error_reason=error_reason,
        response_tree=response_tree,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id=f"check-{index}",
                    method_id=method_id,
                    scenario_id="scenario",
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
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


class ExplodingGrounding:
    reactive_capable = True

    def prepare_reactive(self, *args, **kwargs):
        raise AssertionError("missing_baseline must not call reactive model grounding")


def _workflow(oracle: LatencyOracle) -> LiveWorkflow:
    return assemble_workflow(
        grounding=ExplodingGrounding(),
        scenario_binder=None,
        path_runner=SimpleNamespace(differential=ProbeExecutor(None, None)),
        finding_evaluator=None,
        options=LiveWorkflowOptions(
            latency_oracle=oracle, grounding_runner=ThreadedGroundingRunner()
        ),
    )


@pytest.fixture(autouse=True)
def _local_imports():
    assert Path(cloud_dast.__file__).is_relative_to(Path.cwd())


def _request(method=None, max_checks=None):
    return LiveRequest(
        service=method.service if method else "orders",
        principal_id="principal-attacker",
        resource_id="secret-victim",
        max_checks=max_checks,
    )


def test_bootstrap_baseline_closes_existing_deficit():
    oracle = LatencyOracle()
    oracle.update_baseline("orders.Get", (100.0,), min_samples=1)
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation(1, 100.0))
    queue = DeficitQueue(max_tasks=None)
    queue.add((_baseline_deficit(),))

    assert workflow._replanning.drain_reactive(_request(), queue, accumulator) == 1
    assert not queue.dispatchable
    assert queue.closed_count == 1
    assert oracle.baselines["orders.Get"].samples == 1
    assert workflow._replanning.drain_reactive(_request(), queue, accumulator) == 0


@pytest.mark.parametrize("max_tasks", [None, 1])
def test_insufficient_evidence_waits_until_a_new_sample(max_tasks, scenario_position):
    oracle = LatencyOracle()
    workflow = _workflow(oracle)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.extend((_observation(1, 100.0), _observation(2, 102.0)))
    queue = DeficitQueue(max_tasks=max_tasks)
    queue.add((_baseline_deficit(),))
    assert workflow._replanning.drain_reactive(_request(), queue, accumulator) == 0
    assert queue.pending_count == 1
    assert queue.closed_count == 0
    assert not queue.dispatchable
    for _ in range(3):
        assert workflow._replanning.drain_reactive(_request(), queue, accumulator) == 0
    assert queue.quarantined_signals == 0

    # Production observation classification enriches the same QdlSubgoal;
    # a new observation resumes the deferred deterministic work item.
    new = _observation(3, 104.0)
    accumulator.observations.append(new)
    from cloud_dast.model import PolicyVerdict

    accumulator.policy_verdicts[(new.observation_id, "norm:latency")] = PolicyVerdict(
        status=VerdictStatus.UNSCOREABLE,
        deterministic=True,
        grounded=False,
        confidence=1.0,
        model_id="local",
        rationale="no runtime latency baseline for method action:orders.Get",
    )
    workflow._deficits.collect_deficits(
        _request(),
        _empty_binding(scenario_position),
        CoverageDrivenScheduler(()),
        accumulator,
        queue,
        ClassificationState(paths=set(), observations=2),
        RecoveryCoordinator(),
        expand_graph=False,
    )
    assert queue.dispatchable
    assert workflow._replanning.drain_reactive(_request(), queue, accumulator) == 1
    assert queue.closed_count == 1
    assert oracle.baselines["orders.Get"].samples == 3


def _binding(method, scenario, invariant, graph):
    step = _execution_step(method, scenario, invariant)
    path = QdlExecutionPath("p", "g", "invariant", "", (step,))
    return SimpleNamespace(methods=(method,), graph=graph), path


def test_deferred_payload_reopens_only_its_mode(
    method_spec, scenario_position, invariant
):
    method = method_spec.model_copy(
        update={
            "fields": tuple(FieldSpec(name=name, type="string") for name in ("q", "z"))
        }
    )
    action = Atom(value=f"action:{method.method_id}")
    field = input_field(action, Atom(value="q"))
    second_field = input_field(action, Atom(value="z"))
    base = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="InputField"))),
            _fact("is", (second_field, Atom(value="InputField"))),
        )
    )
    binding, path = _binding(method, scenario_position, invariant, base)
    calls = []
    contexts = []

    class Runner:
        @property
        def differential(self):
            return self

        def execute_step_pair(
            self, step, spec, budget, *, mutable_fields=None, **kwargs
        ):
            calls.append(
                ("factors", spec.factor)
                if mutable_fields is None
                else ("payload", mutable_fields)
            )
            contexts.append(kwargs)
            return self.pair(step)

        def pair(self, step):
            from cloud_dast.model import Check

            checks = tuple(
                Check(
                    invariant_id=step.invariant.invariant_id,
                    method_id=method.method_id,
                    scenario_id=scenario_position.scenario_id,
                    request=(("q", value),),
                    identities=("attacker",),
                )
                for value in ("plain", "canary")
            )
            return (*checks, *(_allowed_target(check) for check in checks))

    workflow = assemble_workflow(
        None,
        Runner(),
        None,
        options=LiveWorkflowOptions(
            diff_mode=True,
            diff_modes=frozenset({"payload", "factors"}),
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )
    owner = scenario_position.model_copy(
        update={
            "scenario_id": "owner",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    workflow._scenario_repository = SimpleNamespace(get_scenario=lambda *a, **kw: owner)
    workflow._differential._probes._specs._scenario_repository = (
        workflow._scenario_repository
    )
    resource = Atom(value="resource:secret-victim")
    subject = Atom(value="subject:owner")
    binding.graph = merge_graphs(
        base,
        QdlGraph(
            facts=(
                _fact("is", (resource, Atom(value="Resource"))),
                _fact("is", (subject, Atom(value="Subject"))),
                _fact("owner", (resource, subject)),
            )
        ),
    )
    scheduler = CoverageDrivenScheduler((path,))
    accumulator = CampaignAccumulator.empty()
    queue = DeficitQueue(max_tasks=None)
    paired = set()
    scope = build_event_scope(_request(method), binding.graph.content_hash)
    budget = CallLimits.from_request(_request(method))

    def sweep():
        workflow._differential._run_differential_round(
            _request(method),
            binding,
            scheduler,
            accumulator,
            queue,
            {},
            paired,
            budget,
            scope,
        )

    sweep()
    assert [mode for mode, _ in calls] == ["factors"]
    assert contexts == [{"scope": scope, "path_id": "p"}]
    assert queue.pending_count == 2
    binding.graph = merge_facts(
        binding.graph, (_fact("has", (field, Atom(value="payload"))),)
    )
    # Even a completed ordinary path must offer its deferred mode again.
    scheduler.state.completed.add(path.path_id)
    sweep()
    assert [mode for mode, _ in calls] == ["factors", "payload"]
    sweep()
    binding.graph = merge_graphs(
        binding.graph,
        QdlGraph(facts=(_fact("is", (Atom(value="unrelated"), Atom(value="Node"))),)),
    )
    scheduler.add_paths((replace(path, path_id="p:pv2"),))
    sweep()
    assert [mode for mode, _ in calls] == ["factors", "payload"]
    assert len(paired) == 2

    # A relevant prerequisite revision opens only this mode once.
    binding.graph = merge_facts(
        binding.graph, (_fact("has", (second_field, Atom(value="mutable_input"))),)
    )
    sweep()
    sweep()
    assert calls[-1] == ("payload", ("q", "z"))
    assert [mode for mode, _ in calls] == ["factors", "payload", "payload"]

    # The authoritative current role projection removes superseded roles.
    from cloud_dast.qdl.graph import Struct

    old = Struct(name="replacement", args=(field, Atom(value="payload")))
    new = Struct(name="replacement", args=(field, Atom(value="credential")))
    binding.graph = merge_facts(
        binding.graph,
        (
            _fact("has", (field, Atom(value="credential"))),
            _fact("is", (Atom(value="credential"), Atom(value="Role"))),
            _fact("is", (Atom(value="payload"), Atom(value="Role"))),
            _fact("is", (old, Atom(value="Node"))),
            _fact("is", (new, Atom(value="Node"))),
            _fact("supersedes", (new, old)),
        ),
    )
    sweep()
    sweep()
    assert calls[-1] == ("payload", ("z",))
    assert [mode for mode, _ in calls] == ["factors", "payload", "payload", "payload"]


class LocalGrounding:
    reactive_capable = True

    def prepare_reactive(self, *args, **kwargs):
        return None


@pytest.mark.parametrize("delivered,max_checks", [(True, 1), (False, None)])
def test_latency_campaign_reaches_fixed_point(
    method_spec,
    verification_plan,
    scenario_position,
    delivered,
    max_checks,
):
    """Actual main loop + runner, including a round with no execution."""
    oracle = LatencyOracle()
    path = _latency_execution_path(method_spec, verification_plan, scenario_position)
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
        execution=QdlExecutionView(graph.content_hash, (path,), {}),
        methods=(method_spec,),
        invariants={},
    )
    calls = []
    events = EventLog()
    bus = _event_bus(events)

    def target(check):
        calls.append(check)
        return _allowed_target(check).model_copy(update={"duration_ms": 100.0})

    event_projection = EventProjection(bus, events)
    runner = assemble_runner(
        _service((method_spec,), target, bus),
        event_projection,
        primitive_oracle=PrimitiveOracleRouter(
            witness_oracle=WitnessSignalOracle(latency_oracle=oracle)
        ),
    )
    if not delivered:

        def empty_round(request, scheduler, **kwargs):
            scheduler.block_remaining()
            return ExecutionResult((), (), {}, {})

        runner.execute_round = empty_round

    def collect_deficits(
        request,
        binding,
        scheduler,
        accumulator,
        deficits,
        classification,
        recovery,
        *,
        expand_graph,
    ):
        action = Atom(value=method_spec.method_id)
        deficits.add(
            (
                Deficit(
                    QdlSubgoal(
                        "causes", (action, duration(action, Variable(name="Ms")))
                    ),
                    "causes",
                    "availability",
                    method_spec.method_id,
                ),
            )
        )
        classification.observations = len(accumulator.observations)

    workflow = assemble_workflow(
        SimpleNamespace(bind=lambda *a, **kw: binding),
        runner,
        FindingEvaluator(event_projection),
        grounding=LocalGrounding(),
        lifecycle=SimpleNamespace(start_grounded=lambda *args: None),
        options=LiveWorkflowOptions(
            latency_oracle=oracle,
            reactive_budget=None,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )
    rebinds = 0
    original_rebind = workflow._rebind_and_extend_paths

    def rebind_and_extend_paths(campaign):
        nonlocal rebinds
        rebinds += 1
        assert rebinds < 8, "unchanged evidence must reach a fixed point"
        original_rebind(campaign)

    workflow._rebind_and_extend_paths = rebind_and_extend_paths
    workflow._deficits.collect_deficits = collect_deficits
    result = workflow.execute(_request(method_spec, max_checks))
    assert len(result.observations) == int(delivered)
    assert len(calls) == int(delivered)
    assert oracle.has_baseline(method_spec.method_id) is delivered


def test_accepted_wave_executes_before_later_consultation_and_startup(
    method_spec,
    scenario_position,
):
    """Real queue, binder and runner, with local consultation/startup doubles."""
    repository = FormalRepository()
    _save_graph(
        repository,
        f"contract:{method_spec.service}",
        _accepted_norm_graph(method_spec),
        adapter_version="local",
    )
    events = EventLog()
    bus = _event_bus(events)
    calls = []
    order = []
    action = Atom(value=f"action:{method_spec.method_id}")
    norm = Atom(value="norm:promoted-wave")
    from cloud_dast.qdl.graph import denied

    promoted_graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("prevents", (norm, denied(action))),
        )
    )

    def target(check):
        calls.append(check)
        order.append("execute")
        return _allowed_target(check)

    class Handle:
        promoted_facts = 0
        error = None
        done = False
        enrichment_status = "not_started"

        def wait_batch(self, timeout=None):
            if len(calls) >= 2:
                self.done = True
                order.append("startup-finished")
                return None
            assert timeout == 0, "startup must not block newly accepted work"
            raise TimeoutError

        def mark_enrichment(self, status):
            self.enrichment_status = status

    waves = 0

    def collect_deficits(
        request,
        binding,
        scheduler,
        accumulator,
        deficits,
        classification,
        recovery,
        *,
        expand_graph,
    ):
        for name in ("first", "second"):
            term = Atom(value=name)
            deficits.add(
                (
                    Deficit(
                        QdlSubgoal("is", (term, Variable(name="Kind"))),
                        "is",
                        "classification",
                        method_spec.method_id,
                        (("classification_term", name),),
                    ),
                )
            )
        classification.observations = len(accumulator.observations)

    def run_wave(request, wave, deficits, accumulator, **kwargs):
        nonlocal waves
        waves += 1
        assert len(wave) == 1  # Existing conflict serialization.
        if waves == 1:
            order.append("promote")
            _save_graph(
                repository,
                f"accepted:{method_spec.service}",
                promoted_graph,
                adapter_version="local",
            )
        else:
            assert len(calls) >= 2, "ready execution starved behind reactive drain"
            order.append("second-consultation")
        for item in wave:
            deficits.record_work_item_success(item)
        return WaveExecution(int(waves == 1), promoted_graph)

    event_projection = EventProjection(bus, events)
    workflow = assemble_workflow(
        ScenarioBinder(
            MethodRepo((method_spec,)),
            ScenarioRepo(scenario_position),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        ),
        assemble_runner(
            _service((method_spec,), target, bus),
            event_projection,
            formal_repository=repository,
        ),
        FindingEvaluator(event_projection),
        grounding=LocalGrounding(),
        lifecycle=SimpleNamespace(start_grounded=lambda *args: Handle()),
        options=LiveWorkflowOptions(
            reactive_budget=None, grounding_runner=ThreadedGroundingRunner()
        ),
    )
    workflow._deficits.collect_deficits = collect_deficits
    workflow._replanning._consultation.run_wave = run_wave
    result = workflow.execute(_request(method_spec))
    assert len(result.observations) >= 2
    promotion = order.index("promote")
    execution = order.index("execute", promotion)
    assert promotion < execution < order.index("second-consultation")
    assert execution < order.index("startup-finished")
    assert waves == 2


def _empty_binding(scenario, paths=()):
    graph = QdlGraph()
    return ScenarioBinding(
        scenario=scenario,
        graph=graph,
        plan=SimpleNamespace(
            graph_hash=graph.content_hash,
            attack_paths=(),
            forbidden_paths=(),
            invariants=(),
        ),
        execution=QdlExecutionView(graph.content_hash, paths, {}),
        methods=tuple(step.method for path in paths for step in path.steps),
        invariants={},
    )


def test_campaign_round_projects_only_appended_observations_per_campaign(
    scenario_position,
    monkeypatch,
):
    from cloud_dast.runtime.deficits import collection

    binding = _empty_binding(scenario_position)
    batches = []
    project = collection.gaps_for_observations

    def project_observations(binding, **kwargs):
        batches.append(kwargs["observations"])
        return project(binding, **kwargs)

    monkeypatch.setattr(collection, "gaps_for_observations", project_observations)
    pending = iter(())
    runner = SimpleNamespace(
        differential=ProbeExecutor(None, None),
        execute_round=lambda *a, **kw: next(pending),
    )
    workflow = assemble_workflow(None, runner, None)

    def campaign():
        return workflow._initializer.prepare_campaign(
            _request(),
            binding,
            build_event_scope(_request(), binding.graph.content_hash),
            handle=None,
        )

    first, second = campaign(), campaign()
    a, b = _observation(101, 100), _observation(102, 110)
    # Interleave two campaigns through the same workflow/real collector. A
    # collector-global cursor would skip second's A or replay first's A.
    pending = iter(
        ExecutionResult(obs, (), {}, {}) for obs in ((a,), (a,), (), (b,), (), (b,))
    )
    for state in (first, second, first, first, second, second):
        workflow._run_campaign_round(state)
    assert batches == [(a,), (a,), (), (b,), (), (b,)]
    assert first.execution.accumulator.observations == [a, b]
    assert second.execution.accumulator.observations == [a, b]


def test_campaign_round_records_recovery_before_classification_and_drains_after(
    method_spec,
    scenario_position,
    invariant,
    monkeypatch,
):
    from cloud_dast.contracts.execution import ObservationProvenance
    from cloud_dast.model import PolicyVerdict
    from cloud_dast.runtime.deficits import collection

    step = _execution_step(method_spec, scenario_position, invariant)
    paths = tuple(
        QdlExecutionPath(name, "g", "invariant", "", (step,)) for name in ("a", "b")
    )
    binding = _empty_binding(scenario_position, paths)
    observation = _observation(201, 100)
    key = (observation.observation_id, invariant.norm_id)
    verdict = PolicyVerdict(
        status=VerdictStatus.UNSCOREABLE,
        deterministic=True,
        grounded=False,
        confidence=1.0,
        model_id="local",
        rationale="no runtime latency baseline for method action:orders.Get",
    )
    provenance = ObservationProvenance("g", "b", step.step_id, invariant.invariant_id)

    def execute_round(request, scheduler, **kwargs):
        scheduler.state.blocked.update(("a", "b"))
        scheduler.state.selections.extend(("a", "b"))
        kwargs["blocked_reasons"].update(
            {"a": "missing_refers_to", "b": "missing_state_semantics"}
        )
        return ExecutionResult((observation,), (), {key: provenance}, {key: verdict})

    workflow = assemble_workflow(
        None,
        SimpleNamespace(
            differential=ProbeExecutor(None, None),
            execute_round=execute_round,
        ),
        None,
    )
    campaign = workflow._initializer.prepare_campaign(
        _request(),
        binding,
        build_event_scope(_request(), binding.graph.content_hash),
        handle=None,
    )
    detected = []
    evaluated = []
    queued = []
    add_deficits = campaign.grounding.deficits.add

    def queue_deficits(deficits):
        deficits = tuple(deficits)
        queued.extend(deficits)
        return add_deficits(deficits)

    monkeypatch.setattr(campaign.grounding.deficits, "add", queue_deficits)
    blocked = collection.blocked_step_deficit
    classify = collection.classify_step_event

    def blocked_deficit(path, step, **kwargs):
        # Real recovery must be populated when the real collector reads it.
        assert [
            intent.blocked_path_id
            for intent in campaign.grounding.recovery.recovery_intents()
        ][:2] == ["b", "a"]
        result = blocked(path, step, **kwargs)
        detected.append(result)
        return result

    def classify_event(event):
        evaluated.append(event)
        result = classify(event)
        assert (event.path_id, event.step_id) == ("b", step.step_id)
        return result

    monkeypatch.setattr(collection, "blocked_step_deficit", blocked_deficit)
    monkeypatch.setattr(collection, "classify_step_event", classify_event)
    workflow._run_campaign_round(campaign)
    contexts = [dict(deficit.context) for deficit in detected]
    assert [context["path_id"] for context in contexts] == ["b", "a"]
    assert [context["reason"] for context in contexts] == [
        "missing_state_semantics",
        "missing_refers_to",
    ]
    assert [context["recovery_action"] for context in contexts] == [
        "ground_alternatives",
        "reuse_clue",
    ]
    assert contexts[1]["clue_observation_id"] == observation.observation_id
    observation_contexts = [
        dict(deficit.context)
        for deficit in queued
        if "observation_id" in dict(deficit.context)
    ]
    assert len(observation_contexts) == 1
    assert observation_contexts[0]["observation_id"] == observation.observation_id
    assert observation_contexts[0]["path_id"] == provenance.path_id
    clue = campaign.grounding.recovery.clue_cache.find_clue(step, excluded_path_id="a")
    assert clue is not None
    assert (clue.observation_id, clue.path_id, clue.step_id) == (
        observation.observation_id,
        provenance.path_id,
        provenance.step_id,
    )
    assert campaign.grounding.recovery.recovery_intents() == ()
    # Classification cursors retain both blocked paths; an empty round must
    # neither manufacture another blocked-path deficit nor replay the verdict.
    workflow._runner.execute_round = lambda *a, **kw: ExecutionResult((), (), {}, {})
    workflow._run_campaign_round(campaign)
    assert len(detected) == 2
    assert len(evaluated) == 1


@pytest.mark.parametrize("failure_stage", ["classification_gaps", "coverage"])
def test_campaign_round_retries_observations_after_projection_failure(
    method_spec,
    scenario_position,
    invariant,
    monkeypatch,
    failure_stage,
):
    from cloud_dast.runtime.deficits import collection

    step = _execution_step(method_spec, scenario_position, invariant)
    path = QdlExecutionPath("blocked", "g", "invariant", "", (step,))
    binding = _empty_binding(scenario_position, (path,))
    a, b = _observation(301, 100), _observation(302, 110)
    results = iter(ExecutionResult(obs, (), {}, {}) for obs in ((a,), (), (b,)))

    def execute_round(request, scheduler, **kwargs):
        scheduler.state.blocked.add(path.path_id)
        scheduler.state.selections.append(path.path_id)
        return next(results)

    workflow = assemble_workflow(
        None,
        SimpleNamespace(
            differential=ProbeExecutor(None, None),
            execute_round=execute_round,
        ),
        None,
        grounding=LocalGrounding(),
    )
    campaign = workflow._initializer.prepare_campaign(
        _request(),
        binding,
        build_event_scope(_request(), binding.graph.content_hash),
        handle=None,
    )
    projected = []
    blocked = []
    error = RuntimeError(f"failed {failure_stage}")
    gaps = collection.gaps_for_observations
    coverage = collection.coverage_gaps
    blocked_step = collection.blocked_step_deficit
    fail = True

    def project(binding, **kwargs):
        projected.append(kwargs["observations"])
        result = gaps(binding, **kwargs)
        if fail and failure_stage == "classification_gaps":
            raise error
        return result

    def project_coverage(*args, **kwargs):
        result = coverage(*args, **kwargs)
        if fail and failure_stage == "coverage":
            raise error
        return result

    def detect_blocked(*args, **kwargs):
        result = blocked_step(*args, **kwargs)
        blocked.append(result)
        return result

    monkeypatch.setattr(collection, "gaps_for_observations", project)
    monkeypatch.setattr(collection, "coverage_gaps", project_coverage)
    monkeypatch.setattr(collection, "blocked_step_deficit", detect_blocked)
    with pytest.raises(RuntimeError) as caught:
        workflow._run_campaign_round(campaign)
    assert caught.value is error
    assert campaign.grounding.recovery.recovery_intents()
    fail = False
    workflow._run_campaign_round(campaign)
    workflow._run_campaign_round(campaign)
    assert projected == [(a,), (a,), (b,)]
    assert len(blocked) == 1  # Path mutations survive failed observation projection.
    assert campaign.grounding.recovery.recovery_intents() == ()
