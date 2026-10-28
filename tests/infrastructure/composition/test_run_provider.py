from __future__ import annotations

import importlib
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from app.cli import _skip_llm_grounding
from hypothesis.database import InMemoryExampleDatabase

from cloud_dast.api import LiveRequest
from cloud_dast.composition.container import make_cloud_dast_container
from cloud_dast.composition.run_provider import (
    RunProvider,
    ScenarioBinderFormalGrounder,
    _skip_llm_grounding_from_environment,
    select_promotion_policy,
)
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.infrastructure.runtime import (
    JsonlEvidenceChannel,
    ThreadedGroundingHandle,
    ThreadedGroundingRunner,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
)
from cloud_dast.model.events import ComponentInvoked, PhaseChanged
from cloud_dast.ports import (
    GroundingBatch,
    ModelRequest,
    ModelResponse,
    ServiceGraphSlice,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    reached,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign import BoundPathRunner
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.promotion import (
    PromotionPolicy,
)
from cloud_dast_fuzzing import FuzzSession
from cloud_dast_llm.threat_model import FormalThreatModeler
from cloud_dast_symbolic.solver import Z3SymbolicGenerator
from tests.support.guardrails import AllowAllGuardrail


class FakeModelClient:
    def complete(self, request: ModelRequest, *, response_type=None) -> ModelResponse:
        raise AssertionError("model client must not be called during wiring")


class StaticMethodRepository:
    def get_method(self, method_id):
        return None

    def list_methods(self, service):
        return ()


class StaticScenarioRepository:
    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        return None


class StaticFormalRepository:
    def load(self, source_id):
        raise AssertionError("formal repository must not be read during wiring")

    def load_merged(self, source_prefix):
        raise AssertionError("formal repository must not be read during wiring")


class PromotionModelClient:
    def __init__(self, action_value: str) -> None:
        self.action_value = action_value

    def complete(self, request, *, response_type=None) -> ModelResponse:
        action = {
            "kind": "atom",
            "value": self.action_value,
            "literal_type": "string",
        }
        norm = {"kind": "atom", "value": "norm:no-read", "literal_type": "string"}
        effect = {"kind": "struct", "name": "allowed", "args": [action]}
        payload = {
            "context": "proposal",
            "facts": (
                {
                    "context": "proposal",
                    "predicate": "is",
                    "args": (
                        action,
                        {"kind": "atom", "value": "Action", "literal_type": "string"},
                    ),
                },
                {
                    "context": "proposal",
                    "predicate": "is",
                    "args": (
                        norm,
                        {"kind": "atom", "value": "Norm", "literal_type": "string"},
                    ),
                },
                {
                    "context": "proposal",
                    "predicate": "prevents",
                    "args": (norm, effect),
                },
            ),
            "rules": (),
        }
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="fake-model",
        )


class SingleMethodRepository:
    def __init__(self, method):
        self.method = method

    def get_method(self, method_id):
        return self.method if method_id == self.method.method_id else None

    def list_methods(self, service):
        return (self.method,)


class SingleScenarioRepository:
    def __init__(self, scenario):
        self.scenario = scenario

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        return self.scenario


class SingleFormalRepository:
    def __init__(self, graph):
        self.graph = graph
        self.saved: list[tuple[str, QdlGraph]] = []

    def load(self, source_id):
        for saved_id, saved_graph in reversed(self.saved):
            if saved_id == source_id:
                return saved_graph
        return self.graph if source_id == "contract:lockbox" else QdlGraph()

    def load_merged(self, source_prefix):
        merged = QdlGraph()
        for saved_id, saved_graph in self.saved:
            if saved_id.startswith(source_prefix):
                merged = merge_graphs(merged, saved_graph)
        if merged.facts:
            return merged
        return self.graph if source_prefix.startswith("contract:") else merged

    def save(self, source_id, graph, *, provenance, adapter_version, mapping_report):
        self.saved.append((source_id, graph))


class StaticOobUrls:
    def url_for(self, marker: str) -> str:
        return f"https://collaborator.test/{marker}"


def test_evidence_channel_derives_durable_sidecar_from_event_log(tmp_path) -> None:
    event_log = tmp_path / "events.jsonl"
    event_store = JsonlEventStore(event_log)

    evidence_channel = RunProvider().evidence_channel(event_store)

    assert isinstance(evidence_channel, JsonlEvidenceChannel)
    assert evidence_channel.path == tmp_path / "events.jsonl.evidence.jsonl"


def test_event_bus_persists_phase_changed_events(tmp_path) -> None:
    event_store = JsonlEventStore(tmp_path / "events.jsonl")
    event = PhaseChanged(phase="executing")

    RunProvider().event_bus(event_store, CampaignMetrics()).publish(event)

    assert tuple(event_store.read()) == (event,)


def test_event_bus_projects_component_activity(tmp_path) -> None:
    event_store = JsonlEventStore(tmp_path / "events.jsonl")
    metrics = CampaignMetrics()
    event = ComponentInvoked(
        component="generator:grammar",
        input_digest="digest",
        input_completeness={"sink_facts": 1},
        invocation_id="invocation",
    )

    RunProvider().event_bus(event_store, metrics).publish(event)

    assert tuple(event_store.read()) == (event,)
    assert metrics.snapshot().component_activity["generator:grammar"].invocations == 1


def test_evidence_channel_honors_explicit_evidence_log(
    tmp_path,
    monkeypatch,
) -> None:
    explicit = tmp_path / "collaborator-events.jsonl"
    monkeypatch.setenv("CLOUD_DAST_EVIDENCE_LOG", str(explicit))

    evidence_channel = RunProvider().evidence_channel(
        JsonlEventStore(tmp_path / "events.jsonl")
    )

    assert isinstance(evidence_channel, JsonlEvidenceChannel)
    assert evidence_channel.path == explicit


def test_latency_oracle_loads_runtime_baselines(monkeypatch) -> None:
    monkeypatch.setenv(
        "CLOUD_DAST_LATENCY_BASELINES",
        json.dumps({"get-secret": {"durations_ms": [100, 102, 104]}}),
    )

    oracle = RunProvider().latency_oracle()

    assert "get-secret" in oracle.baselines
    assert oracle.baselines["get-secret"].samples == 3


def test_infrastructure_repositories_imports_without_missing_module() -> None:
    module = importlib.import_module("cloud_dast.infrastructure.repositories")

    assert module.__name__ == "cloud_dast.infrastructure.repositories"


@pytest.mark.parametrize(
    "value",
    ["1", "true", "yes", "on", "0", "false", "no", "off", ""],
)
def test_cli_and_run_provider_parse_skip_llm_grounding_consistently(
    monkeypatch,
    value: str,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_SKIP_LLM_GROUNDING", value)

    assert _skip_llm_grounding() is _skip_llm_grounding_from_environment()


def test_run_provider_rejects_invalid_skip_llm_grounding_flag(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_SKIP_LLM_GROUNDING", "maybe")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_SKIP_LLM_GROUNDING"):
        _skip_llm_grounding_from_environment()


def test_scenario_binder_wires_formal_threat_modeler_with_model_client() -> None:
    binder = RunProvider(model_client=FakeModelClient()).scenario_binder(
        StaticMethodRepository(),
        StaticScenarioRepository(),
        StaticFormalRepository(),
        select_promotion_policy(),
        qdl_planner=IncrementalQdlPlanner(),
    )

    assert isinstance(binder, ScenarioBinder)
    assert isinstance(binder.formal_threat_modeler, FormalThreatModeler)


def test_scenario_binder_without_model_client_skips_formal_threat_modeler() -> None:
    binder = RunProvider().scenario_binder(
        StaticMethodRepository(),
        StaticScenarioRepository(),
        StaticFormalRepository(),
        select_promotion_policy(),
        qdl_planner=IncrementalQdlPlanner(),
    )

    assert isinstance(binder, ScenarioBinder)
    assert binder.formal_threat_modeler is None


def test_scenario_binder_formal_grounder_delegates_through_port() -> None:
    class RecordingBinder:
        def __init__(self) -> None:
            self.calls: list[tuple[str, PromotionPolicy | None]] = []

        def run_formal_grounding(
            self,
            service: str,
            promotion_policy: PromotionPolicy | None = None,
        ) -> int:
            self.calls.append((service, promotion_policy))
            return 7

    binder = RecordingBinder()
    policy = PromotionPolicy(enabled=True)
    grounder = ScenarioBinderFormalGrounder(binder, policy)  # type: ignore[arg-type]

    assert grounder.ground("orders") == 7
    assert binder.calls == [("orders", policy)]


def test_auto_grounding_wires_workflow_callback_through_formal_grounder(
    monkeypatch,
) -> None:
    for variable in (
        "CPA_NEO4J_URI",
        "CPA_NEO4J_USER",
        "CPA_NEO4J_PASSWORD",
        "CPA_NEO4J_PASSWORD_FILE",
    ):
        monkeypatch.delenv(variable, raising=False)

    class EmptyModelClient:
        release = threading.Event()

        def complete(self, request, *, response_type=None) -> ModelResponse:
            # Hold the axis stream open until the formal batch has been
            # observed, so the detached formal publisher delivers while
            # the sink is still open (deterministic delivery).
            self.release.wait(timeout=5)
            return ModelResponse(
                structured={"facts": [], "rules": []},
                content="{}",
                model_id="fake-model",
            )

    class EmptyContractGraphRepository:
        def load_slice(self, service: str) -> ServiceGraphSlice:
            return ServiceGraphSlice(service=service)

    class EmptyFormalRepository:
        def __init__(self) -> None:
            self.graphs: dict[str, QdlGraph] = {}

        def save(self, *args, **kwargs) -> None:
            self.graphs[args[0]] = args[1]

        def load(self, source_id: str) -> QdlGraph:
            return self.graphs.get(source_id, QdlGraph())

        def load_merged(self, source_prefix: str) -> QdlGraph:
            return QdlGraph()

    class RecordingBinder:
        formal_threat_modeler = object()

        def __init__(self) -> None:
            self.calls: list[str] = []

        def run_formal_grounding(
            self,
            service: str,
            promotion_policy: PromotionPolicy | None = None,
        ) -> int:
            del promotion_policy
            self.calls.append(service)
            return 3

    class EmptyStandSource:
        def project(self, service: str) -> QdlGraph:
            return QdlGraph(
                facts=(
                    Fact(
                        context=Context.CONTRACT,
                        predicate=Predicate.from_name("is"),
                        args=(Atom(value="action:orders.Get"), Atom(value="Action")),
                    ),
                )
            )

    class _EmptyResult:
        def data(self):
            return []

    class _EmptySession:
        def run(self, query):
            del query
            return _EmptyResult()

    @contextmanager
    def session_factory():
        yield _EmptySession()

    binder = RecordingBinder()
    runner = ThreadedGroundingRunner()
    grounding = RunProvider(model_client=EmptyModelClient()).auto_grounding(
        EmptyFormalRepository(),
        EmptyContractGraphRepository(),
        CampaignMetrics(),
        binder,  # type: ignore[arg-type]
        PromotionPolicy(enabled=True),
        EmptyStandSource(),
        runner,
    )

    handle = grounding.start_grounded("orders", runner)
    assert handle is not None
    formal_batch = handle.wait_batch(timeout=5)
    EmptyModelClient.release.set()
    assert formal_batch == GroundingBatch(
        axis="formal",
        batch_key="threat-modeler",
        fact_count=3,
    )
    assert handle.wait_batch(timeout=5) is None
    assert binder.calls == ["orders"]
    assert handle.enrichment_status == "committed"


def test_grounding_runner_provider_wires_threaded_runner() -> None:
    runner = RunProvider().grounding_runner()

    assert isinstance(runner, ThreadedGroundingRunner)


def test_threaded_grounding_runner_streams_batches_and_finishes() -> None:
    runner = ThreadedGroundingRunner()
    started = threading.Event()
    release = threading.Event()

    def work(sink) -> None:
        started.set()
        release.wait(timeout=5)
        sink.publish(GroundingBatch("roles", "b0", 3))
        sink.finish()

    handle = runner.start(work)
    assert started.wait(timeout=1)
    try:
        with pytest.raises(TimeoutError):
            handle.wait_batch(timeout=0.01)
        assert not handle.done
    finally:
        release.set()

    assert handle.wait_batch(timeout=1) == GroundingBatch("roles", "b0", 3)
    assert handle.wait_batch(timeout=1) is None
    deadline = time.monotonic() + 1
    while not handle.done and time.monotonic() < deadline:
        time.sleep(0.01)
    assert handle.done
    assert handle.promoted_facts == 3
    assert handle.error is None


def test_threaded_grounding_handle_keeps_terminal_enrichment_status() -> None:
    handle = ThreadedGroundingHandle()

    handle.mark_enrichment("pending")
    handle.mark_enrichment("discarded")
    handle.mark_enrichment("committed")

    assert handle.enrichment_status == "discarded"


def test_threaded_grounding_runner_surfaces_worker_error() -> None:
    def work(sink) -> None:
        del sink
        raise RuntimeError("worker exploded")

    handle = ThreadedGroundingRunner().start(work)

    assert handle.wait_batch(timeout=1) is None
    assert isinstance(handle.error, RuntimeError)


def test_threaded_grounding_handle_drops_late_batches_after_finish() -> None:
    handle = ThreadedGroundingHandle()
    handle.publish(GroundingBatch("roles", "b0", 3))
    handle.finish()

    # A detached enrichment task may publish after the finish sentinel;
    # dropping the late batch is the sink contract, not an error.
    handle.publish(GroundingBatch("formal", "threat-modeler", 2))

    assert handle.wait_batch(timeout=1) == GroundingBatch("roles", "b0", 3)
    assert handle.wait_batch(timeout=1) is None
    assert handle.promoted_facts == 3
    assert handle.error is None


def test_threaded_grounding_runner_omits_timed_out_tasks() -> None:
    release = threading.Event()

    def slow_task() -> str:
        release.wait(timeout=5)
        return "slow"

    def fast_task() -> str:
        return "fast"

    try:
        results = list(
            ThreadedGroundingRunner().run_tasks(
                (slow_task, fast_task),
                max_workers=2,
                timeout=0.05,
            )
        )
    finally:
        release.set()

    assert results == [(1, "fast")]


def test_threaded_grounding_runner_honors_max_workers() -> None:
    started = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0

    def task() -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        started.set()
        release.wait(timeout=5)
        with lock:
            active -= 1
        return "done"

    runner = ThreadedGroundingRunner()
    result_holder: list[tuple[int, str]] = []

    def collect() -> None:
        result_holder.extend(
            runner.run_tasks((task, task, task), max_workers=1, timeout=5)
        )

    thread = threading.Thread(target=collect)
    thread.start()
    assert started.wait(timeout=1)
    time.sleep(0.05)
    assert peak == 1
    release.set()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert result_holder == [(0, "done"), (1, "done"), (2, "done")]


def test_threaded_grounding_runner_times_out_single_task() -> None:
    release = threading.Event()

    def slow_task() -> str:
        release.wait(timeout=5)
        return "slow"

    task = ThreadedGroundingRunner().start_task(slow_task)
    try:
        with pytest.raises(TimeoutError):
            task.result(timeout=0.05)
    finally:
        release.set()


def test_scenario_binder_reads_explicit_promotion_environment(
    monkeypatch,
    method_spec,
    scenario_position,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS", "1")
    monkeypatch.setenv("CLOUD_DAST_MAX_PROMOTED_NORMS", "1")
    action = Atom(value=f"action:{method_spec.method_id}")
    source = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )

    binder = RunProvider(
        model_client=PromotionModelClient(f"action:{method_spec.method_id}")
    ).scenario_binder(
        SingleMethodRepository(method_spec),
        SingleScenarioRepository(scenario_position),
        SingleFormalRepository(source),
        select_promotion_policy(),
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service="lockbox",
            principal_id="attacker",
            resource_id="resource",
        )
    )

    assert binding.plan.invariants
    assert binding.execution.paths


def test_fuzz_session_factory_builds_session_for_qdl_step(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    provider = RunProvider()
    template = provider.template_generator()
    symbolic = provider.symbolic_generator(template)
    fuzzing = provider.fuzzing_generator(provider.minimal_seed_generator(template))
    textual = provider.textual_generator(template)
    bandit = provider.generator_bandit()
    corpus = provider.payload_corpus()
    selector = provider.generator_selector(
        template,
        symbolic,
        fuzzing,
        textual,
        bandit,
        corpus,
    )
    catalog = provider.generator_catalog(selector, StaticOobUrls(), corpus)
    assert "grammar" in selector.strategies
    assert "textual" in selector.strategies
    assert isinstance(selector.select("symbolic"), Z3SymbolicGenerator)

    symbolic_method = MethodSpec(
        method_id="example.Service.Write",
        service="example",
        name="Write",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(
                name="limit",
                type="int32",
                required=True,
                minimum=0,
                maximum=100,
            ),
        ),
    )
    symbolic_plan = VerificationPlan(
        plan_id="plan:symbolic",
        invariant_id=invariant.invariant_id,
        method_id=symbolic_method.method_id,
        scenario_id=scenario_position.scenario_id,
    )
    candidate = selector.select("symbolic").generate(
        symbolic_plan,
        symbolic_method,
        invariant,
        scenario_position,
    )[0]
    assert candidate.generator == "symbolic"
    value = dict(candidate.request)["limit"]
    assert isinstance(value, int)
    assert 0 <= value <= 100

    factory = provider.fuzz_session_factory(
        catalog,
        bandit,
        AllowAllGuardrail(),
        corpus,
        InMemoryExampleDatabase(),
        provider.promotion_policy(),
    )
    step = QdlExecutionStep(
        step_id="step:factory",
        goal_id="goal:factory",
        plan=verification_plan,
        method=method_spec,
        scenario=scenario_position,
        invariant=invariant,
    )

    session = factory(step)

    assert isinstance(session, FuzzSession)
    assert session.next() is not None


def test_fuzz_session_factory_preserves_qdl_payload_hints(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    provider = RunProvider()
    template = provider.template_generator()
    symbolic = provider.symbolic_generator(template)
    fuzzing = provider.fuzzing_generator(provider.minimal_seed_generator(template))
    textual = provider.textual_generator(template)
    bandit = provider.generator_bandit()
    corpus = provider.payload_corpus()
    selector = provider.generator_selector(
        template,
        symbolic,
        fuzzing,
        textual,
        bandit,
        corpus,
    )
    catalog = provider.generator_catalog(selector, StaticOobUrls(), corpus)
    marker_method = method_spec.model_copy(
        update={
            "fields": (
                *method_spec.fields,
                FieldSpec(name="template", type="string"),
            )
        }
    )
    marker_invariant = invariant.model_copy(
        update={
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:marker"),
                    reached(
                        Atom(value=f"action:{verification_plan.method_id}"),
                        Atom(value="dast-marker-42"),
                    ),
                ),
            )
        }
    )
    marker_plan = verification_plan.model_copy(
        update={"probe_fields": ("template",)},
    )
    factory = provider.fuzz_session_factory(
        catalog,
        bandit,
        AllowAllGuardrail(),
        corpus,
        InMemoryExampleDatabase(),
        provider.promotion_policy(),
    )
    step = QdlExecutionStep(
        step_id="step:marker",
        goal_id="goal:marker",
        plan=marker_plan,
        method=marker_method,
        scenario=scenario_position,
        invariant=marker_invariant,
    )

    session = factory(step)
    check = session.next() if session is not None else None

    assert check is not None
    assert check.probe_marker is not None
    assert check.probe_marker.startswith("dast_marker_42_")
    assert dict(check.request).get("template") == check.probe_marker


def test_fuzz_session_factory_rejects_invalid_budget(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_FUZZ_MAX_CHECKS", "0")
    provider = RunProvider()
    template = provider.template_generator()
    symbolic = provider.symbolic_generator(template)
    fuzzing = provider.fuzzing_generator(provider.minimal_seed_generator(template))
    textual = provider.textual_generator(template)
    bandit = provider.generator_bandit()
    corpus = provider.payload_corpus()
    selector = provider.generator_selector(
        template,
        symbolic,
        fuzzing,
        textual,
        bandit,
        corpus,
    )
    catalog = provider.generator_catalog(selector, StaticOobUrls(), corpus)

    try:
        provider.fuzz_session_factory(
            catalog,
            bandit,
            AllowAllGuardrail(),
            corpus,
            InMemoryExampleDatabase(),
            provider.promotion_policy(),
        )
    except RuntimeError as error:
        assert "CLOUD_DAST_FUZZ_MAX_CHECKS" in str(error)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("invalid fuzz budget must be rejected")


def test_container_wires_fuzz_session_factory_into_bound_path_runner(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")

    @contextmanager
    def session_factory() -> Iterator[object]:
        yield object()

    class EmptyEventStore:
        def append(self, event: object) -> None:
            return None

        def read(self) -> Iterator[object]:
            return iter(())

        def read_new(self, consumer_id: str) -> tuple[object, ...]:
            return ()

    def target(check: Check) -> Observation:
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.DENIED,
            response_summary="denied",
            transport_status=HttpStatus(code=403),
        )

    container = make_cloud_dast_container(
        session_factory,
        target,
        EmptyEventStore(),
    )

    with container as app, app() as run:
        assert isinstance(run.get(BoundPathRunner), BoundPathRunner)
