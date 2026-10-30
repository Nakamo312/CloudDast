"""RFC §9.1 differential modes on the bench.

All modes share the factor-pair pipeline end to end: an isolated paired
execution, the deterministic comparator, an ``unexplained_variance``
deficit, and a (faked) variance-grounding proposal persisted under the
``diff:`` namespace.  What the modes vary is the experiment: payload pairs
mutate the request of one scenario, read-back pairs measure the resource
state before and after a mutated write, timing pairs repeat robust latency
classes, and concurrency batches aggregate parallel probes.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable

from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import (
    CHECK_USERNAME,
    SEARCH_ORDERS,
    SERVICE,
    UPDATE_ORDER,
    methods,
)
from benchmarks.nsfy_bench.graph import build_graph

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    HttpStatus,
    Observation,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.model.events import (
    CheckCompleted,
    DiffPairComputed,
    DomainEvent,
    EvidenceRecorded,
    FactVerified,
    FindingRaised,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    QdlGraph,
    Struct,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.differential.comparator import (
    compare_observations,
)
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast.verification.oracles.witness import WitnessSignalOracle
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_fuzzing.strategies.goal_payload import (
    GoalPayloadGenerator,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import commit_variance, make_grounding
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self) -> Iterable[DomainEvent]:
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class FormalRepository:
    """In-memory append-only formal store."""

    def __init__(self) -> None:
        self.saved: list[dict] = []

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
        from cloud_dast.qdl.graph_ops import merge_graphs

        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


class MethodRepo:
    def list_methods(self, service):
        return methods()


class ScenarioRepo:
    """The attacker position on the victim's order.

    No owner position is resolvable, so factor pairs are skipped when
    enabled — the campaigns here measure only the mode under test.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        identity_class = kwargs.get("identity_class", "attacker")
        self.calls.append((principal_id, resource_id, identity_class))
        if identity_class != "attacker":
            return None
        return _attacker_position(method)


class OwnerAttackerScenarioRepo(ScenarioRepo):
    """Resolve both legs required by a timing factor pair."""

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        identity_class = kwargs.get("identity_class", "attacker")
        self.calls.append((principal_id, resource_id, identity_class))
        if identity_class == "attacker":
            return _attacker_position(method)
        if identity_class == "owner":
            return _owner_position(method)
        return None


class TimingBenchTarget:
    """Give the owner and attacker legs distinct deterministic durations."""

    def __init__(self, inner: Callable[[Check], Observation]) -> None:
        self._inner = inner

    def __call__(self, check) -> Observation:
        observation = self._inner(check)
        duration_ms = 10.0 if check.scenario_id.startswith("owner-") else 100.0
        return observation.model_copy(update={"duration_ms": duration_ms})


class MixedConcurrencyBenchTarget:
    """Alternate allowed/error outcomes so any four probes are mixed."""

    def __init__(self, inner: Callable[[Check], Observation]) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._calls = 0

    def __call__(self, check) -> Observation:
        with self._lock:
            index = self._calls
            self._calls += 1
        observation = self._inner(check)
        if index % 2 == 0:
            return observation
        return observation.model_copy(
            update={
                "observed_outcome": AccessOutcome.ERROR,
                "transport_status": HttpStatus(code=500),
                "response_summary": "concurrent probe failed",
            }
        )


class VarianceModelClient:
    """Fake model: one scripted variance answer, empty startup answers."""

    def __init__(self, variance_payload: dict) -> None:
        self.variance_payload = variance_payload
        self.requests: list[ModelRequest] = []
        self._lock = threading.Lock()

    def complete(self, request: ModelRequest, *, response_type=None) -> ModelResponse:
        with self._lock:
            self.requests.append(request)
        if request.task == "formal_grounding_variance":
            payload = self.variance_payload
        else:
            payload = {"context": "proposal", "facts": [], "rules": []}
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="fake-model",
        )


def _attacker_position(method) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id=f"attacker-{method.method_id.rsplit('.', 1)[-1].lower()}",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service=SERVICE,
                    resource_type="order",
                    resource_id="order-1001",
                ),
            ),
            principals=(PrincipalRef(principal_id="attacker", principal_type="user"),),
            permissions_known=True,
        ),
    )


def _owner_position(method) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id=f"owner-{method.method_id.rsplit('.', 1)[-1].lower()}",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="owner",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service=SERVICE,
                    resource_type="order",
                    resource_id="order-1001",
                ),
            ),
            principals=(PrincipalRef(principal_id="victim", principal_type="user"),),
            permissions_known=True,
        ),
    )


def _atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _struct(name: str, *args: dict) -> dict:
    return {"kind": "struct", "name": name, "args": list(args)}


def _fact(predicate: str, *args: dict) -> dict:
    return {
        "context": "proposal",
        "predicate": predicate,
        "args": list(args),
    }


def _reached_norm_payload() -> dict:
    """The sink-reachability norm the fake model returns for SearchOrders."""

    action = _atom(f"action:{SEARCH_ORDERS}")
    norm = _atom("norm:diff-sql-injection-search")
    sink = _atom("sink:sql_engine")
    resource = _atom("resource:order")
    error_field = _struct("field", resource, _atom("error_message"))
    return {
        "context": "proposal",
        "facts": [
            _fact("is", norm, _atom("Norm")),
            _fact("is", action, _atom("Action")),
            _fact("is", sink, _atom("Sink")),
            _fact("is", resource, _atom("Resource")),
            _fact("is", error_field, _atom("OutputField")),
            _fact("exposes", action, error_field),
            _fact(
                "is",
                _struct("input_field", action, _atom("query")),
                _atom("Field"),
            ),
            _fact(
                "reaches",
                _struct("input_field", action, _atom("query")),
                sink,
            ),
            _fact("prevents", norm, _struct("reached", action, sink)),
        ],
        "rules": [],
    }


def _graph_with_declared_sql_sink() -> QdlGraph:
    """Return the bench graph with the campaign's grounded semantic layer.

    Besides the operator-approved sink classification this relies on the
    contract-declared ``payload`` field roles: payload pairs and read-back
    write legs mutate only fields whose mutability the graph declares
    explicitly.
    """

    return build_graph()


def _changed_norm_payload() -> dict:
    """The state-change norm the fake model returns for UpdateOrder."""

    action = _atom(f"action:{UPDATE_ORDER}")
    norm = _atom("norm:diff-mass-assign-total")
    order = _atom("resource:order")
    return {
        "context": "proposal",
        "facts": [
            _fact("is", norm, _atom("Norm")),
            _fact("is", action, _atom("Action")),
            _fact("is", order, _atom("Resource")),
            _fact("prevents", norm, _struct("changed", order, _atom("total"))),
        ],
        "rules": [],
    }


def _latency_norm_payload(action: str, threshold_ms: int) -> dict:
    """The latency-bound norm the fake model returns for a timing variance."""

    action_atom = _atom(f"action:{action}")
    norm = _atom("norm:diff-latency-bound")
    return {
        "context": "proposal",
        "facts": [
            _fact("is", norm, _atom("Norm")),
            _fact("is", action_atom, _atom("Action")),
            _fact(
                "prevents",
                norm,
                _struct(
                    "duration",
                    action_atom,
                    {
                        "kind": "atom",
                        "value": threshold_ms,
                        "literal_type": "integer",
                    },
                ),
            ),
        ],
        "rules": [],
    }


def _outcome_norm_payload(action: str) -> dict:
    """A generic deterministic norm for an aggregate outcome variance."""

    action_atom = _atom(f"action:{action}")
    norm = _atom("norm:diff-concurrent-outcome")
    return {
        "context": "proposal",
        "facts": [
            _fact("is", norm, _atom("Norm")),
            _fact("is", action_atom, _atom("Action")),
            _fact("prevents", norm, _struct("denied", action_atom)),
        ],
        "rules": [],
    }


def _bus(events: EventLog) -> EventBus:
    bus = EventBus()
    for event_type in (
        CheckCompleted,
        DiffPairComputed,
        EvidenceRecorded,
        FactVerified,
        FindingRaised,
        QdlPathEvaluated,
        QdlStepEvaluated,
    ):
        bus.subscribe(event_type, events.append)
    return bus


def _build_campaign(
    *,
    target_method: str,
    diff_mode: bool,
    diff_modes: frozenset[str] | None,
    variance_payload: dict,
    max_checks: int | None = None,
    target: Callable | None = None,
    scenario_repository: ScenarioRepo | None = None,
    latency_oracle: LatencyOracle | None = None,
):
    """Assemble the full real-component campaign over the bench service."""

    repository = FormalRepository()
    repository.save(
        f"contract:{SERVICE}",
        _graph_with_declared_sql_sink(),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    events = EventLog()
    bus = _bus(events)
    metrics = CampaignMetrics()
    latency_oracle = latency_oracle or LatencyOracle()
    checker = Checker(
        target or BenchTarget(BenchService(BenchState.seed())),
        GoalPayloadGenerator(TemplateGenerator()),
        AllowAllGuardrail(),
        bus,
    )
    service_workflow = checker
    event_projection = EventProjection(bus, events)
    runner = assemble_runner(
        service_workflow,
        event_projection,
        grounded_oracle=GroundedOutcomeOracle(),
        primitive_oracle=PrimitiveOracleRouter(
            witness_oracle=WitnessSignalOracle(latency_oracle=latency_oracle)
        ),
        formal_repository=repository,
    )
    scenario_repo = scenario_repository or ScenarioRepo()
    binder = ScenarioBinder(
        MethodRepo(), scenario_repo, repository, qdl_planner=IncrementalQdlPlanner()
    )
    client = VarianceModelClient(variance_payload)
    grounder_options_1 = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=64,
        max_workers=2,
    )
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=Bootstrap(options=grounder_options_1),
        reactive=Followup(options=grounder_options_1),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    workflow = assemble_workflow(
        binder,
        runner,
        FindingEvaluator(event_projection),
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            grounding_runner=ThreadedGroundingRunner(),
            reactive_budget=4,
            diff_mode=diff_mode,
            diff_modes=diff_modes,
            scenario_repository=scenario_repo,
            formal_repository=repository,
            event_bus=bus,
            metrics=metrics,
            latency_oracle=latency_oracle,
        ),
    )
    request = LiveRequest(
        service=SERVICE,
        principal_id="attacker",
        resource_id="order-1001",
        method_id=target_method,
        max_checks=max_checks,
    )
    return {
        "repository": repository,
        "events": events,
        "metrics": metrics,
        "client": client,
        "workflow": workflow,
        "request": request,
    }


def test_payload_pair_measures_sqli_variance_and_proposes_norm() -> None:
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=True,
        diff_modes=frozenset({"payload"}),
        variance_payload=_reached_norm_payload(),
    )
    result = campaign["workflow"].execute(campaign["request"])
    events = campaign["events"]
    metrics = campaign["metrics"]
    client = campaign["client"]

    # --- The payload pair executed and measured the error-channel variance. ---
    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    pair_event = diff_events[0]
    assert pair_event.action_id == SEARCH_ORDERS
    assert pair_event.has_variance is True
    assert pair_event.dimensions == ("fields",)
    observations = {
        observation.observation_id: observation for observation in result.observations
    }
    baseline = observations[pair_event.control_observation_id]
    treatment = observations[pair_event.treatment_observation_id]
    assert baseline.scenario_id == treatment.scenario_id
    assert "error_message" not in dict(baseline.output.fields)
    treatment_fields = dict(treatment.output.fields)
    assert "error_message" in treatment_fields
    assert "dastpayload" in treatment_fields["error_message"]
    report = compare_observations(SEARCH_ORDERS, baseline, treatment)
    assert report.fields_only_treatment == ("error_message",)
    assert report.has_variance
    assert metrics.snapshot().diff_pairs_evaluated == 1
    assert metrics.snapshot().diff_pairs_by_mode == {"payload": 1}

    # A measured canary echo is structural evidence, not an executable norm.
    # The model still has to propose the reached-norm before promotion.
    variance_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_variance"
    ]
    assert len(variance_requests) == 1

    # --- The sink-reachability norm was promoted under the diff: prefix. ---
    diff_saves = [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
        and item["provenance"]["source_kind"] == "diff-campaign"
    ]
    assert diff_saves
    promoted_facts = [
        fact
        for save in diff_saves
        for fact in save["graph"].facts
        if fact.predicate.name == "prevents"
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "reached"
    ]
    assert promoted_facts
    assert metrics.snapshot().diff_norms_promoted == 1


def test_error_channel_canary_is_evidence_but_not_executable_norm() -> None:
    """A SearchOrders-like error reflection is persisted without promotion."""

    repository = FormalRepository()
    repository.save(
        f"contract:{SERVICE}",
        build_graph(),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    client = VarianceModelClient({"context": "proposal", "facts": [], "rules": []})
    grounder_options_2 = GrounderOptions(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=64,
        max_workers=2,
    )
    grounding = make_grounding(
        repository,
        ingest_contract=None,
        project_stand=None,
        startup=Bootstrap(options=grounder_options_2),
        reactive=Followup(options=grounder_options_2),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    control_check = Check(
        invariant_id="norm:test-error-reflection",
        method_id=SEARCH_ORDERS,
        scenario_id="attacker-search",
        request=(("query", "benign"),),
        identities=("attacker",),
    )
    treatment_check = Check(
        invariant_id="norm:test-error-reflection",
        method_id=SEARCH_ORDERS,
        scenario_id="attacker-search",
        request=(("query", "'dastpayloadgeneric'"),),
        identities=("attacker",),
    )
    control = Observation(
        check_id=control_check.check_id,
        scenario_id=control_check.scenario_id,
        observed_outcome=AccessOutcome.ERROR,
        response_summary="query rejected",
        transport_status=HttpStatus(code=400),
        error_reason="unrecognized token: benign",
    )
    treatment = Observation(
        check_id=treatment_check.check_id,
        scenario_id=treatment_check.scenario_id,
        observed_outcome=AccessOutcome.ERROR,
        response_summary="query rejected",
        transport_status=HttpStatus(code=400),
        error_reason="unrecognized token: dastpayloadgeneric",
    )

    report = compare_observations(SEARCH_ORDERS, control, treatment)
    assert report.dimensions == ("error",)

    promoted = commit_variance(
        grounding,
        SERVICE,
        SEARCH_ORDERS,
        control,
        treatment,
        report,
        control_check=control_check,
        treatment_check=treatment_check,
        llm=False,
    )

    assert promoted is None
    assert client.requests == []
    measured = repository.saved[-1]
    assert measured["provenance"]["source_kind"] == "diff-measured-evidence"
    assert any(
        fact.predicate.name == "reaches"
        and str(fact.args[1].value).startswith("sink:canary-echo:query:")
        for fact in measured["graph"].facts
    )
    assert not any(
        fact.predicate.name == "prevents" for fact in measured["graph"].facts
    )


def test_payload_variance_does_not_compile_measured_echo_into_executable_norm() -> None:
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=True,
        diff_modes=frozenset({"payload"}),
        variance_payload={"context": "proposal", "facts": [], "rules": []},
    )
    campaign["workflow"].execute(campaign["request"])
    events = campaign["events"]

    diff_saves = [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
        and item["provenance"]["source_kind"] == "diff-campaign"
    ]
    measured_saves = [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
        and item["provenance"]["source_kind"] == "diff-measured-evidence"
    ]
    measured_reach = [
        fact
        for item in measured_saves
        for fact in item["graph"].facts
        if fact.predicate.name == "reaches"
    ]
    assert measured_reach
    assert diff_saves == []

    findings = [
        event.finding
        for event in events.events
        if isinstance(event, FindingRaised)
        and "measured-reach" in event.finding.invariant_id
    ]
    assert findings == []


def test_readback_measures_mass_assignment_and_proposes_changed_norm() -> None:
    campaign = _build_campaign(
        target_method=UPDATE_ORDER,
        diff_mode=True,
        diff_modes=frozenset({"readback"}),
        variance_payload=_changed_norm_payload(),
    )
    result = campaign["workflow"].execute(campaign["request"])
    events = campaign["events"]
    metrics = campaign["metrics"]
    client = campaign["client"]

    # --- The read-back pair measured the privileged total change. ---
    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    pair_event = diff_events[0]
    assert pair_event.action_id == UPDATE_ORDER
    assert pair_event.mode == "readback"
    assert pair_event.has_variance is True
    assert pair_event.dimensions == ("value",)
    observations = {
        observation.observation_id: observation for observation in result.observations
    }
    read_before = observations[pair_event.control_observation_id]
    read_after = observations[pair_event.treatment_observation_id]
    # The initial differential sweep runs before ordinary paths, so the
    # read-back baseline is the stand's untouched total rather than a value
    # polluted by an earlier template write.
    assert dict(read_before.output.fields)["total"] == 2500
    assert "dastpayload" in str(dict(read_after.output.fields)["total"])
    report = compare_observations(UPDATE_ORDER, read_before, read_after)
    assert report.value_differs == ("total",)
    assert metrics.snapshot().diff_pairs_evaluated == 1
    assert metrics.snapshot().diff_pairs_by_mode == {"readback": 1}

    # --- The model saw the bounded paired reads, including the canary value. ---
    variance_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_variance"
    ]
    assert len(variance_requests) == 1
    context = variance_requests[0].context
    evidence = context["evidence"]
    assert "paired_observations" not in context
    assert "total" in {
        leaf["path"] for leaf in evidence["control"]["response"]["leaves"]
    }
    assert "total" in {
        leaf["path"] for leaf in evidence["treatment"]["response"]["leaves"]
    }
    assert "dastpayload" in json.dumps(context)
    assert context["diff_report"]["dimensions"] == ["value"]

    # --- The changed-norm was proposed and persisted as a diff product. ---
    diff_saves = [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
        and item["provenance"]["source_kind"] == "diff-campaign"
    ]
    assert diff_saves
    promoted_facts = [
        fact
        for save in diff_saves
        for fact in save["graph"].facts
        if fact.predicate.name == "prevents"
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "changed"
    ]
    assert promoted_facts

    # --- The promoted changed-norm is verified by DifferentialOracle. ---
    # The read-back trace proves that the privileged field changed, so the
    # promoted norm is no longer only a model lead: it raises a finding.
    changed_findings = [
        event.finding
        for event in events.events
        if isinstance(event, FindingRaised)
        and "norm:diff-mass-assign-total" in event.finding.invariant_id
    ]
    assert len(changed_findings) == 1
    changed_finding = changed_findings[0]
    assert changed_finding.method_id == UPDATE_ORDER
    assert changed_finding.rationale.startswith(
        "forbidden resource field 'total' changed"
    )
    assert changed_finding.evidence_refs


def test_timing_mode_measures_robust_latency_and_promotes_bound_norm() -> None:
    campaign = _build_campaign(
        target_method=CHECK_USERNAME,
        diff_mode=True,
        diff_modes=frozenset({"timing"}),
        variance_payload=_latency_norm_payload(CHECK_USERNAME, 90),
        target=TimingBenchTarget(BenchTarget(BenchService(BenchState.seed()))),
        scenario_repository=OwnerAttackerScenarioRepo(),
    )
    result = campaign["workflow"].execute(campaign["request"])
    events = campaign["events"]
    metrics = campaign["metrics"]
    client = campaign["client"]

    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    pair_event = diff_events[0]
    assert pair_event.action_id == CHECK_USERNAME
    assert pair_event.mode == "timing"
    assert pair_event.dimensions == ("latency",)
    assert pair_event.has_variance is True
    assert metrics.snapshot().diff_pairs_evaluated == 1
    assert metrics.snapshot().diff_pairs_by_mode == {"timing": 1}

    variance_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_variance"
    ]
    assert len(variance_requests) == 1
    context = variance_requests[0].context
    assert context["diff_report"]["dimensions"] == ["latency"]
    assert "timing(" in context["diff_report"]["signature"]

    diff_saves = [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
        and item["provenance"]["source_kind"] == "diff-campaign"
    ]
    duration_norms = [
        fact
        for save in diff_saves
        for fact in save["graph"].facts
        if fact.predicate.name == "prevents"
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "duration"
    ]
    assert duration_norms

    latency_findings = [
        event.finding
        for event in events.events
        if isinstance(event, FindingRaised)
        and "norm:diff-latency-bound" in event.finding.invariant_id
    ]
    assert latency_findings
    assert latency_findings[0].evidence_refs
    assert any(
        observation.observation_id == latency_findings[0].observation_id
        for observation in result.observations
    )


def test_concurrency_mode_aggregates_parallel_probe_variance() -> None:
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=True,
        diff_modes=frozenset({"concurrency"}),
        variance_payload=_outcome_norm_payload(SEARCH_ORDERS),
        target=MixedConcurrencyBenchTarget(
            BenchTarget(BenchService(BenchState.seed()))
        ),
    )
    result = campaign["workflow"].execute(campaign["request"])
    events = campaign["events"]
    metrics = campaign["metrics"]
    client = campaign["client"]

    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    pair_event = diff_events[0]
    assert pair_event.action_id == SEARCH_ORDERS
    assert pair_event.mode == "concurrency"
    assert "aggregate" in pair_event.dimensions
    assert "outcome" in pair_event.dimensions
    assert pair_event.has_variance is True
    assert metrics.snapshot().diff_pairs_evaluated == 1
    assert metrics.snapshot().diff_pairs_by_mode == {"concurrency": 1}

    variance_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_variance"
    ]
    assert len(variance_requests) == 1
    context = variance_requests[0].context
    assert "aggregate" in context["diff_report"]["dimensions"]
    assert "concurrency(" in context["diff_report"]["signature"]

    # The mode is honest measurement, not a direct finding: its four probes
    # are evidence in the campaign result, while the only possible verdict
    # comes from the promoted norm and a deterministic oracle.
    assert len(result.observations) >= 5


def test_max_checks_prevents_a_partial_concurrency_batch() -> None:
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=True,
        diff_modes=frozenset({"concurrency"}),
        variance_payload=_reached_norm_payload(),
        max_checks=1,
    )
    result = campaign["workflow"].execute(campaign["request"])

    assert len(result.observations) <= 1
    assert not [
        event
        for event in campaign["events"].events
        if isinstance(event, DiffPairComputed)
    ]
    assert campaign["metrics"].snapshot().diff_pairs_evaluated == 0


def test_default_modes_are_factors_only(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_DIFF_MODES", raising=False)
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=True,
        diff_modes=None,
        variance_payload=_reached_norm_payload(),
    )
    campaign["workflow"].execute(campaign["request"])

    # No owner position is resolvable, so the default factors-only round
    # evaluates no pair at all — payload mode must not run implicitly.
    assert not [
        event
        for event in campaign["events"].events
        if isinstance(event, DiffPairComputed)
    ]
    assert campaign["metrics"].snapshot().diff_pairs_evaluated == 0
    assert campaign["metrics"].snapshot().diff_pairs_by_mode == {}


def test_master_switch_disables_all_modes() -> None:
    campaign = _build_campaign(
        target_method=SEARCH_ORDERS,
        diff_mode=False,
        diff_modes=frozenset({"payload", "readback"}),
        variance_payload=_reached_norm_payload(),
    )
    campaign["workflow"].execute(campaign["request"])

    assert not [
        event
        for event in campaign["events"].events
        if isinstance(event, DiffPairComputed)
    ]
    assert campaign["metrics"].snapshot().diff_pairs_evaluated == 0
