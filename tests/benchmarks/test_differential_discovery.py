"""D4 end-to-end: measured variance becomes a norm, then a grounded finding.

The cycle proven here is the differential discovery loop: a paired
control/treatment execution of ``ExportData`` measures a value variance, the
shape-only context is sent to the (faked) model, the returned possession norm
is promoted under the ``diff:`` prefix, a fresh treatment probe violates it
through the deterministic field-exposure oracle, and the second run's binder
reuses the persisted norm.  The victim's own export stays a PASS — the norm is
scoped to the attacker principal.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable

from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import EXPORT_DATA, SERVICE, methods
from benchmarks.nsfy_bench.graph import build_graph

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    EndpointLayer,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
    VerdictStatus,
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
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, Struct
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.graph import (
    Assembler,
)
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
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import make_grounding
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
    """In-memory append-only formal store with provenance capture."""

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
    """The two stand positions of the differential pair.

    The campaign runs as the attacker (the request principal, whose profile
    identity class is ``attacker``); the resource owner resolves as the
    control leg.  Each position addresses its own user resource, which is
    what makes the measured ``data`` variance observable.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        identity_class = kwargs.get("identity_class")
        self.calls.append((principal_id, resource_id, identity_class))
        if principal_id == "victim" and identity_class == "owner":
            return _position("export-owner", "owner", "victim")
        if principal_id == "attacker":
            return _position("export-attacker", "attacker", "attacker")
        return None


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


def _position(
    scenario_id: str,
    identity_class: str,
    principal: str,
) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id=scenario_id,
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class=identity_class,
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service=SERVICE,
                    resource_type="profile",
                    resource_id=principal,
                ),
            ),
            principals=(PrincipalRef(principal_id=principal, principal_type="user"),),
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


ACTION = f"action:{EXPORT_DATA}"
NORM = "norm:diff-export-data"
ATTACKER = _atom("principal:attacker")
RESOURCE = _atom("resource:profile")
DATA_FIELD = _struct("field", RESOURCE, _atom("data"))


def _variance_payload() -> dict:
    """The possession norm the fake model returns for the variance call.

    ``prevents(N, has(attacker, field(profile, data)))`` compiles to the
    deterministic ``response_field`` primitive; the ``exposes`` fact binds
    the norm to the ExportData action through the witness
    ``field(resource:profile, data)``.
    """

    return {
        "context": "proposal",
        "facts": [
            _fact("is", _atom(NORM), _atom("Norm")),
            _fact("is", ATTACKER, _atom("Subject")),
            _fact("is", RESOURCE, _atom("Resource")),
            _fact("is", DATA_FIELD, _atom("OutputField")),
            _fact("is", _atom(ACTION), _atom("Action")),
            _fact("exposes", _atom(ACTION), DATA_FIELD),
            _fact("has", DATA_FIELD, _atom("sensitive")),
            _fact(
                "prevents",
                _atom(NORM),
                _struct("has", ATTACKER, DATA_FIELD),
            ),
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


def _seeded_state() -> BenchState:
    state = BenchState.seed()
    # The treatment leg exports the attacker's own record: the data field
    # then differs from the victim's control leg, which is the measurable
    # variance the cycle starts from.
    state.users["attacker"] = {
        "user_id": "attacker",
        "display_name": "Attacker",
        "email": "attacker@example.test",
        "password_hash": "$argon2id$v=19$attacker",
    }
    return state


def _has_data_possession_norms(graph: QdlGraph) -> list:
    return [
        fact
        for fact in graph.facts
        if fact.predicate.name == "prevents"
        and len(fact.args) == 2
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "has"
        and _effect_field_name(fact.args[1]) == "data"
    ]


def _effect_field_name(effect: Struct) -> str | None:
    value = effect.args[1] if len(effect.args) == 2 else None
    if not isinstance(value, Struct) or value.name != "field" or len(value.args) != 2:
        return None
    name = value.args[1]
    return getattr(name, "value", None)


def _build_campaign(*, diff_mode: bool):
    """Assemble the full real-component campaign over the bench service."""

    repository = FormalRepository()
    victim_resource = Atom(value="resource:victim")
    victim_subject = Atom(value="subject:victim")
    owner_facts = (
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(victim_resource, Atom(value="Resource")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("is"),
            args=(victim_subject, Atom(value="Subject")),
        ),
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("owner"),
            args=(victim_resource, victim_subject),
        ),
    )
    answer_key = QdlGraph(facts=(*build_graph().facts, *owner_facts))
    repository.save(
        f"contract:{SERVICE}",
        answer_key,
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    events = EventLog()
    bus = _bus(events)
    metrics = CampaignMetrics()
    checker = Checker(
        BenchTarget(BenchService(_seeded_state())),
        TemplateGenerator(),
        AllowAllGuardrail(),
        bus,
    )
    service_workflow = checker
    event_projection = EventProjection(bus, events)
    runner = assemble_runner(
        service_workflow,
        event_projection,
        grounded_oracle=GroundedOutcomeOracle(),
        primitive_oracle=PrimitiveOracleRouter(),
        formal_repository=repository,
    )
    scenario_repo = ScenarioRepo()
    binder = ScenarioBinder(
        MethodRepo(), scenario_repo, repository, qdl_planner=IncrementalQdlPlanner()
    )
    client = VarianceModelClient(_variance_payload())
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
            diff_modes=frozenset({"factors"}),
            scenario_repository=scenario_repo,
            formal_repository=repository,
            event_bus=bus,
            metrics=metrics,
        ),
    )
    request = LiveRequest(
        service=SERVICE,
        principal_id="attacker",
        resource_id="victim",
        method_id=EXPORT_DATA,
    )
    return {
        "repository": repository,
        "events": events,
        "metrics": metrics,
        "client": client,
        "scenario_repo": scenario_repo,
        "service_workflow": service_workflow,
        "workflow": workflow,
        "request": request,
        "answer_key": answer_key,
    }


def test_diff_mode_off_by_default_executes_no_pairs() -> None:
    campaign = _build_campaign(diff_mode=False)

    result = campaign["workflow"].execute(campaign["request"])

    assert not [
        event
        for event in campaign["events"].events
        if isinstance(event, DiffPairComputed)
    ]
    assert not [
        item
        for item in campaign["repository"].saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
    ]
    assert campaign["metrics"].snapshot().diff_pairs_evaluated == 0
    # The ordinary permission probe runs. A marker norm without a carrier
    # remains a graph obligation and must not spend another transport call.
    assert len(result.observations) == 1
    assert any(
        isinstance(event, QdlPathEvaluated)
        and event.action_id == EXPORT_DATA
        and event.probe_count == 0
        and "probe_carrier" in event.reason
        for event in campaign["events"].events
    )


def test_diff_mode_environment_flag_defaults_off(monkeypatch) -> None:
    from cloud_dast.composition.run_provider import _diff_mode_from_environment

    monkeypatch.delenv("CLOUD_DAST_DIFF_MODE", raising=False)
    assert _diff_mode_from_environment() is False
    monkeypatch.setenv("CLOUD_DAST_DIFF_MODE", "1")
    assert _diff_mode_from_environment() is True
    monkeypatch.setenv("CLOUD_DAST_DIFF_MODE", "off")
    assert _diff_mode_from_environment() is False


def test_differential_discovery_promotes_norm_and_finds_export() -> None:
    campaign = _build_campaign(diff_mode=True)
    repository = campaign["repository"]
    answer_key = campaign["answer_key"]
    events = campaign["events"]
    metrics = campaign["metrics"]
    client = campaign["client"]
    # Precondition: the answer key has no possession norm for the data
    # field — the diff cycle must discover it, not inherit it.
    assert _has_data_possession_norms(answer_key) == []
    workflow = campaign["workflow"]
    request = campaign["request"]
    scenario_repo = campaign["scenario_repo"]
    service_workflow = campaign["service_workflow"]
    result = workflow.execute(request)

    # --- The pair executed and measured the data variance. ---
    diff_events = [
        event for event in events.events if isinstance(event, DiffPairComputed)
    ]
    assert len(diff_events) == 1
    pair_event = diff_events[0]
    assert pair_event.action_id == EXPORT_DATA
    assert pair_event.has_variance is True
    assert pair_event.dimensions == ("value",)
    assert pair_event.control_observation_id is not None
    assert pair_event.treatment_observation_id is not None
    pair_observations = {
        observation.observation_id: observation
        for observation in result.observations
        if observation.observation_id
        in {
            pair_event.control_observation_id,
            pair_event.treatment_observation_id,
        }
    }
    control = pair_observations[pair_event.control_observation_id]
    treatment = pair_observations[pair_event.treatment_observation_id]
    control_fields = dict(control.output.fields)
    treatment_fields = dict(treatment.output.fields)
    assert control_fields["user_id"] == "victim"
    assert treatment_fields["user_id"] == "attacker"
    # The response echoes the requested user id, so both whitelisted fields
    # vary; the meaningful signal is that the data field carries
    # principal-dependent content.
    report = compare_observations(EXPORT_DATA, control, treatment)
    assert report.value_differs == ("data", "user_id")
    assert report.has_variance
    assert metrics.snapshot().diff_pairs_evaluated == 1

    # --- The model saw the bounded paired values. Raw domain observations stay separate. ---
    variance_requests = [
        request
        for request in client.requests
        if request.task == "formal_grounding_variance"
    ]
    assert len(variance_requests) == 1
    context = variance_requests[0].context
    evidence = context["evidence"]
    assert "paired_observations" not in context
    assert {leaf["path"] for leaf in evidence["control"]["response"]["leaves"]} == {
        "user_id",
        "data",
    }
    assert {leaf["path"] for leaf in evidence["treatment"]["response"]["leaves"]} == {
        "user_id",
        "data",
    }
    for projected, actual in (
        (evidence["control"], control),
        (evidence["treatment"], treatment),
    ):
        values = {
            leaf["path"]: leaf["value"] for leaf in projected["response"]["leaves"]
        }
        assert values == dict(actual.output.fields)
    assert {item["path"] for item in evidence["diff"]["value_differs"]} == {
        "user_id",
        "data",
    }
    rendered = json.dumps(context, ensure_ascii=False)
    assert "victim@example.test" not in rendered
    assert "attacker@example.test" not in rendered
    assert "$argon2id" not in rendered
    assert context["diff_report"]["dimensions"] == ["value"]

    # --- The norm was promoted and persisted under the diff: prefix. ---
    diff_saves = [
        item
        for item in repository.saved
        if item["source_id"].startswith(f"diff:{SERVICE}:")
    ]
    campaign_saves = [
        item
        for item in diff_saves
        if item["provenance"]["source_kind"] == "diff-campaign"
    ]
    runtime_saves = [
        item
        for item in diff_saves
        if item["provenance"]["source_kind"] == "diff-runtime"
    ]
    assert campaign_saves
    assert all(
        item["adapter_version"] == "diff-grounding-v1" for item in campaign_saves
    )
    assert runtime_saves
    assert metrics.snapshot().diff_norms_promoted == 1

    # --- The fresh treatment probe produced a grounded FAIL finding. ---
    finding_events = [
        event for event in events.events if isinstance(event, FindingRaised)
    ]
    diff_findings = [
        event.finding for event in finding_events if NORM in event.finding.invariant_id
    ]
    assert diff_findings
    assert any(finding.method_id == EXPORT_DATA for finding in diff_findings)
    assert any(NORM in finding.invariant_id for finding in result.findings)
    # The finding never cites the control leg as its evidence.
    assert all(
        pair_event.control_observation_id not in finding.evidence_refs
        for finding in diff_findings
    )

    # --- Control: the victim's self-export stays a grounded PASS. ---
    binder2 = ScenarioBinder(
        MethodRepo(), scenario_repo, repository, qdl_planner=IncrementalQdlPlanner()
    )
    binding2 = binder2.bind(request)
    diff_invariants = [
        invariant
        for invariant in binding2.execution.invariants.values()
        if NORM in invariant.invariant_id
    ]
    assert diff_invariants
    diff_invariant = diff_invariants[0]
    export_method = next(
        method for method in methods() if method.method_id == EXPORT_DATA
    )
    victim = scenario_repo.get_scenario(
        "victim",
        "victim",
        method=export_method,
        identity_class="owner",
    )
    control_checks = service_workflow.generate_pair_checks(
        VerificationPlan(
            plan_id="plan:diff-control-probe",
            invariant_id=diff_invariant.invariant_id,
            method_id=EXPORT_DATA,
            scenario_id=victim.scenario_id,
        ),
        export_method,
        diff_invariant,
        victim,
    )
    assert control_checks
    control_observation = service_workflow.execute_check(control_checks[0])
    assert control_observation is not None
    control_verdict = PrimitiveOracleRouter().evaluate_policy(
        diff_invariant,
        (control_observation,),
        method=export_method,
        scenario=victim,
    )
    assert control_verdict.status is VerdictStatus.UNSCOREABLE
    assert control_verdict.deterministic is True
    assert control_verdict.grounded is False
    assert [deficit.kind for deficit in control_verdict.deficits] == ["principal_scope"]

    # --- Second run: the binder reuses the persisted diff norm. ---
    diff_invariant_ids = {invariant.invariant_id for invariant in diff_invariants}
    assert any(
        step.plan.invariant_id in diff_invariant_ids
        for path in binding2.execution.paths
        for step in path.steps
    )
    assert any(
        fact.predicate.name == "prevents" and fact.args[0].value == NORM
        for fact in Assembler(
            repository,
            None,
            PromotionPolicy(enabled=False),
        )
        .load(SERVICE)
        .facts
    )
