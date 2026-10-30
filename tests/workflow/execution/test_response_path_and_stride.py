"""S19 acceptance: response paths and STRIDE labels come from QDL facts."""

from __future__ import annotations

from cloud_dast.candidates import (
    TemplateGenerator,
)
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest, ScenarioBinding
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
    VerificationPlan,
)
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    ExecutionTrace,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    TraceStep,
)
from cloud_dast.model.events import DomainEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
    allowed,
    field,
    has,
    output_field,
)
from cloud_dast.qdl.reasoning import QdlPlan, QdlSubgoal
from cloud_dast.runtime.deficits import (
    Deficit,
    grounding_result_closes_deficit,
    response_semantics_deficits,
)
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.coverage import Builder
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _binding(graph: QdlGraph) -> ScenarioBinding:
    graph_hash = graph.content_hash
    return ScenarioBinding(
        scenario=_scenario(),
        graph=graph,
        plan=QdlPlan(graph_hash=graph_hash),
        execution=QdlExecutionView(graph_hash=graph_hash, paths=(), invariants={}),
        invariants={},
        methods=(),
    )


def _graph_with_exposed_path(action_key: str, output_path: str) -> QdlGraph:
    action = Atom(value=action_key)
    resource = Atom(value="resource:secret")
    witness = field(Atom(value="resource:secret"), Atom(value=output_path))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (witness, Atom(value="Witness"))),
            _fact("exposes", (action, witness)),
        )
    )


def _response_observation(
    response_tree: tuple[tuple[str, object], ...],
    *,
    observation_id: str = "observation:response",
) -> Observation:
    return Observation(
        check_id="check:response",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="structured response",
        response_tree=response_tree,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id="step:response",
                    method_id="svc.GetUser",
                    scenario_id="scenario",
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
        observation_id=observation_id,
    )


def test_response_semantics_deficit_keeps_distinct_output_paths() -> None:
    """``items.0.foo.bar`` and ``metadata.bar`` never collapse into one field."""

    deficits = response_semantics_deficits(
        _binding(QdlGraph()),
        (
            _response_observation(
                (
                    ("items.0.foo.bar", "value-1"),
                    ("metadata.bar", "value-2"),
                )
            ),
        ),
    )

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("exposes", "svc.GetUser", "response_semantics")
    ]
    context = dict(deficits[0].context)
    assert context["fields"] == "items.0.foo.bar,metadata.bar"


def test_exposed_output_path_does_not_ground_sibling_path() -> None:
    """Grounding one output path leaves a same-named sibling ungrounded."""

    binding = _binding(
        _graph_with_exposed_path("action:svc.GetUser", "items.0.foo.bar")
    )
    deficits = response_semantics_deficits(
        binding,
        (
            _response_observation(
                (
                    ("items.0.foo.bar", "value-1"),
                    ("metadata.bar", "value-2"),
                )
            ),
        ),
    )

    assert [dict(item.context)["fields"] for item in deficits] == ["metadata.bar"]


def test_output_field_role_grounds_response_path() -> None:
    """An accepted output-field role fact grounds exactly its own path."""

    action = Atom(value="action:svc.GetUser")
    output_path = "items.0.foo.bar"
    holder = output_field(action, Atom(value=output_path))
    binding = _binding(
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action"))),
                _fact("is", (holder, Atom(value="Field"))),
                _fact("has", (holder, Atom(value="sensitive"))),
            )
        )
    )
    deficits = response_semantics_deficits(
        binding,
        (_response_observation(((output_path, "value-1"),)),),
    )

    assert deficits == ()


def test_response_semantics_closure_requires_every_output_path() -> None:
    """A promoted graph closes the deficit only when every path is grounded."""

    deficit = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.GetUser"),
                field(
                    Variable(name="AnyResource"),
                    Variable(name="AnyField"),
                ),
            ),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="svc.GetUser",
        context=(("fields", "items.0.foo.bar,metadata.bar"),),
    )
    partial = _graph_with_exposed_path("action:svc.GetUser", "items.0.foo.bar")

    assert not grounding_result_closes_deficit(deficit, partial)

    action = Atom(value="action:svc.GetUser")
    sibling_witness = field(Atom(value="resource:secret"), Atom(value="metadata.bar"))
    complete = QdlGraph(
        facts=(
            *partial.facts,
            _fact("is", (sibling_witness, Atom(value="Witness"))),
            _fact("exposes", (action, sibling_witness)),
        )
    )

    assert grounding_result_closes_deficit(deficit, complete)


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="svc.GetUser",
        service="svc",
        name="GetUser",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="resource_id", type="string", required=True),),
    )


def _norm_invariant(
    statement: str, norm_id: str, effect: object
) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:qdl",
        norm_id=norm_id,
        statement=statement,
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=norm_id), effect),
        ),
    )


class RecordingTarget:
    def __init__(self) -> None:
        self.executed: list[object] = []

    def __call__(self, check: object) -> Observation:
        self.executed.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id="scenario",
            observed_outcome=AccessOutcome.DENIED,
            response_summary="denied",
            transport_status=HttpStatus(code=403),
        )


def _intent_labels(invariant: InvariantProjection) -> dict[str, str]:
    method = _method()
    scenario = _scenario()
    events = EventLog()
    metrics = CampaignMetrics()
    runner = assemble_runner(
        Checker(
            RecordingTarget(),
            TemplateGenerator(),
            AllowAllGuardrail(),
            events,
        ),
        EventProjection(events, events),
        metrics=metrics,
    )
    step = QdlExecutionStep(
        step_id="step:1",
        goal_id="goal:test",
        plan=VerificationPlan(
            plan_id="plan:1",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    path = QdlExecutionPath(
        path_id="path:test",
        goal_id="goal:test",
        kind="invariant",
        description="test path",
        steps=(step,),
    )
    view = QdlExecutionView(
        graph_hash="graph:test",
        paths=(path,),
        invariants={invariant.invariant_id: invariant},
    )

    runner.execute_plan(
        LiveRequest(
            service="svc",
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        QdlPlan(graph_hash="graph:test"),
        view,
    )
    return dict(metrics.snapshot().intent_labels)


def test_intent_letter_projects_stride_from_norm_taxonomy() -> None:
    """The STRIDE label follows the norm's QDL effect, never its wording."""

    misleading = "Elevation disclosure repudiation tampering spoofing denial wording"
    possession = _norm_invariant(
        misleading,
        "norm:spoofing-elevation-tampering",
        has(
            Atom(value="principal:attacker"),
            field(Atom(value="resource:secret"), Atom(value="email")),
        ),
    )
    outcome = _norm_invariant(
        misleading,
        "norm:disclosure-repudiation-denial",
        allowed(Atom(value="action:svc.GetUser")),
    )

    assert _intent_labels(possession) == {"path:test": "I"}
    assert _intent_labels(outcome) == {"path:test": "E"}


def test_intent_letter_defaults_without_norm_fact() -> None:
    """A path without a QDL norm fact keeps the explicit unknown default."""

    invariant = InvariantProjection(
        invariant_id="invariant:qdl",
        norm_id="norm:whatever",
        statement="Attacker must not read a foreign secret",
        severity=Severity.HIGH,
    )

    assert _intent_labels(invariant) == {"path:test": "unknown"}


def test_coverage_keys_exposed_output_paths_verbatim() -> None:
    """Coverage target cells keep exposed output paths as distinct fields."""

    action = Atom(value="action:svc.GetUser")
    resource = Atom(value="resource:secret")
    nested = field(Atom(value="resource:secret"), Atom(value="items.0.foo.bar"))
    metadata = field(Atom(value="resource:secret"), Atom(value="metadata.bar"))
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (nested, Atom(value="Witness"))),
            _fact("is", (metadata, Atom(value="Witness"))),
            _fact("exposes", (action, nested)),
            _fact("exposes", (action, metadata)),
        )
    )

    matrix = Builder().build(graph)

    assert sorted(cell.field_name for cell in matrix.fields) == [
        "items.0.foo.bar",
        "metadata.bar",
    ]
    assert {cell.field_kind for cell in matrix.fields} == {"output"}
    assert {cell.primitive for cell in matrix.fields} == {"response_field"}
    assert {cell.deficit for cell in matrix.fields} == {"semantic_blind"}
