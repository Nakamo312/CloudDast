from __future__ import annotations

from datetime import UTC, datetime

from cloud_dast.contracts.dag import CampaignDag, CampaignEdgeKind, CampaignNodeKind
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Finding,
    HttpStatus,
    Observation,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    DiffPairComputed,
    FactVerified,
    FindingRaised,
    IntentProposed,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.intents import intent_graph
from cloud_dast.runtime.campaign.dag import (
    CLUE_TYPE,
    CONTRADICTS,
    DEFICIT_TYPE,
    DEPENDS_ON,
    HANDOFF_TYPE,
    HYPOTHESIS_TYPE,
    NEXT_STEP,
    OBSERVATION_TYPE,
    OBSERVED_BY,
    PATH_TYPE,
    PRODUCES,
    REFLECTION_TYPE,
    RESOURCE_STATE_TYPE,
    SHARES_RESOURCE,
    STEP_TYPE,
    SUPPORTS,
    VERDICT_TYPE,
    build_campaign_dag,
)
from cloud_dast.runtime.campaign.replay import EventGraph
from cloud_dast.verification.evidence_facts import verified_fact


def _fact(
    predicate: Predicate,
    args: tuple[object, ...],
    context: Context = Context.RUNTIME,
) -> Fact:
    return Fact(
        context=context,
        predicate=predicate,
        args=args,  # type: ignore[arg-type]
    )


def _declaration(
    logical_id: str,
    type_name: str,
    context: Context = Context.RUNTIME,
) -> Fact:
    return _fact(
        Predicate.from_name("is"),
        (Atom(value=logical_id), Atom(value=type_name)),
        context,
    )


def _observation() -> Observation:
    return Observation(
        observation_id="obs-1",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-1",
                    step_id="step:path:0",
                    method_id="grpc:Get",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("resource_id",),
                    resource_state_before=(("state", "created"),),
                    resource_state_after=(("state", "approved"),),
                ),
            )
        ),
    )


def _path_event(
    *,
    event_id: str = "event-path",
    occurred_at: datetime | None = None,
) -> QdlPathEvaluated:
    return QdlPathEvaluated(
        event_id=event_id,
        occurred_at=occurred_at or datetime(2026, 1, 1, tzinfo=UTC),
        path_id="path:read",
        outcome="blocked",
        attempted_steps=2,
        step_count=2,
        probe_count=2,
        reason="step blocked",
    )


def _step_event(
    step_id: str,
    *,
    step_index: int,
    verdict: VerdictStatus,
    phase: str,
    reason: str,
    event_id: str,
) -> QdlStepEvaluated:
    return QdlStepEvaluated(
        event_id=event_id,
        path_id="path:read",
        step_id=step_id,
        verdict=verdict,
        phase=phase,
        reason=reason,
        step_index=step_index,
        completed_steps=(),
    )


def _finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        observation_id="obs-1",
        invariant_id="invariant-1",
        method_id="grpc:Get",
        scenario_id="scenario-1",
        severity=Severity.HIGH,
        title="Security finding",
        description="Security finding description",
        remediation="Restrict access",
        path_id="path:read",
        step_id="step:path:1",
        rationale="invariant violated",
    )


def test_campaign_dag_projects_qdl_nodes_and_edges() -> None:
    facts = (
        _declaration("path:read", PATH_TYPE),
        _declaration("step:path:0", STEP_TYPE),
        _declaration("obs:read", OBSERVATION_TYPE),
        _declaration("clue:read", CLUE_TYPE),
        _declaration("deficit:read", DEFICIT_TYPE),
        _declaration("hypothesis:read", HYPOTHESIS_TYPE),
        _declaration("reflection:read", REFLECTION_TYPE),
        _declaration("state:read", RESOURCE_STATE_TYPE),
        _declaration("verdict:read", VERDICT_TYPE),
        _declaration("handoff:read", HANDOFF_TYPE),
        _fact(DEPENDS_ON, (Atom(value="step:path:0"), Atom(value="path:read"))),
        _fact(PRODUCES, (Atom(value="step:path:0"), Atom(value="verdict:read"))),
        _fact(OBSERVED_BY, (Atom(value="state:read"), Atom(value="obs:read"))),
        _fact(
            SUPPORTS,
            (Atom(value="verdict:read"), Atom(value="hypothesis:read")),
        ),
        _fact(
            CONTRADICTS,
            (Atom(value="clue:read"), Atom(value="hypothesis:read")),
        ),
        _fact(NEXT_STEP, (Atom(value="path:read"), Atom(value="step:path:0"))),
        _fact(SHARES_RESOURCE, (Atom(value="state:read"), Atom(value="obs:read"))),
    )

    dag = build_campaign_dag(QdlGraph(facts=facts), ())

    assert isinstance(dag, CampaignDag)
    assert {node.kind for node in dag.nodes} == {
        kind.value for kind in CampaignNodeKind
    }
    assert {edge.kind for edge in dag.edges} == {
        kind.value for kind in CampaignEdgeKind
    }
    assert all(
        edge.source.node_id in {node.node_id for node in dag.nodes}
        for edge in dag.edges
    )
    assert all(
        edge.target.node_id in {node.node_id for node in dag.nodes}
        for edge in dag.edges
    )


def test_campaign_dag_projects_runtime_events() -> None:
    events = (
        _path_event(),
        _step_event(
            "step:path:0",
            step_index=0,
            verdict=VerdictStatus.UNSCOREABLE,
            phase="unscoreable",
            reason="no runtime latency baseline for method action:get",
            event_id="event-step-0",
        ),
        _step_event(
            "step:path:1",
            step_index=1,
            verdict=VerdictStatus.FAIL,
            phase="goal_reached",
            reason="invariant violated",
            event_id="event-step-1",
        ),
        CheckCompleted(observation=_observation(), method_id="grpc:Get"),
        DiffPairComputed(
            action_id="action:get",
            mode="factors",
            control_observation_id="obs-control",
            treatment_observation_id="obs-treatment",
            dimensions=("field",),
            has_variance=True,
        ),
        FindingRaised(finding=_finding()),
    )

    dag = build_campaign_dag(QdlGraph(), events)

    nodes_by_kind: dict[str, list[object]] = {}
    for node in dag.nodes:
        nodes_by_kind.setdefault(node.kind, []).append(node)
    assert set(nodes_by_kind) >= {
        "path",
        "step",
        "observation",
        "clue",
        "deficit",
        "reflection",
        "resource_state",
        "verdict",
    }
    assert nodes_by_kind["deficit"][0].deficit_kind == "missing_baseline"
    assert nodes_by_kind["observation"][0].method_id == "grpc:Get"
    assert nodes_by_kind["reflection"][0].reason.startswith(
        "no runtime latency baseline"
    )
    report_verdict = next(
        node for node in nodes_by_kind["verdict"] if node.context is Context.REPORT
    )
    assert report_verdict.verdict_id == "finding-1"

    edge_kinds = {edge.kind for edge in dag.edges}
    assert edge_kinds == {kind.value for kind in CampaignEdgeKind}

    def has_edge(kind: str, source_kind: str, target_kind: str) -> bool:
        return any(
            edge.kind == kind
            and edge.source.kind == source_kind
            and edge.target.kind == target_kind
            for edge in dag.edges
        )

    assert has_edge("depends_on", "step", "path")
    assert has_edge("next_step", "step", "step")
    assert has_edge("produces", "step", "verdict")
    assert has_edge("contradicts", "verdict", "path")
    assert has_edge("observed_by", "resource_state", "observation")
    assert has_edge("shares_resource", "resource_state", "resource_state")
    assert has_edge("contradicts", "observation", "observation")
    assert has_edge("depends_on", "clue", "observation")
    assert has_edge("supports", "observation", "verdict")


def test_campaign_dag_is_deterministic_and_hashes_canonically() -> None:
    graph = QdlGraph(
        facts=(
            _declaration("path:read", PATH_TYPE),
            _declaration("step:path:0", STEP_TYPE),
            _fact(
                DEPENDS_ON,
                (Atom(value="step:path:0"), Atom(value="path:read")),
            ),
        )
    )
    first_events = (
        _path_event(event_id="event-1", occurred_at=datetime(2026, 1, 1, tzinfo=UTC)),
    )
    second_events = (
        _path_event(event_id="event-2", occurred_at=datetime(2026, 1, 2, tzinfo=UTC)),
    )

    first = build_campaign_dag(graph, first_events)
    second = build_campaign_dag(graph, second_events)
    changed = build_campaign_dag(
        QdlGraph(facts=graph.facts[:1]),
        second_events,
    )

    assert first == second
    assert first.canonical_hash == second.canonical_hash
    assert first.canonical_hash != changed.canonical_hash


def test_campaign_dag_preserves_context_isolation() -> None:
    facts = (
        _declaration("hypothesis:read", HYPOTHESIS_TYPE, Context.PROPOSAL),
        _declaration("path:read", PATH_TYPE),
        _declaration("verdict:read", VERDICT_TYPE),
        _fact(
            DEPENDS_ON,
            (Atom(value="verdict:read"), Atom(value="hypothesis:read")),
        ),
        _fact(DEPENDS_ON, (Atom(value="path:read"), Atom(value="verdict:read"))),
    )

    dag = build_campaign_dag(QdlGraph(facts=facts), ())

    hypothesis = next(
        node for node in dag.nodes if node.kind == CampaignNodeKind.HYPOTHESIS.value
    )
    verdict = next(
        node for node in dag.nodes if node.kind == CampaignNodeKind.VERDICT.value
    )
    assert hypothesis.context is Context.PROPOSAL
    assert verdict.context is Context.RUNTIME
    assert not any(
        edge.kind == CampaignEdgeKind.DEPENDS_ON.value
        and edge.source.kind == CampaignNodeKind.VERDICT.value
        and edge.target.kind == CampaignNodeKind.HYPOTHESIS.value
        for edge in dag.edges
    )
    assert any(
        edge.kind == CampaignEdgeKind.DEPENDS_ON.value
        and edge.source.kind == CampaignNodeKind.PATH.value
        and edge.target.kind == CampaignNodeKind.VERDICT.value
        for edge in dag.edges
    )


def test_campaign_state_projects_dag_from_qdl_and_events() -> None:
    campaign_events = (
        FactVerified(fact=verified_fact("fact:ready")),
        IntentProposed(
            intent=intent_graph(
                "intent:read",
                prerequisites=("fact:ready",),
                effects=("fact:done",),
            )
        ),
        IntentProposed(intent=intent_graph("intent:use", prerequisites=("fact:done",))),
    )
    state = EventGraph.replay(campaign_events)

    dag = state.project_dag(campaign_events)

    hypothesis = next(
        node for node in dag.nodes if node.kind == CampaignNodeKind.HYPOTHESIS.value
    )
    verdict = next(
        node
        for node in dag.nodes
        if node.kind == CampaignNodeKind.VERDICT.value
        and node.verdict_id == "fact:ready"
    )
    assert hypothesis.context is Context.PROPOSAL
    assert verdict.context is Context.RUNTIME
    assert any(
        edge.kind == CampaignEdgeKind.DEPENDS_ON.value
        and edge.source.node_id == hypothesis.node_id
        and edge.target.node_id == verdict.node_id
        for edge in dag.edges
    )
    assert any(
        edge.kind == CampaignEdgeKind.SUPPORTS.value
        and edge.source.node_id == verdict.node_id
        and edge.target.node_id == hypothesis.node_id
        for edge in dag.edges
    )
    consumer = next(
        node
        for node in dag.nodes
        if node.kind == CampaignNodeKind.HYPOTHESIS.value
        and node.hypothesis_id == "intent:use"
    )
    assert any(
        edge.kind == CampaignEdgeKind.DEPENDS_ON.value
        and edge.source.node_id == consumer.node_id
        and edge.target.node_id == hypothesis.node_id
        for edge in dag.edges
    )
    assert any(
        edge.kind == CampaignEdgeKind.PRODUCES.value
        and edge.source.node_id == hypothesis.node_id
        and edge.target.node_id == consumer.node_id
        for edge in dag.edges
    )
