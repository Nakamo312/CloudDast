"""Persistent runtime Campaign DAG read model.

The DAG is a projection over the canonical QDL graph and the runtime event
log.  It is not a second formal engine and never owns execution or verdict
semantics: nodes preserve their QDL context, while edges only relate already
projected campaign objects.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from cloud_dast.contracts import dag
from cloud_dast.model import (
    JsonValue,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import (
    DiffPairComputed,
    DomainEvent,
    QdlStepEvaluated,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Context,
    Predicate,
    PredicateSchema,
    QdlGraph,
    TermKind,
    canonical_json,
)
from cloud_dast.runtime.campaign.events import EventIndex

_LATENCY_BASELINE_PREFIX = "no runtime latency baseline for method "


def _reference(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
        reference=True,
    )


def _edge_predicate(name: str) -> Predicate:
    return Predicate.from_schema(
        PredicateSchema(
            name=name,
            arguments=(_reference("source"), _reference("target")),
        )
    )


DEPENDS_ON = _edge_predicate("depends_on")
PRODUCES = _edge_predicate("produces")
OBSERVED_BY = _edge_predicate("observed_by")
SUPPORTS = _edge_predicate("supports")
CONTRADICTS = _edge_predicate("contradicts")
NEXT_STEP = _edge_predicate("next_step")
SHARES_RESOURCE = _edge_predicate("shares_resource")

EDGE_PREDICATES: dict[dag.CampaignEdgeKind, Predicate] = {
    dag.CampaignEdgeKind.DEPENDS_ON: DEPENDS_ON,
    dag.CampaignEdgeKind.PRODUCES: PRODUCES,
    dag.CampaignEdgeKind.OBSERVED_BY: OBSERVED_BY,
    dag.CampaignEdgeKind.SUPPORTS: SUPPORTS,
    dag.CampaignEdgeKind.CONTRADICTS: CONTRADICTS,
    dag.CampaignEdgeKind.NEXT_STEP: NEXT_STEP,
    dag.CampaignEdgeKind.SHARES_RESOURCE: SHARES_RESOURCE,
}
_EDGE_KIND_BY_NAME = {
    predicate.name: kind for kind, predicate in EDGE_PREDICATES.items()
}

_NODE_TYPE_BY_KIND: dict[dag.CampaignNodeKind, str] = {
    dag.CampaignNodeKind.PATH: "Path",
    dag.CampaignNodeKind.STEP: "Step",
    dag.CampaignNodeKind.OBSERVATION: "Observation",
    dag.CampaignNodeKind.CLUE: "Clue",
    dag.CampaignNodeKind.DEFICIT: "Deficit",
    dag.CampaignNodeKind.HYPOTHESIS: "Hypothesis",
    dag.CampaignNodeKind.REFLECTION: "Reflection",
    dag.CampaignNodeKind.RESOURCE_STATE: "ResourceState",
    dag.CampaignNodeKind.VERDICT: "Verdict",
    dag.CampaignNodeKind.HANDOFF: "Handoff",
}
_NODE_KIND_BY_TYPE = {value: key for key, value in _NODE_TYPE_BY_KIND.items()}

PATH_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.PATH]
STEP_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.STEP]
OBSERVATION_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.OBSERVATION]
CLUE_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.CLUE]
DEFICIT_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.DEFICIT]
HYPOTHESIS_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.HYPOTHESIS]
REFLECTION_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.REFLECTION]
RESOURCE_STATE_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.RESOURCE_STATE]
VERDICT_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.VERDICT]
HANDOFF_TYPE = _NODE_TYPE_BY_KIND[dag.CampaignNodeKind.HANDOFF]


def _node_id(kind: dag.CampaignNodeKind, context: Context, logical_id: str) -> str:
    return f"{kind.value}:{context.value}:{logical_id}"


def _logical_id(node: dag.CampaignNode) -> str:
    if isinstance(node, dag.PathNode):
        return node.path_id
    if isinstance(node, dag.StepNode):
        return node.step_id
    if isinstance(node, dag.ObservationNode):
        return node.observation_id
    if isinstance(node, dag.ClueNode):
        return node.clue_id
    if isinstance(node, dag.DeficitNode):
        return node.deficit_id
    if isinstance(node, dag.HypothesisNode):
        return node.hypothesis_id
    if isinstance(node, dag.ReflectionNode):
        return node.reflection_id
    if isinstance(node, dag.ResourceStateNode):
        return node.resource_state_id
    if isinstance(node, dag.VerdictNode):
        return node.verdict_id
    if isinstance(node, dag.HandoffNode):
        return node.handoff_id
    raise TypeError(f"unsupported campaign node: {type(node).__name__}")


def _payload_digest(payload: tuple[tuple[str, JsonValue], ...]) -> str:
    rendered = json.dumps(
        [[key, value] for key, value in payload],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _edge_id(
    kind: dag.CampaignEdgeKind,
    source: dag.CampaignNodeRef,
    target: dag.CampaignNodeRef,
    payload: tuple[tuple[str, JsonValue], ...],
) -> str:
    return f"{kind.value}:{source.node_id}->{target.node_id}:{_payload_digest(payload)}"


def _source_digest(graph: QdlGraph, events: tuple[DomainEvent, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(dag.CAMPAIGN_DAG_SCHEMA_VERSION.encode("utf-8"))
    digest.update(b"\n")
    digest.update(canonical_json(graph).encode("utf-8"))
    digest.update(b"\n")
    for event in events:
        content = event.model_dump(mode="json", exclude={"event_id", "occurred_at"})
        rendered = json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        digest.update(rendered.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _declaration_node(
    kind: dag.CampaignNodeKind,
    logical_id: str,
    context: Context,
) -> dag.CampaignNode:
    node_id = _node_id(kind, context, logical_id)
    if kind is dag.CampaignNodeKind.PATH:
        return dag.PathNode(node_id=node_id, context=context, path_id=logical_id)
    if kind is dag.CampaignNodeKind.STEP:
        return dag.StepNode(node_id=node_id, context=context, step_id=logical_id)
    if kind is dag.CampaignNodeKind.OBSERVATION:
        return dag.ObservationNode(
            node_id=node_id, context=context, observation_id=logical_id
        )
    if kind is dag.CampaignNodeKind.CLUE:
        return dag.ClueNode(node_id=node_id, context=context, clue_id=logical_id)
    if kind is dag.CampaignNodeKind.DEFICIT:
        return dag.DeficitNode(node_id=node_id, context=context, deficit_id=logical_id)
    if kind is dag.CampaignNodeKind.HYPOTHESIS:
        return dag.HypothesisNode(
            node_id=node_id, context=context, hypothesis_id=logical_id
        )
    if kind is dag.CampaignNodeKind.REFLECTION:
        return dag.ReflectionNode(
            node_id=node_id, context=context, reflection_id=logical_id
        )
    if kind is dag.CampaignNodeKind.RESOURCE_STATE:
        return dag.ResourceStateNode(
            node_id=node_id, context=context, resource_state_id=logical_id
        )
    if kind is dag.CampaignNodeKind.VERDICT:
        return dag.VerdictNode(node_id=node_id, context=context, verdict_id=logical_id)
    if kind is dag.CampaignNodeKind.HANDOFF:
        return dag.HandoffNode(node_id=node_id, context=context, handoff_id=logical_id)
    raise ValueError(f"unsupported campaign node kind: {kind}")


def _observation_node(
    observation: Observation,
    method_id: str | None,
) -> dag.ObservationNode:
    digest = observation.response_digest
    if digest is None and observation.response_tree:
        digest = response_tree_digest(observation.response_tree)
    return dag.ObservationNode(
        node_id=_node_id(
            dag.CampaignNodeKind.OBSERVATION,
            Context.RUNTIME,
            observation.observation_id,
        ),
        context=Context.RUNTIME,
        observation_id=observation.observation_id,
        check_id=observation.check_id,
        scenario_id=observation.scenario_id,
        observed_outcome=observation.observed_outcome,
        response_summary=observation.response_summary,
        method_id=method_id,
        probe_marker=observation.probe_marker,
        response_digest=digest,
    )


def _minimal_observation_node(
    observation_id: str,
    method_id: str | None = None,
) -> dag.ObservationNode:
    return dag.ObservationNode(
        node_id=_node_id(
            dag.CampaignNodeKind.OBSERVATION, Context.RUNTIME, observation_id
        ),
        context=Context.RUNTIME,
        observation_id=observation_id,
        method_id=method_id,
    )


def _step_verdict_logical_id(
    path_id: str,
    step_id: str,
    verdict: VerdictStatus,
) -> str:
    return f"{path_id}:{step_id}:{verdict.value}"


def _reflection_logical_id(path_id: str, step_id: str) -> str:
    return f"{path_id}:{step_id}"


def _clue_logical_id(event: DiffPairComputed) -> str:
    control = event.control_observation_id or ""
    treatment = event.treatment_observation_id or ""
    return f"{event.action_id}:{event.mode}:{control}:{treatment}"


def _classify_unscoreable_step(
    event: QdlStepEvaluated,
) -> tuple[str, str, str | None, tuple[tuple[str, str], ...]]:
    if event.reason.startswith(_LATENCY_BASELINE_PREFIX):
        action = event.reason[len(_LATENCY_BASELINE_PREFIX) :]
        return (
            "missing_baseline",
            action,
            "availability",
            (("path_id", event.path_id), ("reason", event.reason)),
        )
    return (
        "unscoreable",
        event.step_id,
        None,
        (("path_id", event.path_id), ("reason", event.reason)),
    )


from cloud_dast.runtime.campaign.dag_edges import EdgeProjectionMixin
from cloud_dast.runtime.campaign.dag_nodes import NodeProjectionMixin


class _Projection(NodeProjectionMixin, EdgeProjectionMixin):
    """Run-local accumulator used by ``build_campaign_dag``."""

    def __init__(self, graph: QdlGraph, events: Iterable[DomainEvent]) -> None:
        self.graph = graph
        self.events = tuple(events)
        self.event_index = EventIndex.from_events(self.events)
        self.nodes: dict[str, dag.CampaignNode] = {}
        self.edges: dict[str, dag.CampaignEdge] = {}
        self.logical_refs: dict[tuple[Context, str], list[dag.CampaignNodeRef]] = {}

    def build(self) -> dag.CampaignDag:
        self.project_graph_nodes()
        self.project_event_nodes()
        self.project_qdl_edges()
        self.connect_event_edges()
        return dag.CampaignDag(
            source_digest=_source_digest(self.graph, self.events),
            nodes=tuple(self.nodes.values()),
            edges=tuple(self.edges.values()),
        )

    def add_node(self, node: dag.CampaignNode, *, replace: bool = True) -> None:
        if not replace and node.node_id in self.nodes:
            return
        self.nodes[node.node_id] = node
        key = (node.context, _logical_id(node))
        refs = self.logical_refs.setdefault(key, [])
        ref = dag._node_ref(node)
        if ref not in refs:
            refs.append(ref)

    def add_edge(
        self,
        kind: dag.CampaignEdgeKind,
        source: dag.CampaignNodeRef,
        target: dag.CampaignNodeRef,
        payload: tuple[tuple[str, JsonValue], ...] = (),
    ) -> None:
        edge = dag.CampaignEdge(
            edge_id=_edge_id(kind, source, target, payload),
            kind=kind,
            source=source,
            target=target,
            payload=payload,
        )
        self.edges[edge.edge_id] = edge

    def resolve_node(
        self,
        context: Context,
        logical_id: str,
    ) -> dag.CampaignNodeRef | None:
        refs = self.logical_refs.get((context, logical_id))
        if not refs:
            return None
        return sorted(refs, key=lambda ref: ref.node_id)[0]

    def node(
        self,
        kind: dag.CampaignNodeKind,
        context: Context,
        logical_id: str,
    ) -> dag.CampaignNode | None:
        return self.nodes.get(_node_id(kind, context, logical_id))


def build_campaign_dag(
    graph: QdlGraph,
    events: Iterable[DomainEvent],
) -> dag.CampaignDag:
    """Build a Campaign DAG from one QDL graph and runtime event log.

    The builder is pure: the same graph and the same event sequence always
    produce the same canonical DAG.  It keeps no state between calls.
    """

    return _Projection(graph, events).build()


__all__ = [
    "CONTRADICTS",
    "CLUE_TYPE",
    "DEFICIT_TYPE",
    "DEPENDS_ON",
    "EDGE_PREDICATES",
    "HANDOFF_TYPE",
    "HYPOTHESIS_TYPE",
    "NEXT_STEP",
    "OBSERVED_BY",
    "OBSERVATION_TYPE",
    "PATH_TYPE",
    "PRODUCES",
    "REFLECTION_TYPE",
    "RESOURCE_STATE_TYPE",
    "SHARES_RESOURCE",
    "SUPPORTS",
    "STEP_TYPE",
    "VERDICT_TYPE",
    "build_campaign_dag",
]
