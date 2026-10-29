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
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.intents import PlannedIntent, planned_intents
from cloud_dast.runtime.campaign.events import EventIndex
from cloud_dast.verification.evidence_facts import verified_fact_id, verified_fact_ids

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


class _Projection:
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

    def project_graph_nodes(self) -> None:
        for fact in self.graph.facts:
            if fact.predicate.name != "is" or len(fact.args) != 2:
                continue
            logical_id = atom_value(fact.args[0])
            type_name = atom_value(fact.args[1])
            kind = _NODE_KIND_BY_TYPE.get(type_name) if type_name else None
            if logical_id is None or kind is None:
                continue
            self.add_node(_declaration_node(kind, logical_id, fact.context))

        for intent in planned_intents(self.graph):
            self._add_hypothesis_node(intent)

        for fact_id in sorted(verified_fact_ids(self.graph)):
            self._add_verified_fact_node(fact_id)

    def project_event_nodes(self) -> None:
        self._project_intents()
        self._project_verified_facts()
        self._project_observations()
        self._project_paths()
        self._project_steps()
        self._project_evidence_observations()
        self._project_diffs()
        self._project_findings()

    def _project_intents(self) -> None:
        for intent_graph in self.event_index.intent_graphs:
            for intent in planned_intents(intent_graph):
                self._add_hypothesis_node(intent)

    def _project_verified_facts(self) -> None:
        for event in self.event_index.verified_facts:
            fact_id = verified_fact_id(event.fact)
            if fact_id is None:
                continue
            self._add_verified_fact_node(fact_id)

    def _add_verified_fact_node(self, fact_id: str) -> None:
        self.add_node(
            dag.VerdictNode(
                node_id=_node_id(
                    dag.CampaignNodeKind.VERDICT, Context.RUNTIME, fact_id
                ),
                context=Context.RUNTIME,
                verdict_id=fact_id,
                status=VerdictStatus.PASS,
                reason="QDL fact verified",
            )
        )

    def _project_observations(self) -> None:
        for observation_id, observation in self.event_index.observations.items():
            self.add_node(
                _observation_node(
                    observation,
                    self.event_index.observation_methods.get(observation_id),
                )
            )
            self._add_resource_state_nodes(observation)

    def _project_paths(self) -> None:
        for path_id, event in self.event_index.paths.items():
            self.add_node(
                dag.PathNode(
                    node_id=_node_id(
                        dag.CampaignNodeKind.PATH, Context.RUNTIME, path_id
                    ),
                    context=Context.RUNTIME,
                    path_id=path_id,
                    outcome=event.outcome,
                    attempted_steps=event.attempted_steps,
                    step_count=event.step_count,
                    probe_count=event.probe_count,
                    reason=event.reason,
                )
            )

    def _project_steps(self) -> None:
        for step_id, event in self.event_index.steps.items():
            self.add_node(
                dag.StepNode(
                    node_id=_node_id(
                        dag.CampaignNodeKind.STEP, Context.RUNTIME, step_id
                    ),
                    context=Context.RUNTIME,
                    step_id=step_id,
                    path_id=event.path_id,
                    step_index=event.step_index,
                    phase=event.phase,
                    verdict=event.verdict,
                    reason=event.reason,
                    completed_steps=event.completed_steps,
                )
            )
            self._add_step_verdict_node(event)
            if event.verdict is VerdictStatus.UNSCOREABLE:
                self._add_reflection_nodes(event)

    def _project_evidence_observations(self) -> None:
        for event in self.event_index.evidence:
            if event.fact.predicate.name != "evidence" or not event.fact.args:
                continue
            observation_id = atom_value(event.fact.args[0])
            if observation_id is None:
                continue
            self.add_node(_minimal_observation_node(observation_id), replace=False)

    def _project_diffs(self) -> None:
        for event in self.event_index.diffs:
            for observation_id in (
                event.control_observation_id,
                event.treatment_observation_id,
            ):
                if observation_id is not None:
                    self.add_node(
                        _minimal_observation_node(observation_id),
                        replace=False,
                    )
            if not event.has_variance:
                continue
            clue_id = _clue_logical_id(event)
            self.add_node(
                dag.ClueNode(
                    node_id=_node_id(
                        dag.CampaignNodeKind.CLUE, Context.RUNTIME, clue_id
                    ),
                    context=Context.RUNTIME,
                    clue_id=clue_id,
                    action_id=event.action_id,
                    mode=event.mode,
                    control_observation_id=event.control_observation_id,
                    treatment_observation_id=event.treatment_observation_id,
                    dimensions=event.dimensions,
                    reason="differential variance",
                )
            )

    def _project_findings(self) -> None:
        for event in self.event_index.findings:
            finding = event.finding
            self.add_node(
                _minimal_observation_node(
                    finding.observation_id,
                    self.event_index.observation_methods.get(finding.observation_id),
                ),
                replace=False,
            )
            self.add_node(
                dag.VerdictNode(
                    node_id=_node_id(
                        dag.CampaignNodeKind.VERDICT,
                        Context.REPORT,
                        finding.finding_id,
                    ),
                    context=Context.REPORT,
                    verdict_id=finding.finding_id,
                    status=VerdictStatus.FAIL,
                    path_id=finding.path_id,
                    step_id=finding.step_id,
                    observation_id=finding.observation_id,
                    reason=finding.rationale or finding.description,
                )
            )

    def _add_hypothesis_node(self, intent: PlannedIntent) -> None:
        self.add_node(
            dag.HypothesisNode(
                node_id=_node_id(
                    dag.CampaignNodeKind.HYPOTHESIS,
                    Context.PROPOSAL,
                    intent.intent_id,
                ),
                context=Context.PROPOSAL,
                hypothesis_id=intent.intent_id,
                prerequisites=intent.prerequisites,
                effects=intent.effects,
                assumptions=intent.assumptions,
            )
        )

    def _add_step_verdict_node(self, event: QdlStepEvaluated) -> None:
        logical_id = _step_verdict_logical_id(
            event.path_id,
            event.step_id,
            event.verdict,
        )
        self.add_node(
            dag.VerdictNode(
                node_id=_node_id(
                    dag.CampaignNodeKind.VERDICT,
                    Context.RUNTIME,
                    logical_id,
                ),
                context=Context.RUNTIME,
                verdict_id=logical_id,
                status=event.verdict,
                path_id=event.path_id,
                step_id=event.step_id,
                reason=event.reason,
            )
        )

    def _add_reflection_nodes(self, event: QdlStepEvaluated) -> None:
        logical_id = _reflection_logical_id(event.path_id, event.step_id)
        self.add_node(
            dag.ReflectionNode(
                node_id=_node_id(
                    dag.CampaignNodeKind.REFLECTION,
                    Context.RUNTIME,
                    logical_id,
                ),
                context=Context.RUNTIME,
                reflection_id=logical_id,
                step_id=event.step_id,
                path_id=event.path_id,
                verdict=event.verdict,
                reason=event.reason,
            )
        )
        deficit_kind, action, axis, details = _classify_unscoreable_step(event)
        self.add_node(
            dag.DeficitNode(
                node_id=_node_id(
                    dag.CampaignNodeKind.DEFICIT,
                    Context.RUNTIME,
                    logical_id,
                ),
                context=Context.RUNTIME,
                deficit_id=logical_id,
                deficit_kind=deficit_kind,
                action=action,
                axis=axis,
                details=details,
                reason=event.reason,
            )
        )

    def _add_resource_state_nodes(self, observation: Observation) -> None:
        if observation.trace is None:
            return
        for trace_step in observation.trace.steps:
            for phase, values in (
                ("before", trace_step.resource_state_before),
                ("after", trace_step.resource_state_after),
            ):
                if not values:
                    continue
                logical_id = (
                    f"{observation.observation_id}:{trace_step.step_id}:{phase}"
                )
                self.add_node(
                    dag.ResourceStateNode(
                        node_id=_node_id(
                            dag.CampaignNodeKind.RESOURCE_STATE,
                            Context.RUNTIME,
                            logical_id,
                        ),
                        context=Context.RUNTIME,
                        resource_state_id=logical_id,
                        observation_id=observation.observation_id,
                        step_id=trace_step.step_id,
                        method_id=trace_step.method_id,
                        scenario_id=trace_step.scenario_id,
                        phase=phase,
                        attributes=values,
                    )
                )

    def project_qdl_edges(self) -> None:
        for fact in self.graph.facts:
            kind = _EDGE_KIND_BY_NAME.get(fact.predicate.name)
            if kind is None or len(fact.args) != 2:
                continue
            source_logical = atom_value(fact.args[0])
            target_logical = atom_value(fact.args[1])
            if source_logical is None or target_logical is None:
                continue
            source = self.resolve_node(fact.context, source_logical)
            target = self.resolve_node(fact.context, target_logical)
            if source is None or target is None:
                continue
            self.add_edge(kind, source, target, (("source", "qdl"),))

    def connect_event_edges(self) -> None:
        self.connect_path_steps()
        self.connect_step_verdicts()
        self.connect_reflections()
        self.connect_resource_states()
        self.connect_diffs()
        self.connect_findings()
        self.connect_hypotheses()

    def connect_path_steps(self) -> None:
        steps = [
            node
            for node in self.nodes.values()
            if isinstance(node, dag.StepNode) and node.path_id is not None
        ]
        for step in steps:
            path = self.node(
                dag.CampaignNodeKind.PATH,
                Context.RUNTIME,
                step.path_id,
            )
            if path is not None:
                self.add_edge(
                    dag.CampaignEdgeKind.DEPENDS_ON,
                    dag._node_ref(step),
                    dag._node_ref(path),
                    (("source", "event"),),
                )

        steps_by_path: dict[str, list[dag.StepNode]] = {}
        for step in steps:
            steps_by_path.setdefault(step.path_id, []).append(step)
        for path_steps in steps_by_path.values():
            path_steps.sort(
                key=lambda step: (
                    step.step_index if step.step_index is not None else 0,
                    step.step_id,
                )
            )
            for left, right in zip(path_steps, path_steps[1:], strict=False):
                self.add_edge(
                    dag.CampaignEdgeKind.NEXT_STEP,
                    dag._node_ref(left),
                    dag._node_ref(right),
                    (("source", "event"),),
                )

    def connect_step_verdicts(self) -> None:
        for step in self.nodes.values():
            if not isinstance(step, dag.StepNode):
                continue
            if step.verdict is None or step.path_id is None:
                continue
            verdict = self.node(
                dag.CampaignNodeKind.VERDICT,
                Context.RUNTIME,
                _step_verdict_logical_id(step.path_id, step.step_id, step.verdict),
            )
            if verdict is None:
                continue
            self.add_edge(
                dag.CampaignEdgeKind.PRODUCES,
                dag._node_ref(step),
                dag._node_ref(verdict),
                (("source", "event"), ("event", "QdlStepEvaluated")),
            )
            path = self.node(
                dag.CampaignNodeKind.PATH,
                Context.RUNTIME,
                step.path_id,
            )
            if path is None:
                continue
            relation = {
                VerdictStatus.PASS: dag.CampaignEdgeKind.SUPPORTS,
                VerdictStatus.FAIL: dag.CampaignEdgeKind.CONTRADICTS,
            }.get(step.verdict)
            if relation is None:
                continue
            self.add_edge(
                relation,
                dag._node_ref(verdict),
                dag._node_ref(path),
                (("source", "event"), ("event", "QdlStepEvaluated")),
            )

    def connect_reflections(self) -> None:
        for reflection in self.nodes.values():
            if not isinstance(reflection, dag.ReflectionNode):
                continue
            if reflection.step_id is not None:
                step = self.node(
                    dag.CampaignNodeKind.STEP,
                    Context.RUNTIME,
                    reflection.step_id,
                )
                if step is not None:
                    self.add_edge(
                        dag.CampaignEdgeKind.DEPENDS_ON,
                        dag._node_ref(reflection),
                        dag._node_ref(step),
                        (("source", "event"),),
                    )
            if reflection.path_id is not None and reflection.step_id is not None:
                deficit = self.node(
                    dag.CampaignNodeKind.DEFICIT,
                    Context.RUNTIME,
                    _reflection_logical_id(reflection.path_id, reflection.step_id),
                )
                if deficit is not None:
                    self.add_edge(
                        dag.CampaignEdgeKind.PRODUCES,
                        dag._node_ref(reflection),
                        dag._node_ref(deficit),
                        (("source", "event"),),
                    )

    def connect_resource_states(self) -> None:
        states_by_step: dict[tuple[str, str], list[dag.ResourceStateNode]] = {}
        for node in self.nodes.values():
            if not isinstance(node, dag.ResourceStateNode):
                continue
            if node.observation_id is None or node.step_id is None:
                continue
            states_by_step.setdefault((node.observation_id, node.step_id), []).append(
                node
            )

        for (observation_id, _), states in states_by_step.items():
            observation = self.node(
                dag.CampaignNodeKind.OBSERVATION,
                Context.RUNTIME,
                observation_id,
            )
            for state in states:
                if observation is not None:
                    self.add_edge(
                        dag.CampaignEdgeKind.OBSERVED_BY,
                        dag._node_ref(state),
                        dag._node_ref(observation),
                        (("source", "event"),),
                    )
            before = next((state for state in states if state.phase == "before"), None)
            after = next((state for state in states if state.phase == "after"), None)
            if before is not None and after is not None:
                self.add_edge(
                    dag.CampaignEdgeKind.SHARES_RESOURCE,
                    dag._node_ref(before),
                    dag._node_ref(after),
                    (("source", "event"),),
                )

    def connect_diffs(self) -> None:
        for event in self.event_index.diffs:
            control = self._observation(event.control_observation_id)
            treatment = self._observation(event.treatment_observation_id)
            if control is not None and treatment is not None:
                self.add_edge(
                    dag.CampaignEdgeKind.CONTRADICTS
                    if event.has_variance
                    else dag.CampaignEdgeKind.SUPPORTS,
                    dag._node_ref(control),
                    dag._node_ref(treatment),
                    (
                        ("source", "event"),
                        ("event", "DiffPairComputed"),
                        ("mode", event.mode),
                    ),
                )
            if not event.has_variance:
                continue
            clue = self.node(
                dag.CampaignNodeKind.CLUE,
                Context.RUNTIME,
                _clue_logical_id(event),
            )
            if clue is None:
                continue
            for observation in (control, treatment):
                if observation is None:
                    continue
                self.add_edge(
                    dag.CampaignEdgeKind.DEPENDS_ON,
                    dag._node_ref(clue),
                    dag._node_ref(observation),
                    (
                        ("source", "event"),
                        ("event", "DiffPairComputed"),
                        ("mode", event.mode),
                    ),
                )

    def connect_findings(self) -> None:
        for event in self.event_index.findings:
            finding = event.finding
            verdict = self.node(
                dag.CampaignNodeKind.VERDICT,
                Context.REPORT,
                finding.finding_id,
            )
            observation = self._observation(finding.observation_id)
            if verdict is not None and observation is not None:
                self.add_edge(
                    dag.CampaignEdgeKind.SUPPORTS,
                    dag._node_ref(observation),
                    dag._node_ref(verdict),
                    (("source", "event"), ("event", "FindingRaised")),
                )
            if verdict is None:
                continue
            if finding.path_id is not None:
                path = self.node(
                    dag.CampaignNodeKind.PATH,
                    Context.RUNTIME,
                    finding.path_id,
                )
                if path is not None:
                    self.add_edge(
                        dag.CampaignEdgeKind.CONTRADICTS,
                        dag._node_ref(verdict),
                        dag._node_ref(path),
                        (("source", "event"), ("event", "FindingRaised")),
                    )
            if finding.step_id is not None:
                step = self.node(
                    dag.CampaignNodeKind.STEP,
                    Context.RUNTIME,
                    finding.step_id,
                )
                if step is not None:
                    self.add_edge(
                        dag.CampaignEdgeKind.CONTRADICTS,
                        dag._node_ref(verdict),
                        dag._node_ref(step),
                        (("source", "event"), ("event", "FindingRaised")),
                    )

    def connect_hypotheses(self) -> None:
        hypotheses = [
            node for node in self.nodes.values() if isinstance(node, dag.HypothesisNode)
        ]
        producers_by_effect: dict[str, list[dag.HypothesisNode]] = {}
        for producer in hypotheses:
            for effect in producer.effects:
                producers_by_effect.setdefault(effect, []).append(producer)

        for hypothesis in hypotheses:
            self._connect_hypothesis_facts(hypothesis)

        for consumer in hypotheses:
            for prerequisite in consumer.prerequisites:
                for producer in producers_by_effect.get(prerequisite, ()):
                    if producer.hypothesis_id == consumer.hypothesis_id:
                        continue
                    self.add_edge(
                        dag.CampaignEdgeKind.DEPENDS_ON,
                        dag._node_ref(consumer),
                        dag._node_ref(producer),
                        (("source", "derived"), ("rule", "intent-chain")),
                    )
                    self.add_edge(
                        dag.CampaignEdgeKind.PRODUCES,
                        dag._node_ref(producer),
                        dag._node_ref(consumer),
                        (("source", "derived"), ("rule", "intent-chain")),
                    )

    def _connect_hypothesis_facts(self, hypothesis: dag.HypothesisNode) -> None:
        for fact_id in hypothesis.prerequisites:
            verdict = self._runtime_verdict(fact_id)
            if verdict is None:
                continue
            self.add_edge(
                dag.CampaignEdgeKind.DEPENDS_ON,
                dag._node_ref(hypothesis),
                dag._node_ref(verdict),
                (("source", "derived"), ("rule", "intent_prerequisite")),
            )
            self.add_edge(
                dag.CampaignEdgeKind.SUPPORTS,
                dag._node_ref(verdict),
                dag._node_ref(hypothesis),
                (("source", "derived"), ("rule", "intent_prerequisite")),
            )
        for fact_id in hypothesis.effects:
            verdict = self._runtime_verdict(fact_id)
            if verdict is None:
                continue
            self.add_edge(
                dag.CampaignEdgeKind.PRODUCES,
                dag._node_ref(hypothesis),
                dag._node_ref(verdict),
                (("source", "derived"), ("rule", "intent_effect")),
            )
            self.add_edge(
                dag.CampaignEdgeKind.SUPPORTS,
                dag._node_ref(verdict),
                dag._node_ref(hypothesis),
                (("source", "derived"), ("rule", "intent_effect")),
            )

    def _observation(self, observation_id: str | None) -> dag.ObservationNode | None:
        if observation_id is None:
            return None
        return self.node(
            dag.CampaignNodeKind.OBSERVATION,
            Context.RUNTIME,
            observation_id,
        )

    def _runtime_verdict(self, verdict_id: str) -> dag.VerdictNode | None:
        verdict = self.node(
            dag.CampaignNodeKind.VERDICT,
            Context.RUNTIME,
            verdict_id,
        )
        return verdict if isinstance(verdict, dag.VerdictNode) else None


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
