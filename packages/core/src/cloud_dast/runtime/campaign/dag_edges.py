"""Campaign DAG edge projection over already projected nodes."""

from __future__ import annotations

from cloud_dast.contracts import dag
from cloud_dast.model import VerdictStatus
from cloud_dast.qdl.graph import Context
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.runtime.campaign.dag import (
    _EDGE_KIND_BY_NAME,
    _clue_logical_id,
    _reflection_logical_id,
    _step_verdict_logical_id,
)


class EdgeProjectionMixin:
    """Build QDL- and event-derived relations between campaign nodes."""

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


__all__ = ["EdgeProjectionMixin"]
