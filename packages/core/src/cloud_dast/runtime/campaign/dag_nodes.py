"""Campaign DAG node projection over QDL and indexed runtime events."""

from __future__ import annotations

from cloud_dast.contracts import dag
from cloud_dast.model import Observation, VerdictStatus
from cloud_dast.model.events import QdlStepEvaluated
from cloud_dast.qdl.graph import Context
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.intents import PlannedIntent, planned_intents
from cloud_dast.runtime.campaign.dag import (
    _NODE_KIND_BY_TYPE,
    _classify_unscoreable_step,
    _clue_logical_id,
    _declaration_node,
    _minimal_observation_node,
    _node_id,
    _observation_node,
    _reflection_logical_id,
    _step_verdict_logical_id,
)
from cloud_dast.verification.evidence_facts import verified_fact_id, verified_fact_ids


class NodeProjectionMixin:
    """Project campaign nodes without constructing relations between them."""

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


__all__ = ["NodeProjectionMixin"]
