"""Recover checks, evaluate findings and replay campaign publication events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from cloud_dast.contracts.execution import EvaluationResult, ExecutionResult
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model.events import CheckCompleted, DomainEvent, FindingRaised
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.verification.findings import collect
from cloud_dast.verification.oracles import leads
from cloud_dast.verification.taxonomy import ClassificationFacts


class FindingEvaluator:
    """Own campaign finding evaluation, publication and replay read models."""

    def __init__(self, projection: EventProjection) -> None:
        self._projection = projection
        self._leads: tuple[leads.Lead, ...] = ()

    @property
    def events(self) -> Iterable[DomainEvent]:
        """Return complete history from the shared incremental projection."""
        return self._projection.refresh()

    @property
    def leads(self) -> tuple[leads.Lead, ...]:
        """Classification leads evaluated by the most recent evaluation."""
        return self._leads

    def evaluate(
        self,
        execution: ExecutionResult,
        invariants: Mapping[str, InvariantProjection],
        graph: QdlGraph | None = None,
    ) -> EvaluationResult:
        classification_facts = ClassificationFacts.from_graph(graph)
        self._leads = leads.evaluate(graph)
        events = self._projection.refresh()
        observation_ids = {
            observation.observation_id for observation in execution.observations
        }
        checks = {
            event.check.check_id: event.check
            for event in events
            if isinstance(event, CheckCompleted)
            and event.check is not None
            and event.observation.observation_id in observation_ids
        }
        # Physical checks retain the original request and identity; journal checks
        # are replay fallbacks and may be redacted.
        checks.update({check.check_id: check for check in execution.checks})
        findings = collect(execution, invariants, checks, classification_facts)
        observations_by_id = {
            observation.observation_id: observation
            for observation in execution.observations
        }
        for finding in findings:
            self._projection.publisher.publish(
                FindingRaised(
                    finding=finding,
                    correlation_id=observations_by_id[finding.observation_id].check_id,
                )
            )
        replayed = self._projection.refresh()
        finding_ids = {item.finding_id for item in findings}
        replayed_observations = tuple(
            event.observation
            for event in replayed
            if isinstance(event, CheckCompleted)
            and event.observation.observation_id in observation_ids
        )
        replayed_findings = tuple(
            event.finding
            for event in replayed
            if isinstance(event, FindingRaised)
            and event.finding.finding_id in finding_ids
        )
        return EvaluationResult(
            findings=findings,
            replayed_observations=replayed_observations,
            replayed_findings=replayed_findings,
        )


__all__ = ["FindingEvaluator"]
