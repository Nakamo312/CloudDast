"""Evaluate grounded observations and project replayable findings.

This is a verification boundary: it consumes execution evidence and emits
finding events, but owns neither campaign sequencing nor transport.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from uuid import uuid4

from cloud_dast.contracts.candidate_metrics import request_complexity
from cloud_dast.contracts.execution import (
    EvaluationResult,
    ExecutionResult,
    ObservationProvenance,
)
from cloud_dast.model import (
    Check,
    Finding,
    JsonValue,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import CheckCompleted, DomainEvent, FindingRaised
from cloud_dast.ports import EventPublisher, EventStore
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.verification.findings import (
    finding_from_observation,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles.classification_lead import (
    ClassificationLead,
    evaluate_classification_leads,
)
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict
from cloud_dast.verification.taxonomy import ClassificationFacts


class FindingEvaluator:
    """Evaluate observations and project replayable finding events.

    Classification suspicions remain explicit leads and never become findings
    unless a deterministic, graph-grounded policy verdict authorizes them.
    """

    def __init__(
        self,
        event_bus: EventPublisher,
        event_store: EventStore,
    ) -> None:
        self._event_bus = event_bus
        self._events = event_store
        self._event_consumer_id = f"finding-evaluator:{uuid4().hex}"
        self._projected_events: list[DomainEvent] = []
        self._leads: tuple[ClassificationLead, ...] = ()

    @property
    def events(self) -> Iterable[DomainEvent]:
        """Replayable events accumulated by this evaluator."""

        self._refresh_event_projection()
        return tuple(self._projected_events)

    @property
    def leads(self) -> tuple[ClassificationLead, ...]:
        """Classification leads evaluated by the most recent evaluation."""

        return self._leads

    def _refresh_event_projection(self) -> tuple[DomainEvent, ...]:
        """Extend the evaluator projection with newly appended events."""

        new_events = self._events.read_new(self._event_consumer_id)
        self._projected_events.extend(new_events)
        return tuple(self._projected_events)

    def evaluate(
        self,
        execution: ExecutionResult,
        invariants: Mapping[str, InvariantProjection],
        graph: QdlGraph | None = None,
    ) -> EvaluationResult:
        classification_facts = ClassificationFacts.from_graph(graph)
        self._leads = evaluate_classification_leads(graph)
        self._refresh_event_projection()
        observation_ids = {
            observation.observation_id for observation in execution.observations
        }
        checks = {
            event.check.check_id: event.check
            for event in self._projected_events
            if isinstance(event, CheckCompleted)
            and event.check is not None
            and event.observation.observation_id in observation_ids
        }
        # Physical checks are authoritative; journal projections may redact
        # requests and must not replace the original PoC or identity.
        checks.update({check.check_id: check for check in execution.checks})
        findings = self._raise_findings(
            execution.observations,
            checks,
            invariants,
            execution.provenance,
            execution.policy_verdicts,
            execution.minimal_checks,
            classification_facts,
        )
        self._refresh_event_projection()
        replayed = tuple(self._projected_events)
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
            findings=tuple(findings),
            replayed_observations=replayed_observations,
            replayed_findings=replayed_findings,
        )

    def _raise_findings(
        self,
        observations: tuple[Observation, ...],
        checks: Mapping[str, Check],
        invariants: Mapping[str, InvariantProjection],
        provenance: Mapping[tuple[str, str], ObservationProvenance],
        policy_verdicts: Mapping[tuple[str, str], object],
        minimal_checks: Mapping[tuple[str, str], Check],
        classification_facts: ClassificationFacts,
    ) -> list[Finding]:
        findings: dict[
            tuple[str, str, tuple[str, ...], tuple[str, ...], str], Finding
        ] = {}
        correlations: dict[
            tuple[str, str, tuple[str, ...], tuple[str, ...], str], str
        ] = {}
        observations_by_id = {
            observation.observation_id: observation for observation in observations
        }
        for evaluation_key, observation_provenance in provenance.items():
            observation_id, invariant_id = evaluation_key
            observation = observations_by_id.get(observation_id)
            if (
                observation is None
                or observation_provenance.invariant_id != invariant_id
            ):
                continue
            check = checks.get(observation.check_id)
            if check is None:
                continue
            invariant = invariants.get(observation_provenance.invariant_id)
            if invariant is None:
                continue
            policy_verdict = policy_verdicts.get(evaluation_key)
            if not isinstance(policy_verdict, PolicyVerdict):
                continue
            verdict = policy_verdict.status
            can_raise_finding = (
                verdict is VerdictStatus.FAIL
                and policy_verdict.deterministic
                and policy_verdict.grounded
            )
            if verdict is not VerdictStatus.FAIL or not can_raise_finding:
                continue
            finding = finding_from_observation(
                check,
                observation,
                invariant,
                title=f"Security policy violated: {invariant.invariant_id}",
                description=invariant.statement,
                remediation="Review and enforce the invariant's security policy.",
                verdict=verdict,
                goal_id=observation_provenance.goal_id,
                path_id=observation_provenance.path_id,
                step_id=observation_provenance.step_id,
                rationale=policy_verdict.rationale,
                minimal_poc=minimal_checks.get(evaluation_key, check).request,
                confidence=policy_verdict.confidence,
                evidence_refs=policy_verdict.evidence_refs,
                policy_verdict=policy_verdict,
                classification_facts=classification_facts,
            )
            if not finding.evidence_refs:
                finding = finding.model_copy(
                    update={"evidence_refs": (observation.observation_id,)}
                )
            fingerprint = finding.fingerprint
            if fingerprint is None:
                raise ValueError("finding evaluator requires a finding fingerprint")
            key = fingerprint.key
            existing = findings.get(key)
            if existing is None:
                findings[key] = finding
                correlations.setdefault(key, check.check_id)
            else:
                findings[key] = merge_finding_witnesses(existing, finding)
        merged_findings = list(findings.values())
        for finding in merged_findings:
            fingerprint = finding.fingerprint
            if fingerprint is None:
                raise ValueError("finding evaluator requires a finding fingerprint")
            self._event_bus.publish(
                FindingRaised(
                    finding=finding,
                    correlation_id=correlations[fingerprint.key],
                )
            )
        return merged_findings


def merge_finding_witnesses(finding: Finding, witness: Finding) -> Finding:
    """Merge a repeated FAIL into the first finding for one fingerprint."""

    witness_refs = witness.evidence_refs or (witness.observation_id,)
    evidence_refs = tuple(dict.fromkeys((*finding.evidence_refs, *witness_refs)))
    minimal_poc = select_minimal_poc(finding.minimal_poc, witness.minimal_poc)
    if evidence_refs == finding.evidence_refs and minimal_poc == finding.minimal_poc:
        return finding
    return finding.model_copy(
        update={"evidence_refs": evidence_refs, "minimal_poc": minimal_poc}
    )


def select_minimal_poc(
    current: tuple[tuple[str, JsonValue], ...] | None,
    candidate: tuple[tuple[str, JsonValue], ...] | None,
) -> tuple[tuple[str, JsonValue], ...] | None:
    """Return the shorter of two reproducing request payloads."""

    if current is None:
        return candidate
    if candidate is None:
        return current
    if _poc_size(candidate) < _poc_size(current):
        return candidate
    return current


def _poc_size(poc: tuple[tuple[str, JsonValue], ...]) -> tuple[int, int]:
    return (request_complexity(poc), len(poc))


__all__ = [
    "FindingEvaluator",
    "merge_finding_witnesses",
    "select_minimal_poc",
]
