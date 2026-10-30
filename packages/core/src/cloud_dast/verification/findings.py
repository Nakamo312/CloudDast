"""Build stable finding identities and findings from verified observations."""

from __future__ import annotations

from collections.abc import Mapping

from cloud_dast.contracts.candidate_metrics import request_complexity
from cloud_dast.contracts.execution import ExecutionResult
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    Check,
    Finding,
    FindingFingerprint,
    JsonValue,
    Observation,
    PolicyVerdict,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Struct
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.taxonomy import (
    DEFAULT_CATALOG,
    ClassificationFacts,
)


def attach_finding_identity(
    policy_verdict: PolicyVerdict,
    *,
    invariant: InvariantProjection,
    probe_fields: tuple[str, ...],
) -> PolicyVerdict:
    """Attach the norm's value-free sink and carrier identity to a verdict."""

    return policy_verdict.model_copy(
        update={
            "sink_ids": sink_ids_from_invariant(invariant),
            "probe_fields": tuple(dict.fromkeys(probe_fields)),
        }
    )


def sink_ids_from_invariant(invariant: InvariantProjection) -> tuple[str, ...]:
    """Return formal sink identifiers named by reached or external-call norms."""

    fact = invariant.norm_fact
    if fact is None or len(fact.args) != 2:
        return ()
    effect = fact.args[1]
    if not isinstance(effect, Struct) or effect.name not in {
        "reached",
        "external_call",
    }:
        return ()
    identifiers = {
        identifier
        for argument in effect.args[1:]
        if (identifier := atom_value(argument)) is not None
    }
    return tuple(sorted(identifiers))


def finding_fingerprint(
    *,
    invariant: InvariantProjection,
    observation: Observation,
    policy_verdict: PolicyVerdict | None,
) -> FindingFingerprint:
    """Build the value-free identity shared by repeated deterministic FAILs."""

    return FindingFingerprint(
        invariant_id=invariant.invariant_id,
        scenario_id=observation.scenario_id,
        sink_ids=(
            policy_verdict.sink_ids
            if policy_verdict is not None and policy_verdict.sink_ids
            else sink_ids_from_invariant(invariant)
        ),
        probe_fields=(
            policy_verdict.probe_fields if policy_verdict is not None else ()
        ),
        witness_kind=policy_verdict.model_id if policy_verdict is not None else "",
    )


def collect(
    execution: ExecutionResult,
    invariants: Mapping[str, InvariantProjection],
    checks: Mapping[str, Check],
    classification_facts: ClassificationFacts,
) -> tuple[Finding, ...]:
    """Collect and merge findings admitted by the current norm registry."""

    findings: dict[tuple[str, str, tuple[str, ...], tuple[str, ...], str], Finding] = {}
    observations_by_id = {
        observation.observation_id: observation
        for observation in execution.observations
    }
    for evaluation_key, observation_provenance in execution.provenance.items():
        observation_id, invariant_id = evaluation_key
        observation = observations_by_id.get(observation_id)
        if observation is None or observation_provenance.invariant_id != invariant_id:
            continue
        check = checks.get(observation.check_id)
        if check is None:
            continue
        invariant = invariants.get(observation_provenance.invariant_id)
        if invariant is None or invariant.norm_fact is None:
            continue
        policy_verdict = execution.policy_verdicts.get(evaluation_key)
        if not isinstance(policy_verdict, PolicyVerdict):
            continue
        if not (
            policy_verdict.status is VerdictStatus.FAIL
            and policy_verdict.deterministic
            and policy_verdict.grounded
            and any((ref in observations_by_id for ref in policy_verdict.evidence_refs))
        ):
            continue
        try:
            norm = NormCompiler().compile(invariant.norm_fact)
        except ValueError:
            continue
        if norm.verdict_policy != "deterministic":
            continue
        minimal_poc = execution.minimal_checks.get(evaluation_key, check).request
        if observation.check_id != check.check_id:
            raise ValueError("observation does not belong to the check")
        if observation.scenario_id != check.scenario_id:
            raise ValueError("observation scenario does not belong to the check")

        classification = DEFAULT_CATALOG.classify_finding(
            invariant,
            facts=classification_facts,
            action_id=f"action:{check.method_id}",
        )
        fingerprint = finding_fingerprint(
            invariant=invariant,
            observation=observation,
            policy_verdict=policy_verdict,
        )
        finding = Finding(
            observation_id=observation.observation_id,
            invariant_id=invariant.invariant_id,
            method_id=check.method_id,
            scenario_id=observation.scenario_id,
            severity=invariant.severity,
            title=f"Security policy violated: {invariant.invariant_id}",
            description=invariant.statement,
            remediation="Review and enforce the invariant's security policy.",
            goal_id=observation_provenance.goal_id,
            path_id=observation_provenance.path_id,
            step_id=observation_provenance.step_id,
            rationale=policy_verdict.rationale,
            fingerprint=fingerprint,
            minimal_poc=minimal_poc,
            confidence=policy_verdict.confidence,
            evidence_refs=policy_verdict.evidence_refs,
            vulnerability_class=classification.vulnerability_class,
            classification_deficits=classification.deficit_reasons,
            cwe=classification.cwe,
            owasp=classification.owasp,
            stride=classification.stride,
            norm_fact=invariant.norm_fact,
        )
        fingerprint = finding.fingerprint
        if fingerprint is None:
            raise ValueError("finding evaluator requires a finding fingerprint")
        key = fingerprint.key
        existing = findings.get(key)
        if existing is None:
            findings[key] = finding
        else:
            findings[key] = merge_finding_witnesses(existing, finding)
    return tuple(findings.values())


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
    "collect",
    "merge_finding_witnesses",
    "select_minimal_poc",
    "attach_finding_identity",
    "finding_fingerprint",
    "sink_ids_from_invariant",
]
