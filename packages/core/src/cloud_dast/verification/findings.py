"""Build stable finding identities and findings from verified observations."""

from __future__ import annotations

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


def finding_from_observation(
    check: Check,
    observation: Observation,
    invariant: InvariantProjection,
    *,
    title: str,
    description: str,
    remediation: str,
    verdict: VerdictStatus | None = None,
    goal_id: str | None = None,
    path_id: str | None = None,
    step_id: str | None = None,
    rationale: str = "",
    minimal_poc: tuple[tuple[str, JsonValue], ...] | None = None,
    confidence: float | None = None,
    evidence_refs: tuple[str, ...] = (),
    policy_verdict: PolicyVerdict | None = None,
    classification_facts: ClassificationFacts | None = None,
) -> Finding:
    """Build a finding only when the observation violates the invariant."""

    if observation.check_id != check.check_id:
        raise ValueError("observation does not belong to the check")
    if observation.scenario_id != check.scenario_id:
        raise ValueError("observation scenario does not belong to the check")

    if verdict is None:
        raise ValueError("finding requires an explicit verdict")
    if verdict is not VerdictStatus.FAIL:
        raise ValueError("finding requires a failed observation")

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
    return Finding(
        observation_id=observation.observation_id,
        invariant_id=invariant.invariant_id,
        method_id=check.method_id,
        scenario_id=observation.scenario_id,
        severity=invariant.severity,
        title=title,
        description=description,
        remediation=remediation,
        goal_id=goal_id,
        path_id=path_id,
        step_id=step_id,
        rationale=rationale,
        fingerprint=fingerprint,
        minimal_poc=minimal_poc,
        confidence=confidence,
        evidence_refs=evidence_refs,
        vulnerability_class=classification.vulnerability_class,
        classification_deficits=classification.deficit_reasons,
        cwe=classification.cwe,
        owasp=classification.owasp,
        stride=classification.stride,
        norm_fact=invariant.norm_fact,
    )


__all__ = [
    "attach_finding_identity",
    "finding_fingerprint",
    "finding_from_observation",
    "sink_ids_from_invariant",
]
