"""Explicit owner handoff for grounding policy tests outside a campaign."""

from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.verification.evidence import (
    build_evidence_view,
    build_paired_evidence_view,
)
from cloud_dast.verification.slices import build_sibling_action_slice


def commit_reactive(grounding, service, axis, actions, **kwargs):
    source = grounding.load_source(service, failure_log="test_source_failed")
    if source is None or not grounding.reactive_capable or not actions:
        return None
    evidence = _reactive_evidence(
        kwargs.pop("evidence", None),
        check=kwargs.get("check"),
        observation=kwargs.get("observation"),
        oob_events=kwargs.pop("oob_events", ()),
    )
    proposal = grounding.prepare_reactive_batch(
        source, axis, actions, evidence=evidence, **kwargs
    )
    if proposal is None:
        return None
    return grounding.commit_reactive_batch(
        service,
        source,
        axis,
        actions,
        proposal,
        evidence=evidence,
        context=kwargs.get("context"),
    )


def commit_branch(grounding, service, action, **kwargs):
    source = grounding.load_source(service, failure_log="test_source_failed")
    if source is None or not grounding.reactive_capable:
        return None
    evidence = _reactive_evidence(
        kwargs.pop("evidence", None),
        check=kwargs.get("check"),
        observation=kwargs.get("observation"),
        oob_events=kwargs.pop("oob_events", ()),
    )
    siblings = build_sibling_action_slice(source, action=action)
    proposal = grounding.prepare_branch_batch(
        source, action, sibling_slice=siblings, evidence=evidence, **kwargs
    )
    if proposal is None:
        return None
    return grounding.commit_branch_batch(
        service, source, action, proposal, sibling_slice=siblings, evidence=evidence
    )


def commit_variance(grounding, service, action, control, treatment, report, **kwargs):
    measured = grounding.persist_measured_evidence(
        service,
        action,
        control,
        treatment,
        report,
        control_check=kwargs.get("control_check"),
        treatment_check=kwargs.get("treatment_check"),
    )
    if not kwargs.pop("llm", True) or not grounding.reactive_capable:
        return None
    source = grounding.load_source(service, failure_log="test_source_failed")
    if source is None:
        return None
    source = merge_graphs(source, measured) if measured is not None else source
    evidence = kwargs.pop("evidence", None) or build_paired_evidence_view(
        control=control,
        treatment=treatment,
        report=report,
        control_check=kwargs.get("control_check"),
        treatment_check=kwargs.get("treatment_check"),
        oob_events=kwargs.get("oob_events", ()),
    )
    proposal = grounding.prepare_variance_batch(
        PairInput(
            source=source,
            action_id=action,
            control=control,
            treatment=treatment,
            report=report,
            control_check=kwargs.pop("control_check", None),
            treatment_check=kwargs.pop("treatment_check", None),
            oob_events=kwargs.pop("oob_events", ()),
            evidence=evidence,
        )
    )
    if proposal is None:
        return None
    return grounding.commit_variance_batch(
        service, source, action, report, proposal, evidence=evidence
    )


def _reactive_evidence(evidence, *, check, observation, oob_events):
    if evidence is not None or (check is None and observation is None):
        return evidence
    return build_evidence_view(
        check=check, observation=observation, oob_events=oob_events, label="reactive"
    )
