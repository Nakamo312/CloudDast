"""Explicit owner handoff for grounding policy tests outside a campaign."""

from types import SimpleNamespace

from dishka import Provider, make_container, provide

from cloud_dast.composition.grounding import Provider as GroundingProvider
from cloud_dast.composition.grounding import ServiceOptions
from cloud_dast.composition.scopes import CloudDastScopes, RunScope
from cloud_dast.ports import FormalRepository
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.classification import ApprovalFlow
from cloud_dast.runtime.grounding.consultation import DispatchFlow
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator
from cloud_dast.runtime.grounding.promotion import ProposalPromoter
from cloud_dast.runtime.grounding.runtime import BatchFlow
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.verification.evidence import (
    build_evidence_view,
    build_paired_evidence_view,
)
from cloud_dast.verification.slices import build_sibling_action_slice


def make_grounding(repository, *, options: ServiceOptions | None = None, **values):
    """Resolve real run-scoped owners through the production DI provider."""
    settings = options if options is not None else ServiceOptions(**values)

    class InputsProvider(Provider):
        @provide(scope=RunScope)
        def formal_repository(self) -> FormalRepository:
            return repository

        @provide(scope=RunScope)
        def grounding_settings(self) -> ServiceOptions:
            return settings

    with make_container(
        InputsProvider(),
        GroundingProvider(),
        scopes=CloudDastScopes,
    ) as app:
        with app(scope=RunScope) as run:
            return SimpleNamespace(
                batches=run.get(BatchFlow),
                lifecycle=run.get(RunCoordinator),
                source=run.get(Loader),
                promotion=run.get(ProposalPromoter),
                classification=run.get(ApprovalFlow),
                consultation=run.get(DispatchFlow),
                variance=run.get(DifferentialFlow),
            )


def commit_reactive(grounding, service, axis, actions, **kwargs):
    source = grounding.source.load(service, failure_log="test_source_failed")
    if source is None or not grounding.batches.reactive_capable or not actions:
        return None
    evidence = _reactive_evidence(
        kwargs.pop("evidence", None),
        check=kwargs.get("check"),
        observation=kwargs.get("observation"),
        oob_events=kwargs.pop("oob_events", ()),
    )
    proposal = grounding.batches.prepare_reactive(
        source, axis, actions, evidence=evidence, **kwargs
    )
    if proposal is None:
        return None
    return grounding.batches.commit(
        service,
        source,
        axis,
        actions,
        proposal,
        evidence=evidence,
    )


def commit_branch(grounding, service, action, **kwargs):
    source = grounding.source.load(service, failure_log="test_source_failed")
    if source is None or not grounding.batches.reactive_capable:
        return None
    evidence = _reactive_evidence(
        kwargs.pop("evidence", None),
        check=kwargs.get("check"),
        observation=kwargs.get("observation"),
        oob_events=kwargs.pop("oob_events", ()),
    )
    siblings = build_sibling_action_slice(source, action=action)
    proposal = grounding.batches.prepare_branch(
        source, action, sibling_slice=siblings, evidence=evidence, **kwargs
    )
    if proposal is None:
        return None
    return grounding.batches.commit(
        service,
        source,
        "alternatives",
        (action,),
        proposal,
        sibling_slice=siblings,
        evidence=evidence,
    )


def commit_variance(grounding, service, action, control, treatment, report, **kwargs):
    measured = grounding.variance.persist_measured_evidence(
        service,
        action,
        control,
        treatment,
        report,
        control_check=kwargs.get("control_check"),
        treatment_check=kwargs.get("treatment_check"),
    )
    if not kwargs.pop("llm", True) or not grounding.batches.reactive_capable:
        return None
    source = grounding.source.load(service, failure_log="test_source_failed")
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
    proposal = grounding.variance.prepare_batch(
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
    return grounding.variance.commit_batch(
        service, source, action, report, proposal, evidence=evidence
    )


def _reactive_evidence(evidence, *, check, observation, oob_events):
    if evidence is not None or (check is None and observation is None):
        return evidence
    return build_evidence_view(
        check=check, observation=observation, oob_events=oob_events, label="reactive"
    )
