from __future__ import annotations

import os
from dataclasses import dataclass

from cloud_dast.composition.formal_ingestion import QdlIngestionService
from cloud_dast.infrastructure.advisory import AdvisoryPreScanService
from cloud_dast.ports import EventPublisher, EventSubscriber
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign import LiveWorkflow
from cloud_dast.runtime.campaign.finalization import Finalizer, FinalizerDeps
from cloud_dast.runtime.campaign.initialization import Bootstrap, BootstrapDeps
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.consultation.calls import Invoker
from cloud_dast.runtime.consultation.commit import Committer
from cloud_dast.runtime.consultation.outcomes import OutcomePolicy
from cloud_dast.runtime.consultation.wave import Coordinator as WaveCoordinator
from cloud_dast.runtime.deficits.collection import (
    DeficitCollector,
)
from cloud_dast.runtime.differential.campaign import ExperimentDeps, Runner
from cloud_dast.runtime.evidence_gate import Gate
from cloud_dast.runtime.execution.runner import BoundPathRunner
from cloud_dast.runtime.grounding import BatchFlow
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.runtime.replanning import Coordinator
from cloud_dast.verification.differential.modes import DIFF_MODES
from cloud_dast.verification.finding_evaluator import FindingEvaluator


@dataclass(frozen=True)
class CloudDastRuntime:
    live_workflow: LiveWorkflow
    event_bus: EventPublisher
    event_subscriber: EventSubscriber
    formal_ingestion: QdlIngestionService
    advisory_pre_scan: AdvisoryPreScanService

    def pre_scan_advisories(self, service: str) -> QdlGraph | None:
        """Run the deterministic external-knowledge pre-scan boundary."""

        return self.advisory_pre_scan.pre_scan(service)


_DEFAULT_DIFF_MODES: frozenset[str] = frozenset({"factors"})


def diff_modes_from_environment() -> frozenset[str]:
    """Parse ``CLOUD_DAST_DIFF_MODES`` (comma list, default factors-only).

    The variable selects which differential discovery modes run when the
    ``CLOUD_DAST_DIFF_MODE`` master switch is on: ``factors`` (factor
    pairs), ``payload`` (payload pairs), ``readback`` (before/after
    read-back), ``timing`` (repeated robust latency classes) and
    ``concurrency`` (parallel aggregate probes).  An unset or empty value
    keeps the historical factors-only behavior; unknown modes fail fast.
    """

    raw = os.environ.get("CLOUD_DAST_DIFF_MODES", "")
    requested = frozenset(
        part.strip().lower() for part in raw.split(",") if part.strip()
    )
    if not requested:
        return _DEFAULT_DIFF_MODES
    unknown = requested - DIFF_MODES
    if unknown:
        raise RuntimeError(
            "CLOUD_DAST_DIFF_MODES must be a comma list of: "
            + ", ".join(sorted(DIFF_MODES))
        )
    return requested


def assemble_workflow(
    scenario_binder: ScenarioBinder,
    path_runner: BoundPathRunner,
    finding_evaluator: FindingEvaluator,
    grounding: BatchFlow | None = None,
    *,
    lifecycle: RunCoordinator | None = None,
    source: Loader | None = None,
    variance: DifferentialFlow | None = None,
    options: LiveWorkflowOptions | None = None,
) -> LiveWorkflow:
    """Assemble one campaign dependency graph for the caller's run scope."""

    settings = options if options is not None else LiveWorkflowOptions()
    if settings.reactive_max_workers <= 0:
        raise ValueError("reactive_max_workers must be positive")
    diff_modes = (
        settings.diff_modes
        if settings.diff_modes is not None
        else diff_modes_from_environment()
    )
    differential = Runner(
        ExperimentDeps(
            executor=path_runner.differential,
            diff_mode=settings.diff_mode,
            diff_modes=diff_modes,
            latency_oracle=settings.latency_oracle,
            scenario_repository=settings.scenario_repository,
            formal_repository=settings.formal_repository,
            event_bus=settings.event_bus,
            metrics=settings.metrics,
        )
    )
    replanning = _assemble_replanning(grounding, source, variance, settings)
    finalizer = Finalizer(
        FinalizerDeps(
            binder=scenario_binder,
            runner=path_runner,
            evaluator=finding_evaluator,
            grounding_runner=settings.grounding_runner,
            event_bus=settings.event_bus,
            metrics=settings.metrics,
        )
    )
    initializer = Bootstrap(
        BootstrapDeps(
            binder=scenario_binder,
            evaluator=finding_evaluator,
            differential=differential,
            grounding=lifecycle,
            reactive=grounding,
            grounding_runner=settings.grounding_runner,
            reactive_budget=settings.reactive_budget,
            latency_oracle=settings.latency_oracle,
            diff_mode=settings.diff_mode,
            report_publisher=settings.report_publisher,
            event_bus=settings.event_bus,
            metrics=settings.metrics,
        )
    )
    return LiveWorkflow(
        scenario_binder,
        path_runner,
        DeficitCollector(grounding),
        initializer,
        differential,
        replanning,
        finalizer,
        options=settings,
    )


def _assemble_replanning(
    grounding: BatchFlow | None,
    source: Loader | None,
    variance: DifferentialFlow | None,
    settings: LiveWorkflowOptions,
) -> Coordinator:
    """Bind one gate and one policy to both scheduling and owner admission."""

    gate = Gate(
        formal_repository=settings.formal_repository, event_bus=settings.event_bus
    )
    policy = OutcomePolicy()
    committer = Committer(
        grounding,
        settings.event_bus,
        settings.metrics,
        gate,
        policy,
        source,
        variance,
    )
    consultation = WaveCoordinator(
        grounding_runner=settings.grounding_runner,
        batch_timeout=settings.batch_timeout,
        reactive_max_workers=settings.reactive_max_workers,
        latency_oracle=settings.latency_oracle,
        policy=policy,
        invoker=Invoker(grounding, settings.event_bus, variance),
        committer=committer,
        source=source,
    )
    return Coordinator(
        grounding,
        gate,
        consultation,
        variance,
    )
