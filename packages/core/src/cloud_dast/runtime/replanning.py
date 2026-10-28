"""Reactive campaign replanning and evidence-driven work-item execution."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass

from cloud_dast.api import LiveRequest
from cloud_dast.model.events import (
    EventScope,
)
from cloud_dast.ports import EventPublisher, FormalRepository, GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.campaign.state import RuntimeState
from cloud_dast.runtime.consultation.outcomes import (
    OutcomePolicy,
)
from cloud_dast.runtime.consultation.runner import (
    Callbacks as WaveCallbacks,
)
from cloud_dast.runtime.consultation.runner import (
    Coordinator as WaveCoordinator,
)
from cloud_dast.runtime.deficits.collection import (
    ClassificationState,
    DeficitCollectionCallbacks,
    DeficitCollector,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
)
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.evidence_gate import EvidenceDeficitRecord, Gate
from cloud_dast.runtime.execution.runner import paths_for_request
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.recovery import Coordinator as RecoveryCoordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.oracles.latency import LatencyOracle

logger = logging.getLogger("cloud_dast.runtime.replanning")

_EVIDENCE_REQUIRED_AXES: frozenset[str] = frozenset({"response_semantics", "variance"})


@dataclass(frozen=True, slots=True)
class Callbacks:
    """Runtime services required by the reactive replanning owner."""

    grounding: AutoGroundingService | None
    grounding_runner: GroundingRunner | None
    batch_timeout: float
    reactive_max_workers: int
    latency_oracle: LatencyOracle | None
    formal_repository: FormalRepository | None
    event_bus: EventPublisher | None
    metrics: CampaignMetrics | None


class Coordinator:
    """Own deficit closure, consultation waves, and reactive replanning."""

    def __init__(self, callbacks: Callbacks) -> None:
        self._grounding = callbacks.grounding
        self._deficit_collector = DeficitCollector(
            DeficitCollectionCallbacks(grounding=callbacks.grounding)
        )
        self._evidence_gate = Gate(
            formal_repository=callbacks.formal_repository,
            event_bus=callbacks.event_bus,
        )
        self._consultation = WaveCoordinator(
            WaveCallbacks(
                grounding=callbacks.grounding,
                grounding_runner=callbacks.grounding_runner,
                batch_timeout=callbacks.batch_timeout,
                reactive_max_workers=callbacks.reactive_max_workers,
                latency_oracle=callbacks.latency_oracle,
                event_bus=callbacks.event_bus,
                metrics=callbacks.metrics,
                evidence_gate=self._evidence_gate,
            )
        )

    @property
    def evidence_deficits(
        self,
    ) -> Mapping[tuple[str, tuple[str, ...]], EvidenceDeficitRecord]:
        return self._evidence_gate.evidence_deficits

    @property
    def consultation_outcomes(self) -> OutcomePolicy:
        return self._consultation.consultation_outcomes

    def collect_deficits(
        self,
        campaign: RuntimeState,
        *,
        expand_graph: bool,
    ) -> int:
        """Collect runtime deficits through the dedicated discovery owner."""

        return self._deficit_collector.collect_deficits(
            campaign.request,
            campaign.binding,
            campaign.execution.scheduler,
            campaign.execution.accumulator,
            campaign.grounding.deficits,
            ClassificationState(
                paths=campaign.grounding.classified_paths,
                observations=campaign.grounding.classified_observations,
            ),
            campaign.grounding.recovery,
            expand_graph=expand_graph,
        )

    def record_recovery(
        self,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        recovery: RecoveryCoordinator,
        *,
        blocked_reasons: Mapping[str, str] | None = None,
    ) -> None:
        """Record blocked-path clues through the dedicated discovery owner."""

        self._deficit_collector.record_recovery(
            scheduler,
            accumulator,
            recovery,
            blocked_reasons=blocked_reasons,
        )

    def drain_reactive(
        self,
        request: LiveRequest,
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
        *,
        variance_records: dict[tuple[str, ...], VarianceRecord] | None = None,
        scope: EventScope | None = None,
        graph: QdlGraph | None = None,
        active_path_ids: frozenset[str] | None = None,
    ) -> int:
        """Run one dependency wave, then yield to binding and execution.

        S30 v3: pending deficits are coalesced into work items and dispatched
        in waves of mutually independent items planned against one immutable
        graph snapshot.  One work item is one model call regardless of how
        many path-fanout deficits it covers; after the whole wave merges, all
        pending subgoals are re-derived against the merged graph.  Dependent
        and conflicting items are ordered into later waves, and deterministic
        baseline work runs inline on the campaign thread.

        S26R admission runs before a fair-share slot is consumed: an S33R
        consultation outcome that is already absorbing for this evidence
        signature is invisible to the scheduler instead of spending another
        class's budget.
        """

        if self._grounding is None or not self._grounding.reactive_capable:
            return 0
        measured = self._persist_measured_variance_evidence(request, variance_records)
        base_graph = (
            merge_graphs(graph or QdlGraph(), measured) if measured.facts else graph
        )
        snapshot = base_graph.content_hash if base_graph is not None else ""

        def work_item_ready(work_item: WorkItem) -> bool:
            return self._consultation.work_item_ready(
                request.service,
                work_item,
                accumulator,
            )

        wave = deficits.pop_wave(
            graph_snapshot=snapshot,
            ready=work_item_ready,
        )
        if not wave:
            return 0
        execution = self._consultation._run_work_item_wave(
            request,
            wave,
            deficits,
            accumulator,
            variance_records=variance_records,
            scope=scope,
            base_graph=base_graph,
            active_path_ids=active_path_ids,
        )
        # Yield after one dependency wave: accepted facts must reach the
        # binder and executable paths before the next consultation wave.
        return execution.promoted

    @staticmethod
    def _active_path_ids(campaign: RuntimeState) -> frozenset[str]:
        """Return path ids present in the current bound plan or backlog."""

        current_paths = paths_for_request(
            campaign.binding.execution.paths,
            campaign.request.method_id,
        )
        return frozenset(
            path.path_id
            for path in (*current_paths, *campaign.execution.branch_backlog)
        )

    def _persist_measured_variance_evidence(
        self,
        request: LiveRequest,
        variance_records: dict[tuple[str, ...], VarianceRecord] | None,
    ) -> QdlGraph:
        """Persist measured canary echoes before shared LLM budget use."""

        # Persist measured canary echoes as runtime evidence before the shared
        # LLM budget.  The variance deficit stays open: only a validated model
        # proposal may become an executable norm.
        measured_graphs = []
        for record in list((variance_records or {}).values()):
            measured = self._grounding.persist_measured_evidence(
                request.service,
                record.report.action_id,
                record.control,
                record.treatment,
                record.report,
                control_check=record.control_check,
                treatment_check=record.treatment_check,
            )
            if measured is None:
                continue
            measured_graphs.append(measured)
            logger.info(
                "measured_variance_evidence_available service=%s action=%s facts=%d",
                request.service,
                record.report.action_id,
                len(measured.facts),
            )
        return merge_graphs(*measured_graphs)
