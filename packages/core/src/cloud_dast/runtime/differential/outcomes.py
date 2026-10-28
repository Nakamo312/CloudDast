"""Route completed differential measurements into campaign evidence."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from cloud_dast.api import LiveRequest
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import (
    DiffPairComputed,
    DomainEvent,
    EventScope,
)
from cloud_dast.ports import EventPublisher, FormalRepository
from cloud_dast.runtime.deficits import variance_deficit
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.differential.comparator import (
    compare_concurrency_measurements,
    compare_observations,
)
from cloud_dast.verification.differential.contracts import ConcurrencyResult
from cloud_dast.verification.differential.projection import project_diff
from cloud_dast.verification.differential.report import DiffReport, diff_campaign_key

logger = logging.getLogger("cloud_dast.runtime.differential.outcomes")


class OutcomeRecorder:
    """Own the policy-independent routing of measured differential outcomes.

    The campaign runner owns when and how live pairs are executed.  This
    component owns what a completed pair means to the campaign: comparison,
    event publication, runtime projection, and variance-deficit storage.
    """

    def __init__(
        self,
        *,
        formal_repository: FormalRepository | None = None,
        event_bus: EventPublisher | None = None,
        metrics: CampaignMetrics | None = None,
    ) -> None:
        self._formal_repository = formal_repository
        self._event_bus = event_bus
        self._metrics = metrics

    def record_pair(
        self,
        request: LiveRequest,
        action: str,
        mode: str,
        control: Observation,
        treatment: Observation,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        scope: EventScope,
        *,
        correlation_check_id: str,
        control_check: Check | None = None,
        treatment_check: Check | None = None,
    ) -> None:
        """Compare one pair and route a measured variance."""

        report = compare_observations(action, control, treatment)
        if report is None:
            logger.info(
                "diff_pair_unscoreable action=%s reason=incomplete-response",
                action,
            )
            return
        self.record_report(
            request,
            action,
            mode,
            report,
            control,
            treatment,
            deficits,
            variance_records,
            scope,
            correlation_check_id=correlation_check_id,
            control_check=control_check,
            treatment_check=treatment_check,
        )

    def record_concurrency(
        self,
        request: LiveRequest,
        action: str,
        result: ConcurrencyResult,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        scope: EventScope,
    ) -> None:
        """Accumulate concurrency evidence and route any measured variance."""

        evidence_pairs: list[tuple[Check, Observation]] = []
        if result.read_before is not None:
            evidence_pairs.append(result.read_before)
        evidence_pairs.extend(result.probes)
        if result.read_after is not None:
            evidence_pairs.append(result.read_after)
        accumulator.checks.extend(check for check, _ in evidence_pairs)
        accumulator.observations.extend(
            observation for _, observation in evidence_pairs
        )

        report = compare_concurrency_measurements(
            action,
            tuple(
                observation
                for check, observation in result.probes
                if check.method_id == action
            ),
            read_before=(
                result.read_before[1] if result.read_before is not None else None
            ),
            read_after=(
                result.read_after[1] if result.read_after is not None else None
            ),
        )
        if report is None:
            return
        control = self.observation_for_report(
            evidence_pairs,
            report.control_observation_id,
        )
        treatment = self.observation_for_report(
            evidence_pairs,
            report.treatment_observation_id,
        )
        control_check = self.check_for_report(
            evidence_pairs,
            report.control_observation_id,
        )
        treatment_check = self.check_for_report(
            evidence_pairs,
            report.treatment_observation_id,
        )
        self.record_report(
            request,
            action,
            "concurrency",
            report,
            control,
            treatment,
            deficits,
            variance_records,
            scope,
            correlation_check_id=treatment_check.check_id,
            control_check=control_check,
            treatment_check=treatment_check,
        )

    def record_report(
        self,
        request: LiveRequest,
        action: str,
        mode: str,
        report: DiffReport,
        control: Observation,
        treatment: Observation,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        scope: EventScope,
        *,
        correlation_check_id: str,
        control_check: Check | None,
        treatment_check: Check | None,
    ) -> None:
        """Publish one report and retain only unexplained variance."""

        self._publish(
            DiffPairComputed(
                action_id=action,
                mode=mode,
                control_observation_id=control.observation_id,
                treatment_observation_id=treatment.observation_id,
                dimensions=report.dimensions,
                has_variance=report.has_variance,
                correlation_id=correlation_check_id,
            ),
            scope,
        )
        if self._metrics is not None:
            self._metrics.record_diff_pair(mode)
        logger.info(
            "diff_pair_computed mode=%s action=%s dimensions=%s variance=%s",
            mode,
            action,
            ",".join(report.dimensions) or "none",
            report.has_variance,
        )
        if not report.has_variance:
            return

        self._persist_runtime_facts(request, action, report)
        deficit = variance_deficit(report)
        if deficits.add((deficit,)):
            variance_records[deficit.work_item_key] = VarianceRecord(
                control=control,
                treatment=treatment,
                report=report,
                control_check=control_check,
                treatment_check=treatment_check,
            )
            logger.info(
                "variance_deficit_detected mode=%s action=%s signature=%.120s",
                mode,
                action,
                report.signature,
            )

    @staticmethod
    def observation_for_report(
        pairs: Sequence[tuple[Check, Observation]],
        observation_id: str,
    ) -> Observation:
        return next(
            observation
            for _, observation in pairs
            if observation.observation_id == observation_id
        )

    @staticmethod
    def check_for_report(
        pairs: Sequence[tuple[Check, Observation]],
        observation_id: str,
    ) -> Check:
        return next(
            check
            for check, observation in pairs
            if observation.observation_id == observation_id
        )

    def _persist_runtime_facts(
        self,
        request: LiveRequest,
        action: str,
        report: DiffReport,
    ) -> None:
        """Persist measured variance as runtime QDL facts, never a finding."""

        if self._formal_repository is None:
            return
        graph = project_diff(report)
        self._formal_repository.save(
            f"diff:{request.service}:{diff_campaign_key(action, report)}:runtime",
            graph,
            provenance={
                "source_kind": "diff-runtime",
                "action": action,
                "diff": report.signature,
            },
            adapter_version="diff-projection-v1",
            mapping_report={"mapped": len(graph.facts), "unmapped": 0},
        )

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)


__all__ = ["OutcomeRecorder"]
