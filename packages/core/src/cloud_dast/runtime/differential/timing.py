"""Timing differential mode and repeated pair measurement."""

from __future__ import annotations

import logging

from cloud_dast.contracts.plan import QdlExecutionStep
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import EventScope
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.differential.context import ProbeContext
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.results import PartialExecutionError
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.verification.differential import contracts
from cloud_dast.verification.differential.comparator import compare_timing_measurements
from cloud_dast.verification.differential.modes import (
    TIMING_MIN_SAMPLES,
    TIMING_REPEATS,
)

logger = logging.getLogger("cloud_dast.runtime.differential.timing")


class LatencyProbe:
    """Repeat paired calls and route robust latency variance."""

    def _evaluate_timing_pair(
        self,
        context: ProbeContext,
    ) -> None:
        """Repeat one factor pair and compare robust latency classes."""

        request = context.request
        step = context.step
        graph = context.graph
        accumulator = context.accumulator
        deficits = context.deficits
        variance_records = context.variance_records
        budget = context.budget
        scope = context.scope
        path_id = context.path_id
        paired_steps = context.paired_steps
        action = step.method.method_id
        spec = self._specs.differential_spec(request, step, graph, deficits)
        if spec is None:
            logger.debug(
                "diff_timing_skipped action=%s reason=no-second-position", action
            )
            return

        key = self._measurement_key("timing", step, spec.control, spec.treatment)
        if paired_steps is not None and key in paired_steps:
            return
        control_pairs, treatment_pairs = self._measure_timing_pairs(
            action,
            step,
            spec,
            budget,
            accumulator,
            scope=scope,
            path_id=path_id,
        )
        if not control_pairs or not treatment_pairs:
            return
        if paired_steps is not None:
            paired_steps.add(key)

        report = compare_timing_measurements(
            action,
            tuple(observation for _, observation in control_pairs),
            tuple(observation for _, observation in treatment_pairs),
            min_samples=TIMING_MIN_SAMPLES,
        )
        if report is None:
            return

        if self._latency_oracle is not None:
            self._latency_oracle.update_baseline_from_observations(
                action,
                tuple(observation for _, observation in control_pairs),
            )

        control = self._outcomes.observation_for_report(
            control_pairs,
            report.control_observation_id,
        )
        treatment = self._outcomes.observation_for_report(
            treatment_pairs,
            report.treatment_observation_id,
        )
        control_check = self._outcomes.check_for_report(
            control_pairs,
            report.control_observation_id,
        )
        treatment_check = self._outcomes.check_for_report(
            treatment_pairs,
            report.treatment_observation_id,
        )
        self._outcomes.record_report(
            request,
            action,
            "timing",
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

    def _measure_timing_pairs(
        self,
        action: str,
        step: QdlExecutionStep,
        spec: contracts.Spec,
        budget: CallLimits,
        accumulator: CampaignAccumulator,
        *,
        scope: EventScope | None = None,
        path_id: str | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> tuple[
        list[tuple[Check, Observation]],
        list[tuple[Check, Observation]],
    ]:
        """Repeat one differential pair until a local failure stops the sweep."""

        control_pairs: list[tuple[Check, Observation]] = []
        treatment_pairs: list[tuple[Check, Observation]] = []
        for _ in range(TIMING_REPEATS):
            pair = self._measure_timing_pair(
                action,
                step,
                spec,
                budget,
                accumulator,
                scope=scope,
                path_id=path_id,
            )
            if pair is None:
                break
            control_check, treatment_check, control, treatment = pair
            control_pairs.append((control_check, control))
            treatment_pairs.append((treatment_check, treatment))
            accumulator.observations.extend((control, treatment))
            accumulator.checks.extend((control_check, treatment_check))
        return control_pairs, treatment_pairs

    def _measure_timing_pair(
        self,
        action: str,
        step: QdlExecutionStep,
        spec: contracts.Spec,
        budget: CallLimits,
        accumulator: CampaignAccumulator,
        *,
        scope: EventScope | None = None,
        path_id: str | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> tuple[Check, Check, Observation, Observation] | None:
        """Execute one timing repeat or stop the sweep on a local failure."""

        try:
            return self._executor.execute_step_pair(
                step,
                spec,
                budget,
                scope=scope,
                path_id=path_id,
            )
        except PartialExecutionError as error:
            accumulator.add_partial(error.partial_result)
            logger.info("diff_timing_stopped action=%s reason=%s", action, error)
        except ValueError as error:
            logger.info("diff_timing_stopped action=%s reason=%s", action, error)
        return None


__all__ = ["LatencyProbe"]
