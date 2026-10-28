"""Concurrent differential probe mode and evidence collection."""

from __future__ import annotations

import logging

from cloud_dast.api import LiveRequest
from cloud_dast.model import MethodSpec
from cloud_dast.model.events import EventScope
from cloud_dast.qdl.graph import Atom
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.context import ProbeContext
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.results import (
    PartialExecutionError,
    VarianceRecord,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.verification.differential.contracts import (
    read_resource_reference,
    select_read_method,
)
from cloud_dast.verification.differential.modes import (
    CONCURRENCY_MAX_WORKERS,
    CONCURRENCY_PROBES,
)

logger = logging.getLogger("cloud_dast.runtime.differential.concurrency")


class ParallelProbe:
    """Execute identical probes in parallel and route their evidence."""

    def _evaluate_concurrency_pair(
        self,
        context: ProbeContext,
    ) -> None:
        """Execute identical probes in parallel and aggregate their evidence."""

        request = context.request
        step = context.step
        graph = context.graph
        method_pool = context.method_pool
        accumulator = context.accumulator
        deficits = context.deficits
        variance_records = context.variance_records
        budget = context.budget
        scope = context.scope
        path_id = context.path_id
        evidence_store = context.evidence_store
        paired_steps = context.paired_steps
        action = step.method.method_id
        read_method = select_read_method(
            step.method,
            method_pool.values(),
            graph=graph,
        )
        if read_method is None:
            self._specs.record_missing_role(deficits, action, "readback")
        read_reference = (
            read_resource_reference(step.method, read_method, graph=graph)
            if read_method is not None
            else None
        )
        required = CONCURRENCY_PROBES + (2 if read_method is not None else 0)
        if not budget.can_spend(required):
            logger.info(
                "diff_concurrency_skipped action=%s reason=budget required=%d",
                action,
                required,
            )
            return

        key = self._measurement_key(
            "concurrency",
            step,
            *((read_method,) if read_method is not None else ()),
            *(
                (Atom(value=value) for value in read_reference)
                if read_reference is not None
                else ()
            ),
        )
        if paired_steps is not None and key in paired_steps:
            return
        result = self._execute_concurrency_measurement(
            request,
            action,
            step,
            read_method,
            () if read_reference is None else (read_reference,),
            budget,
            accumulator,
            scope=scope,
            path_id=path_id,
            evidence_store=evidence_store,
        )
        if result is None:
            return

        if paired_steps is not None:
            paired_steps.add(key)
        self._record_concurrency_result(
            request,
            step,
            result,
            accumulator,
            deficits,
            variance_records,
            scope,
        )

    def _record_concurrency_result(
        self,
        request: LiveRequest,
        step: QdlExecutionStep,
        result,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        variance_records: dict[tuple[str, ...], VarianceRecord],
        scope: EventScope,
    ) -> None:
        """Route a completed concurrency measurement."""

        self._outcomes.record_concurrency(
            request,
            step.method.method_id,
            result,
            accumulator,
            deficits,
            variance_records,
            scope,
        )

    def _execute_concurrency_measurement(
        self,
        request: LiveRequest,
        action: str,
        step: QdlExecutionStep,
        read_method: MethodSpec | None,
        read_resource_types: tuple[tuple[str, str], ...],
        budget: CallLimits,
        accumulator: CampaignAccumulator,
        *,
        scope: EventScope | None = None,
        path_id: str | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ):
        """Execute one concurrency batch and retain its evidence."""

        try:
            result = self._executor.execute_concurrency_step(
                step,
                read_method=read_method,
                read_resource_types=read_resource_types,
                max_workers=CONCURRENCY_MAX_WORKERS,
                budget=budget,
                scope=scope,
                path_id=path_id,
            )
            self._executor.record_concurrency_evidence(
                self._executor.build_evidence_key(step, request),
                result,
                evidence_store=evidence_store or Store[MeasurementKey](),
            )
            return result
        except PartialExecutionError as error:
            accumulator.add_partial(error.partial_result)
            logger.info("diff_concurrency_skipped action=%s reason=%s", action, error)
        except ValueError as error:
            logger.info("diff_concurrency_skipped action=%s reason=%s", action, error)
        return None


__all__ = ["ParallelProbe"]
