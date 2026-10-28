"""Execute differential mode probes and bind specifications."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_dast.model import Check, MethodSpec, Observation, ScenarioPosition
from cloud_dast.model.events import canonical_action_id
from cloud_dast.ports import ScenarioRepository
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Term,
    hash_content,
    input_field,
)
from cloud_dast.runtime.differential.concurrency import ParallelProbe
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.differential.outcomes import OutcomeRecorder
from cloud_dast.runtime.differential.results import PartialExecutionError
from cloud_dast.runtime.differential.specs import SpecResolver
from cloud_dast.runtime.differential.timing import LatencyProbe
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.verification.differential.contracts import (
    payload_canary,
)
from cloud_dast.verification.differential.modes import (
    TIMING_REPEATS,
    DiffMode,
)
from cloud_dast.verification.oracles.latency import LatencyOracle

logger = logging.getLogger("cloud_dast.runtime.differential.probes")
_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})

if TYPE_CHECKING:
    from cloud_dast.runtime.differential.context import ProbeContext


@dataclass(frozen=True, slots=True)
class ProbeCallbacks:
    """Capabilities required to execute one differential probe mode."""

    executor: ProbeExecutor
    outcomes: OutcomeRecorder
    latency_oracle: LatencyOracle | None = None
    scenario_repository: ScenarioRepository | None = None


class ProbeRunner(LatencyProbe, ParallelProbe):
    """Execute configured differential modes for one bound step.

    This component owns mode-specific live calls and prerequisite resolution.
    Campaign lifecycle, reserve policy, scheduler mutation, and result routing
    stay outside it.
    """

    def __init__(self, callbacks: ProbeCallbacks) -> None:
        self._executor = callbacks.executor
        self._outcomes = callbacks.outcomes
        self._latency_oracle = callbacks.latency_oracle
        self._specs = SpecResolver(
            scenario_repository=callbacks.scenario_repository,
        )

    def evaluate_step_modes(
        self,
        context: ProbeContext,
    ) -> None:
        """Execute every enabled differential mode for one bound position."""

        budget = context.budget
        diff_modes = context.diff_modes

        if "factors" in diff_modes and budget.can_spend(2):
            self._evaluate_differential_pair(context)
        if "payload" in diff_modes and budget.can_spend(2):
            self._evaluate_payload_pair(context)
        if "readback" in diff_modes and budget.can_spend(3):
            self._evaluate_readback_pair(context)
        if "timing" in diff_modes and budget.can_spend(TIMING_REPEATS * 2):
            self._evaluate_timing_pair(context)
        if "concurrency" in diff_modes:
            self._evaluate_concurrency_pair(context)

    @staticmethod
    def _measurement_key(
        mode: DiffMode,
        step: QdlExecutionStep,
        *prerequisites: Term | MethodSpec | ScenarioPosition,
    ) -> tuple[str, ...]:
        """Identify an experiment by its resolved executable inputs."""

        return (
            canonical_action_id(step.method.method_id),
            step.scenario.scenario_id,
            mode,
            hash_content((step.method, step.scenario, *prerequisites)),
        )

    def _evaluate_differential_pair(
        self,
        context: ProbeContext,
    ) -> None:
        """Execute, compare, and persist one control/treatment pair."""

        request = context.request
        step = context.step
        graph = context.graph
        accumulator = context.accumulator
        deficits = context.deficits
        budget = context.budget
        scope = context.scope
        path_id = context.path_id
        paired_steps = context.paired_steps
        action = step.method.method_id
        spec = self._specs.differential_spec(request, step, graph, deficits)
        if spec is None:
            logger.debug(
                "diff_pair_skipped action=%s reason=no-second-position", action
            )
            return
        key = self._measurement_key("factors", step, spec.control, spec.treatment)
        if paired_steps is not None and key in paired_steps:
            return
        try:
            control_check, treatment_check, control, treatment = (
                self._executor.execute_step_pair(
                    step,
                    spec,
                    budget,
                    scope=scope,
                    path_id=path_id,
                )
            )
        except PartialExecutionError as error:
            accumulator.add_partial(error.partial_result)
            logger.info(
                "diff_pair_skipped action=%s reason=%s",
                action,
                error,
            )
            return
        except ValueError as error:
            logger.info(
                "diff_pair_skipped action=%s reason=%s",
                action,
                error,
            )
            return

        if paired_steps is not None:
            paired_steps.add(key)
        # Pair legs are evidence, not verdicts: without a policy verdict the
        # evaluator can never raise a finding from them.
        accumulator.observations.extend((control, treatment))
        accumulator.checks.extend((control_check, treatment_check))
        self._record_measured_pair(
            context,
            "factors",
            control,
            treatment,
            correlation_check_id=treatment.check_id,
            control_check=control_check,
            treatment_check=treatment_check,
        )

    def _evaluate_payload_pair(
        self,
        context: ProbeContext,
    ) -> None:
        """Execute, compare, and persist one baseline/mutated-payload pair.

        Both legs run the step's own method and scenario; only the payload
        fields differ (a benign value vs. a quoted canary), so the pair
        measures how the action's behavior changes with its input rather
        than with the caller or the resource.
        """

        step = context.step
        graph = context.graph
        accumulator = context.accumulator
        deficits = context.deficits
        budget = context.budget
        scope = context.scope
        path_id = context.path_id
        paired_steps = context.paired_steps
        action = step.method.method_id
        mutable_fields = self._specs.payload_fields(step, graph, deficits)
        if not mutable_fields:
            logger.debug(
                "diff_payload_skipped action=%s reason=no-payload-field", action
            )
            return
        key = self._measurement_key(
            "payload",
            step,
            *(
                input_field(Atom(value=canonical_action_id(action)), Atom(value=field))
                for field in mutable_fields
            ),
        )
        if paired_steps is not None and key in paired_steps:
            return
        try:
            baseline_check, treatment_check, baseline_obs, treatment_obs = (
                self._executor.execute_payload_pair(
                    step,
                    mutable_fields=mutable_fields,
                    canary=payload_canary(action),
                    budget=budget,
                    scope=scope,
                    path_id=path_id,
                )
            )
        except PartialExecutionError as error:
            accumulator.add_partial(error.partial_result)
            logger.info(
                "diff_payload_skipped action=%s reason=%s",
                action,
                error,
            )
            return
        except ValueError as error:
            logger.info(
                "diff_payload_skipped action=%s reason=%s",
                action,
                error,
            )
            return

        if paired_steps is not None:
            paired_steps.add(key)
        accumulator.observations.extend((baseline_obs, treatment_obs))
        accumulator.checks.extend((baseline_check, treatment_check))
        self._record_measured_pair(
            context,
            "payload",
            baseline_obs,
            treatment_obs,
            correlation_check_id=treatment_check.check_id,
            control_check=baseline_check,
            treatment_check=treatment_check,
        )

    def _evaluate_readback_pair(
        self,
        context: ProbeContext,
    ) -> None:
        """Execute, compare, and persist one read-before/write/read-back.

        The pair's both legs are reads of the write's target resource:
        control is the read before a canary-mutated write, treatment the
        read after it, re-bound to the resource id resolved from the write
        response.  The measured difference is attributed to the *write*
        action — the cause of the state change — so the variance grounding
        slice shows the mutator, while the paired observations document the
        state channel.
        """

        request = context.request
        step = context.step
        graph = context.graph
        method_pool = context.method_pool
        accumulator = context.accumulator
        deficits = context.deficits
        budget = context.budget
        scope = context.scope
        path_id = context.path_id
        evidence_store = context.evidence_store
        paired_steps = context.paired_steps
        action = step.method.method_id
        spec = self._specs.readback_spec(step, graph, method_pool, deficits)
        if spec is None:
            logger.debug(
                "diff_readback_skipped action=%s reason=no-read-method", action
            )
            return
        key = self._measurement_key(
            "readback",
            step,
            spec.read_method,
            Atom(value=spec.resource_binding),
            *(
                Atom(value=value)
                for reference in spec.read_resource_types
                for value in reference
            ),
        )
        if paired_steps is not None and key in paired_steps:
            return
        try:
            result = self._executor.execute_readback(
                step,
                spec,
                request,
                budget,
                scope=scope,
                path_id=path_id,
                evidence_store=evidence_store,
            )
        except PartialExecutionError as error:
            accumulator.add_partial(error.partial_result)
            logger.info(
                "diff_readback_skipped action=%s reason=%s",
                action,
                error,
            )
            return
        except ValueError as error:
            logger.info(
                "diff_readback_skipped action=%s reason=%s",
                action,
                error,
            )
            return

        if paired_steps is not None:
            paired_steps.add(key)
        accumulator.observations.extend(
            (result.read_before, result.write, result.read_after)
        )
        accumulator.checks.extend(
            (result.read_before_check, result.write_check, result.read_after_check)
        )
        self._record_measured_pair(
            context,
            "readback",
            result.read_before,
            result.read_after,
            correlation_check_id=result.read_after.check_id,
            control_check=result.read_before_check,
            treatment_check=result.read_after_check,
        )

    def _record_measured_pair(
        self,
        context: ProbeContext,
        mode: DiffMode,
        control: Observation,
        treatment: Observation,
        *,
        correlation_check_id: str,
        control_check: Check | None = None,
        treatment_check: Check | None = None,
    ) -> None:
        """Route one completed pair into differential campaign evidence."""

        self._outcomes.record_pair(
            context.request,
            context.step.method.method_id,
            mode,
            control,
            treatment,
            context.deficits,
            context.variance_records,
            context.scope,
            correlation_check_id=correlation_check_id,
            control_check=control_check,
            treatment_check=treatment_check,
        )


__all__ = ["ProbeCallbacks", "ProbeRunner"]
