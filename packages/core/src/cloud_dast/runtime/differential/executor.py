"""Execute differential probes over the shared QDL boundary."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any
from uuid import uuid4

from cloud_dast.model import (
    Check,
    MethodSpec,
    Observation,
)
from cloud_dast.model.events import EventScope
from cloud_dast.model.evidence import IdentityRelation, identity_relation
from cloud_dast.ports import EventPublisher
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.results import (
    PairPartialResult,
    PartialExecutionError,
    PartialExecutionResult,
)
from cloud_dast.runtime.execution.calls import spend_calls
from cloud_dast.runtime.execution.checks import bind_event_context
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    DifferentialSpec,
    PayloadPairSpec,
    ReadBackResult,
    ReadBackSpec,
    payload_canary,
)
from cloud_dast.verification.differential.modes import CONCURRENCY_PROBES

logger = logging.getLogger("cloud_dast.runtime.differential.executor")


class ProbeExecutor:
    """Execute paired, read-back, and concurrent probes with shared budgets."""

    def __init__(
        self,
        checker: Checker,
        event_bus: EventPublisher,
    ) -> None:
        self._checker = checker
        self._event_bus = event_bus

    @staticmethod
    def build_evidence_key(
        step: QdlExecutionStep,
        request: Any,
    ) -> MeasurementKey:
        """Return the stable identity used by differential evidence."""

        return MeasurementKey(
            method_id=step.method.method_id,
            scenario_id=step.scenario.scenario_id,
            resource_id=request.resource_id,
            invariant_id=step.invariant.invariant_id,
        )

    def execute_step_pair(
        self,
        step: QdlExecutionStep,
        spec: DifferentialSpec,
        budget: CallLimits,
        *,
        scope: EventScope | None = None,
        path_id: str | None = None,
    ) -> tuple[Check, Check, Observation, Observation]:
        """Execute one QDL step as an isolated control/treatment pair."""

        control_step = replace(
            step,
            scenario=spec.control,
            plan=step.plan.model_copy(
                update={"scenario_id": spec.control.scenario_id},
            ),
        )
        treatment_step = replace(
            step,
            scenario=spec.treatment,
            plan=step.plan.model_copy(
                update={"scenario_id": spec.treatment.scenario_id},
            ),
        )
        prepared = self._prepare_differential_steps(
            (control_step, treatment_step),
            budget,
            live_calls=2,
            scope=scope,
            path_id=path_id,
        )
        if prepared is None:
            raise PartialExecutionError(
                f"differential pair for step {step.step_id} exceeds the "
                "campaign budget",
                result=PartialExecutionResult((), ()),
            )
        control_step, treatment_step = prepared
        control = self.pair_check(control_step)
        treatment = self.pair_check(treatment_step)
        calls_before_pair = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=step.method.method_id,
                path_id=path_id,
                step_id=step.step_id,
                check_ids=(control.check_id, treatment.check_id),
            ):
                control_result, treatment_result = self._checker.execute_pair(
                    control,
                    treatment,
                )
        finally:
            spend_calls(
                budget,
                calls_before_pair,
                len(self._checker.checks),
                kind="diff_leg",
            )
        if control_result is None or treatment_result is None:
            raise PartialExecutionError(
                f"differential pair for step {step.step_id} requires both "
                "legs to pass the guardrail",
                result=self._pair_partial_result(
                    calls_before_pair,
                    control_result,
                    treatment_result,
                ),
            )
        control_check, control_observation = control_result
        treatment_check, treatment_observation = treatment_result
        relation = identity_relation(
            control_check.identities,
            treatment_check.identities,
        )
        logger.info(
            "diff_pair_identity action=%s step=%s relation=%s",
            step.method.method_id,
            step.step_id,
            relation.value,
        )
        return (
            control_check,
            treatment_check,
            control_observation,
            treatment_observation,
        )

    def execute_payload_pair(
        self,
        step: QdlExecutionStep,
        *,
        mutable_fields: tuple[str, ...],
        canary: str,
        budget: CallLimits,
        scope: EventScope | None = None,
        path_id: str | None = None,
    ) -> tuple[Check, Check, Observation, Observation]:
        """Execute one baseline/mutated-payload pair for a QDL step."""

        prepared = self._prepare_differential_steps(
            (step,),
            budget,
            live_calls=2,
            scope=scope,
            path_id=path_id,
        )
        if prepared is None:
            raise PartialExecutionError(
                f"payload pair for step {step.step_id} exceeds the campaign budget",
                result=PartialExecutionResult((), ()),
            )
        prepared_step = prepared[0]
        baseline = self.pair_check(prepared_step)
        spec = PayloadPairSpec.from_baseline(
            prepared_step.method,
            prepared_step.scenario,
            baseline,
            canary=canary,
            mutable_fields=mutable_fields,
        )
        calls_before_pair = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=step.method.method_id,
                path_id=path_id,
                step_id=step.step_id,
                check_ids=(spec.baseline.check_id, spec.treatment.check_id),
            ):
                baseline_result, treatment_result = self._checker.execute_pair(
                    spec.baseline,
                    spec.treatment,
                )
        finally:
            spend_calls(
                budget,
                calls_before_pair,
                len(self._checker.checks),
                kind="diff_leg",
            )
        if baseline_result is None or treatment_result is None:
            raise PartialExecutionError(
                f"payload pair for step {step.step_id} requires both "
                "legs to pass the guardrail",
                result=self._pair_partial_result(
                    calls_before_pair,
                    baseline_result,
                    treatment_result,
                ),
            )
        baseline_check, baseline_observation = baseline_result
        treatment_check, treatment_observation = treatment_result
        return (
            baseline_check,
            treatment_check,
            baseline_observation,
            treatment_observation,
        )

    def execute_readback(
        self,
        step: QdlExecutionStep,
        spec: ReadBackSpec,
        request: Any,
        budget: CallLimits,
        *,
        scope: EventScope | None = None,
        path_id: str | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> ReadBackResult:
        """Execute read-before, mutated write, and read-after for one step."""

        prepared = self._prepare_differential_steps(
            (step,),
            budget,
            live_calls=3,
            scope=scope,
            path_id=path_id,
        )
        if prepared is None:
            raise PartialExecutionError(
                f"read-back for step {step.step_id} exceeds the campaign budget",
                result=PartialExecutionResult((), ()),
            )
        step = prepared[0]
        write_check = self._readback_write_check(step)
        read_check = self._readback_read_check(
            step,
            spec.read_method,
            resource_types=spec.read_resource_types,
        )
        if (
            identity_relation(write_check.identities, read_check.identities)
            is not IdentityRelation.SAME
        ):
            raise ValueError(
                "read-back legs must run as the same identity; "
                "identity variation belongs to differential pairs"
            )
        calls_before_readback = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=step.method.method_id,
                path_id=path_id,
                step_id=step.step_id,
                check_ids=(write_check.check_id, read_check.check_id),
            ):
                result = self._checker.execute_readback(
                    write_check,
                    read_check,
                    resource_binding=spec.resource_binding,
                )
        finally:
            spend_calls(
                budget,
                calls_before_readback,
                len(self._checker.checks),
                kind="diff_leg",
            )
        store = evidence_store or Store[MeasurementKey]()
        store.put_readback(self.build_evidence_key(step, request), result)
        return result

    def execute_concurrency_step(
        self,
        step: QdlExecutionStep,
        *,
        read_method: MethodSpec | None,
        read_resource_types: tuple[tuple[str, str], ...] = (),
        max_workers: int,
        budget: CallLimits,
        scope: EventScope | None = None,
        path_id: str | None = None,
    ) -> ConcurrencyResult:
        """Execute one concurrency batch through setup and the shared budget."""

        required = CONCURRENCY_PROBES + (2 if read_method is not None else 0)
        prepared = self._prepare_differential_steps(
            (step,),
            budget,
            live_calls=required,
            scope=scope,
            path_id=path_id,
        )
        if prepared is None:
            raise PartialExecutionError(
                f"concurrency batch for step {step.step_id} exceeds the "
                "campaign budget",
                result=PartialExecutionResult((), ()),
            )
        prepared_step = prepared[0]
        base_probe = self.pair_check(prepared_step)
        probes = tuple(
            base_probe.model_copy(
                update={"check_id": uuid4().hex, "probe_marker": None}
            )
            for _ in range(CONCURRENCY_PROBES)
        )
        read_before = None
        read_after = None
        if read_method is not None:
            read_check = self._readback_read_check(
                prepared_step,
                read_method,
                resource_types=read_resource_types,
            )
            read_before = read_check.model_copy(
                update={"check_id": uuid4().hex, "probe_marker": None}
            )
            read_after = read_check.model_copy(
                update={"check_id": uuid4().hex, "probe_marker": None}
            )
        return self.execute_concurrency_batch(
            probes,
            read_before=read_before,
            read_after=read_after,
            max_workers=max_workers,
            budget=budget,
            scope=scope,
            path_id=path_id,
        )

    def execute_concurrency_batch(
        self,
        probes: tuple[Check, ...],
        *,
        read_before: Check | None,
        read_after: Check | None,
        max_workers: int,
        budget: CallLimits,
        scope: EventScope | None = None,
        path_id: str | None = None,
    ) -> ConcurrencyResult:
        """Execute an already generated concurrency batch through the budget."""

        calls_before_batch = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=probes[0].method_id if probes else None,
                path_id=path_id,
                check_ids=tuple(
                    check.check_id
                    for check in (
                        *probes,
                        *(() if read_before is None else (read_before,)),
                        *(() if read_after is None else (read_after,)),
                    )
                ),
            ):
                return self._checker.execute_parallel_batch(
                    probes,
                    read_before=read_before,
                    read_after=read_after,
                    max_workers=max_workers,
                )
        finally:
            spend_calls(
                budget,
                calls_before_batch,
                len(self._checker.checks),
                kind="diff_leg",
            )

    @staticmethod
    def record_concurrency_evidence(
        evidence_key: MeasurementKey,
        result: ConcurrencyResult,
        *,
        evidence_store: Store[MeasurementKey],
    ) -> None:
        """Retain one executed concurrency batch for changed-norm scoring."""

        evidence_store.put_concurrency(evidence_key, result)

    def pair_check(self, step: QdlExecutionStep) -> Check:
        """Generate the single check executed for one differential leg."""

        checks = self._checker.generate_pair_checks(
            step.plan,
            step.method,
            step.invariant,
            step.scenario,
            strategy=step.plan.generator,
        )
        if not checks:
            raise ValueError(
                f"differential pair for step {step.step_id} has no executable check"
            )
        return checks[0]

    def _prepare_differential_steps(
        self,
        steps: tuple[QdlExecutionStep, ...],
        budget: CallLimits,
        *,
        live_calls: int,
        scope: EventScope | None,
        path_id: str | None,
    ) -> tuple[QdlExecutionStep, ...] | None:
        """Prepare differential legs while preserving their event scope."""

        action_id = steps[0].method.method_id if steps else None
        step_id = steps[0].step_id if steps else None
        with bind_event_context(
            self._event_bus,
            scope=scope,
            action_id=action_id,
            path_id=path_id,
            step_id=step_id,
        ):
            return steps if budget.can_spend(live_calls) else None

    def _readback_write_check(self, step: QdlExecutionStep) -> Check:
        """Generate the canary-mutated write check for one read-back."""

        baseline = self.pair_check(step)
        return PayloadPairSpec.from_baseline(
            step.method,
            step.scenario,
            baseline,
            canary=payload_canary(step.method.method_id),
        ).treatment

    def _readback_read_check(
        self,
        step: QdlExecutionStep,
        read_method: MethodSpec,
        *,
        resource_types: tuple[tuple[str, str], ...] = (),
    ) -> Check:
        """Generate the read leg bound to the write step's scenario."""

        read_plan = step.plan.model_copy(
            update={
                "plan_id": f"{step.plan.plan_id}:readback:{read_method.method_id}",
                "method_id": read_method.method_id,
                "resource_params": tuple(field for field, _ in resource_types),
                "resource_types": resource_types,
            },
        )
        checks = self._checker.generate_pair_checks(
            read_plan,
            read_method,
            step.invariant,
            step.scenario,
            strategy=step.plan.generator,
        )
        if not checks:
            raise ValueError(
                f"read-back for step {step.step_id} has no executable read check"
            )
        return checks[0]

    def _pair_partial_result(
        self,
        calls_before: int,
        first: tuple[Check, Observation] | None,
        second: tuple[Check, Observation] | None,
    ) -> PairPartialResult:
        """Retain completed evidence when a pair leg is guardrail-blocked."""

        observations = tuple(
            result[1] for result in (first, second) if result is not None
        )
        completed = {observation.check_id for observation in observations}
        checks = self._checker.checks[calls_before:]
        return PairPartialResult(
            checks=tuple(checks),
            observations=observations,
            failed_checks=tuple(
                check for check in checks if check.check_id not in completed
            ),
            control=first,
            treatment=second,
        )


__all__ = ["ProbeExecutor"]
