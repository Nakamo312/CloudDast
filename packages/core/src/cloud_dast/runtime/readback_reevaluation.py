"""Reinterpret stored write observations under newly bound QDL norms."""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.api import LiveRequest
from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.model import Observation
from cloud_dast.model.events import EventScope
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionPath, QdlExecutionStep
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict


class Reevaluation:
    """Evaluate prior write measurements without executing another request."""

    def __init__(
        self,
        *,
        norm_compiler: NormCompiler,
        build_evidence_key: Callable[[QdlExecutionStep, LiveRequest], MeasurementKey],
        classify_observation: Callable[..., object],
        trace_for_step: Callable[..., tuple[Observation, ...]],
        publish_step_event: Callable[..., None],
    ) -> None:
        self._norm_compiler = norm_compiler
        self._build_evidence_key = build_evidence_key
        self._classify_observation = classify_observation
        self._trace_for_step = trace_for_step
        self._publish_step_event = publish_step_event

    def reevaluate(
        self,
        request: LiveRequest,
        paths: tuple[QdlExecutionPath, ...],
        execution: ExecutionResult,
        *,
        scope: EventScope | None = None,
        evidence_store: Store[MeasurementKey] | None = None,
    ) -> ExecutionResult:
        """Return evaluation maps for existing readback measurements."""

        checks = {check.check_id: check for check in execution.checks}
        observations = {
            observation.observation_id: observation
            for observation in execution.observations
        }
        traces: dict[str, tuple[Observation, ...]] = {}
        provenance: dict[tuple[str, str], ObservationProvenance] = {}
        verdicts: dict[tuple[str, str], PolicyVerdict] = {}
        store = evidence_store or Store[MeasurementKey]()

        for path in paths:
            for step_index, step in enumerate(path.steps):
                if step.invariant.norm_fact is None:
                    continue
                try:
                    compilation = self._norm_compiler.compile(step.invariant.norm_fact)
                except ValueError:
                    continue
                if compilation.effect.name not in {"changed", "transition"}:
                    continue
                key = self._build_evidence_key(step, request)
                for measured_key, measurement in store.iter_readbacks():
                    if measured_key[:3] != key[:3]:
                        continue
                    observation = measurement.write
                    check = checks.get(observation.check_id)
                    if (
                        check != measurement.write_check
                        or observations.get(observation.observation_id) != observation
                    ):
                        continue
                    evaluation_key = (
                        observation.observation_id,
                        step.invariant.invariant_id,
                    )
                    previous = provenance.get(
                        evaluation_key, execution.provenance.get(evaluation_key)
                    )
                    if (
                        previous is not None
                        and previous.invariant_id == step.invariant.invariant_id
                    ):
                        continue
                    classification = self._classify_observation(
                        step,
                        observation,
                        request,
                        (observation,),
                        default_reason="readback reinterpreted under a bound norm",
                        evidence_store=store,
                    )
                    verdict = classification.policy_verdict
                    if verdict is None:
                        continue
                    traces[observation.observation_id] = self._trace_for_step(
                        step.invariant,
                        (observation,),
                        evidence_key=key,
                        evidence_store=store,
                    )
                    verdicts[evaluation_key] = verdict
                    provenance[evaluation_key] = ObservationProvenance(
                        step.goal_id,
                        path.path_id,
                        step.step_id,
                        step.invariant.invariant_id,
                        check.identities,
                    )
                    self._publish_step_event(
                        path.path_id,
                        step,
                        classification.progress,
                        classification.reason,
                        step_index=step_index,
                        is_final_step=step_index == len(path.steps) - 1,
                        correlation_id=check.check_id,
                        observation_id=observation.observation_id,
                        oracle=verdict.model_id,
                        scope=scope,
                    )

        return ExecutionResult((), (), traces, provenance, verdicts)


__all__ = ["Reevaluation"]
