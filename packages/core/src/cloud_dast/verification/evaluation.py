"""QDL observation evaluation and differential trace assembly.

The runtime executes checks and owns campaign state.  This module owns the
security decision made from a bound invariant, observed trace, and the
read-only differential evidence contract.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import InvariantProjection, QdlExecutionStep
from cloud_dast.model import (
    AccessOutcome,
    MethodSpec,
    Observation,
    PolicyVerdict,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Struct
from cloud_dast.verification.differential import contracts
from cloud_dast.verification.findings import attach_finding_identity
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.oracles import primitive_router
from cloud_dast.verification.projection import ObservationProjector


@dataclass(frozen=True, slots=True)
class ObservationEvaluation:
    """Security decision plus scheduler-safe grounding metadata."""

    verdict: VerdictStatus
    policy_verdict: PolicyVerdict | None
    progress: VerdictStatus
    reason: str
    grounded: bool
    effect_verified: bool = False


class ObservationEvaluator:
    """Evaluate one bound observation without owning transport or campaign state."""

    def __init__(
        self,
        *,
        primitive_oracle: primitive_router.Oracle,
        observation_projector: ObservationProjector | None,
        build_evidence_key: Callable[[QdlExecutionStep, LiveRequest], tuple[str, ...]],
        norm_compiler: NormCompiler | None = None,
    ) -> None:
        self._primitive_oracle = primitive_oracle
        self._observation_projector = observation_projector
        self._build_evidence_key = build_evidence_key
        self._norm_compiler = norm_compiler or NormCompiler()

    def evaluate(
        self,
        step: QdlExecutionStep,
        observation: Observation,
        request: LiveRequest,
        path_observations: tuple[Observation, ...],
        *,
        default_reason: str,
        evidence_store: contracts.EvidenceView | None = None,
    ) -> ObservationEvaluation:
        """Classify an observation and derive scheduler-safe progress."""

        evidence_key = self._build_evidence_key(step, request)
        verdict, policy_verdict = self.classify(
            step.invariant,
            observation,
            self.trace_for_step(
                step.invariant,
                path_observations,
                evidence_key=evidence_key,
                evidence_store=evidence_store,
            ),
            method=step.method,
            scenario=step.scenario,
            evidence_key=evidence_key,
            probe_fields=step.plan.probe_fields,
            sink_types=dict(step.plan.sink_types),
            evidence_store=evidence_store,
        )
        grounded = (
            policy_verdict is not None
            and policy_verdict.deterministic
            and policy_verdict.grounded
        )
        effect_verified = grounded and verdict is VerdictStatus.FAIL
        if step.required_effects:
            verified = set(
                self._observation_projector.verified_effects(
                    observation,
                    step.method.method_id,
                    step.evidence_graph,
                )
                if self._observation_projector is not None
                and step.evidence_graph is not None
                else ()
            )
            norm = step.invariant.norm_fact
            if (
                effect_verified
                and norm is not None
                and isinstance(norm.args[1], Struct)
            ):
                verified.add(norm.args[1])
            effect_verified = all(
                effect in verified for effect in step.required_effects
            )
        return ObservationEvaluation(
            verdict=verdict,
            policy_verdict=policy_verdict,
            progress=verdict if grounded else VerdictStatus.UNSCOREABLE,
            reason=policy_verdict.rationale
            if policy_verdict is not None
            else default_reason,
            grounded=grounded,
            effect_verified=effect_verified,
        )

    def classify(
        self,
        invariant: InvariantProjection,
        observation: Observation,
        trace: tuple[Observation, ...],
        *,
        method: MethodSpec,
        scenario: ScenarioPosition,
        evidence_key: tuple[str, ...],
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
        evidence_store: contracts.EvidenceView | None = None,
    ) -> tuple[VerdictStatus, PolicyVerdict | None]:
        if invariant.norm_fact is not None:
            try:
                compilation = self._norm_compiler.compile(invariant.norm_fact)
            except ValueError:
                return self._unscoreable(observation, "invalid QDL norm fact")
            if compilation.verdict_policy == "unscoreable":
                return self._unscoreable(
                    observation,
                    "QDL norm has no deterministic oracle",
                )
            if compilation.effect.name == "changed":
                concurrency_verdict = self._concurrency_verdict(
                    invariant,
                    method,
                    evidence_key,
                    observation,
                    evidence_store=evidence_store,
                )
                if concurrency_verdict is not None:
                    return concurrency_verdict.status, attach_finding_identity(
                        concurrency_verdict,
                        invariant=invariant,
                        probe_fields=probe_fields,
                    )
                if not trace:
                    return self._unscoreable(
                        observation,
                        "changed QDL norm requires a paired or read-back trace",
                    )
                if observation not in trace[1:-1]:
                    return self._unscoreable(
                        observation,
                        "paired state evidence does not belong to this candidate",
                    )
            if compilation.effect.name == "transition":
                if observation not in trace:
                    return self._unscoreable(
                        observation,
                        "transition evidence does not belong to this candidate",
                    )
                if observation not in trace[1:-1]:
                    trace = (observation,)
            policy_verdict = self._primitive_oracle.evaluate_policy(
                invariant,
                trace,
                method=method,
                scenario=scenario,
                probe_fields=probe_fields,
                sink_types=sink_types,
            )
            return policy_verdict.status, attach_finding_identity(
                policy_verdict,
                invariant=invariant,
                probe_fields=probe_fields,
            )

        if self._is_infrastructure_failure(observation):
            return self._unscoreable(
                observation,
                "policy result is not observable from this probe",
            )
        return self._unscoreable(
            observation,
            "QDL invariant has no executable norm fact",
        )

    def _concurrency_verdict(
        self,
        invariant: InvariantProjection,
        method: MethodSpec,
        evidence_key: tuple[str, ...],
        observation: Observation,
        *,
        evidence_store: contracts.EvidenceView | None = None,
    ) -> PolicyVerdict | None:
        """Score a changed norm from a complete saved concurrency batch."""

        trace = self._concurrency_trace(
            evidence_key,
            observation,
            evidence_store=evidence_store,
        )
        if not trace:
            return None
        return self._primitive_oracle.evaluate_concurrency_policy(
            invariant,
            read_before=trace[0],
            probes=trace[1:-1],
            read_after=trace[-1],
            method=method,
        )

    def trace_for_step(
        self,
        invariant: InvariantProjection,
        path_trace: tuple[Observation, ...],
        *,
        evidence_key: tuple[str, ...],
        evidence_store: contracts.EvidenceView | None = None,
    ) -> tuple[Observation, ...]:
        """Return the evidence trace explicitly required by one invariant."""

        if invariant.norm_fact is None:
            return path_trace
        try:
            compilation = self._norm_compiler.compile(invariant.norm_fact)
        except ValueError:
            return path_trace
        if not path_trace:
            return ()
        observation = path_trace[-1]
        if compilation.effect.name == "changed":
            return (
                self._readback_trace_for_measurement(
                    evidence_key,
                    observation,
                    evidence_store=evidence_store,
                )
                or ()
            )
        if compilation.effect.name == "transition":
            concurrency_trace = self._concurrency_trace(
                evidence_key,
                observation,
                evidence_store=evidence_store,
            )
            if concurrency_trace:
                return concurrency_trace
            readback_trace = self._readback_trace_for_measurement(
                evidence_key,
                observation,
                evidence_store=evidence_store,
            )
            if readback_trace is not None:
                return readback_trace
            return (observation,)
        return path_trace

    @staticmethod
    def _readback_trace_for_measurement(
        evidence_key: tuple[str, ...],
        observation: Observation,
        *,
        evidence_store: contracts.EvidenceView | None = None,
    ) -> tuple[Observation, ...] | None:
        if evidence_store is None:
            return None
        for key, measurement in evidence_store.iter_readbacks():
            if key[:3] == evidence_key[:3] and measurement.write == observation:
                return (
                    measurement.read_before,
                    measurement.write,
                    measurement.read_after,
                )
        return None

    @staticmethod
    def _concurrency_trace(
        evidence_key: tuple[str, ...],
        observation: Observation,
        *,
        evidence_store: contracts.EvidenceView | None = None,
    ) -> tuple[Observation, ...]:
        if evidence_store is None:
            return ()
        result = evidence_store.get_concurrency(evidence_key)
        if result is None or result.read_before is None or result.read_after is None:
            return ()
        if not any(probe == observation for _, probe in result.probes):
            return ()
        return (
            result.read_before[1],
            *(item for _, item in result.probes),
            result.read_after[1],
        )

    @staticmethod
    def _unscoreable(
        observation: Observation,
        rationale: str,
    ) -> tuple[VerdictStatus, PolicyVerdict]:
        verdict = VerdictStatus.UNSCOREABLE
        return verdict, PolicyVerdict(
            status=verdict,
            confidence=1.0,
            rationale=rationale,
            evidence_refs=(observation.observation_id,),
            model_id="deterministic",
            deterministic=True,
            grounded=False,
            oracle_called=False,
        )

    @staticmethod
    def _is_infrastructure_failure(observation: Observation) -> bool:
        return observation.auth_failed or observation.observed_outcome in {
            AccessOutcome.ERROR,
            AccessOutcome.UNKNOWN,
        }


__all__ = ["ObservationEvaluation", "ObservationEvaluator"]
