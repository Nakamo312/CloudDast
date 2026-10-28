"""Record and score one observation produced by a live path step.

This module owns the round-local observation lifecycle: provenance, security
classification, generator feedback, and finding finalisation.  Transport,
event construction, and evidence-graph persistence remain injected callbacks;
the coordinator therefore does not become another service or repository
adapter.
"""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.contracts.execution import ObservationProvenance
from cloud_dast.model import Check, Observation, VerdictStatus
from cloud_dast.runtime.candidates.feedback import invariant_effect, trace_proximity
from cloud_dast.runtime.candidates.session import _StepContext
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.evaluation import ObservationEvaluation


class Coordinator:
    """Own the deterministic lifecycle after a candidate reached transport."""

    def __init__(
        self,
        *,
        classify_observation: Callable[..., ObservationEvaluation],
        executed_check_identities: Callable[[Observation], tuple[str, ...]],
        publish_effects: Callable[
            [_StepContext, Observation, ObservationEvaluation], None
        ],
        service_checks: Callable[[], list[Check]],
        metrics: CampaignMetrics | None,
    ) -> None:
        self._classify_observation = classify_observation
        self._executed_check_identities = executed_check_identities
        self._publish_effects = publish_effects
        self._service_checks = service_checks
        self._metrics = metrics

    def record(
        self,
        context: _StepContext,
        observation: Observation,
        *,
        prefilter_solved: bool,
    ) -> ObservationEvaluation:
        """Record one observation in the established execution order."""

        classification = self._classify_and_record(context, observation)
        self._publish_effects(context, observation, classification)
        self._record_feedback(
            context,
            observation,
            classification,
            prefilter_solved=prefilter_solved,
        )
        self._finalize(context, classification)
        return classification

    def _classify_and_record(
        self,
        context: _StepContext,
        observation: Observation,
    ) -> ObservationEvaluation:
        """Store provenance and classify before side effects are published."""

        path = context.attempt.path
        identities = self._executed_check_identities(observation)
        context.state.observations.append(observation)
        context.attempt.observations.append(observation)
        context.state.traces[observation.observation_id] = tuple(
            context.attempt.observations
        )
        context.state.provenance[
            (
                observation.observation_id,
                context.step.invariant.invariant_id,
            )
        ] = ObservationProvenance(
            goal_id=context.step.goal_id,
            path_id=path.path_id,
            step_id=context.step.step_id,
            invariant_id=context.step.invariant.invariant_id,
            identities=identities,
        )
        classification = self._classify_observation(
            context.step,
            observation,
            context.request,
            tuple(context.attempt.observations),
            default_reason="QDL step evaluated",
            evidence_store=context.state.differential_evidence,
        )
        if classification.policy_verdict is not None:
            context.state.policy_verdicts[
                (observation.observation_id, context.step.invariant.invariant_id)
            ] = classification.policy_verdict
        context.state.path_reasons[path.path_id] = classification.reason
        return classification

    def _record_feedback(
        self,
        context: _StepContext,
        observation: Observation,
        classification: ObservationEvaluation,
        *,
        prefilter_solved: bool,
    ) -> None:
        """Feed the result back to the adaptive generator, if present."""

        step = context.step
        fuzz_session = context.fuzz_session
        recorded_check = self._service_checks()[-1]
        if self._metrics is not None:
            self._metrics.record_generator_outcome(
                step.method.method_id,
                getattr(fuzz_session, "current_strategy", "unknown")
                if fuzz_session is not None
                else "oneshot",
                classification.progress,
            )
        if fuzz_session is None or recorded_check is None:
            return

        effect = invariant_effect(step.invariant)
        proximity = (
            trace_proximity(
                effect,
                tuple(context.attempt.observations),
                classification.verdict,
                step_count=len(context.attempt.path.steps),
            )
            if effect is not None
            else None
        )
        if classification.verdict is VerdictStatus.FAIL and not classification.grounded:
            # An ungrounded FAIL is a lead, not progress: its unverified
            # violation proximity must not grow the path reward.
            proximity = 0.0 if proximity is not None else None
        if proximity is not None:
            context.attempt.best_proximity = max(
                context.attempt.best_proximity,
                proximity,
            )
        fuzz_session.record(
            recorded_check,
            classification.verdict,
            grounded=classification.grounded,
            proximity=proximity,
            observation=observation,
            solver_prefiltered=prefilter_solved,
        )

    def _finalize(
        self,
        context: _StepContext,
        classification: ObservationEvaluation,
    ) -> None:
        """Persist the minimal deterministic check and finding metric."""

        context.attempt.effect_verified |= classification.effect_verified
        if classification.progress is not VerdictStatus.FAIL:
            return
        recorded_check = self._service_checks()[-1]
        strategy = getattr(context.fuzz_session, "current_strategy", "oneshot")
        if recorded_check is not None and strategy != "replay":
            context.state.minimal_checks[
                (
                    context.attempt.observations[-1].observation_id,
                    context.step.invariant.invariant_id,
                )
            ] = recorded_check
        if self._metrics is not None:
            self._metrics.record_finding()


__all__ = ["Coordinator"]
