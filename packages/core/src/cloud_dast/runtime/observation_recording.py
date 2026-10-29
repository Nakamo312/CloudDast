"""Record and finalize one observation produced by a live path step.

This module owns the round-local observation lifecycle: provenance, security
classification and finding finalisation around candidate feedback. Transport,
event construction, and evidence-graph persistence remain injected callbacks;
the coordinator therefore does not become another service or repository
adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from cloud_dast.contracts.execution import LiveRequest, ObservationProvenance
from cloud_dast.contracts.plan import QdlExecutionStep
from cloud_dast.extensions import FuzzSession
from cloud_dast.model import Check, Observation, VerdictStatus
from cloud_dast.model.events import EventScope
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.execution.terminal import PathAttempt
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
            ..., Callable[[Observation, ObservationEvaluation, str | None, str], None]
        ],
        latest_check: Callable[[], Check],
        metrics: CampaignMetrics | None,
    ) -> None:
        self._classify_observation = classify_observation
        self._executed_check_identities = executed_check_identities
        self._publish_effects = publish_effects
        self._latest_check = latest_check
        self._metrics = metrics

    def bind(
        self,
        request: LiveRequest,
        attempt: PathAttempt,
        state: CampaignRoundState,
        *,
        step_index: int,
        fuzz_session: FuzzSession | None,
        scope: EventScope | None,
    ) -> Callable[
        [Observation, str | None, str],
        tuple[ObservationEvaluation, Sequence[Observation], Callable[[], None]],
    ]:
        """Bind one step's synchronous observation lifecycle to its owners."""

        step = attempt.path.steps[step_index]
        publish = self._publish_effects(
            request.service,
            attempt.path,
            state.replay.verified_fact_ids,
            step_index=step_index,
            scope=scope,
        )

        def record(
            observation: Observation,
            component_invocation_id: str | None,
            component_generator: str,
        ) -> tuple[ObservationEvaluation, Sequence[Observation], Callable[[], None]]:
            classification = self._classify_and_record(
                request, attempt, step, state, observation
            )
            publish(
                observation,
                classification,
                component_invocation_id,
                component_generator,
            )
            return (
                classification,
                attempt.observations,
                lambda: self._finalize(
                    attempt, step, state, classification, fuzz_session=fuzz_session
                ),
            )

        return record

    def _classify_and_record(
        self,
        request: LiveRequest,
        attempt: PathAttempt,
        step: QdlExecutionStep,
        state: CampaignRoundState,
        observation: Observation,
    ) -> ObservationEvaluation:
        """Store provenance and classify before side effects are published."""

        path = attempt.path
        identities = self._executed_check_identities(observation)
        state.observations.append(observation)
        attempt.observations.append(observation)
        state.provenance[
            (
                observation.observation_id,
                step.invariant.invariant_id,
            )
        ] = ObservationProvenance(
            goal_id=step.goal_id,
            path_id=path.path_id,
            step_id=step.step_id,
            invariant_id=step.invariant.invariant_id,
            identities=identities,
        )
        classification = self._classify_observation(
            step,
            observation,
            request,
            tuple(attempt.observations),
            default_reason="QDL step evaluated",
            evidence_store=state.differential_evidence,
        )
        if classification.policy_verdict is not None:
            state.policy_verdicts[
                (observation.observation_id, step.invariant.invariant_id)
            ] = classification.policy_verdict
        state.path_reasons[path.path_id] = classification.reason
        return classification

    def _finalize(
        self,
        attempt: PathAttempt,
        step: QdlExecutionStep,
        state: CampaignRoundState,
        classification: ObservationEvaluation,
        *,
        fuzz_session: FuzzSession | None,
    ) -> None:
        """Persist the minimal deterministic check and finding metric."""

        attempt.effect_verified |= classification.effect_verified
        if classification.progress is not VerdictStatus.FAIL:
            return
        recorded_check = self._latest_check()
        strategy = getattr(fuzz_session, "current_strategy", "oneshot")
        if recorded_check is not None and strategy != "replay":
            state.minimal_checks[
                (
                    attempt.observations[-1].observation_id,
                    step.invariant.invariant_id,
                )
            ] = recorded_check
        if self._metrics is not None:
            self._metrics.record_finding()


__all__ = ["Coordinator"]
