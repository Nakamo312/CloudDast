"""Publish and persist the effects of one executed observation.

The path runner supplies a classified observation; this component translates it
into domain events, runtime facts, and the event-backed evidence projection.
It owns no transport, scheduling, or security classification policy.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model import Observation, VerdictStatus
from cloud_dast.model.events import (
    ComponentOutput,
    DomainEvent,
    DownstreamDecision,
    EventScope,
    EvidenceRecorded,
    FactVerified,
    QdlStepEvaluated,
)
from cloud_dast.runtime.evidence_projection import Projection
from cloud_dast.verification.evaluation import ObservationEvaluation
from cloud_dast.verification.evidence_facts import evidence_fact, verified_fact


class Publisher:
    """Translate one classified observation into runtime side effects."""

    def __init__(
        self,
        *,
        publish: Callable[[DomainEvent, EventScope | None], None],
        evidence_projection: Projection,
        executed_check_identities: Callable[[Observation], tuple[str, ...]],
    ) -> None:
        self._publish = publish
        self._evidence_projection = evidence_projection
        self._executed_check_identities = executed_check_identities

    def bind(
        self,
        service: str,
        path: QdlExecutionPath,
        verified_fact_ids: set[str],
        *,
        step_index: int,
        scope: EventScope | None,
    ) -> Callable[[Observation, ObservationEvaluation, str | None, str], None]:
        """Bind domain values for publishing observations of one step."""

        step = path.steps[step_index]

        def publish_observation(
            observation: Observation,
            classification: ObservationEvaluation,
            component_invocation_id: str | None,
            component_generator: str,
        ) -> None:
            oracle = (
                classification.policy_verdict.model_id
                if classification.policy_verdict is not None
                else None
            )
            self.publish_component_result(
                path,
                step,
                observation,
                classification,
                scope=scope,
                component_invocation_id=component_invocation_id,
                component_generator=component_generator,
            )
            self.publish_step_event(
                path.path_id,
                step,
                classification.progress,
                classification.reason,
                step_index=step_index,
                is_final_step=step_index == len(path.steps) - 1,
                correlation_id=observation.check_id,
                observation_id=observation.observation_id,
                oracle=oracle,
                scope=scope,
                effect_verified=classification.effect_verified,
            )
            self._evidence_projection.persist_observation(
                step,
                observation,
                service,
                graph=self._evidence_projection.observed_graph(path),
                identities=self._executed_check_identities(observation),
            )
            self.publish_runtime_facts(
                step,
                observation,
                classification.progress,
                verified_fact_ids,
                scope,
                path_id=path.path_id,
                oracle=oracle,
            )

        return publish_observation

    def publish_component_result(
        self,
        path: QdlExecutionPath,
        step: QdlExecutionStep,
        observation: Observation,
        classification: ObservationEvaluation,
        *,
        scope: EventScope | None,
        component_invocation_id: str | None,
        component_generator: str,
    ) -> None:
        """Publish the scored output of the selected generator."""

        component = f"generator:{component_generator}"
        invocation_id = component_invocation_id or observation.check_id
        summary = {
            "candidates_produced": 1,
            "candidates_survived_prefilter": 1,
            "candidates_survived_guardrail": 1,
            "scored": 1,
            "witnesses": int(classification.progress is VerdictStatus.FAIL),
        }
        oracle = (
            classification.policy_verdict.model_id
            if classification.policy_verdict is not None
            else None
        )
        self._publish(
            ComponentOutput(
                component=component,
                summary=summary,
                invocation_id=invocation_id,
                check_id=observation.check_id,
                observation_id=observation.observation_id,
                path_id=path.path_id,
                action_id=step.method.method_id,
                step_id=step.step_id,
                oracle=oracle,
                correlation_id=observation.check_id,
            ),
            scope,
        )
        self._publish(
            DownstreamDecision(
                component=component,
                consumed=True,
                by="oracle",
                outcome=classification.progress.value,
                invocation_id=invocation_id,
                check_id=observation.check_id,
                observation_id=observation.observation_id,
                path_id=path.path_id,
                action_id=step.method.method_id,
                step_id=step.step_id,
                oracle=oracle,
                correlation_id=observation.check_id,
            ),
            scope,
        )

    def publish_step_event(
        self,
        path_id: str,
        step: QdlExecutionStep,
        verdict: VerdictStatus,
        reason: str,
        *,
        step_index: int,
        is_final_step: bool,
        correlation_id: str,
        observation_id: str | None = None,
        oracle: str | None = None,
        scope: EventScope | None = None,
        effect_verified: bool | None = None,
    ) -> None:
        """Publish one step progress event."""

        self._publish(
            QdlStepEvaluated(
                path_id=path_id,
                step_id=step.step_id,
                verdict=verdict,
                phase=_phase_for(
                    verdict,
                    is_final_step=is_final_step,
                    effect_verified=effect_verified,
                ),
                reason=reason,
                step_index=step_index,
                completed_steps=(step.step_id,)
                if (
                    verdict is VerdictStatus.FAIL
                    if effect_verified is None
                    else effect_verified
                )
                else (),
                correlation_id=correlation_id,
                action_id=step.method.method_id,
                check_id=correlation_id,
                observation_id=observation_id,
                oracle=oracle,
                norm_fact=step.invariant.norm_fact,
            ),
            scope,
        )

    def publish_runtime_facts(
        self,
        step: QdlExecutionStep,
        observation: Observation,
        verdict: VerdictStatus,
        verified_fact_ids: set[str],
        scope: EventScope | None = None,
        *,
        path_id: str | None = None,
        oracle: str | None = None,
    ) -> None:
        """Publish newly verified effects and observed response fields."""

        if verdict is VerdictStatus.FAIL:
            for effect_id in step.effect_ids:
                if effect_id in verified_fact_ids:
                    continue
                self._publish(
                    FactVerified(
                        fact=verified_fact(effect_id),
                        correlation_id=observation.check_id,
                        action_id=step.method.method_id,
                        path_id=path_id,
                        step_id=step.step_id,
                        check_id=observation.check_id,
                        observation_id=observation.observation_id,
                        oracle=oracle,
                    ),
                    scope,
                )
                verified_fact_ids.add(effect_id)

        if observation.output is None:
            return
        for field_name, _ in observation.output.fields:
            self._publish(
                EvidenceRecorded(
                    fact=evidence_fact(observation.observation_id, field_name),
                    correlation_id=observation.check_id,
                    action_id=step.method.method_id,
                    path_id=path_id,
                    step_id=step.step_id,
                    check_id=observation.check_id,
                    observation_id=observation.observation_id,
                    oracle=oracle,
                ),
                scope,
            )


def _phase_for(
    verdict: VerdictStatus,
    *,
    is_final_step: bool,
    effect_verified: bool | None = None,
) -> Literal["active", "blocked", "goal_reached", "unscoreable"]:
    verified = (
        verdict is VerdictStatus.FAIL if effect_verified is None else effect_verified
    )
    if verified:
        return "goal_reached" if is_final_step else "active"
    if verdict in {VerdictStatus.PASS, VerdictStatus.FAIL}:
        return "blocked"
    return "unscoreable"


__all__ = ["Publisher"]
