"""Finding minimization orchestration for the live execution runtime.

The fuzzing package supplies the shrinker implementation.  This module owns
only the runtime protocol around it: selecting deterministic finding seeds,
spending the execution budget, re-evaluating candidates, and persisting the
minimal replay example.  Live transport and security evaluation are injected
as callbacks so this coordinator does not become another path runner.
"""

from __future__ import annotations

from typing import Protocol

from cloud_dast.api import LiveRequest
from cloud_dast.contracts.finding_examples import save_finding_example
from cloud_dast.extensions import FindingShrinker, FindingShrinkerFactory
from cloud_dast.model import Check, Observation, VerdictStatus
from cloud_dast.model.events import EventScope
from cloud_dast.ports import FindingExampleStore
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.execution.terminal import PathAttempt
from cloud_dast.verification.evaluation import ObservationEvaluation


class FindingCandidateExecutor(Protocol):
    def __call__(
        self,
        check: Check,
        budget: CallLimits,
        *,
        scope: EventScope | None,
        action_id: str,
        path_id: str,
        step_id: str,
    ) -> Observation | None: ...


class FindingCandidateClassifier(Protocol):
    def __call__(
        self,
        step: QdlExecutionStep,
        observation: Observation,
        request: LiveRequest,
        path_observations: tuple[Observation, ...],
        *,
        default_reason: str,
        evidence_store: Store[MeasurementKey] | None,
    ) -> ObservationEvaluation: ...


class FindingShrinkCoordinator:
    """Coordinate bounded minimization without owning execution internals."""

    def __init__(
        self,
        *,
        factory: FindingShrinkerFactory | None,
        example_database: FindingExampleStore | None,
        execute_check: FindingCandidateExecutor,
        classify_observation: FindingCandidateClassifier,
    ) -> None:
        self._factory = factory
        self._example_database = example_database
        self._execute_check = execute_check
        self._classify_observation = classify_observation

    def shrink_attempt_findings(
        self,
        request: LiveRequest,
        attempt: PathAttempt,
        state: CampaignRoundState,
        *,
        budget: CallLimits,
        scope: EventScope | None,
    ) -> None:
        """Minimize every deterministic finding after its path attempt."""

        if self._example_database is None or self._factory is None:
            return
        steps = {step.step_id: step for step in attempt.path.steps}
        observations = {
            observation.observation_id: observation
            for observation in attempt.observations
        }
        for evaluation_key in tuple(state.minimal_checks):
            observation = observations.get(evaluation_key[0])
            if observation is None:
                continue
            provenance = state.provenance.get(evaluation_key)
            if provenance is None:
                continue
            step = steps.get(provenance.step_id)
            if step is None:
                continue
            self._shrink_finding(
                state,
                step,
                request,
                budget,
                observation,
                scope=scope,
                path_id=provenance.path_id,
            )

    def _shrink_finding(
        self,
        state: CampaignRoundState,
        step: QdlExecutionStep,
        request: LiveRequest,
        budget: CallLimits,
        origin_observation: Observation,
        *,
        scope: EventScope | None,
        path_id: str,
    ) -> None:
        seed_key = (
            origin_observation.observation_id,
            step.invariant.invariant_id,
        )
        seed = state.minimal_checks.get(seed_key)
        if seed is None or self._factory is None:
            return
        try:
            shrinker: FindingShrinker = self._factory(
                seed=seed,
                plan=step.plan,
                method=step.method,
                invariant=step.invariant,
            )
        except ValueError:
            return

        while budget.can_spend():
            candidate = shrinker.next()
            if candidate is None:
                break
            observation = self._execute_check(
                candidate,
                budget,
                scope=scope,
                action_id=step.method.method_id,
                path_id=path_id,
                step_id=step.step_id,
            )
            if observation is None:
                shrinker.discard(candidate)
                continue
            classification = self._classify_observation(
                step,
                observation,
                request,
                (observation,),
                default_reason="finding shrink witness",
                evidence_store=state.differential_evidence,
            )
            reproduced = (
                classification.policy_verdict is not None
                and classification.policy_verdict.deterministic
                and classification.policy_verdict.grounded
                and classification.verdict is VerdictStatus.FAIL
            )
            shrinker.record(candidate, reproduced=reproduced)
            if reproduced:
                state.minimal_checks[seed_key] = candidate

        minimal = shrinker.result.check
        state.minimal_checks[seed_key] = minimal
        save_finding_example(self._example_database, minimal)


__all__ = [
    "FindingCandidateClassifier",
    "FindingCandidateExecutor",
    "FindingShrinkCoordinator",
]
