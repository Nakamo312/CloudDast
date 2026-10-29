"""Deficit discovery and recovery for campaign replanning."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from cloud_dast.contracts.execution import LiveRequest, ScenarioBinding
from cloud_dast.contracts.plan import QdlExecutionStep
from cloud_dast.model import Observation, PolicyVerdict, VerdictStatus
from cloud_dast.model.events import QdlStepEvaluated
from cloud_dast.qdl.graph import Atom
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.deficits.classification import gaps_for_observations
from cloud_dast.runtime.deficits.coverage import gaps as coverage_gaps
from cloud_dast.runtime.deficits.detection import (
    blocked_step_deficit,
    classify_step_event,
    missing_role_deficit,
    response_semantics_deficits,
    witness_deficits,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.routing import consultation_deficit
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding import BatchFlow
from cloud_dast.runtime.recovery import Coordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.deficits.collection")


@dataclass(slots=True)
class ClassificationState:
    """Mutable cursors for one campaign's deficit classification pass."""

    paths: set[str] = field(default_factory=set)
    observations: int = 0


class DeficitCollector:
    """Translate runtime outcomes into typed deficits and recovery clues."""

    def __init__(self, grounding: BatchFlow | None) -> None:
        self._batches = grounding

    def collect_deficits(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        classification: ClassificationState,
        recovery: Coordinator,
        *,
        expand_graph: bool,
    ) -> None:
        """Turn round outcomes into typed, deduplicated deficits."""

        self._collect_binding_deficits(request, binding, deficits)
        deficits.add(witness_deficits(binding.execution.select(request.method_id)))
        self._collect_blocked_path_deficits(
            request,
            binding,
            scheduler,
            accumulator,
            deficits,
            classification.paths,
            recovery,
        )
        new_observations, classified_observations = self._classify_new_observations(
            request,
            accumulator,
            deficits,
            classification.observations,
        )
        self._collect_classification_gaps(
            request,
            binding,
            accumulator,
            deficits,
            new_observations,
        )
        if self._batches is not None and self._batches.reactive_capable:
            self._collect_coverage_deficits(
                request,
                binding,
                deficits,
                new_observations,
                expand_graph=expand_graph,
            )
        classification.observations = classified_observations

    def _collect_classification_gaps(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        new_observations: tuple[Observation, ...],
    ) -> None:
        """Queue classification work for newly grounded failures."""

        checks = {check.check_id: check for check in accumulator.checks}
        classification = gaps_for_observations(
            binding,
            checks=checks,
            observations=new_observations,
            policy_verdicts=accumulator.policy_verdicts,
        )
        added = deficits.add(classification)
        if added:
            logger.info(
                "classification_deficits_detected service=%s added=%d",
                request.service,
                added,
            )

    def _collect_binding_deficits(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        deficits: DeficitQueue,
    ) -> None:
        """Queue missing role facts reported by the binder."""

        actions = self._request_actions(request, binding)
        for binding_deficit in binding.deficits:
            if (
                actions is not None
                and binding_deficit.action.removeprefix("action:") not in actions
            ):
                continue
            context = (
                ("coverage", "binding"),
                ("reason", binding_deficit.reason),
                *binding_deficit.context,
            )
            if binding_deficit.reason == "probe_schema_mismatch":
                # Two trusted input contracts disagree. A semantic proposal
                # cannot repair an executable method's structural schema.
                deficit = consultation_deficit(
                    QdlSubgoal("input_schema", (Atom(value=binding_deficit.action),)),
                    action=binding_deficit.action,
                    context=context,
                )
            else:
                deficit = missing_role_deficit(binding_deficit.action, context)
            if deficits.add((deficit,)):
                logger.info(
                    "deficit_detected service=%s class=%s action=%s reason=%s",
                    request.service,
                    deficit.predicate_class,
                    deficit.action,
                    binding_deficit.reason,
                )

    def _collect_blocked_path_deficits(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        classified_paths: set[str],
        recovery: Coordinator,
    ) -> None:
        """Queue one recovery deficit for each newly blocked path."""

        paths_by_id = {path.path_id: path for path in scheduler.paths}
        for path_id in self._blocked_path_ids(scheduler):
            if path_id in classified_paths:
                continue
            classified_paths.add(path_id)
            path = paths_by_id.get(path_id)
            if path is None or not path.steps:
                continue
            if any(
                step.witness_requirement is not None and not step.plan.probe_fields
                for step in path.steps
            ):
                # The path's exact graph obligation is already queued,
                # including when a later step prevented the chain starting.
                continue
            blocked_step = self._blocked_step(path, accumulator)
            if blocked_step is None:
                continue
            intent = recovery.recovery_for(path_id)
            deficit = blocked_step_deficit(
                path,
                blocked_step,
                reason=(intent.reason if intent is not None and intent.reason else ""),
                recovery_action=intent.recovery if intent is not None else None,
                clue_observation_id=(
                    intent.clue_observation_id
                    if intent is not None and intent.recovery == "reuse_clue"
                    else None
                ),
            )
            if deficits.add((deficit,)):
                logger.info(
                    "deficit_detected service=%s class=%s action=%s path=%s",
                    request.service,
                    deficit.predicate_class,
                    deficit.action,
                    path_id,
                )

    def _classify_new_observations(
        self,
        request: LiveRequest,
        accumulator: CampaignAccumulator,
        deficits: DeficitQueue,
        classified_observations: int,
    ) -> tuple[tuple[Observation, ...], int]:
        """Normalize unscoreable rationales of new observations."""

        observations = accumulator.observations
        new_observations = tuple(observations[classified_observations:])
        new_observation_ids = {o.observation_id for o in new_observations}
        for evaluation_key, verdict in accumulator.policy_verdicts.items():
            if evaluation_key[0] not in new_observation_ids:
                continue
            if verdict is None or verdict.status is not VerdictStatus.UNSCOREABLE:
                continue
            provenance = accumulator.provenance.get(evaluation_key)
            event = QdlStepEvaluated(
                path_id=provenance.path_id if provenance is not None else "-",
                step_id=provenance.step_id if provenance is not None else "-",
                verdict=VerdictStatus.UNSCOREABLE,
                phase="unscoreable",
                reason=verdict.rationale,
                step_index=0,
            )
            deficit = classify_step_event(event)
            if deficit is not None:
                deficit = replace(
                    deficit,
                    context=(
                        *deficit.context,
                        ("observation_id", evaluation_key[0]),
                    ),
                )
            if deficit is not None and deficits.add((deficit,)):
                logger.info(
                    "deficit_detected service=%s class=%s action=%s",
                    request.service,
                    deficit.predicate_class,
                    deficit.action,
                )
        return new_observations, len(observations)

    def _collect_coverage_deficits(
        self,
        request: LiveRequest,
        binding: ScenarioBinding,
        deficits: DeficitQueue,
        new_observations: tuple[Observation, ...],
        *,
        expand_graph: bool,
    ) -> None:
        """Queue coverage and response-semantics deficits for reactive grounding.

        Declared-action coverage is deferred until the currently bound execution
        surface is drained: expanding the contract graph while paths remain can
        consume the reactive budget needed to unblock those paths and deadlock
        the campaign.
        """

        coverage = coverage_gaps(
            binding,
            include_declared_actions=expand_graph,
        )
        actions = self._request_actions(request, binding)
        coverage_added = deficits.add(
            deficit
            for deficit in coverage
            if actions is None or deficit.action.removeprefix("action:") in actions
        )
        if coverage_added:
            logger.info(
                "coverage_deficits_detected service=%s added=%d",
                request.service,
                coverage_added,
            )
        response_added = deficits.add(
            response_semantics_deficits(binding, new_observations)
        )
        if response_added:
            logger.info(
                "response_semantics_deficits_detected service=%s added=%d",
                request.service,
                response_added,
            )

    @staticmethod
    def _request_actions(
        request: LiveRequest,
        binding: ScenarioBinding,
    ) -> frozenset[str] | None:
        """Return the action universe of the requested execution paths.

        A method-scoped campaign may repair any step of its selected chains,
        including setup predecessors. Unrelated service actions must not
        consume its consultation budget. A full-service request stays open.
        """

        if request.method_id is None:
            return None
        return frozenset(
            {
                request.method_id.removeprefix("action:"),
                *(
                    step.method.method_id.removeprefix("action:")
                    for path in binding.execution.select(request.method_id)
                    for step in path.steps
                ),
            }
        )

    def _blocked_step(self, path, accumulator: CampaignAccumulator):
        """Find the step where an AND-chain path stopped verifying."""

        observations_by_step: dict[str, list[tuple[str, str]]] = {}
        for evaluation_key, provenance in accumulator.provenance.items():
            if provenance.path_id != path.path_id:
                continue
            observations_by_step.setdefault(provenance.step_id, []).append(
                evaluation_key
            )

        for step in path.steps:
            observation_ids = observations_by_step.get(step.step_id)
            if not observation_ids:
                return step
            verified = any(
                _effect_verified(accumulator.policy_verdicts.get(observation_id))
                for observation_id in observation_ids
            )
            if not verified:
                return step
        return None

    def record_recovery(
        self,
        scheduler: CoverageDrivenScheduler,
        accumulator: CampaignAccumulator,
        recovery: Coordinator,
        *,
        blocked_reasons: Mapping[str, str] | None = None,
    ) -> None:
        """Fold the latest round into clues and ordered blocked branches."""

        paths_by_id = {path.path_id: path for path in scheduler.paths}
        blocked_steps: dict[str, QdlExecutionStep] = {}
        for path_id in reversed(scheduler.state.selections):
            if path_id not in scheduler.state.blocked or path_id in blocked_steps:
                continue
            path = paths_by_id.get(path_id)
            if path is None:
                continue
            step = self._blocked_step(path, accumulator)
            if step is not None:
                blocked_steps[path_id] = step
        recovery.record_round(
            scheduler.paths,
            accumulator.observations,
            accumulator.provenance,
            accumulator.policy_verdicts,
            blocked_steps,
            tuple(blocked_steps),
            blocked_reasons,
        )

    @staticmethod
    def _blocked_path_ids(scheduler: CoverageDrivenScheduler) -> tuple[str, ...]:
        """Return blocked paths in deterministic reverse-selection order."""

        selected_blocked = tuple(
            path_id
            for path_id in reversed(scheduler.state.selections)
            if path_id in scheduler.state.blocked
        )
        remaining_blocked = tuple(
            path_id
            for path_id in sorted(scheduler.state.blocked)
            if path_id not in selected_blocked
        )
        return (*selected_blocked, *remaining_blocked)


def _effect_verified(verdict: PolicyVerdict | None) -> bool:
    """Return whether a verdict proves a deterministic grounded effect."""

    return (
        verdict is not None
        and verdict.status is VerdictStatus.FAIL
        and verdict.deterministic
        and verdict.grounded
    )
