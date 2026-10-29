"""Live execution of one bound QDL path and its candidate callbacks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model.events import EventScope
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.candidates.session import StepCandidateRunner
from cloud_dast.runtime.deficits import witness_deficit
from cloud_dast.runtime.evidence_projection import Projection
from cloud_dast.runtime.evidence_reuse import Reuse
from cloud_dast.runtime.execution.prefilter import SymbolicPathPrefilter
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.execution.terminal import PathAttempt, PathTerminalizer
from cloud_dast.runtime.finding_shrinking import FindingShrinkCoordinator
from cloud_dast.runtime.observation_recording import Coordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

logger = logging.getLogger("cloud_dast.runtime.execution")


@dataclass(frozen=True, slots=True)
class Executor:
    """Execute one bound path using explicitly supplied run-scoped services."""

    checker: Checker
    evidence: Projection
    reuse: Reuse
    prefilter: SymbolicPathPrefilter
    candidates: StepCandidateRunner
    recorder: Coordinator
    shrinking: FindingShrinkCoordinator
    terminal: PathTerminalizer

    def execute(
        self,
        request: LiveRequest,
        path: QdlExecutionPath,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        *,
        budget: CallLimits,
        scope: EventScope | None,
    ) -> bool:
        """Execute one path and record its scheduler outcome."""

        if state.blocked_reasons is not None:
            state.blocked_reasons.pop(path.path_id, None)
        missing = tuple(
            step
            for step in path.steps
            if step.witness_requirement is not None and not step.plan.probe_fields
        )
        if missing:
            for step in missing:
                deficit = witness_deficit(path, step)
                if state.deficit_sink is not None:
                    state.deficit_sink(deficit)
            reason = (
                "unprovable witness requirement: "
                f"{missing[0].witness_requirement.render()}"
            )
            self.terminal.block(
                path,
                scheduler,
                state,
                reason=reason,
                prerequisite=True,
                scope=scope,
                step=missing[0],
            )
            return True

        evidence_graph = self.evidence.observed_graph(path)
        self.checker.set_coupling_context(
            tuple((step.plan, step.method, step.scenario) for step in path.steps),
            evidence_graph=evidence_graph,
        )
        attempt = PathAttempt(path=path)
        attempt.prefiltered = self.prefilter.run(path, scope=scope)
        if attempt.prefiltered is not None and attempt.prefiltered.status == "unsat":
            self.terminal.block(
                path,
                scheduler,
                state,
                reason="symbolically unsatisfiable path",
                prerequisite=False,
                scope=scope,
            )
            logger.debug("qdl_path_symbolically_unsat path=%s", path.path_id)
            return True
        self._execute_steps(
            request,
            attempt,
            scheduler,
            state,
            budget=budget,
            scope=scope,
            evidence_graph=evidence_graph,
        )
        self.shrinking.shrink_attempt_findings(
            request,
            attempt,
            state,
            budget=budget,
            scope=scope,
        )
        self.terminal.finish(attempt, scheduler, state, scope=scope)
        return True

    def _execute_steps(
        self,
        request: LiveRequest,
        attempt: PathAttempt,
        scheduler: CoverageDrivenScheduler,
        state: CampaignRoundState,
        *,
        budget: CallLimits,
        scope: EventScope | None,
        evidence_graph: QdlGraph,
    ) -> None:
        """Execute ordinary requests, keeping value acquisition separate from proof."""

        path = attempt.path
        for step_index, step in enumerate(path.steps):
            if self.reuse.resume_observed_step(path, step, scope=scope):
                continue
            if self.reuse.proved_effects(
                step,
                evidence_graph=evidence_graph,
                path=path,
                step_index=step_index,
                scope=scope,
            ):
                continue
            if not budget.can_spend():
                break
            fuzz_session = self.candidates.session_for(
                step,
                attempt.prefiltered,
                step_index=step_index,
            )
            observations_before = len(attempt.observations)
            effect_verified, attempt.prefiltered = self.candidates.run(
                path,
                step_index,
                budget,
                prefiltered=attempt.prefiltered,
                fuzz_session=fuzz_session,
                scope=scope,
                record_observation=self.recorder.bind(
                    request,
                    attempt,
                    state,
                    step_index=step_index,
                    fuzz_session=fuzz_session,
                    scope=scope,
                ),
                record_proximity=attempt.record_proximity,
            )
            final_step = step_index == len(path.steps) - 1
            observes_values = (
                not step.required_effects and step.evidence_graph is not None
            )
            if (not effect_verified and (not observes_values or final_step)) or len(
                attempt.observations
            ) == observations_before:
                logger.debug(
                    "qdl_path_blocked path=%s step=%s",
                    path.path_id,
                    step.step_id,
                )
                break
            attempt.effect_verified = final_step and effect_verified
            evidence_graph = self.evidence.observed_graph(path)
            self.checker.set_coupling_context(
                tuple((item.plan, item.method, item.scenario) for item in path.steps),
                evidence_graph=evidence_graph,
                reset=False,
            )


def scope_step(
    step: QdlExecutionStep,
    path: QdlExecutionPath,
) -> QdlExecutionStep:
    """Give one path its own output-forwarding scope."""

    return replace(
        step,
        plan=step.plan.model_copy(
            update={"plan_id": f"path:{path.path_id}"},
        ),
    )


__all__ = ["Executor", "scope_step"]
