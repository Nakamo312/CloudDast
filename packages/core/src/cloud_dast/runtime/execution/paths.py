"""Live execution of one bound QDL path and its candidate callbacks."""

from __future__ import annotations

import logging
from dataclasses import replace

from cloud_dast.api import LiveRequest
from cloud_dast.model import Observation
from cloud_dast.model.events import EventScope, QdlPathEvaluated
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.candidates.session import _StepContext
from cloud_dast.runtime.deficits import witness_deficit
from cloud_dast.runtime.execution.contracts import QdlExecutionPath, QdlExecutionStep
from cloud_dast.runtime.execution.state import CampaignRoundState
from cloud_dast.runtime.execution.terminal import PathAttempt
from cloud_dast.runtime.metrics import IntentState
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.evaluation import ObservationEvaluation

logger = logging.getLogger("cloud_dast.runtime.execution")


class PathRunnerMixin:
    """Path-level execution behavior composed by the execution coordinator."""

    def _execute_path(
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
            state.path_reasons[path.path_id] = reason
            if state.blocked_reasons is not None:
                state.blocked_reasons[path.path_id] = reason
            scheduler.block_prerequisite(path.path_id, reason)
            if self._metrics is not None:
                self._metrics.set_intent_state(path.path_id, IntentState.BLOCKED)
            self._publish(
                QdlPathEvaluated(
                    path_id=path.path_id,
                    outcome="blocked",
                    attempted_steps=0,
                    step_count=len(path.steps),
                    probe_count=0,
                    reason=reason,
                    action_id=missing[0].method.method_id,
                    step_id=missing[0].step_id,
                    evidence_signature=self._evidence_signature(path),
                ),
                scope,
            )
            return True

        evidence_graph = self._evidence_projection.observed_graph(path)
        self._checker.set_coupling_context(
            tuple((step.plan, step.method, step.scenario) for step in path.steps),
            evidence_graph=evidence_graph,
        )
        attempt = PathAttempt(path=path)
        attempt.prefiltered = self._path_prefilter.run(path, scope=scope)
        if attempt.prefiltered is not None and attempt.prefiltered.status == "unsat":
            self._block_symbolically_unsat(path, scheduler, scope)
            return True
        self._execute_path_steps(
            request,
            attempt,
            scheduler,
            state,
            budget=budget,
            scope=scope,
            evidence_graph=evidence_graph,
        )
        self._shrink_attempt_findings(
            request,
            attempt,
            state,
            budget=budget,
            scope=scope,
        )
        self._path_terminal.finish(attempt, scheduler, state, scope=scope)
        return True

    def _execute_path_steps(
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
            if self._evidence_reuse.resume_observed_step(path, step, scope=scope):
                continue
            if self._evidence_reuse.proved_effects(
                step,
                evidence_graph=evidence_graph,
                path=path,
                step_index=step_index,
                scope=scope,
            ):
                continue
            if not budget.can_spend():
                break
            fuzz_session = self._step_candidates.session_for(
                step,
                attempt.prefiltered,
                step_index=step_index,
            )
            context = _StepContext(
                request=request,
                attempt=attempt,
                step=step,
                step_index=step_index,
                prefiltered=attempt.prefiltered,
                fuzz_session=fuzz_session,
                state=state,
                budget=budget,
                scope=scope,
            )
            observations_before = len(attempt.observations)
            effect_verified = self._step_candidates.run(
                context,
                record_observation=self._record_step_candidate,
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
            evidence_graph = self._evidence_projection.observed_graph(path)
            self._checker.set_coupling_context(
                tuple((item.plan, item.method, item.scenario) for item in path.steps),
                evidence_graph=evidence_graph,
                reset=False,
            )

    def _record_step_candidate(
        self,
        context: _StepContext,
        observation: Observation,
        prefilter_solved: bool,
    ) -> ObservationEvaluation:
        """Project a candidate result while keeping evidence in the runner."""

        return self._observation_recording.record(
            context,
            observation,
            prefilter_solved=prefilter_solved,
        )

    def _shrink_attempt_findings(
        self,
        request: LiveRequest,
        attempt: PathAttempt,
        state: CampaignRoundState,
        *,
        budget: CallLimits,
        scope: EventScope | None,
    ) -> None:
        """Delegate bounded finding minimization to the runtime coordinator."""

        self._finding_shrinking.shrink_attempt_findings(
            request,
            attempt,
            state,
            budget=budget,
            scope=scope,
        )

    @staticmethod
    def _path_scoped_step(
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

    def _block_symbolically_unsat(
        self,
        path: QdlExecutionPath,
        scheduler: CoverageDrivenScheduler,
        scope: EventScope | None = None,
    ) -> None:
        """Terminate a path before live execution when Z3 refutes it."""

        scheduler.record_outcome(path.path_id, "blocked", attempted_steps=())
        if self._metrics is not None:
            self._metrics.set_intent_state(path.path_id, IntentState.BLOCKED)
        self._publish(
            QdlPathEvaluated(
                path_id=path.path_id,
                outcome="blocked",
                attempted_steps=0,
                step_count=len(path.steps),
                probe_count=0,
                reason="symbolically unsatisfiable path",
                action_id=path.steps[-1].method.method_id if path.steps else None,
                evidence_signature=self._evidence_signature(path),
            ),
            scope,
        )
        logger.debug("qdl_path_symbolically_unsat path=%s", path.path_id)


__all__ = ["PathRunnerMixin"]
