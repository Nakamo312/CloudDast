"""Per-step candidate selection and execution boundary.

    The campaign runner owns path sequencing.  Evidence projection lives in
    ``runtime.evidence_projection``.  This module owns the local candidate
    lifecycle for one QDL step: session creation, preview
and selection, symbolic prefiltering, guardrail telemetry, budgeted
transport invocation, and adaptive generator feedback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.extensions import (
    FuzzSession,
    FuzzSessionFactory,
    FuzzSessionRequest,
    SymbolicPrefilter,
)
from cloud_dast.model import Check, Observation, VerdictStatus
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    ComponentSkipped,
    DomainEvent,
    DownstreamDecision,
    EventScope,
)
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.candidates.feedback import invariant_effect, trace_proximity
from cloud_dast.runtime.execution.contracts import PrefilterResult
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.verification.evaluation import ObservationEvaluation


def _component_input_digest(step: QdlExecutionStep) -> str:
    """Return an opaque digest of the component's execution-plan input."""

    return hashlib.sha256(step.plan.model_dump_json().encode("utf-8")).hexdigest()


def _component_input_completeness(step: QdlExecutionStep) -> dict[str, int]:
    return {
        "sink_facts": len(step.plan.sink_types),
        "probe_fields": len(step.plan.probe_fields),
        "dialects": len(step.plan.grammar_dialects),
    }


def _component_fallback_modes(step: QdlExecutionStep) -> tuple[str, ...]:
    modes: list[str] = []
    if not step.plan.sink_types:
        modes.append("generic")
    if not step.plan.probe_fields:
        modes.append("all_fields")
    if not step.plan.grammar_dialects:
        modes.append("no_dialects")
    return tuple(modes)


def _prefilter_input_digest(steps: tuple[QdlExecutionStep, ...]) -> str:
    payload = "\n".join(step.plan.model_dump_json() for step in steps)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _prefilter_input_completeness(
    steps: tuple[QdlExecutionStep, ...],
) -> dict[str, int]:
    return {
        "constraints": sum(len(step.plan.grammar_constraints) for step in steps),
        "couplings": sum(len(step.plan.couplings) for step in steps),
        "steps": len(steps),
    }


@dataclass(slots=True)
class _StepRun:
    """Local selection and telemetry state for one immutable path step."""

    path: QdlExecutionPath
    step_index: int
    prefiltered: PrefilterResult | None
    fuzz_session: FuzzSession | None
    budget: CallLimits
    scope: EventScope | None
    component_invocation_id: str | None = None
    component_generator: str = "oneshot"

    @property
    def step(self) -> QdlExecutionStep:
        return self.path.steps[self.step_index]


@dataclass(frozen=True, slots=True)
class _CandidateResult:
    """Outcome of selecting and executing one step candidate."""

    observation: Observation | None
    prefilter_solved: bool = False
    exhausted: bool = False


def request_for_step(step: QdlExecutionStep) -> FuzzSessionRequest:
    """Project one runtime step into the public fuzzing extension contract."""

    return FuzzSessionRequest(
        step_id=step.step_id,
        goal_id=step.goal_id,
        plan=step.plan,
        method=step.method,
        invariant=step.invariant,
        scenario=step.scenario,
    )


class StepCandidateRunner:
    """Own the mutable candidate lifecycle for one executable QDL step."""

    def __init__(
        self,
        *,
        fuzz_session_factory: FuzzSessionFactory | None,
        symbolic_prefilter: SymbolicPrefilter | None,
        publish: Callable[[DomainEvent, EventScope | None], None],
        execute_step_with_budget: Callable[..., Observation | None],
        execute_check_with_budget: Callable[..., Observation | None],
        path_scoped_step: Callable[
            [QdlExecutionStep, QdlExecutionPath], QdlExecutionStep
        ],
        latest_check: Callable[[], Check],
        metrics: CampaignMetrics | None,
    ) -> None:
        self._latest_check = latest_check
        self._metrics = metrics
        self._fuzz_session_factory = fuzz_session_factory
        self._symbolic_prefilter = symbolic_prefilter
        self._publish = publish
        self._execute_step_with_budget = execute_step_with_budget
        self._execute_check_with_budget = execute_check_with_budget
        self._path_scoped_step = path_scoped_step

    def session_for(
        self,
        step: QdlExecutionStep,
        prefiltered: PrefilterResult | None,
        *,
        step_index: int,
    ) -> FuzzSession | None:
        """Return the local adaptive session for one ordinary path step."""

        if prefiltered is not None:
            return prefiltered.sessions[step_index]
        if self._fuzz_session_factory is None:
            return None
        return self._fuzz_session_factory(request_for_step(step))

    def preview_path(
        self,
        path: QdlExecutionPath,
        *,
        generate_checks: Callable[[QdlExecutionStep], tuple[Check, ...]],
    ) -> tuple[tuple[FuzzSession | None, ...], tuple[Check, ...]] | None:
        """Preview one candidate per step for whole-path symbolic filtering.

        Preview uses the same session factory as ordinary step execution.  The
        service-specific one-shot generator is supplied as a callback because
        candidate construction remains an injected execution capability, not a
        second implementation in this module.
        """

        sessions: list[FuzzSession | None] = []
        seeds: list[Check] = []
        for step in path.steps:
            session = (
                self._fuzz_session_factory(request_for_step(step))
                if self._fuzz_session_factory is not None
                else None
            )
            if session is None:
                generated = generate_checks(step)
                if not generated:
                    return None
                seed = generated[0]
            else:
                seed = session.preview()
                if seed is None:
                    return None
            sessions.append(session)
            seeds.append(seed)
        return tuple(sessions), tuple(seeds)

    def run(
        self,
        path: QdlExecutionPath,
        step_index: int,
        budget: CallLimits,
        *,
        prefiltered: PrefilterResult | None,
        fuzz_session: FuzzSession | None,
        scope: EventScope | None,
        record_observation: Callable[
            [Observation, str | None, str],
            tuple[ObservationEvaluation, Sequence[Observation], Callable[[], None]],
        ],
        record_proximity: Callable[[float], None],
    ) -> tuple[bool, PrefilterResult | None]:
        """Execute candidates and return the remaining valid path preview."""

        context = _StepRun(path, step_index, prefiltered, fuzz_session, budget, scope)
        effect_verified = False
        while budget.can_spend():
            candidate = self._next_observation(context)
            if candidate.observation is None:
                if candidate.exhausted or fuzz_session is None:
                    break
                continue
            evaluation, trace, finalize = record_observation(
                candidate.observation,
                context.component_invocation_id,
                context.component_generator,
            )
            self._record_feedback(
                context,
                candidate.observation,
                evaluation,
                trace,
                record_proximity,
                prefilter_solved=candidate.prefilter_solved,
            )
            finalize()
            effect_verified |= evaluation.effect_verified
            if step_index < len(path.steps) - 1 and (
                (
                    not context.step.required_effects
                    and context.step.evidence_graph is not None
                )
                or effect_verified
            ):
                break
            if fuzz_session is None or fuzz_session.stopped:
                break
        return effect_verified, context.prefiltered

    def _record_feedback(
        self,
        context: _StepRun,
        observation: Observation,
        evaluation: ObservationEvaluation,
        trace: Sequence[Observation],
        record_proximity: Callable[[float], None],
        *,
        prefilter_solved: bool,
    ) -> None:
        """Feed the result back to the adaptive generator, if present."""

        step = context.step
        fuzz_session = context.fuzz_session
        recorded_check = self._latest_check()
        cached = context.prefiltered
        if (
            cached is not None
            and cached.checks
            and recorded_check.request != cached.checks[context.step_index].request
        ):
            context.prefiltered = replace(cached, checks=())
        if self._metrics is not None:
            self._metrics.record_generator_outcome(
                step.method.method_id,
                getattr(fuzz_session, "current_strategy", "unknown")
                if fuzz_session is not None
                else "oneshot",
                evaluation.progress,
            )
        if fuzz_session is None or recorded_check is None:
            return

        effect = invariant_effect(step.invariant)
        proximity = (
            trace_proximity(
                effect,
                tuple(trace),
                evaluation.verdict,
                step_count=len(context.path.steps),
            )
            if effect is not None
            else None
        )
        if evaluation.verdict is VerdictStatus.FAIL and not evaluation.grounded:
            # An ungrounded FAIL is a lead, not progress: its unverified
            # violation proximity must not grow the path reward.
            proximity = 0.0 if proximity is not None else None
        if proximity is not None:
            record_proximity(proximity)
        fuzz_session.record(
            recorded_check,
            evaluation.verdict,
            grounded=evaluation.grounded,
            proximity=proximity,
            observation=observation,
            solver_prefiltered=prefilter_solved,
        )

    def _next_observation(self, context: _StepRun) -> _CandidateResult:
        """Select one candidate, retaining the one-shot step boundary."""

        if context.fuzz_session is None and context.prefiltered is None:
            context.component_generator = context.step.plan.generator
            context.component_invocation_id = (
                f"{context.path.path_id}:"
                f"{context.step.step_id}:{context.component_generator}"
            )
            self._publish_component_invoked(context, None)
            return _CandidateResult(
                self._execute_step_with_budget(
                    self._path_scoped_step(context.step, context.path),
                    context.budget,
                    scope=context.scope,
                    action_id=context.step.method.method_id,
                    path_id=context.path.path_id,
                    step_id=context.step.step_id,
                )
            )

        if context.fuzz_session is None:
            check = context.prefiltered.seeds[context.step_index]
        else:
            check = context.fuzz_session.next()
        if check is None:
            if context.prefiltered is None:
                self._publish(
                    ComponentSkipped(
                        component=f"generator:{context.step.plan.generator}",
                        reason="no_candidates",
                        input_digest=_component_input_digest(context.step),
                        input_completeness=_component_input_completeness(context.step),
                        fallback_modes=_component_fallback_modes(context.step),
                        path_id=context.path.path_id,
                        action_id=context.step.method.method_id,
                        step_id=context.step.step_id,
                    ),
                    context.scope,
                )
            return _CandidateResult(None, exhausted=True)
        return self._execute_candidate(check, context)

    def _execute_candidate(self, check: Check, context: _StepRun) -> _CandidateResult:
        """Reuse a solved preview only for its original input candidate."""

        cached = context.prefiltered
        if cached is not None and (
            not cached.checks or check != cached.seeds[context.step_index]
        ):
            context.prefiltered = replace(cached, checks=())
            cached = None
        if cached is not None:
            check = cached.checks[context.step_index]
        context.component_generator = check.generator
        context.component_invocation_id = (
            f"{context.path.path_id}:"
            f"{context.step.step_id}:{check.generator}:{check.check_id}"
        )
        self._publish_component_invoked(context, check)
        if cached is None:
            executable, prefilter_solved = self._prefilter_candidate(check, context)
        else:
            executable = check
            prefilter_solved = (
                cached.status == "sat"
                or check.request != cached.seeds[context.step_index].request
            )
        if executable is None:
            return _CandidateResult(None)
        return _CandidateResult(
            self._execute_check_with_budget(
                executable,
                context.budget,
                scope=context.scope,
                action_id=context.step.method.method_id,
                path_id=context.path.path_id,
                step_id=context.step.step_id,
            ),
            prefilter_solved=prefilter_solved,
        )

    def _prefilter_candidate(
        self,
        check: Check,
        context: _StepRun,
    ) -> tuple[Check | None, bool]:
        if self._symbolic_prefilter is None:
            return check, False

        invocation_id = f"{check.check_id}:symbolic_prefilter"
        path_id = context.path.path_id
        self._publish(
            ComponentInvoked(
                component="symbolic_prefilter",
                input_digest=_prefilter_input_digest((context.step,)),
                input_completeness=_prefilter_input_completeness((context.step,)),
                invocation_id=invocation_id,
                check_id=check.check_id,
                path_id=path_id,
            ),
            context.scope,
        )
        decision = self._symbolic_prefilter.prefilter(
            check,
            context.step.plan,
            context.step.method,
        )
        survived = decision.status != "unsat"
        self._publish(
            ComponentOutput(
                component="symbolic_prefilter",
                summary={
                    "candidates_produced": 1,
                    "candidates_survived_prefilter": int(survived),
                    "candidates_survived_guardrail": 1,
                    "scored": int(survived),
                },
                invocation_id=invocation_id,
                check_id=check.check_id,
                path_id=path_id,
            ),
            context.scope,
        )
        self._publish(
            DownstreamDecision(
                component="symbolic_prefilter",
                consumed=survived,
                by="path_runner",
                outcome=decision.status,
                invocation_id=invocation_id,
                check_id=check.check_id,
                path_id=path_id,
            ),
            context.scope,
        )
        if decision.status == "unsat":
            return None, False
        if decision.status == "solved":
            return decision.check, True
        return check, False

    def _publish_component_invoked(
        self,
        context: _StepRun,
        check: Check | None,
    ) -> None:
        """Publish generator selection and its guardrail decision."""

        path = context.path
        component = f"generator:{context.component_generator}"
        self._publish(
            ComponentInvoked(
                component=component,
                input_digest=_component_input_digest(context.step),
                input_completeness=_component_input_completeness(context.step),
                fallback_modes=_component_fallback_modes(context.step),
                invocation_id=context.component_invocation_id,
                check_id=check.check_id if check is not None else None,
                path_id=path.path_id,
                action_id=context.step.method.method_id,
                step_id=context.step.step_id,
                correlation_id=check.check_id if check is not None else None,
            ),
            context.scope,
        )
        if check is None:
            return
        self._publish(
            DownstreamDecision(
                component=component,
                consumed=True,
                by="guardrail",
                outcome="allowed",
                invocation_id=context.component_invocation_id,
                check_id=check.check_id,
                path_id=path.path_id,
                action_id=context.step.method.method_id,
                step_id=context.step.step_id,
                correlation_id=check.check_id,
            ),
            context.scope,
        )


__all__ = ["StepCandidateRunner"]
