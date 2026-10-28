"""Per-step candidate selection and execution boundary.

    The campaign runner owns path sequencing.  Evidence projection lives in
    ``runtime.evidence_projection``.  This module owns the local candidate
    lifecycle for one QDL step: session creation, preview
and selection, symbolic prefiltering, guardrail telemetry, and budgeted
transport invocation.  It deliberately does not classify observations or
mutate campaign accumulators.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cloud_dast.extensions import (
    FuzzSession,
    FuzzSessionFactory,
    FuzzSessionRequest,
    SymbolicPrefilter,
)
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    ComponentSkipped,
    DomainEvent,
    DownstreamDecision,
    EventScope,
)
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.execution.contracts import QdlExecutionPath, QdlExecutionStep


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


def _generator_component(generator: str) -> str:
    return f"generator:{generator}"


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


@dataclass(frozen=True, slots=True)
class _PrefilteredPath:
    """One whole-path candidate set produced before live execution."""

    seeds: tuple[Check, ...]
    checks: tuple[Check, ...]
    sessions: tuple[FuzzSession | None, ...]
    status: str


@dataclass(slots=True)
class _StepContext:
    """Inputs needed to execute candidates for one QDL step."""

    request: Any
    attempt: Any
    step: QdlExecutionStep
    step_index: int
    prefiltered: _PrefilteredPath | None
    fuzz_session: FuzzSession | None
    state: Any
    budget: CallLimits
    scope: EventScope | None
    component_invocation_id: str | None = None
    component_generator: str = "oneshot"


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
        checks_for_step: Callable[[_StepContext], Check],
    ) -> None:
        self._fuzz_session_factory = fuzz_session_factory
        self._symbolic_prefilter = symbolic_prefilter
        self._publish = publish
        self._execute_step_with_budget = execute_step_with_budget
        self._execute_check_with_budget = execute_check_with_budget
        self._path_scoped_step = path_scoped_step
        self._checks_for_step = checks_for_step

    def session_for(
        self,
        step: QdlExecutionStep,
        prefiltered: _PrefilteredPath | None,
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
        context: _StepContext,
        *,
        record_observation: Callable[[_StepContext, Observation, bool], object],
    ) -> bool:
        """Execute candidates until the local session or budget is exhausted."""

        while context.budget.can_spend():
            candidate = self._next_observation(context)
            if candidate.observation is None:
                if candidate.exhausted or context.fuzz_session is None:
                    break
                continue
            record_observation(
                context,
                candidate.observation,
                candidate.prefilter_solved,
            )
            if context.step_index < len(context.attempt.path.steps) - 1 and (
                (
                    not context.step.required_effects
                    and context.step.evidence_graph is not None
                )
                or context.attempt.effect_verified
            ):
                break
            if context.fuzz_session is None:
                # A one-shot QDL step executes exactly one generated candidate;
                # bounded finding shrinking is separate from adaptive retries.
                break
            if context.fuzz_session.stopped:
                break
        return bool(context.attempt.effect_verified)

    def _next_observation(self, context: _StepContext) -> _CandidateResult:
        if context.prefiltered is None:
            return self._next_unprefiltered(context)
        return self._next_prefiltered(context)

    def _next_unprefiltered(self, context: _StepContext) -> _CandidateResult:
        """Execute one-shot or adaptive candidate without a path prefilter."""

        if context.fuzz_session is None:
            context.component_generator = context.step.plan.generator
            context.component_invocation_id = (
                f"{context.attempt.path.path_id}:"
                f"{context.step.step_id}:{context.component_generator}"
            )
            self._publish_component_invoked(context, None)
            return _CandidateResult(
                self._execute_step_with_budget(
                    self._path_scoped_step(context.step, context.attempt.path),
                    context.budget,
                    scope=context.scope,
                    action_id=context.step.method.method_id,
                    path_id=context.attempt.path.path_id,
                    step_id=context.step.step_id,
                )
            )

        check = context.fuzz_session.next()
        if check is None:
            self._publish(
                ComponentSkipped(
                    component=_generator_component(context.step.plan.generator),
                    reason="no_candidates",
                    input_digest=_component_input_digest(context.step),
                    input_completeness=_component_input_completeness(context.step),
                    fallback_modes=_component_fallback_modes(context.step),
                    path_id=context.attempt.path.path_id,
                    action_id=context.step.method.method_id,
                    step_id=context.step.step_id,
                ),
                context.scope,
            )
            return _CandidateResult(None, exhausted=True)

        context.component_generator = check.generator
        context.component_invocation_id = (
            f"{context.attempt.path.path_id}:"
            f"{context.step.step_id}:{check.generator}:{check.check_id}"
        )
        self._publish_component_invoked(context, check)
        executable, prefilter_solved = self._prefilter_candidate(check, context)
        if executable is None:
            return _CandidateResult(None)
        return _CandidateResult(
            self._execute_check_with_budget(
                executable,
                context.budget,
                scope=context.scope,
                action_id=context.step.method.method_id,
                path_id=context.attempt.path.path_id,
                step_id=context.step.step_id,
            ),
            prefilter_solved=prefilter_solved,
        )

    def _prefilter_candidate(
        self,
        check: Check,
        context: _StepContext,
    ) -> tuple[Check | None, bool]:
        if self._symbolic_prefilter is None:
            return check, False

        invocation_id = f"{check.check_id}:symbolic_prefilter"
        path_id = context.attempt.path.path_id
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

    def _next_prefiltered(self, context: _StepContext) -> _CandidateResult:
        """Execute the next candidate from an already solved path prefilter."""

        if context.fuzz_session is not None:
            check = context.fuzz_session.next()
            if check is None:
                return _CandidateResult(None, exhausted=True)
        executable = self._checks_for_step(context)
        if context.component_invocation_id is None:
            context.component_generator = executable.generator
            context.component_invocation_id = (
                f"{context.attempt.path.path_id}:"
                f"{context.step.step_id}:{executable.generator}:"
                f"{executable.check_id}"
            )
            self._publish_component_invoked(context, executable)
        return _CandidateResult(
            self._execute_check_with_budget(
                executable,
                context.budget,
                scope=context.scope,
                action_id=context.step.method.method_id,
                path_id=context.attempt.path.path_id,
                step_id=context.step.step_id,
            ),
            prefilter_solved=context.prefiltered.status == "sat",
        )

    def _publish_component_invoked(
        self,
        context: _StepContext,
        check: Check | None,
    ) -> None:
        """Publish generator selection and its guardrail decision."""

        path = context.attempt.path
        component = _generator_component(context.component_generator)
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
