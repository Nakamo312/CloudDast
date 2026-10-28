"""Budgeted ordinary check calls at the live transport boundary."""

from __future__ import annotations

from cloud_dast.model import Check, Observation
from cloud_dast.model.events import EventScope
from cloud_dast.runtime.budget import CallKind, CallLimits
from cloud_dast.runtime.execution.checks import bind_event_context
from cloud_dast.runtime.execution.contracts import QdlExecutionStep


def spend_calls(
    budget: CallLimits,
    calls_before: int,
    calls_after: int,
    *,
    kind: CallKind = "check",
) -> None:
    """Record calls added by one transport operation."""

    budget.spend(calls_after - calls_before, kind=kind)


class CallRunnerMixin:
    """Execute one ordinary step or check and account for its live calls."""

    def _execute_step(self, step: QdlExecutionStep) -> Observation | None:
        step_observations = self._checker.execute_bindings(
            (
                (
                    step.plan,
                    step.method,
                    step.scenario,
                    step.invariant,
                    step.plan.generator,
                ),
            ),
            max_checks=1,
            reset=False,
        )
        return step_observations[-1] if step_observations else None

    def _execute_step_with_budget(
        self,
        step: QdlExecutionStep,
        budget: CallLimits,
        *,
        scope: EventScope | None = None,
        action_id: str | None = None,
        path_id: str | None = None,
        step_id: str | None = None,
    ) -> Observation | None:
        calls_before = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=action_id or step.method.method_id,
                path_id=path_id,
                step_id=step_id or step.step_id,
            ):
                return self._execute_step(step)
        finally:
            spend_calls(budget, calls_before, len(self._checker.checks))

    def _execute_check_with_budget(
        self,
        check: Check,
        budget: CallLimits,
        *,
        scope: EventScope | None = None,
        action_id: str | None = None,
        path_id: str | None = None,
        step_id: str | None = None,
    ) -> Observation | None:
        calls_before = len(self._checker.checks)
        try:
            with bind_event_context(
                self._event_bus,
                scope=scope,
                action_id=action_id,
                path_id=path_id,
                step_id=step_id,
                check_ids=(check.check_id,),
            ):
                return self._checker.execute_check(check)
        finally:
            spend_calls(budget, calls_before, len(self._checker.checks))


__all__ = ["CallRunnerMixin", "spend_calls"]
