"""Budgeted ordinary check calls at the live transport boundary."""

from __future__ import annotations

from cloud_dast.contracts.plan import QdlExecutionStep
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import EventScope
from cloud_dast.ports import EventPublisher
from cloud_dast.runtime.budget import CallKind, CallLimits
from cloud_dast.runtime.execution.checks import bind_event_context
from cloud_dast.runtime.execution.scenarios import Checker


def spend_calls(
    budget: CallLimits,
    calls_before: int,
    calls_after: int,
    *,
    kind: CallKind = "check",
) -> None:
    """Record calls added by one transport operation."""

    budget.spend(calls_after - calls_before, kind=kind)


def execute(
    checker: Checker,
    event_bus: EventPublisher | None,
    check: QdlExecutionStep | Check,
    budget: CallLimits,
    *,
    scope: EventScope | None = None,
    action_id: str | None = None,
    path_id: str | None = None,
    step_id: str | None = None,
) -> Observation | None:
    """Execute a bound step or materialized check under one accounting boundary."""

    calls_before = checker.count
    try:
        check_ids: tuple[str, ...]
        if isinstance(check, QdlExecutionStep):
            action_id = action_id or check.method.method_id
            step_id = step_id or check.step_id
            check_ids = ()
        else:
            check_ids = (check.check_id,)
        with bind_event_context(
            event_bus,
            scope=scope,
            action_id=action_id,
            path_id=path_id,
            step_id=step_id,
            check_ids=check_ids,
        ):
            if not isinstance(check, QdlExecutionStep):
                return checker.execute_check(check)
            observations = checker.execute_bindings(
                (
                    (
                        check.plan,
                        check.method,
                        check.scenario,
                        check.invariant,
                        check.plan.generator,
                    ),
                ),
                max_checks=1,
                reset=False,
            )
            return observations[-1] if observations else None
    finally:
        spend_calls(budget, calls_before, checker.count)


__all__ = ["execute", "spend_calls"]
