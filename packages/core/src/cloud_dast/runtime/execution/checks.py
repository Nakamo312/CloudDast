from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from threading import RLock

from cloud_dast.model import (
    Check,
    ExecutionTrace,
    Observation,
    TraceStep,
)
from cloud_dast.model.events import CheckCompleted, CoverageUpdated, EventScope
from cloud_dast.ports import EventPublisher

Target = Callable[[Check], Observation]


@dataclass(frozen=True, slots=True)
class _EventContext:
    scope: EventScope | None = None
    action_id: str | None = None
    path_id: str | None = None
    step_id: str | None = None
    oracle: str | None = None


_ACTIVE_CONTEXT: ContextVar[tuple[int, _EventContext] | None] = ContextVar(
    "cloud_dast_check_event_context",
    default=None,
)
_CHECK_CONTEXTS: dict[tuple[int, str], _EventContext] = {}
_CHECK_CONTEXTS_LOCK = RLock()


@contextmanager
def bind_event_context(
    event_bus: EventPublisher | None,
    *,
    scope: EventScope | None = None,
    action_id: str | None = None,
    path_id: str | None = None,
    step_id: str | None = None,
    oracle: str | None = None,
    check_ids: Iterable[str] = (),
):
    """Bind runtime event metadata across the checker execution boundary.

    ``Checker`` owns the call to :func:`run_check`, so the path
    runner cannot pass metadata through that API without changing its public
    contract.  The context is therefore explicit at this boundary and
    check-id bindings also cover worker threads used by differential probes.
    Direct callers can continue using ``run_check`` without a context; that
    is the deliberate JSONL compatibility path for legacy producers.
    """

    if event_bus is None:
        yield
        return

    context = _EventContext(
        scope=scope,
        action_id=action_id,
        path_id=path_id,
        step_id=step_id,
        oracle=oracle,
    )
    token = _ACTIVE_CONTEXT.set((id(event_bus), context))
    keys = tuple((id(event_bus), check_id) for check_id in check_ids)
    with _CHECK_CONTEXTS_LOCK:
        previous = {key: _CHECK_CONTEXTS.get(key) for key in keys}
        _CHECK_CONTEXTS.update({key: context for key in keys})
    try:
        yield
    finally:
        with _CHECK_CONTEXTS_LOCK:
            for key, old_context in previous.items():
                if old_context is None:
                    _CHECK_CONTEXTS.pop(key, None)
                else:
                    _CHECK_CONTEXTS[key] = old_context
        _ACTIVE_CONTEXT.reset(token)


def _event_context(
    event_bus: EventPublisher,
    check_id: str,
) -> _EventContext:
    with _CHECK_CONTEXTS_LOCK:
        bound = _CHECK_CONTEXTS.get((id(event_bus), check_id))
    if bound is not None:
        return bound
    active = _ACTIVE_CONTEXT.get()
    if active is not None and active[0] == id(event_bus):
        return active[1]
    return _EventContext()


def _publish(
    event_bus: EventPublisher,
    event,
    context: _EventContext,
) -> None:
    updates = {
        name: value
        for name, value in {
            "action_id": context.action_id,
            "path_id": context.path_id,
            "step_id": context.step_id,
            "oracle": context.oracle,
        }.items()
        if value is not None
    }
    if context.scope is not None:
        updates.update(
            campaign_id=context.scope.campaign_id,
            run_id=context.scope.run_id,
        )
    event_bus.publish(event.model_copy(update=updates) if updates else event)


def run_check(
    check: Check,
    target: Target,
    event_bus: EventPublisher | None = None,
    *,
    scope: EventScope | None = None,
) -> Observation:
    observation = target(check)
    if observation.check_id != check.check_id:
        raise ValueError(
            f"target returned observation for another check: "
            f"{observation.check_id}, expected {check.check_id}"
        )
    if observation.scenario_id != check.scenario_id:
        raise ValueError(
            f"target returned observation for another scenario: "
            f"{observation.scenario_id}, expected {check.scenario_id}"
        )

    observation = observation.model_copy(update={"probe_marker": check.probe_marker})
    if observation.trace is None:
        observation = observation.model_copy(
            update={
                "trace": ExecutionTrace(
                    steps=(
                        TraceStep(
                            observation_id=observation.observation_id,
                            step_id=check.check_id,
                            method_id=check.method_id,
                            scenario_id=check.scenario_id,
                            status=observation.observed_outcome,
                            request_fields=tuple(name for name, _ in check.request),
                            response=observation.output,
                        ),
                    )
                )
            }
        )

    if event_bus is not None:
        context = _event_context(event_bus, check.check_id)
        if scope is not None:
            context = _EventContext(
                scope=scope,
                action_id=context.action_id,
                path_id=context.path_id,
                step_id=context.step_id,
                oracle=context.oracle,
            )
        _publish(
            event_bus,
            CheckCompleted(
                check=check,
                method_id=check.method_id,
                observation=observation,
                correlation_id=check.check_id,
            ),
            context,
        )
        _publish(
            event_bus,
            CoverageUpdated(
                check_id=check.check_id,
                method_id=check.method_id,
                invariant_id=check.invariant_id,
                scenario_id=check.scenario_id,
                observation_id=observation.observation_id,
                correlation_id=check.check_id,
            ),
            context,
        )

    return observation


def run_probes(
    checks: Sequence[Check],
    target: Target,
    event_bus: EventPublisher | None,
    results: list[tuple[Check, Observation | None]],
    *,
    max_workers: int,
) -> Exception | None:
    """Collect successful probes in input order and retain the first error."""

    error: Exception | None = None
    try:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(checks))) as pool:
            futures = [
                pool.submit(run_check, check, target, event_bus) for check in checks
            ]
            for check, future in zip(checks, futures, strict=True):
                try:
                    results.append((check, future.result()))
                except Exception as failure:
                    if error is None:
                        error = failure
    except Exception as failure:
        # A pool shutdown failure must not replace an earlier probe error.
        return failure if error is None else error
    return error
