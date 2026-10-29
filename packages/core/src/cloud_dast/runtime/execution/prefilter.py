"""Whole-path symbolic candidate prefiltering."""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.couplings import normalise_action
from cloud_dast.extensions import FuzzSession, SymbolicPrefilter
from cloud_dast.model import Check
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    DomainEvent,
    DownstreamDecision,
    EventScope,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.runtime.candidates.session import (
    _prefilter_input_completeness,
    _prefilter_input_digest,
)
from cloud_dast.runtime.execution.contracts import PrefilterResult


class SymbolicPathPrefilter:
    """Generate and solve one candidate sequence before live path execution."""

    def __init__(
        self,
        *,
        symbolic_prefilter: SymbolicPrefilter | None,
        preview_path: Callable[
            ...,
            tuple[
                tuple[FuzzSession | None, ...],
                tuple[Check, ...],
            ]
            | None,
        ],
        generate_checks: Callable[[QdlExecutionStep], tuple[Check, ...]],
        publish: Callable[[DomainEvent, EventScope | None], None],
    ) -> None:
        self._symbolic_prefilter = symbolic_prefilter
        self._preview_path = preview_path
        self._generate_checks = generate_checks
        self._publish = publish

    def run(
        self,
        path: QdlExecutionPath,
        *,
        scope: EventScope | None,
    ) -> PrefilterResult | None:
        """Return the solved path candidates, or no prefilter decision."""

        if self._symbolic_prefilter is None or not _has_cross_action_couplings(path):
            return None
        candidates = self._preview_path(
            path,
            generate_checks=self._generate_checks,
        )
        if candidates is None:
            return None
        sessions, seeds = candidates
        steps = tuple(path.steps)
        input_completeness = _prefilter_input_completeness(steps)
        fallback_modes = tuple(
            mode
            for mode, count in (
                ("unconstrained", input_completeness["constraints"]),
                ("no_couplings", input_completeness["couplings"]),
            )
            if count == 0
        )
        invocation_id = f"{path.path_id}:symbolic_prefilter"
        self._publish(
            ComponentInvoked(
                component="symbolic_prefilter",
                input_digest=_prefilter_input_digest(steps),
                input_completeness=input_completeness,
                fallback_modes=fallback_modes,
                invocation_id=invocation_id,
                path_id=path.path_id,
            ),
            scope,
        )
        solution = self._symbolic_prefilter.prefilter_sequence(
            seeds,
            tuple((step.plan, step.method) for step in path.steps),
        )
        survived = solution.status != "unsat"
        self._publish(
            ComponentOutput(
                component="symbolic_prefilter",
                summary={
                    "candidates_produced": len(seeds),
                    "candidates_survived_prefilter": len(solution.checks)
                    if survived
                    else 0,
                    "candidates_survived_guardrail": len(seeds),
                    "scored": int(survived),
                },
                invocation_id=invocation_id,
                path_id=path.path_id,
            ),
            scope,
        )
        self._publish(
            DownstreamDecision(
                component="symbolic_prefilter",
                consumed=survived,
                by="path_runner",
                outcome=solution.status,
                invocation_id=invocation_id,
                path_id=path.path_id,
            ),
            scope,
        )
        return PrefilterResult(
            seeds=seeds,
            checks=solution.checks,
            sessions=sessions,
            status=solution.status,
        )


def _has_cross_action_couplings(path: QdlExecutionPath) -> bool:
    return any(
        normalise_action(atom_value(left.args[0]))
        != normalise_action(atom_value(right.args[0]))
        for step in path.steps
        for left, right, _operator in step.plan.couplings
    )


__all__ = ["SymbolicPathPrefilter"]
