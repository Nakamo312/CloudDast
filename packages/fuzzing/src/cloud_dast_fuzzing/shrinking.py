"""Bounded live-call shrinking for deterministic finding witnesses."""

from __future__ import annotations

import json

from cloud_dast.candidates import refresh_probe_marker
from cloud_dast.contracts.candidate_metrics import request_complexity
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.extensions import RequestSolver, ShrinkResult
from cloud_dast.model import (
    Check,
    JsonValue,
    MethodSpec,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing.corpus import PayloadCorpusCompiler
from cloud_dast_fuzzing.strategies.grammar import (
    build_simpler_check,
    compile_plan_grammar,
)

MAX_SHRINK_STEPS = 10


class FindingShrinker:
    """Minimize a failing request through the plan's Hypothesis strategy.

    Hypothesis ``find`` supplies each candidate and minimizes terminals and
    repeated values. The caller executes every returned candidate as a live
    call and reports only the cheap deterministic witness signal.
    """

    def __init__(
        self,
        *,
        seed: Check,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        max_steps: int = MAX_SHRINK_STEPS,
        request_solver: RequestSolver | None = None,
    ) -> None:
        if max_steps <= 0 or max_steps > MAX_SHRINK_STEPS:
            raise ValueError(f"max_steps must be between 1 and {MAX_SHRINK_STEPS}")
        self._current = seed
        self._method = method
        self._grammar = compile_plan_grammar(
            plan,
            method,
            invariant,
            payload_compiler=PayloadCorpusCompiler(),
            request_solver=request_solver,
        )
        self._max_steps = max_steps
        self._steps = 0
        self._pending: Check | None = None
        self._rejected = {seed.request}
        self._rejected_examples: set[str] = set()

    @property
    def result(self) -> ShrinkResult:
        return ShrinkResult(check=self._current, steps=self._steps)

    @property
    def exhausted(self) -> bool:
        return self._steps >= self._max_steps

    def next(self) -> Check | None:
        """Return the next simpler candidate, or ``None`` when exhausted."""

        if self._pending is not None or self.exhausted:
            return None

        current_complexity = request_complexity(self._current.request)
        while True:
            candidate = build_simpler_check(
                self._current,
                self._grammar,
                method=self._method,
                max_complexity=current_complexity - 1,
                exclude=self._rejected_examples,
            )
            if candidate is None:
                return None
            example_key = _request_key(dict(candidate.request))
            if (
                candidate.request in self._rejected
                or request_complexity(candidate.request) >= current_complexity
            ):
                self._rejected_examples.add(example_key)
                continue
            self._rejected_examples.add(example_key)
            self._pending = candidate
            return refresh_probe_marker(candidate)

    def record(self, check: Check, *, reproduced: bool) -> None:
        """Record the live witness outcome of the pending candidate."""

        if self._pending is None or check.check_id != self._pending.check_id:
            raise ValueError("record requires the candidate returned by next()")
        if reproduced:
            self._current = check
            self._rejected = {check.request}
            self._rejected_examples = set()
        else:
            self._rejected.add(check.request)
        self._pending = None
        self._steps += 1

    def discard(self, check: Check) -> None:
        """Discard a candidate that never reached the transport boundary."""

        if self._pending is None or check.check_id != self._pending.check_id:
            raise ValueError("discard requires the candidate returned by next()")
        self._rejected.add(check.request)
        self._rejected_examples.add(_request_key(dict(check.request)))
        self._pending = None


def _request_key(request: dict[str, JsonValue]) -> str:
    return json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


__all__ = ["FindingShrinker", "MAX_SHRINK_STEPS"]
