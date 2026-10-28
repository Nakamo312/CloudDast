"""Hypothesis-backed structural fuzzing for seed checks."""

from __future__ import annotations

from cloud_dast.binding import validate_binding
from cloud_dast.contracts.grammar import GrammarFacts
from cloud_dast.couplings import (
    couplings_for_method,
)
from cloud_dast.extensions import (
    ExecutionFeedback,
    PayloadStrategyCompiler,
    RequestSolver,
    TestCaseGenerator,
    VerificationPlan,
)
from cloud_dast.model import (
    Check,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing.strategies.grammar import (
    GrammarCompiler,
    build_checks_from_grammar,
)

_DEFAULT_CANDIDATES = 4


class FuzzingGenerator:
    """Generate schema-valid alternatives with Hypothesis shrinking.

    This is the structural layer of the grammar engine.  Sink-aware payload
    grammars are compiled by :class:`GrammarGenerator`; this strategy keeps
    transport schema constraints and Z3 couplings without hand-written
    mutation operators.
    """

    def __init__(
        self,
        seed_generator: TestCaseGenerator,
        *,
        max_candidates: int = _DEFAULT_CANDIDATES,
        payload_compiler: PayloadStrategyCompiler | None = None,
        request_solver: RequestSolver | None = None,
    ) -> None:
        self._seed_generator = seed_generator
        self._max_candidates = max_candidates
        self._payload_compiler = payload_compiler
        self._request_solver = request_solver

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        validate_binding(plan, method, invariant, scenario)
        compiled = GrammarCompiler(
            self._payload_compiler,
            self._request_solver,
        ).compile(
            method,
            GrammarFacts(),
            couplings=couplings_for_method(plan.couplings, method.method_id),
        )
        checks: list[Check] = []
        seen: set[tuple[tuple[tuple[str, object], ...], tuple[str, ...]]] = set()
        for seed in self._seed_generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        ):
            for candidate in build_checks_from_grammar(
                seed,
                method,
                compiled,
                generator="fuzzing",
                count=self._max_candidates,
            ):
                key = (candidate.request, candidate.identities)
                if key in seen:
                    continue
                seen.add(key)
                checks.append(candidate)
        return tuple(checks)
