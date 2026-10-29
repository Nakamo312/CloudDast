from __future__ import annotations

import random
from collections.abc import Mapping
from types import MappingProxyType

from river import bandit, proba

from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.extensions import GeneratorPolicy, TestCaseGenerator
from cloud_dast.model import (
    Check,
    MethodSpec,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast_fuzzing.strategies.optional import (
    OmitOptionalFieldGenerator,
)

DEFAULT_GOAL_KEY = "generic"
OMIT_OPTIONAL_FIELD_STRATEGY = "omit_optional_field"


class GeneratorBandit:
    """River selector over (goal × strategy) arms with graded rewards.

    Arms are namespaced by goal key so the policy learns which mutation
    family works for which violation class — the Sefz operator×goal
    combination — instead of keeping one global strategy ranking.

    River's Beta distribution counts boolean outcomes. Map a clamped reward r
    to a Bernoulli trial B with P(B=1)=r, so E[B]=r instead of bool(r).
    River owns the Beta(1, 1) prior, posterior updates (alpha += B,
    beta += 1-B), and Thompson sampling. After n observations the expected
    posterior mean is (1 + sum(r)) / (2 + n). This unbiased mapping adds
    quantization noise for fractional rewards; endpoints remain exact.
    """

    def __init__(self, *, seed: int = 0) -> None:
        self._policy = bandit.ThompsonSampling(
            reward_obj=proba.Beta(alpha=1, beta=1),
            seed=seed,
        )
        self._reward_rng = random.Random(seed)

    @staticmethod
    def arm_name(strategy: str, goal_key: str = DEFAULT_GOAL_KEY) -> str:
        return f"{goal_key}:{strategy}"

    def choose(
        self,
        strategies: tuple[str, ...],
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
    ) -> str:
        if not strategies:
            raise ValueError("generator bandit requires at least one strategy")
        arms = [self.arm_name(strategy, goal_key) for strategy in strategies]
        arm = self._policy.pull(arms)
        return arm[len(goal_key) + 1 :]

    def update(
        self,
        strategy: str,
        reward: float,
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
        verdict: VerdictStatus | None = None,
    ) -> None:
        """Record one graded reward in [0, 1] for a goal-scoped arm.

        ``action_id`` and ``verdict`` are accepted for interface
        compatibility with :class:`FailingStrategyFilter`; the base bandit
        ignores them.
        """

        reward = min(1.0, max(0.0, float(reward)))
        self._policy.update(
            self.arm_name(strategy, goal_key), self._reward_rng.random() < reward
        )


class FailingStrategyFilter:
    """Per-action failure filter around the generator bandit.

    For each action and strategy, this keeps only the trailing count of
    unscoreable/error outcomes and temporarily excludes saturated arms. The
    base bandit still handles exploration/exploitation among the remaining
    strategies.

    This is the PrediQL contribution: execution memory feeds back into
    generator selection, so the fuzzer learns "template keeps failing for
    this action — try symbolic instead" without a human tuning anything.
    """

    def __init__(
        self,
        base: GeneratorPolicy,
        *,
        max_consecutive_failures: int = 2,
    ) -> None:
        if max_consecutive_failures <= 0:
            raise ValueError("max_consecutive_failures must be positive")
        self._base = base
        self._max_consecutive = max_consecutive_failures
        self._failure_counts: dict[tuple[str, str], int] = {}

    @property
    def base(self) -> GeneratorPolicy:
        """The wrapped base bandit (for direct access in tests)."""
        return self._base

    def choose(
        self,
        strategies: tuple[str, ...],
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
    ) -> str:
        """Choose a strategy, filtering out recently-failing ones.

        When ``action_id`` is provided and the action has recorded
        consecutive unscoreable outcomes for a strategy, that strategy
        is temporarily excluded. If ALL strategies are excluded, the
        filter is lifted to avoid deadlock.
        """
        if not strategies:
            raise ValueError("generator bandit requires at least one strategy")
        if action_id is None:
            return self._base.choose(strategies, goal_key=goal_key)

        allowed = tuple(
            strategy
            for strategy in strategies
            if self._consecutive_failures(action_id, strategy) < self._max_consecutive
        )
        if not allowed:
            # All strategies have consecutive failures — lift the filter
            # rather than deadlock; the base bandit will still learn.
            allowed = strategies

        return self._base.choose(allowed, goal_key=goal_key)

    def update(
        self,
        strategy: str,
        reward: float,
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
        verdict: VerdictStatus | None = None,
    ) -> None:
        """Update the base bandit and the trailing per-action failure state."""

        self._base.update(strategy, reward, goal_key=goal_key)
        if action_id is not None and verdict is not None:
            key = (action_id, strategy)
            if verdict in {VerdictStatus.UNSCOREABLE, VerdictStatus.ERROR}:
                self._failure_counts[key] = min(
                    self._failure_counts.get(key, 0) + 1,
                    self._max_consecutive,
                )
            else:
                self._failure_counts.pop(key, None)

    def _consecutive_failures(
        self,
        action_id: str,
        strategy: str,
    ) -> int:
        """Count trailing unscoreable/error outcomes for a strategy."""
        return self._failure_counts.get((action_id, strategy), 0)


class GeneratorSelector:
    """Resolve the generator strategy named by a verification plan.

    The generic optional-field omission strategy is derived from the template
    seed generator (or the first injected generator when no template exists),
    so every selector exposes the same contract-driven strategy without
    duplicating composition wiring.
    """

    def __init__(
        self,
        generators: Mapping[str, TestCaseGenerator],
        default: str = "template",
        policy: GeneratorPolicy | None = None,
    ) -> None:
        if not generators:
            raise ValueError("at least one generator is required")
        self._generators = _with_generic_strategies(generators)
        if default not in self._generators and not (
            default == "adaptive" and policy is not None
        ):
            raise ValueError(f"unknown default generator: {default}")
        self._default = default
        self._policy = policy

    @property
    def default(self) -> str:
        return self._default

    @property
    def strategies(self) -> tuple[str, ...]:
        return tuple(sorted(self._generators))

    @property
    def generators(self) -> Mapping[str, TestCaseGenerator]:
        """Return the injected generators for adaptive fuzz sessions."""

        return MappingProxyType(self._generators)

    def select(
        self,
        strategy: str | None = None,
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
    ) -> TestCaseGenerator:
        name = self._default if strategy is None else strategy
        if name == "adaptive":
            if self._policy is None:
                raise ValueError("adaptive generator selection requires a policy")
            name = self._policy.choose(
                self.strategies,
                goal_key=goal_key,
                action_id=action_id,
            )
        try:
            return self._generators[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._generators))
            raise ValueError(
                f"unknown generator strategy {name!r}; available: {available}"
            ) from exc

    def update(
        self,
        strategy: str,
        verdict: object,
        *,
        goal_key: str = DEFAULT_GOAL_KEY,
        action_id: str | None = None,
    ) -> None:
        if self._policy is not None:
            name = getattr(verdict, "value", verdict)
            if name not in {"pass", "fail"}:
                return
            self._policy.update(
                strategy,
                1.0 if name == "fail" else 0.0,
                goal_key=goal_key,
                action_id=action_id,
            )

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        return self.select(
            plan.generator,
            action_id=method.method_id,
        ).generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )


def _with_generic_strategies(
    generators: Mapping[str, TestCaseGenerator],
) -> dict[str, TestCaseGenerator]:
    result = dict(generators)
    if OMIT_OPTIONAL_FIELD_STRATEGY in result:
        return result
    base = result.get("template")
    if base is None:
        base = next(iter(result.values()))
    result[OMIT_OPTIONAL_FIELD_STRATEGY] = OmitOptionalFieldGenerator(base)
    return result
