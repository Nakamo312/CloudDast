"""A bounded adaptive fuzz session for one QDL execution step."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4

from cloud_dast.candidates import goal_key, refresh_probe_marker
from cloud_dast.contracts.feedback import (
    ExecutionFeedback,
    ExecutionFeedbackEntry,
)
from cloud_dast.contracts.finding_examples import load_finding_examples
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.extensions import (
    GeneratorPolicy,
    SeedEnrichmentHook,
    TestCaseGenerator,
)
from cloud_dast.model import (
    Check,
    MethodSpec,
    Observation,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.ports import FindingExampleStore, Guardrail
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing.history import (
    SaturatedHistory,
    build_saturated_history,
)

FuzzStopReason = Literal["budget", "entropy", "guardrail", "exhausted"]


@dataclass(slots=True)
class FuzzSessionState:
    """Mutable progress state for one local fuzz session."""

    emitted: int = 0
    failures: int = 0
    passes: int = 0
    unscoreable: int = 0
    repeated: int = 0
    reward: float = 0.0
    best_proximity: float = 0.0
    signatures: set[tuple[object, ...]] = field(default_factory=set)
    stop_reason: FuzzStopReason | None = None
    entropy_events: int = 0
    enrichments: int = 0

    @property
    def stopped(self) -> bool:
        return self.stop_reason is not None


class FuzzSession:
    """Generate bounded, adaptive candidates for one executable QDL step.

    The session is deliberately independent from transport.  A caller asks for
    the next allowed check, executes it, and reports the verdict.  Strategy
    selection is delegated to an injected strategy policy, while the local
    state tracks budget, reward, repeated-candidate entropy, and a bounded
    Check/Observation history for feedback-aware generators.
    A FAIL is a witness, not a stop signal: different payloads may expose
    different root causes, so only budget, entropy, or guardrails stop the
    local session.
    """

    def __init__(
        self,
        *,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        generators: Mapping[str, TestCaseGenerator],
        policy: GeneratorPolicy,
        guardrail: Guardrail,
        max_checks: int = 8,
        max_repeats: int = 3,
        max_feedback_history: int = 8,
        example_database: FindingExampleStore | None = None,
        seed_enrichment: SeedEnrichmentHook | None = None,
        max_enrichments: int = 1,
        max_saturated_candidates: int = 16,
    ) -> None:
        if not generators:
            raise ValueError("fuzz session requires at least one generator")
        if max_checks <= 0:
            raise ValueError("max_checks must be positive")
        if max_repeats <= 0:
            raise ValueError("max_repeats must be positive")
        if max_feedback_history <= 0:
            raise ValueError("max_feedback_history must be positive")
        if max_enrichments <= 0:
            raise ValueError("max_enrichments must be positive")
        if max_saturated_candidates <= 0:
            raise ValueError("max_saturated_candidates must be positive")

        self._plan = plan
        self._method = method
        self._invariant = invariant
        self._scenario = scenario
        self._generators = dict(generators)
        self._policy = policy
        self._guardrail = guardrail
        self._max_checks = max_checks
        self._max_repeats = max_repeats
        self._max_feedback_history = max_feedback_history
        self._example_database = example_database
        self._seed_enrichment = seed_enrichment
        self._max_enrichments = max_enrichments
        self._max_saturated_candidates = max_saturated_candidates
        self._state = FuzzSessionState()
        self._goal_key = goal_key(invariant)
        self._current_strategy: str | None = None
        self._current_check: Check | None = None
        self._preview: deque[tuple[Check, str]] = deque()
        self._pending: dict[str, list[Check]] = {}
        for example in self._replay_checks():
            self._preview.append((example, "replay"))
        self._generated: set[str] = set()
        self._history: list[ExecutionFeedbackEntry] = []
        self._candidate_history: deque[Check] = deque(
            maxlen=self._max_saturated_candidates
        )
        self._feedback_strategies = frozenset(
            strategy
            for strategy, generator in self._generators.items()
            if getattr(generator, "uses_feedback", False)
        )

    @property
    def state(self) -> FuzzSessionState:
        return self._state

    @property
    def stopped(self) -> bool:
        return self._state.stopped

    @property
    def stop_reason(self) -> FuzzStopReason | None:
        return self._state.stop_reason

    @property
    def current_strategy(self) -> str | None:
        """Strategy that emitted the candidate awaiting ``record``."""

        return self._current_strategy

    @property
    def feedback(self) -> ExecutionFeedback:
        """Return the bounded execution history passed to adaptive generators."""

        return ExecutionFeedback(entries=tuple(self._history))

    def _replay_checks(self) -> tuple[Check, ...]:
        """Load prior minimal examples before any newly generated candidate."""

        if self._example_database is None:
            return ()
        examples = load_finding_examples(
            self._example_database,
            method_id=self._method.method_id,
            invariant_id=self._invariant.invariant_id,
            scenario_id=self._scenario.scenario_id,
        )
        return tuple(
            refresh_probe_marker(
                example.model_copy(
                    update={
                        "check_id": uuid4().hex,
                        "generator": "fuzzing",
                    }
                )
            )
            for example in examples
        )

    def saturated_history(self) -> SaturatedHistory:
        """Return the bounded history supplied only at an entropy point."""

        return build_saturated_history(
            plan=self._plan,
            method=self._method,
            invariant=self._invariant,
            scenario=self._scenario,
            candidates=tuple(self._candidate_history),
            feedback=self.feedback,
        )

    def preview(self) -> Check | None:
        """Return the next candidate without spending a fuzz slot.

        Prefilters need a concrete seed before live execution, but that seed
        must not consume the adaptive budget.  Previewed candidates are queued
        and returned by the next ``next()`` call, which is the only operation
        that charges the local fuzz budget.
        """

        if self.stopped:
            return None

        previewed = {
            _signature(check, self._scenario) for check, _strategy in self._preview
        }
        remaining = set(self._generators)
        while remaining:
            strategy = self._policy.choose(
                tuple(sorted(remaining)),
                goal_key=self._goal_key,
                action_id=self._method.method_id,
            )
            remaining.discard(strategy)
            if strategy not in self._generated:
                self._pending[strategy] = list(
                    self._generators[strategy].generate(
                        self._plan,
                        self._method,
                        self._invariant,
                        self._scenario,
                        feedback=self.feedback or None,
                    )
                )
                self._generated.add(strategy)
            for check in self._pending.get(strategy, []):
                if not self._guardrail.allows(check):
                    continue
                signature = _signature(check, self._scenario)
                if signature in self._state.signatures or signature in previewed:
                    continue
                self._preview.append((check, strategy))
                return check
        return None

    def next(self) -> Check | None:
        """Return the next novel, guardrail-allowed candidate."""

        if self.stopped:
            return None

        if self._preview:
            check, strategy = self._preview.popleft()
            self._state.signatures.add(_signature(check, self._scenario))
            self._state.emitted += 1
            self._current_strategy = strategy
            self._current_check = check
            self._candidate_history.append(check)
            self._check_budget()
            return check

        strategies = tuple(sorted(self._generators))
        while not self.stopped:
            strategy = self._policy.choose(
                strategies,
                goal_key=self._goal_key,
                action_id=self._method.method_id,
            )
            if strategy not in self._generated:
                self._pending[strategy] = list(
                    self._generators[strategy].generate(
                        self._plan,
                        self._method,
                        self._invariant,
                        self._scenario,
                        feedback=self.feedback or None,
                    )
                )
                self._generated.add(strategy)
            checks = self._pending.get(strategy, [])
            for check in checks:
                if not self._guardrail.allows(check):
                    continue
                signature = _signature(check, self._scenario)
                if signature in self._state.signatures:
                    continue
                self._state.signatures.add(signature)
                self._state.emitted += 1
                self._current_strategy = strategy
                self._current_check = check
                self._candidate_history.append(check)
                self._check_budget()
                return check
            self._pending.pop(strategy, None)
            self._state.repeated += 1
            if self._state.repeated >= self._max_repeats:
                self._state.entropy_events += 1
                if self._try_seed_enrichment():
                    continue
                self._state.stop_reason = "entropy"
                return None

        return None

    def record(
        self,
        check: Check,
        verdict: VerdictStatus,
        *,
        grounded: bool = True,
        proximity: float | None = None,
        observation: Observation | None = None,
        solver_prefiltered: bool = False,
    ) -> None:
        """Record one grounded verdict and the goal-proximity grade.

        The session reward keeps its verdict emphasis (FAIL 3.0, PASS 1.0);
        unscoreable outcomes now earn their deterministic proximity instead
        of nothing.  The bandit arm reward is the Sefz graded signal: a
        trace that approaches the witness pattern steers strategy selection
        even before a full violation is observed.  When an observation is
        supplied, its full response and trace/resource state also become
        bounded generator feedback for the next candidate.

        An ungrounded FAIL is an unverified violation claim, not progress:
        it is recorded as an unscoreable outcome with zero proximity, so it
        can grow neither the session reward nor the bandit credit.

        ``solver_prefiltered`` marks an executed check whose concrete request
        values were replaced by the symbolic prefilter.  Its identity must still
        match the candidate emitted by ``next()``; only request values may differ.
        """

        if self._current_strategy is None:
            raise ValueError("record requires a candidate from next()")
        if self._current_check is None or not _is_recordable_check(
            check,
            self._current_check,
            solver_prefiltered=solver_prefiltered,
        ):
            raise ValueError("record requires the candidate returned by next()")
        if observation is not None and not _is_recordable_observation(
            check,
            observation,
        ):
            raise ValueError("observation does not belong to the recorded check")

        if not grounded and verdict is VerdictStatus.FAIL:
            verdict = VerdictStatus.UNSCOREABLE
            proximity = 0.0 if proximity is not None else None

        scoreable = grounded and verdict in {VerdictStatus.PASS, VerdictStatus.FAIL}
        violation = scoreable and verdict is VerdictStatus.FAIL
        effective_proximity = (
            1.0
            if violation
            else min(1.0, max(0.0, proximity))
            if proximity is not None
            else None
        )
        if violation:
            self._state.best_proximity = max(self._state.best_proximity, 1.0)
        elif effective_proximity is not None:
            self._state.best_proximity = max(
                self._state.best_proximity,
                effective_proximity,
            )
        if not scoreable:
            self._state.unscoreable += 1
            if effective_proximity is not None:
                self._state.reward += effective_proximity
        elif verdict is VerdictStatus.FAIL:
            self._state.failures += 1
            self._state.reward += 3.0
        else:
            self._state.passes += 1
            self._state.reward += 1.0

        if self._current_strategy == "replay":
            pass
        elif proximity is not None:
            arm_reward = (
                1.0
                if scoreable and verdict is VerdictStatus.FAIL
                else effective_proximity * (1.0 if scoreable else 0.5)
            )
            self._policy.update(
                self._current_strategy,
                arm_reward,
                goal_key=self._goal_key,
                action_id=self._method.method_id,
                verdict=verdict,
            )
        elif scoreable:
            self._policy.update(
                self._current_strategy,
                1.0 if verdict is VerdictStatus.FAIL else 0.0,
                goal_key=self._goal_key,
                action_id=self._method.method_id,
                verdict=verdict,
            )

        if observation is not None:
            self._record_feedback(
                check,
                observation,
                verdict,
                grounded=grounded,
                proximity=effective_proximity,
            )

        self._check_budget()

    def _record_feedback(
        self,
        check: Check,
        observation: Observation,
        verdict: VerdictStatus,
        *,
        grounded: bool,
        proximity: float | None,
    ) -> None:
        self._history.append(
            ExecutionFeedbackEntry(
                check=check,
                observation=observation,
                verdict=verdict,
                grounded=grounded,
                proximity=proximity,
            )
        )
        if len(self._history) > self._max_feedback_history:
            del self._history[: len(self._history) - self._max_feedback_history]

        # A batch generated before an execution is stale for feedback-aware
        # generators.  Keep legacy generators' one-batch behavior unchanged.
        for strategy in self._feedback_strategies:
            self._pending.pop(strategy, None)
            self._generated.discard(strategy)

    def _check_budget(self) -> None:
        if self._state.emitted >= self._max_checks:
            self._state.stop_reason = "budget"

    def _try_seed_enrichment(self) -> bool:
        """Run the model only once per saturation point, then resume generation."""

        if (
            self._seed_enrichment is None
            or self._state.enrichments >= self._max_enrichments
        ):
            return False
        result = self._seed_enrichment.enrich(self.saturated_history())
        self._state.enrichments += 1
        if not result.continued or result.additional_checks <= 0:
            return False

        # The enriched corpus is compiled by deterministic generators on their
        # next batch.  Existing batches and previews intentionally remain
        # deduplicated against every already-tried signature.
        self._max_checks += result.additional_checks
        self._state.repeated = 0
        self._state.stop_reason = None
        self._pending.clear()
        self._generated.clear()
        self._preview.clear()
        return True


def _signature(check: Check, scenario: ScenarioPosition) -> tuple[object, ...]:
    """Fingerprint one candidate together with its scenario identity state.

    ``Check.identities`` alone is not a reliable identity discriminant:
    generators may emit a fixed identity while the stand varies, so principal
    and binding tuples keep variants that differ only in identity wiring from
    being collapsed by session deduplication.
    """
    return (
        check.method_id,
        check.scenario_id,
        check.request,
        check.identities,
        check.probe_marker,
        scenario.stand.principals,
        scenario.stand.bindings,
    )


def _is_recordable_check(
    executed: Check,
    candidate: Check,
    *,
    solver_prefiltered: bool = False,
) -> bool:
    """Accept an executed copy of the candidate emitted by ``next``.

    Transport execution may fill missing request fields from earlier response
    output.  It must not replace an already supplied value, identity, or check
    identity; otherwise the verdict belongs to another candidate.
    """

    if (
        executed.check_id != candidate.check_id
        or executed.invariant_id != candidate.invariant_id
        or executed.method_id != candidate.method_id
        or executed.scenario_id != candidate.scenario_id
        or executed.identities != candidate.identities
        or executed.probe_marker != candidate.probe_marker
    ):
        return False

    candidate_values = dict(candidate.request)
    executed_values = dict(executed.request)
    if not set(candidate_values).issubset(executed_values):
        return False
    if solver_prefiltered:
        return True
    for name, candidate_value in candidate_values.items():
        executed_value = executed_values[name]
        if executed_value == candidate_value:
            continue
        if candidate_value is not None:
            return False
    return True


def _is_recordable_observation(check: Check, observation: Observation) -> bool:
    """Reject feedback that would pair a request with another execution."""

    return (
        observation.check_id == check.check_id
        and observation.scenario_id == check.scenario_id
    )
