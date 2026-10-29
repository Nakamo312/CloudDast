"""State and identity values owned by coverage scheduling."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.runtime.prioritization import ColdScore

logger = logging.getLogger("cloud_dast.runtime.scheduler")
_RETRY_REWARD_THRESHOLD = 0.1
_MAX_RETRIES = 2

PathOutcome = str


@dataclass(frozen=True, order=True, slots=True)
class CoverageKey:
    """One executable action/effect/primitive coverage cell."""

    action_id: str
    effect: str
    witness: str
    primitive: str
    effect_name: str


@dataclass(slots=True)
class State:
    """Mutable selection state for one campaign execution."""

    completed: set[str] = field(default_factory=set)
    blocked: set[str] = field(default_factory=set)
    superseded: set[str] = field(default_factory=set)
    in_flight: set[str] = field(default_factory=set)
    outcomes: dict[str, PathOutcome] = field(default_factory=dict)
    terminal_reasons: dict[str, str] = field(default_factory=dict)
    evidence_signatures: dict[str, str | None] = field(default_factory=dict)
    selections: list[str] = field(default_factory=list)
    attempts: dict[str, int] = field(default_factory=dict)
    progress: dict[str, float] = field(default_factory=dict)
    covered: set[CoverageKey] = field(default_factory=set)
    canonical_attempts: dict[CoverageKey, int] = field(default_factory=dict)
    prewarmed: set[str] = field(default_factory=set)
    latency_bootstrap_paths: set[str] = field(default_factory=set)
    latency_bootstrapped_paths: set[str] = field(default_factory=set)
    latency_bootstrap_actions: set[str] = field(default_factory=set)
    effect_selections: dict[str, int] = field(default_factory=dict)
    primitive_selections: dict[str, int] = field(default_factory=dict)
    action_selections: dict[str, int] = field(default_factory=dict)
    action_primitive_selections: dict[tuple[str, str], int] = field(
        default_factory=dict
    )
    action_outcomes: set[str] = field(default_factory=set)
    actions_without_outcome: set[str] = field(default_factory=set)
    action_allowed: set[str] = field(default_factory=set)
    cold_scores: dict[str, ColdScore] = field(default_factory=dict)
    effect_reward_totals: dict[str, float] = field(default_factory=dict)
    effect_reward_counts: dict[str, int] = field(default_factory=dict)
    quarantined_features: dict[str, frozenset[str]] = field(default_factory=dict)
    quarantined_rewards: int = 0

    released_latency_actions: set[str] = field(default_factory=set)

    def record_outcome(
        self,
        path_id: str,
        outcome: PathOutcome,
        paths: Callable[[], Sequence[QdlExecutionPath]],
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
        *,
        attempted_keys: Callable[[], set[CoverageKey]],
        reward: float | None = None,
        trusted: bool = True,
        remaining: Callable[[], int],
    ) -> PathOutcome:
        """Apply an attempt without renewing canonical-cell retry budgets.

        Resolve attempted keys after releasing flight and charging the path;
        count each cell once. Only trusted rewards update priors. Partial
        progress permits bounded retries; bootstrap paths retain their
        separate one-sample baseline permission. Read remaining work only
        at the original logging points.
        """
        reward = self._prepare_reward(path_id, outcome, reward, trusted)
        was_latency_bootstrap = self._record_attempt(
            path_id,
            attempted_keys,
            reward,
            trusted,
            path_keys,
        )
        if outcome in ("completed", "goal_reached"):
            return self._complete(path_id, outcome)

        if self.exhausted(path_id, path_keys):
            self._block_exhausted(path_id)
            if not was_latency_bootstrap:
                self._block_neighbors(path_id, paths, path_keys)
            return "blocked"

        if outcome == "blocked" and (
            (
                reward > _RETRY_REWARD_THRESHOLD
                and not self.exhausted(path_id, path_keys)
            )
            or was_latency_bootstrap
        ):
            # Non-terminal: bounded retry work remains eligible under the
            # deterministic coverage order.  A bootstrap path stays prewarmed
            # until its delivered response creates the missing baseline.
            return self._retry(path_id, reward, remaining)

        return self._record_terminal(
            path_id, outcome, was_latency_bootstrap, paths, path_keys, remaining
        )

    def _prepare_reward(
        self,
        path_id: str,
        outcome: PathOutcome,
        reward: float | None,
        trusted: bool,
    ) -> float:
        if reward is None:
            reward = 1.0 if outcome in ("completed", "goal_reached") else 0.0
        if trusted:
            self.quarantined_features.pop(path_id, None)
            return reward
        self.quarantined_features[path_id] = frozenset({"reward_state"})
        self.quarantined_rewards += 1
        logger.warning(
            "scheduler_reward_quarantined path=%s outcome=%s",
            path_id,
            outcome,
        )
        return 0.0

    def _record_attempt(
        self,
        path_id: str,
        attempted_keys: Callable[[], set[CoverageKey]],
        reward: float,
        trusted: bool,
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
    ) -> bool:
        was_bootstrap = path_id in self.latency_bootstrap_paths
        self.in_flight.discard(path_id)
        if was_bootstrap:
            self.latency_bootstrap_paths.discard(path_id)
            self.latency_bootstrapped_paths.add(path_id)
        self.attempts[path_id] = self.attempts.get(path_id, 0) + 1
        keys = attempted_keys()
        for key in keys:
            self.canonical_attempts[key] = self.canonical_attempts.get(key, 0) + 1
        self.progress[path_id] = max(self.progress.get(path_id, 0.0), reward)
        if trusted:
            self._record_effect_reward(path_id, reward, path_keys)
        return was_bootstrap

    def _complete(self, path_id: str, outcome: PathOutcome) -> PathOutcome:
        self.completed.add(path_id)
        self.outcomes[path_id] = outcome
        return outcome

    def _block_exhausted(self, path_id: str) -> None:
        self._block(path_id, "canonical coverage retry budget exhausted")

    def _retry(
        self, path_id: str, reward: float, remaining: Callable[[], int]
    ) -> PathOutcome:
        self.outcomes[path_id] = "retryable"
        logger.info(
            "scheduler_path_retryable path=%s attempts=%d reward=%.3f remaining=%d",
            path_id,
            self.attempts[path_id],
            reward,
            remaining(),
        )
        return "retryable"

    def _record_terminal(
        self,
        path_id: str,
        outcome: PathOutcome,
        was_latency_bootstrap: bool,
        paths: Callable[[], Sequence[QdlExecutionPath]],
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
        remaining: Callable[[], int],
    ) -> PathOutcome:
        self.outcomes[path_id] = outcome
        if outcome != "blocked":
            return outcome
        self.blocked.add(path_id)
        if not was_latency_bootstrap:
            self._block_neighbors(path_id, paths, path_keys)
        logger.info(
            "scheduler_path_blocked path=%s remaining=%d",
            path_id,
            remaining(),
        )
        return outcome

    def _record_effect_reward(
        self,
        path_id: str,
        reward: float,
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
    ) -> None:
        for effect_name in {key.effect_name for key in path_keys.get(path_id, ())}:
            self.effect_reward_totals[effect_name] = (
                self.effect_reward_totals.get(effect_name, 0.0) + reward
            )
            self.effect_reward_counts[effect_name] = (
                self.effect_reward_counts.get(effect_name, 0) + 1
            )

    def exhausted(
        self, path_id: str, path_keys: Mapping[str, tuple[CoverageKey, ...]]
    ) -> bool:
        return any(
            self.canonical_attempts.get(key, 0) > _MAX_RETRIES
            for key in path_keys.get(path_id, ())
        )

    def _block_neighbors(
        self,
        path_id: str,
        paths: Callable[[], Sequence[QdlExecutionPath]],
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
    ) -> None:
        exhausted = {
            key
            for key in path_keys.get(path_id, ())
            if self.canonical_attempts.get(key, 0) > _MAX_RETRIES
        }
        if not exhausted:
            return
        protected = self.completed | self.superseded | self.in_flight
        for path in paths():
            if path.path_id in protected or not exhausted.intersection(
                path_keys.get(path.path_id, ())
            ):
                continue
            self._block(
                path.path_id,
                "canonical coverage neighbor blocked after retry budget exhaustion",
            )
            self.prewarmed.discard(path.path_id)

    def select(
        self, path_id: str, path_keys: Mapping[str, tuple[CoverageKey, ...]]
    ) -> None:
        """Record one selection in every canonical coverage dimension."""

        self.in_flight.add(path_id)
        self.selections.append(path_id)
        keys = set(path_keys.get(path_id, ()))
        self.covered.update(keys)
        self.action_outcomes.update(
            key.action_id for key in keys if key.primitive == "outcome"
        )
        self.action_allowed.update(
            key.action_id for key in keys if key.effect_name == "allowed"
        )
        self.actions_without_outcome.update(
            key.action_id for key in keys if key.primitive != "outcome"
        )
        for key in keys:
            self.effect_selections[key.effect_name] = (
                self.effect_selections.get(key.effect_name, 0) + 1
            )
            self.primitive_selections[key.primitive] = (
                self.primitive_selections.get(key.primitive, 0) + 1
            )
            self.action_selections[key.action_id] = (
                self.action_selections.get(key.action_id, 0) + 1
            )
            action_primitive = (key.action_id, key.primitive)
            self.action_primitive_selections[action_primitive] = (
                self.action_primitive_selections.get(action_primitive, 0) + 1
            )

    def eligible(
        self, path: QdlExecutionPath, path_keys: Mapping[str, tuple[CoverageKey, ...]]
    ) -> bool:
        return (
            path.path_id not in self.completed
            and path.path_id not in self.blocked
            and path.path_id not in self.superseded
            and path.path_id not in self.in_flight
            and (
                path.path_id not in self.prewarmed
                or path.path_id in self.latency_bootstrap_paths
            )
            and not self.exhausted(path.path_id, path_keys)
        )

    def reopen(
        self, path_id: str, path_keys: Mapping[str, tuple[CoverageKey, ...]]
    ) -> bool:
        """Invalidate a terminal decision without renewing execution budgets."""

        if (
            path_id in self.superseded
            or path_id in self.in_flight
            or self.exhausted(path_id, path_keys)
        ):
            return False
        self.completed.discard(path_id)
        self.blocked.discard(path_id)
        self.outcomes.pop(path_id, None)
        self.terminal_reasons.pop(path_id, None)
        return True

    def retire(
        self, replacements: Mapping[str, str], paths: Sequence[QdlExecutionPath]
    ) -> int:
        """Retire executable path versions while retaining their history."""

        known = {path.path_id for path in paths}
        superseded = 0
        for old_path_id, replacement_id in sorted(replacements.items()):
            if old_path_id == replacement_id or old_path_id not in known:
                continue
            if old_path_id in self.in_flight:
                raise RuntimeError(f"cannot supersede in-flight path {old_path_id!r}")
            self.superseded.add(old_path_id)
            self.in_flight.discard(old_path_id)
            self.prewarmed.discard(old_path_id)
            self.latency_bootstrap_paths.discard(old_path_id)
            self.terminal_reasons[old_path_id] = (
                f"superseded by QDL path {replacement_id}"
            )
            superseded += 1
        if superseded:
            logger.info("scheduler_paths_superseded count=%d", superseded)
        return superseded

    def block_prerequisite(self, path_id: str, reason: str) -> None:
        """Park an unexecutable path without charging probe retries."""

        self.in_flight.discard(path_id)
        self.prewarmed.discard(path_id)
        self.blocked.add(path_id)
        self.outcomes[path_id] = "blocked"
        self.terminal_reasons[path_id] = reason

    def block_remaining(
        self,
        paths: Sequence[QdlExecutionPath],
        path_keys: Mapping[str, tuple[CoverageKey, ...]],
    ) -> tuple[str, ...]:
        """Mark every eligible path blocked without selecting it."""

        path_ids = tuple(
            path.path_id for path in paths if self.eligible(path, path_keys)
        )
        for path_id in path_ids:
            self._block(
                path_id, "campaign check budget exhausted before path execution"
            )
        return path_ids

    def _block(self, path_id: str, reason: str) -> None:
        self.outcomes[path_id] = "blocked"
        self.blocked.add(path_id)
        self.terminal_reasons[path_id] = reason

    def record_score(self, path_id: str, score: ColdScore) -> None:
        self.cold_scores[path_id] = score

    def remember_evidence(self, path_id: str, signature: str | None) -> None:
        self.evidence_signatures[path_id] = signature

    def forget_evidence(self, path_id: str) -> None:
        self.evidence_signatures.pop(path_id, None)

    def hold(self, path_id: str, waiting: bool) -> None:
        if waiting:
            self.prewarmed.add(path_id)
        else:
            self.prewarmed.discard(path_id)

    def bootstrap(self, path_id: str, action: str) -> None:
        self.latency_bootstrap_actions.add(action)
        self.latency_bootstrap_paths.add(path_id)

    def release_unattempted(self) -> int:
        """Release reserve-deferred paths without changing attempt history."""
        deferred = [
            path_id for path_id in self.blocked if not self.attempts.get(path_id)
        ]
        for path_id in deferred:
            self.blocked.discard(path_id)
            self.outcomes.pop(path_id, None)
        return len(deferred)

    def release_latency(
        self,
        actions: set[str],
        paths: Sequence[QdlExecutionPath],
        latency_actions: Callable[[QdlExecutionPath], tuple[str, ...]],
    ) -> None:
        for path in paths:
            if path.path_id not in self.latency_bootstrapped_paths:
                continue
            if path.path_id not in self.blocked:
                continue
            if any(action in actions for action in latency_actions(path)):
                self.blocked.discard(path.path_id)
                self.outcomes.pop(path.path_id, None)
        self.released_latency_actions.update(actions)
        self.latency_bootstrap_actions.difference_update(actions)
        affected = {
            path.path_id
            for path in paths
            if any(action in actions for action in latency_actions(path))
        }
        self.latency_bootstrap_paths.difference_update(affected)
        self.latency_bootstrapped_paths.difference_update(affected)


__all__ = ["CoverageKey", "PathOutcome", "State"]
