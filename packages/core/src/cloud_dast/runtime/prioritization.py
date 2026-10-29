"""Pure deterministic prioritization for runtime work items."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_COLD_SCORE_FEATURES = frozenset({"coverage_gain", "bandit_prior", "reward_state"})
_SEED_DIGEST_SPACE = 1_000_000


@dataclass(frozen=True, slots=True)
class ColdScore:
    """Deterministic advisory interest score for one executable work item."""

    work_item_id: str
    coverage_gain: int
    bandit_prior: float
    reward_state: float
    interest: float
    seed: int
    seed_digest: int
    quarantined_features: frozenset[str] = frozenset()

    @property
    def rank(self) -> tuple[float, int, str]:
        """Return the score-only ordering key (higher interest first)."""

        return (-self.interest, self.seed_digest, self.work_item_id)


class InterestPrioritizer:
    """Combine coverage, prior, and reward into a deterministic cold score.

    The score is an advisory feature for the deterministic scheduler. It does
    not call a model, issue a verdict, or own the final path decision. A
    quarantined feature is replaced by its neutral value, so an untrusted
    runtime signal cannot raise or lower interest.
    """

    def __init__(self, *, seed: int = 0) -> None:
        self._seed = seed

    @property
    def seed(self) -> int:
        return self._seed

    def score(
        self,
        work_item_id: str,
        *,
        coverage_gain: int,
        bandit_prior: float,
        reward_state: float,
        quarantined_features: frozenset[str] = frozenset(),
    ) -> ColdScore:
        """Return the seeded score for one work item.

        ``seed == 0`` disables tie-break jitter and preserves identifier
        order. Non-zero seeds derive a stable digest from the seed and work
        item identifier; the digest never changes the feature values.
        """

        if not work_item_id:
            raise ValueError("work item identifier must not be empty")
        if coverage_gain < 0:
            raise ValueError("coverage gain must not be negative")
        if not 0.0 <= bandit_prior <= 1.0:
            raise ValueError("bandit prior must be in [0, 1]")
        if not 0.0 <= reward_state <= 1.0:
            raise ValueError("reward state must be in [0, 1]")
        unknown_features = quarantined_features - _COLD_SCORE_FEATURES
        if unknown_features:
            raise ValueError(
                "unknown cold-score feature(s): " + ", ".join(sorted(unknown_features))
            )

        effective_prior = (
            0.0 if "bandit_prior" in quarantined_features else bandit_prior
        )
        effective_reward = (
            0.0 if "reward_state" in quarantined_features else reward_state
        )
        effective_coverage = (
            0 if "coverage_gain" in quarantined_features else coverage_gain
        )
        interest = (
            (effective_coverage + 1)
            * (1.0 + effective_prior)
            * (1.0 + effective_reward)
        )
        return ColdScore(
            work_item_id=work_item_id,
            coverage_gain=coverage_gain,
            bandit_prior=bandit_prior,
            reward_state=reward_state,
            interest=interest,
            seed=self._seed,
            seed_digest=self._seed_digest(work_item_id),
            quarantined_features=frozenset(quarantined_features),
        )

    def _seed_digest(self, work_item_id: str) -> int:
        if self._seed == 0:
            return 0
        payload = f"{self._seed}:{work_item_id}".encode()
        digest = hashlib.blake2b(payload, digest_size=8).digest()
        return int.from_bytes(digest, "big") % _SEED_DIGEST_SPACE


__all__ = ["ColdScore", "InterestPrioritizer"]
