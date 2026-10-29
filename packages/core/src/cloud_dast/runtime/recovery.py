"""Deterministic recovery over the QDL execution view.

The clue graph is a run-local projection of runtime observations.  It never
creates executable truth: branch switching only selects another path already
derived from QDL, while alternative generation remains a grounding proposal.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from cloud_dast.contracts.execution import ObservationProvenance
from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model import (
    Observation,
    PolicyVerdict,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Struct, canonical_json
from cloud_dast.runtime.candidates.feedback import (
    goal_proximity,
    invariant_effect,
)
from cloud_dast.runtime.deficits import LATENCY_BASELINE_PREFIX

__all__ = [
    "Coordinator",
    "State",
    "BranchSelector",
    "BranchDecision",
    "BranchSelection",
    "ClueCache",
    "RecoveryAction",
    "Intent",
    "Reviewer",
    "Clue",
]


type BranchReason = Literal["clue_reuse", "sibling_goal"]
type RecoveryAction = Literal[
    "ground_alternatives",
    "reuse_clue",
    "switch_branch",
    "update_runtime_baseline",
]

_CLUE_PROXIMITY_THRESHOLD = 2.0 / 3.0
_CLUE_CACHE_CAPACITY = 256


@dataclass(frozen=True, slots=True)
class Clue:
    """One reusable runtime witness, projected from a QDL step effect."""

    effect_key: str
    action: str
    observation_id: str
    path_id: str | None
    step_id: str
    proximity: float


@dataclass(frozen=True, slots=True)
class BranchDecision:
    """The deterministic result of one recovery choice."""

    path_id: str
    reason: BranchReason
    blocked_path_id: str
    clue: Clue | None = None


@dataclass(frozen=True, slots=True)
class Intent:
    """A typed recovery action for one blocked or unscoreable step."""

    blocked_path_id: str
    step_id: str
    action: str
    recovery: RecoveryAction
    target: str | None
    clue_observation_id: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class BranchSelection:
    """Paths to schedule now and paths deferred by one deterministic switch."""

    paths: tuple[QdlExecutionPath, ...]
    remaining: tuple[QdlExecutionPath, ...]
    decision: BranchDecision | None
    recovery: Intent | None


@dataclass(slots=True)
class State:
    """Mutable evidence and recovery state for one recovery lifecycle."""

    clues: ClueCache
    blocked: tuple[tuple[QdlExecutionPath, QdlExecutionStep], ...] = ()
    recoveries: tuple[Intent, ...] = ()


class ClueCache:
    """Index recent runtime witnesses by effect shape."""

    def __init__(self) -> None:
        self._by_effect: dict[str, deque[Clue]] = {}
        self._seen: set[tuple[str, str, str]] = set()

    def record_step(
        self,
        step: QdlExecutionStep,
        observation: Observation,
        verdict: VerdictStatus,
    ) -> Clue | None:
        """Record one observation when it establishes the step's witness."""

        effect = invariant_effect(step.invariant)
        if effect is None:
            return None
        proximity = goal_proximity(effect, observation, verdict)
        if proximity < _CLUE_PROXIMITY_THRESHOLD:
            return None

        effect_key = _effect_key(effect)
        identity = (effect_key, step.method.method_id, observation.observation_id)
        if identity in self._seen:
            return None
        self._seen.add(identity)
        clue = Clue(
            effect_key=effect_key,
            action=step.method.method_id,
            observation_id=observation.observation_id,
            path_id=None,
            step_id=step.step_id,
            proximity=proximity,
        )
        clues = self._by_effect.setdefault(
            effect_key, deque(maxlen=_CLUE_CACHE_CAPACITY)
        )
        if len(clues) == _CLUE_CACHE_CAPACITY:
            oldest = clues[0]
            self._seen.discard(
                (oldest.effect_key, oldest.action, oldest.observation_id)
            )
        clues.append(clue)
        return clue

    def attach_path(self, clue: Clue, path_id: str) -> Clue:
        """Return the same clue with the path that produced its observation."""

        if clue.path_id == path_id:
            return clue
        attached = Clue(
            effect_key=clue.effect_key,
            action=clue.action,
            observation_id=clue.observation_id,
            path_id=path_id,
            step_id=clue.step_id,
            proximity=clue.proximity,
        )
        clues = self._by_effect.get(clue.effect_key)
        if clues is not None:
            for index, item in enumerate(clues):
                if item.observation_id == clue.observation_id:
                    clues[index] = attached
                    break
        return attached

    def find_clue(
        self,
        step: QdlExecutionStep,
        *,
        excluded_path_id: str | None = None,
    ) -> Clue | None:
        """Return the strongest reusable clue for one QDL effect."""

        effect = invariant_effect(step.invariant)
        if effect is None:
            return None
        clues = self._by_effect.get(_effect_key(effect))
        if clues is None:
            return None
        return min(
            (clue for clue in clues if clue.path_id != excluded_path_id),
            key=lambda clue: (-clue.proximity, clue.observation_id),
            default=None,
        )


class BranchSelector:
    """Select a QDL branch after a blocked AND-chain step."""

    def __init__(self, clues: ClueCache) -> None:
        self._clues = clues

    def select_branch(
        self,
        paths: Sequence[QdlExecutionPath],
        blocked_path: QdlExecutionPath,
        blocked_step: QdlExecutionStep,
        *,
        completed: Iterable[str] = (),
        blocked: Iterable[str] = (),
        in_flight: Iterable[str] = (),
    ) -> BranchDecision | None:
        """Return a deterministic sibling or clue-backed branch, if one exists."""

        eligible = _eligible_paths(
            paths,
            completed=completed,
            blocked=blocked,
            in_flight=in_flight,
        )
        if not eligible:
            return None

        clue = self._clues.find_clue(
            blocked_step,
            excluded_path_id=blocked_path.path_id,
        )
        if clue is not None:
            clue_paths = tuple(
                path for path in eligible if _path_needs_effect(path, blocked_step)
            )
            if clue_paths:
                selected = min(
                    clue_paths,
                    key=lambda path: (len(path.steps), path.path_id),
                )
                return BranchDecision(
                    path_id=selected.path_id,
                    reason="clue_reuse",
                    blocked_path_id=blocked_path.path_id,
                    clue=clue,
                )

        siblings = tuple(
            path for path in eligible if _path_has_sibling_goal(path, blocked_step)
        )
        if not siblings:
            return None
        selected = min(siblings, key=lambda path: (len(path.steps), path.path_id))
        return BranchDecision(
            path_id=selected.path_id,
            reason="sibling_goal",
            blocked_path_id=blocked_path.path_id,
        )


class Reviewer:
    """Turn a blocked or unscoreable step into one typed recovery action."""

    @staticmethod
    def review_blocked(
        path: QdlExecutionPath,
        step: QdlExecutionStep,
        clue: Clue | None,
        reason: str = "",
    ) -> Intent:
        """Recover a blocked path without rolling back runtime state."""

        if clue is not None:
            return Intent(
                blocked_path_id=path.path_id,
                step_id=step.step_id,
                action=step.method.method_id,
                recovery="reuse_clue",
                target=clue.observation_id,
                clue_observation_id=clue.observation_id,
                reason=reason,
            )
        return Intent(
            blocked_path_id=path.path_id,
            step_id=step.step_id,
            action=step.method.method_id,
            recovery="ground_alternatives",
            target=step.method.method_id,
            reason=reason,
        )

    @staticmethod
    def review_unscoreable(
        path: QdlExecutionPath,
        step: QdlExecutionStep,
        verdict: PolicyVerdict,
        clue: Clue | None,
    ) -> Intent:
        """Recover one unscoreable observation through graph-backed work."""

        if verdict.status is not VerdictStatus.UNSCOREABLE:
            raise ValueError("review_unscoreable requires an UNSCOREABLE verdict")
        if verdict.rationale.startswith(LATENCY_BASELINE_PREFIX):
            return Intent(
                blocked_path_id=path.path_id,
                step_id=step.step_id,
                action=step.method.method_id,
                recovery="update_runtime_baseline",
                target=step.method.method_id,
            )
        if clue is not None:
            return Intent(
                blocked_path_id=path.path_id,
                step_id=step.step_id,
                action=step.method.method_id,
                recovery="reuse_clue",
                target=clue.observation_id,
                clue_observation_id=clue.observation_id,
            )
        return Intent(
            blocked_path_id=path.path_id,
            step_id=step.step_id,
            action=step.method.method_id,
            recovery="ground_alternatives",
            target=step.method.method_id,
        )


class Coordinator:
    """Own the run-local clue projection and deterministic branch queue."""

    def __init__(self, state: State | None = None) -> None:
        self.state = state or State(clues=ClueCache())
        self._strategist = BranchSelector(self.state.clues)
        self._reviewer = Reviewer()

    @property
    def clue_cache(self) -> ClueCache:
        return self.state.clues

    def record_round(
        self,
        paths: Sequence[QdlExecutionPath],
        observations: Iterable[Observation],
        provenance: Mapping[tuple[str, str], ObservationProvenance],
        policy_verdicts: Mapping[tuple[str, str], PolicyVerdict],
        blocked_steps: Mapping[str, QdlExecutionStep],
        blocked_path_ids: Sequence[str],
        blocked_reasons: Mapping[str, str] | None = None,
    ) -> None:
        """Fold one execution round into clues and recovery intents."""

        paths_by_id = {path.path_id: path for path in paths}
        steps_by_id = {step.step_id: step for path in paths for step in path.steps}
        unscoreable: list[Intent] = []
        observations_by_id = {o.observation_id: o for o in observations}
        for evaluation_key, observation_provenance in provenance.items():
            observation = observations_by_id.get(evaluation_key[0])
            if observation is None:
                continue
            step = steps_by_id.get(observation_provenance.step_id)
            if step is None:
                continue
            verdict = policy_verdicts.get(evaluation_key)
            if verdict is None:
                continue
            clue = self.state.clues.record_step(
                step,
                observation,
                verdict.status,
            )
            if clue is not None:
                self.state.clues.attach_path(clue, observation_provenance.path_id)
            if verdict.status is VerdictStatus.UNSCOREABLE:
                path = paths_by_id.get(observation_provenance.path_id)
                if path is None:
                    continue
                reusable = self.state.clues.find_clue(
                    step,
                    excluded_path_id=path.path_id,
                )
                unscoreable.append(
                    self._reviewer.review_unscoreable(
                        path,
                        step,
                        verdict,
                        reusable,
                    )
                )

        blocked: list[tuple[QdlExecutionPath, QdlExecutionStep]] = []
        blocked_recoveries: list[Intent] = []
        for path_id in blocked_path_ids:
            path = paths_by_id.get(path_id)
            step = blocked_steps.get(path_id)
            if path is None or step is None:
                continue
            blocked.append((path, step))
            clue = self.state.clues.find_clue(
                step,
                excluded_path_id=path_id,
            )
            blocked_recoveries.append(
                self._reviewer.review_blocked(
                    path,
                    step,
                    clue,
                    reason=(blocked_reasons or {}).get(path_id, ""),
                )
            )

        self.state.blocked = tuple(blocked)
        self.state.recoveries = (*blocked_recoveries, *unscoreable)

    def recovery_intents(self) -> tuple[Intent, ...]:
        """Return recovery intents queued by the latest recorded round."""

        return self.state.recoveries

    def drain_recovery_intents(self) -> tuple[Intent, ...]:
        """Return and remove queued recovery intents.

        A caller must either execute an intent (for example by turning it
        into a deficit or a scheduled branch) or let this drain remove it.
        Recovery intents must not live only in a log line.
        """

        intents = self.state.recoveries
        self.state.recoveries = ()
        return intents

    def recovery_for(self, path_id: str) -> Intent | None:
        """Return the latest recovery intent for one blocked path."""

        return next(
            (
                intent
                for intent in self.state.recoveries
                if intent.blocked_path_id == path_id
            ),
            None,
        )

    def select_next_paths(
        self,
        paths: Sequence[QdlExecutionPath],
        *,
        completed: Iterable[str] = (),
        blocked: Iterable[str] = (),
        in_flight: Iterable[str] = (),
    ) -> BranchSelection:
        """Select one switch branch first and defer the remaining branches."""

        unique = _unique_paths(paths)
        for blocked_path, blocked_step in self.state.blocked:
            decision = self._strategist.select_branch(
                unique,
                blocked_path,
                blocked_step,
                completed=completed,
                blocked=blocked,
                in_flight=in_flight,
            )
            if decision is None:
                continue
            selected = next(path for path in unique if path.path_id == decision.path_id)
            remaining = tuple(
                path for path in unique if path.path_id != decision.path_id
            )
            recovery = Intent(
                blocked_path_id=blocked_path.path_id,
                step_id=blocked_step.step_id,
                action=blocked_step.method.method_id,
                recovery="switch_branch",
                target=selected.path_id,
                clue_observation_id=(
                    decision.clue.observation_id if decision.clue is not None else None
                ),
            )
            return BranchSelection(
                paths=(selected,),
                remaining=remaining,
                decision=decision,
                recovery=recovery,
            )
        return BranchSelection(
            paths=unique,
            remaining=(),
            decision=None,
            recovery=None,
        )


def _effect_key(effect: Struct) -> str:
    """Return the action-independent witness shape of a QDL effect."""

    if len(effect.args) <= 1:
        return effect.name
    return canonical_json(effect.args[1:])


def _eligible_paths(
    paths: Sequence[QdlExecutionPath],
    *,
    completed: Iterable[str],
    blocked: Iterable[str],
    in_flight: Iterable[str],
) -> tuple[QdlExecutionPath, ...]:
    excluded = {*completed, *blocked, *in_flight}
    return tuple(
        path
        for path in _unique_paths(paths)
        if path.steps and path.path_id not in excluded
    )


def _unique_paths(paths: Sequence[QdlExecutionPath]) -> tuple[QdlExecutionPath, ...]:
    unique: list[QdlExecutionPath] = []
    seen: set[str] = set()
    for path in paths:
        if path.path_id in seen:
            continue
        seen.add(path.path_id)
        unique.append(path)
    return tuple(unique)


def _path_needs_effect(
    path: QdlExecutionPath,
    blocked_step: QdlExecutionStep,
) -> bool:
    blocked_effect = invariant_effect(blocked_step.invariant)
    if blocked_effect is None:
        return False
    needed_key = _effect_key(blocked_effect)
    return any(
        (effect := invariant_effect(step.invariant)) is not None
        and _effect_key(effect) == needed_key
        for step in path.steps
    )


def _path_has_sibling_goal(
    path: QdlExecutionPath,
    blocked_step: QdlExecutionStep,
) -> bool:
    blocked_effect = invariant_effect(blocked_step.invariant)
    if blocked_effect is None:
        return False
    return any(
        (effect := invariant_effect(step.invariant)) is not None
        and effect.name == blocked_effect.name
        and step.method.method_id != blocked_step.method.method_id
        for step in path.steps
    )
