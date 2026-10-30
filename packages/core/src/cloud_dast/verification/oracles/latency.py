from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from statistics import median

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Observation,
    PolicyVerdict,
    VerdictStatus,
)
from cloud_dast.model.events import normalize_action
from cloud_dast.qdl.graph import Atom, Context, Struct
from cloud_dast.verification.oracles.action_alignment import (
    explain_mismatch,
)
from cloud_dast.verification.oracles.trace import ObservationTrace

_TIMEOUT_REASON_MARKERS = (
    "timed out",
    "timeout expired",
    "deadline exceeded",
)


@dataclass(frozen=True, slots=True)
class LatencyBaseline:
    """Runtime latency norm for one method."""

    method_id: str
    median_ms: float
    mad_ms: float
    threshold_ms: float
    samples: int
    paired: bool = False

    @classmethod
    def from_durations(
        cls,
        method_id: str,
        durations: Sequence[float],
        *,
        min_samples: int = 3,
    ) -> LatencyBaseline:
        values = tuple(float(value) for value in durations if value >= 0)
        if len(values) < min_samples:
            raise ValueError(
                f"latency baseline for {method_id} requires {min_samples} samples"
            )
        center = median(values)
        deviation = median(tuple(abs(value - center) for value in values))
        spread = max(3.0 * deviation, 0.1 * center, 1.0)
        return cls(
            method_id=method_id,
            median_ms=center,
            mad_ms=deviation,
            threshold_ms=center + spread,
            samples=len(values),
        )

    @classmethod
    def from_paired_durations(
        cls,
        method_id: str,
        pairs: Sequence[tuple[float, float]],
        *,
        min_pairs: int = 3,
    ) -> LatencyBaseline:
        """Build a baseline from paired control/probe duration deltas."""

        deltas = tuple(_paired_delta(pair) for pair in pairs)
        if len(deltas) < min_pairs:
            raise ValueError(
                f"paired latency baseline for {method_id} requires {min_pairs} pairs"
            )
        center = median(deltas)
        deviation = median(tuple(abs(delta - center) for delta in deltas))
        spread = max(3.0 * deviation, 0.1 * abs(center), 1.0)
        return cls(
            method_id=method_id,
            median_ms=center,
            mad_ms=deviation,
            threshold_ms=center + spread,
            samples=len(deltas),
            paired=True,
        )


@dataclass(frozen=True, slots=True)
class _LatencyNorm:
    action_id: str | None
    duration_ms: float | None


@dataclass(frozen=True, slots=True)
class _PairedLatencyEvidence:
    observation: Observation
    controls: tuple[Observation, ...]
    control_ms: float
    delta_ms: float
    exceeded: bool


def collect_delivered_durations(
    observations: Sequence[Observation],
) -> tuple[float, ...]:
    """Return durations only from response-bearing observations.

    A delivered error response is valid timing evidence, while an unobservable
    transport failure is not. Explicit timeouts are handled by
    ``AvailabilityOracle`` instead of contaminating the latency baseline.
    """

    return tuple(
        observation.duration_ms
        for observation in _delivered_duration_observations(observations)
    )


class AvailabilityOracle:
    """Score an explicit transport timeout against the configured deadline."""

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        norm = _parse_latency_norm(invariant)
        if norm is None:
            return self._unscoreable("invariant is not a latency-bound QDL norm")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        if norm.action_id is None or norm.duration_ms is None:
            return self._unscoreable("latency-bound QDL norm is incomplete")
        if not trace:
            return self._unscoreable("latency-bound QDL norm has no observation")

        observation = trace[-1]
        if not _is_explicit_timeout(observation):
            return self._unscoreable("observation is not an explicit transport timeout")
        if observation.duration_ms is None:
            return self._unscoreable("explicit timeout has no duration")
        if observation.duration_ms < norm.duration_ms:
            return self._unscoreable(
                "explicit timeout occurred before the configured deadline "
                f"{norm.duration_ms:.3f} ms"
            )

        return PolicyVerdict(
            status=VerdictStatus.FAIL,
            confidence=0.9,
            rationale=(
                f"explicit timeout after {observation.duration_ms:.3f} ms "
                f"reached configured deadline {norm.duration_ms:.3f} ms"
            ),
            evidence_refs=(observation.observation_id,),
            model_id="availability",
            deterministic=True,
            grounded=True,
        )

    @staticmethod
    def _unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="availability",
            deterministic=True,
            grounded=False,
        )


class LatencyOracle:
    """Primitive P4: score abnormal response latency against a runtime baseline."""

    def __init__(
        self,
        baselines: Mapping[str, LatencyBaseline] | None = None,
        *,
        availability_oracle: AvailabilityOracle | None = None,
        adversarial_target: bool = False,
    ) -> None:
        self._baselines = dict(baselines or {})
        self._availability = availability_oracle or AvailabilityOracle()
        self._adversarial_target = adversarial_target

    @property
    def baselines(self) -> Mapping[str, LatencyBaseline]:
        return self._baselines

    def has_baseline(self, action_id: str) -> bool:
        """Whether a runtime baseline is available for one action."""

        return normalize_action(action_id) in self._baselines

    def update_baseline(
        self,
        action_id: str,
        delivered_durations_ms: Sequence[float],
        *,
        min_samples: int = 3,
    ) -> None:
        """Build a runtime baseline from already-delivered durations."""

        if min_samples < 1:
            raise ValueError("latency baseline min_samples must be positive")
        if len(delivered_durations_ms) < min_samples:
            return
        normalized = normalize_action(action_id)
        baseline = LatencyBaseline.from_durations(
            normalized,
            delivered_durations_ms,
            min_samples=min_samples,
        )
        self._baselines[normalized] = baseline

    def update_paired_baseline(
        self,
        action_id: str,
        paired_durations: Sequence[tuple[float, float]],
    ) -> None:
        """Build a paired control/probe baseline for one action."""

        if len(paired_durations) < 3:
            return
        normalized = normalize_action(action_id)
        baseline = LatencyBaseline.from_paired_durations(
            normalized,
            paired_durations,
        )
        self._baselines[normalized] = baseline

    def update_baseline_from_observations(
        self,
        action_id: str,
        observations: Sequence[Observation],
        *,
        min_samples: int = 3,
    ) -> bool:
        """Build a runtime baseline using only delivered observations."""

        durations = collect_delivered_durations(observations)
        if len(durations) < min_samples:
            return False
        self.update_baseline(action_id, durations, min_samples=min_samples)
        return True

    def evaluate_pair(
        self,
        invariant: InvariantProjection,
        control: Observation,
        treatment: Observation,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        """Score one explicit control/treatment timing witness.

        The method keeps pair construction at the caller so grammar and workflow
        code cannot accidentally turn an arbitrary two-observation trace into a
        paired witness.  Scoring semantics remain identical to
        :meth:`evaluate_policy`.
        """

        return self.evaluate_policy(
            invariant,
            (control, treatment),
            method_id=method_id,
        )

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        norm = _parse_latency_norm(invariant)
        if norm is None:
            return self._unscoreable("invariant is not a latency-bound QDL norm")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        if norm.action_id is None or norm.duration_ms is None:
            return self._unscoreable("latency-bound QDL norm is incomplete")
        if not trace:
            return self._unscoreable("latency-bound QDL norm has no observation")

        if _is_explicit_timeout(trace[-1]):
            return self._availability.evaluate_policy(
                invariant,
                trace,
                method_id=method_id,
            )
        duration_observations = _delivered_duration_observations(trace)
        observation = (
            max(
                duration_observations,
                key=lambda candidate: (
                    candidate.duration_ms if candidate.duration_ms is not None else 0.0
                ),
            )
            if duration_observations
            else trace[-1]
        )
        if not _is_delivered(observation):
            return self._unscoreable(
                "latency observation has no delivered response and is not "
                "policy evidence"
            )
        if observation.duration_ms is None:
            return self._unscoreable("observation has no duration")
        if self._adversarial_target:
            return self._unscoreable(
                "adversarial target policy does not trust target-controlled "
                "duration evidence"
            )
        baseline = self._baselines.get(normalize_action(norm.action_id))
        if baseline is None:
            return self._unscoreable(
                f"no runtime latency baseline for method {norm.action_id}"
            )

        if baseline.paired:
            evidence = _worst_paired_latency(
                trace,
                threshold_ms=baseline.threshold_ms,
                deadline_ms=norm.duration_ms,
            )
            if evidence is None:
                return self._unscoreable(
                    "paired latency baseline has no delivered control observation"
                )
            observation = evidence.observation
            controls = evidence.controls
            control_ms = evidence.control_ms
            paired_delta = evidence.delta_ms
            exceeded = evidence.exceeded
            return PolicyVerdict(
                status=VerdictStatus.FAIL if exceeded else VerdictStatus.PASS,
                confidence=0.9,
                rationale=(
                    f"worst-case duration {observation.duration_ms:.3f} ms is "
                    f"{paired_delta:.3f} ms above paired control "
                    f"{control_ms:.3f} ms and "
                    f"{'exceeds' if exceeded else 'is within'} paired "
                    f"threshold {baseline.threshold_ms:.3f} ms and configured "
                    f"deadline {norm.duration_ms:.3f} ms "
                    f"({baseline.samples} paired samples)"
                ),
                evidence_refs=(
                    observation.observation_id,
                    *(control.observation_id for control in controls),
                ),
                model_id="latency",
                negative_scope=(
                    (
                        "delivered_duration",
                        "paired_control_duration",
                        "runtime_baseline",
                    )
                    if not exceeded
                    else ()
                ),
                deterministic=True,
                grounded=True,
            )

        threshold = baseline.threshold_ms
        exceeded = observation.duration_ms > threshold
        return PolicyVerdict(
            status=VerdictStatus.FAIL if exceeded else VerdictStatus.PASS,
            confidence=0.9,
            rationale=(
                f"worst-case duration {observation.duration_ms:.3f} ms "
                f"{'exceeds' if exceeded else 'is within'} threshold "
                f"{threshold:.3f} ms from runtime baseline "
                f"({baseline.samples} samples)"
            ),
            evidence_refs=(observation.observation_id,),
            model_id="latency",
            negative_scope=(
                ("delivered_duration", "runtime_baseline") if not exceeded else ()
            ),
            deterministic=True,
            grounded=True,
        )

    @staticmethod
    def _unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="latency",
            deterministic=True,
            grounded=False,
        )


def _paired_delta(pair: tuple[float, float]) -> float:
    if len(pair) != 2:
        raise ValueError("paired latency sample requires control and probe durations")
    control, probe = pair
    if not isfinite(control) or not isfinite(probe) or control < 0 or probe < 0:
        raise ValueError("paired latency durations must be finite non-negative numbers")
    return float(probe) - float(control)


def _parse_latency_norm(invariant: InvariantProjection) -> _LatencyNorm | None:
    fact = invariant.norm_fact
    if (
        fact is None
        or fact.context is not Context.ACCEPTED
        or fact.predicate.name != "prevents"
        or len(fact.args) != 2
    ):
        return None

    effect = fact.args[1]
    if not isinstance(effect, Struct) or effect.name != "duration":
        return None
    if len(effect.args) != 2:
        return None

    action = effect.args[0]
    duration = effect.args[1]
    action_id = (
        action.value
        if isinstance(action, Atom) and isinstance(action.value, str)
        else None
    )
    duration_ms = (
        float(duration.value)
        if isinstance(duration, Atom) and isinstance(duration.value, int)
        else None
    )
    return _LatencyNorm(action_id=action_id, duration_ms=duration_ms)


def _is_delivered(observation: Observation) -> bool:
    if observation.observed_outcome is AccessOutcome.UNKNOWN:
        return False
    status = observation.transport_status
    if observation.auth_failed or (status is not None and status.is_auth_failure()):
        return False
    if observation.observed_outcome is AccessOutcome.ERROR:
        return _has_response_payload(observation)
    return True


def _delivered_control_observations(
    observations: Sequence[Observation],
) -> tuple[Observation, ...]:
    return tuple(
        observation
        for observation in observations
        if (
            observation.duration_ms is not None
            and not observation.probe_marker
            and _is_delivered(observation)
            and not _is_explicit_timeout(observation)
        )
    )


def _delivered_duration_observations(
    observations: Sequence[Observation],
) -> tuple[Observation, ...]:
    return tuple(
        observation
        for observation in observations
        if (
            observation.duration_ms is not None
            and _is_delivered(observation)
            and not _is_explicit_timeout(observation)
        )
    )


def _worst_paired_latency(
    trace: Sequence[Observation],
    *,
    threshold_ms: float,
    deadline_ms: float,
) -> _PairedLatencyEvidence | None:
    worst: _PairedLatencyEvidence | None = None
    for index, treatment in enumerate(trace):
        if index == 0:
            continue
        if (
            treatment.duration_ms is None
            or not _is_delivered(treatment)
            or _is_explicit_timeout(treatment)
        ):
            continue
        controls = _delivered_control_observations(trace[:index])
        if not controls:
            continue
        control_ms = median(
            tuple(
                control.duration_ms
                for control in controls
                if control.duration_ms is not None
            )
        )
        delta_ms = treatment.duration_ms - control_ms
        exceeded = delta_ms > threshold_ms and treatment.duration_ms > deadline_ms
        evidence = _PairedLatencyEvidence(
            observation=treatment,
            controls=controls,
            control_ms=control_ms,
            delta_ms=delta_ms,
            exceeded=exceeded,
        )
        if worst is None or (
            (evidence.exceeded and not worst.exceeded)
            or (
                evidence.exceeded == worst.exceeded
                and evidence.delta_ms > worst.delta_ms
            )
        ):
            worst = evidence
    return worst


def _has_response_payload(observation: Observation) -> bool:
    return (
        observation.output is not None
        or bool(observation.response_tree)
        or observation.response_digest is not None
    )


def _is_explicit_timeout(observation: Observation) -> bool:
    if observation.observed_outcome not in {
        AccessOutcome.ERROR,
        AccessOutcome.UNKNOWN,
    }:
        return False

    reason = (observation.error_reason or "").casefold()
    if any(marker in reason for marker in _TIMEOUT_REASON_MARKERS):
        return True

    # A status-only timeout without response payload (HTTP 504, gRPC
    # DEADLINE_EXCEEDED) is transport noise. A delivered HTTP 504 response
    # retains a response digest/tree and remains latency evidence instead.
    status = observation.transport_status
    return (
        status is not None
        and status.is_timeout()
        and not _has_response_payload(observation)
    )
