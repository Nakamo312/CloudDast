from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from cloud_dast.config import OOB_PROBE_TIMEOUT_SECONDS
from cloud_dast.model import VerdictStatus
from cloud_dast.ports import EvidenceChannel, EvidenceEvent
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    action_alignment_rationale,
)
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict
from cloud_dast.verification.oracles.trace import ObservationTrace

_MAX_PENDING_EVALUATIONS = 10_000


@dataclass(frozen=True, slots=True)
class _PendingEvaluation:
    invariant: InvariantProjection
    trace: ObservationTrace
    method_id: str | None


class OobOracle:
    """Primitive P3: verify an asynchronous collaborator callback."""

    def __init__(
        self,
        events: EvidenceChannel,
        *,
        wait_seconds: float = OOB_PROBE_TIMEOUT_SECONDS,
        allowed_sources: Sequence[str] = (),
        adversarial_target: bool = False,
        clock: Callable[[], float] = time.monotonic,
        pending_capacity: int = _MAX_PENDING_EVALUATIONS,
    ) -> None:
        if wait_seconds < 0:
            raise ValueError("wait_seconds must not be negative")
        if pending_capacity <= 0:
            raise ValueError("pending_capacity must be positive")
        try:
            self._allowed_sources = tuple(
                ip_network(source, strict=False) for source in allowed_sources
            )
        except ValueError as error:
            raise ValueError(
                "allowed OOB sources must be IP addresses or networks"
            ) from error
        self._events = events
        self._wait_seconds = wait_seconds
        self._adversarial_target = adversarial_target
        self._clock = clock
        self._pending_capacity = pending_capacity
        self._pending_lock = threading.Lock()
        self._pending: OrderedDict[str, _PendingEvaluation] = OrderedDict()

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        norm = NormView.from_invariant(invariant)
        if norm is None or norm.primitive != "oob_event":
            return self._unscoreable("invariant is not an oob-event QDL norm")
        mismatch = action_alignment_rationale(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        marker = trace[-1].probe_marker if trace else None
        if not marker:
            return self._unscoreable(
                "out-of-band observation has no non-empty candidate probe marker"
            )

        event = self._events.wait_for(marker, 0.0, channel="oob")
        if event is not None:
            return self._event_verdict(trace, event)

        blocked_reason = self._events.blocked_reason()
        if blocked_reason is not None:
            return self._unscoreable(
                f"out-of-band channel is blocked: {blocked_reason}"
            )
        if not self._events.ready():
            return self._unscoreable("out-of-band listener is not ready")

        event = self._events.wait_for(marker, self._wait_seconds, channel="oob")
        if event is not None:
            return self._event_verdict(trace, event)
        self._remember_pending(marker, invariant, trace, method_id)
        return self._unscoreable(
            "no out-of-band callback arrived within "
            f"{self._wait_seconds} seconds; timeout is negative evidence, "
            "not a grounded pass, and a late callback can be re-evaluated"
        )

    def observe(self, marker: str) -> EvidenceEvent | None:
        """Return an already-arrived callback without waiting or scoring."""

        if not marker:
            return None
        return self._events.wait_for(marker, 0.0, channel="oob")

    def reevaluate(self, marker: str, *, timeout: float = 0.0) -> PolicyVerdict | None:
        """Re-evaluate one timed-out candidate by its unique marker."""

        if timeout < 0:
            raise ValueError("timeout must not be negative")
        pending = self._pending_marker(marker)
        if pending is None:
            return None
        event = self._events.wait_for(marker, timeout, channel="oob")
        if event is None:
            return None
        return self.evaluate_policy(
            pending.invariant,
            pending.trace,
            method_id=pending.method_id,
        )

    def reevaluate_pending(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, PolicyVerdict]:
        """Sweep timed-out candidates after asynchronous evidence may arrive.

        The optional timeout is one shared deadline for the whole sweep, not a
        per-marker delay.  Verdicts are keyed by the pending observation id so
        a campaign can replace its earlier UNSCOREABLE policy verdict.
        """

        selected_timeout = self._wait_seconds if timeout is None else timeout
        if selected_timeout < 0:
            raise ValueError("timeout must not be negative")
        pending_items = self._pending_items()
        if not pending_items:
            return {}
        deadline = self._clock() + selected_timeout
        verdicts: dict[str, PolicyVerdict] = {}
        for marker, pending in pending_items:
            event = self._events.wait_for(marker, 0.0, channel="oob")
            if event is None and self._events.blocked_reason() is None:
                remaining = deadline - self._clock()
                if remaining > 0:
                    event = self._events.wait_for(
                        marker,
                        remaining,
                        channel="oob",
                    )
            if event is None:
                continue
            verdict = self.evaluate_policy(
                pending.invariant,
                pending.trace,
                method_id=pending.method_id,
            )
            observation_id = (
                pending.trace[-1].observation_id if pending.trace else marker
            )
            verdicts[observation_id] = verdict
        return verdicts

    @staticmethod
    def _verified(
        trace: ObservationTrace,
        event: EvidenceEvent,
    ) -> PolicyVerdict:
        evidence = (
            (trace[-1].observation_id, event.event_id) if trace else (event.event_id,)
        )
        return PolicyVerdict(
            status=VerdictStatus.FAIL,
            confidence=1.0,
            rationale=(
                f"out-of-band callback received for marker "
                f"{event.correlation_id!r} from {event.source or 'unknown source'}"
            ),
            evidence_refs=evidence,
            model_id="oob",
            deterministic=True,
            grounded=True,
        )

    def _source_rationale(self, event: EvidenceEvent) -> str | None:
        if not event.source:
            return "out-of-band callback has no source address"
        try:
            address = ip_address(event.source)
        except ValueError:
            return (
                f"out-of-band callback source {event.source!r} is not a "
                "valid IP address"
            )
        if address.is_unspecified or address.is_multicast:
            return (
                f"out-of-band callback source {event.source!r} is not a "
                "usable unicast address"
            )
        if self._allowed_sources and not any(
            address in network for network in self._allowed_sources
        ):
            return (
                f"out-of-band callback source {event.source!r} is not in "
                "the allowed source policy"
            )
        return None

    def _event_verdict(
        self,
        trace: ObservationTrace,
        event: EvidenceEvent,
    ) -> PolicyVerdict:
        self._forget_pending(event.correlation_id)
        source_error = self._source_rationale(event)
        if source_error is not None:
            return self._unscoreable(source_error)
        if self._adversarial_target:
            return self._unscoreable(
                "adversarial target policy does not trust an out-of-band "
                "callback as deterministic sink evidence"
            )
        return self._verified(trace, event)

    def _remember_pending(
        self,
        marker: str,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        method_id: str | None,
    ) -> None:
        pending = _PendingEvaluation(
            invariant=invariant,
            trace=trace,
            method_id=method_id,
        )
        with self._pending_lock:
            if (
                len(self._pending) >= self._pending_capacity
                and marker not in self._pending
            ):
                self._pending.popitem(last=False)
            self._pending[marker] = pending
            self._pending.move_to_end(marker)

    def _forget_pending(self, marker: str) -> None:
        with self._pending_lock:
            self._pending.pop(marker, None)

    def _pending_marker(self, marker: str) -> _PendingEvaluation | None:
        with self._pending_lock:
            return self._pending.get(marker)

    def _pending_items(
        self,
    ) -> tuple[tuple[str, _PendingEvaluation], ...]:
        with self._pending_lock:
            return tuple(self._pending.items())

    @staticmethod
    def _unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="oob",
            deterministic=True,
            grounded=False,
        )
