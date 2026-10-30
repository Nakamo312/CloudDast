from __future__ import annotations

from collections.abc import Sequence
from ipaddress import ip_address, ip_network

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import PolicyVerdict, VerdictStatus
from cloud_dast.ports import EvidenceEvent
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles.action_alignment import explain_mismatch
from cloud_dast.verification.oracles.trace import ObservationTrace


class Oracle:
    """Interpret OOB policy and callback evidence without collecting events."""

    def __init__(
        self,
        *,
        allowed_sources: Sequence[str] = (),
        adversarial_target: bool = False,
    ) -> None:
        try:
            self._allowed_sources = tuple(
                ip_network(source, strict=False) for source in allowed_sources
            )
        except ValueError as error:
            raise ValueError(
                "allowed OOB sources must be IP addresses or networks"
            ) from error
        self._adversarial_target = adversarial_target

    def validate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict | None:
        norm = NormView.from_invariant(invariant)
        if norm is None or norm.primitive != "oob_event":
            return self.unscoreable("invariant is not an oob-event QDL norm")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return self.unscoreable(mismatch)
        marker = trace[-1].probe_marker if trace else None
        if not marker:
            return self.unscoreable(
                "out-of-band observation has no non-empty candidate probe marker"
            )

        return None

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

    def evaluate_event(
        self,
        trace: ObservationTrace,
        event: EvidenceEvent,
    ) -> PolicyVerdict:
        source_error = self._source_rationale(event)
        if source_error is not None:
            return self.unscoreable(source_error)
        if self._adversarial_target:
            return self.unscoreable(
                "adversarial target policy does not trust an out-of-band "
                "callback as deterministic sink evidence"
            )
        return self._verified(trace, event)

    @staticmethod
    def unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="oob",
            deterministic=True,
            grounded=False,
        )
