from __future__ import annotations

from collections.abc import Sequence

from cloud_dast.model import (
    MethodSpec,
    Observation,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.differential import (
    DifferentialOracle,
)
from cloud_dast.verification.oracles.field_exposure import (
    FieldExposureOracle,
)
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.oracles.marker import MarkerOracle
from cloud_dast.verification.oracles.oob import OobOracle
from cloud_dast.verification.oracles.policy_verdict import (
    PolicyVerdict,
    WitnessRolePolicy,
)
from cloud_dast.verification.oracles.sequence import SequenceOracle
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.oracles.witness import WitnessSignalOracle


class PrimitiveOracleRouter:
    """Dispatch a QDL norm to its deterministic primitive oracle.

    Witness primitives are selected only after observation projection: every
    cheap signal is extracted first, then the norm names the signal channel to
    score.  The router never maps a sink type to a production vulnerability
    class; that interpretation belongs to the QDL threat rule-pack.
    """

    def __init__(
        self,
        *,
        grounded_oracle: GroundedOutcomeOracle | None = None,
        field_oracle: FieldExposureOracle | None = None,
        latency_oracle: LatencyOracle | None = None,
        marker_oracle: MarkerOracle | None = None,
        differential_oracle: DifferentialOracle | None = None,
        oob_oracle: OobOracle | None = None,
        sequence_oracle: SequenceOracle | None = None,
        witness_oracle: WitnessSignalOracle | None = None,
        witness_policy: WitnessRolePolicy | None = None,
    ) -> None:
        self._grounded = grounded_oracle or GroundedOutcomeOracle()
        self._field = field_oracle or FieldExposureOracle()
        self._latency = latency_oracle or LatencyOracle()
        self._marker = marker_oracle or MarkerOracle(witness_policy=witness_policy)
        self._differential = differential_oracle or DifferentialOracle()
        self._oob = oob_oracle
        self._sequence = sequence_oracle or SequenceOracle()
        self._witness = witness_oracle or WitnessSignalOracle(
            latency_oracle=self._latency,
            marker_oracle=self._marker,
            oob_oracle=self._oob,
        )

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method: MethodSpec,
        scenario: ScenarioPosition,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
    ) -> PolicyVerdict:
        try:
            norm = NormView.from_invariant(invariant)
        except ValueError as error:
            return self._unscoreable(f"invalid QDL norm: {error}")
        if norm is None:
            return self._unscoreable("invariant has no QDL norm fact")
        if not trace:
            return self._unscoreable("QDL norm has no observation")

        signals = self._witness.extract_signals(
            trace,
            method_id=method.method_id,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        if norm.primitive in {"latency_bound", "marker", "oob_event"}:
            return self._witness.evaluate_policy(
                invariant,
                trace,
                method_id=method.method_id,
                probe_fields=probe_fields,
                sink_types=sink_types,
                signals=signals,
            )

        if norm.primitive == "outcome":
            return self._grounded.evaluate_outcome(
                invariant,
                trace[-1],
                method,
                scenario,
                norm=norm,
            )
        if norm.primitive == "sequence":
            return self._sequence.evaluate_policy(
                invariant,
                trace,
                action_id=method.method_id,
            )
        if norm.primitive == "response_field":
            return self._field.evaluate_policy(
                invariant,
                trace,
                scenario=scenario,
                method_id=method.method_id,
            )
        if norm.primitive == "differential":
            return self._differential.evaluate_policy(
                invariant,
                trace,
                method_id=method.method_id,
            )
        return self._unscoreable(
            f"QDL primitive {norm.primitive} requires a paired or sequence detector"
        )

    def evaluate_concurrency_policy(
        self,
        invariant: InvariantProjection,
        *,
        read_before: Observation,
        probes: Sequence[Observation],
        read_after: Observation,
        method: MethodSpec,
    ) -> PolicyVerdict:
        """Dispatch a changed norm to the deterministic concurrency oracle."""

        return self._differential.evaluate_concurrency_policy(
            invariant,
            read_before=read_before,
            probes=probes,
            read_after=read_after,
            method_id=method.method_id,
        )

    def reevaluate_oob_pending(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, PolicyVerdict]:
        """Sweep timed-out OOB candidates through the configured oracle."""

        if self._oob is None:
            return {}
        return self._oob.reevaluate_pending(timeout=timeout)

    @staticmethod
    def _unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="primitive-router",
            deterministic=True,
            grounded=False,
        )
