"""Signal-first deterministic witnesses for grammar-generated candidates.

Observation scoring first extracts every cheap runtime signal.  The primitive
oracles below remain class-free: they prove that a signal exists, not which
production vulnerability it belongs to.  Threat interpretation is supplied by
the QDL signal rule-pack in the formal layer.
"""

from __future__ import annotations

from collections.abc import Sequence

from cloud_dast.contracts.feedback import Signal
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    Observation,
    OracleDeficit,
    PolicyVerdict,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent, OobEvaluator
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles import latency, marker
from cloud_dast.verification.oracles.action_alignment import (
    explain_mismatch,
)
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.witness import (
    KnownContentWitness,
    ObservationPair,
    extract_witness_signals,
    grounded_sink_fields,
    is_echo_path,
    known_content_paths,
    matching_paths,
    path_witness,
    response_is_incomplete,
)


class Oracle:
    """Score class-free witness signals with deterministic primitives."""

    def __init__(
        self,
        *,
        latency_oracle: latency.Oracle | None = None,
        marker_oracle: marker.Oracle | None = None,
        oob_oracle: OobEvaluator | None = None,
    ) -> None:
        self._latency = latency_oracle or latency.Oracle()
        self._marker = marker_oracle or marker.Oracle()
        self._oob = oob_oracle

    def extract_signals(
        self,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
        known_content: KnownContentWitness | None = None,
        oob_events: Sequence[EvidenceEvent] = (),
    ) -> tuple[Signal, ...]:
        """Extract every cheap signal from one observation trace.

        Signal extraction is independent of the norm being scored.  It never
        records raw response values: paths, markers, bounded timing deltas, and
        observation/event identifiers are enough for QDL interpretation.
        """

        events = tuple(oob_events)
        if self._oob is not None:
            events += tuple(
                event
                for observation in trace
                if (event := self._oob.observe(observation.probe_marker or ""))
                is not None
            )

        return extract_witness_signals(
            trace,
            method_id=method_id,
            probe_fields=probe_fields,
            sink_types=sink_types,
            known_content=known_content,
            oob_events=events,
        )

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
        signals: tuple[Signal, ...] | None = None,
    ) -> PolicyVerdict:
        """Score the primitive named by a QDL norm without sink-class dispatch."""

        norm = _norm(invariant)
        if norm is None:
            return _unscoreable("witness-signal", "invariant has no QDL norm fact")

        if signals is None:
            signals = self.extract_signals(
                trace,
                method_id=method_id,
                probe_fields=probe_fields,
                sink_types=sink_types,
            )
        observed_signals = ", ".join(dict.fromkeys(signal.kind for signal in signals))
        if norm.primitive == "latency_bound":
            return self._latency.evaluate_policy(
                invariant,
                trace,
                method_id=method_id,
            )
        if norm.primitive == "marker":
            return self._marker.evaluate_policy(
                invariant,
                trace,
                method_id=method_id,
                probe_fields=probe_fields,
                sink_types=sink_types,
            )
        if norm.primitive == "oob_event":
            if self._oob is None:
                return _unscoreable(
                    "oob-signal", "out-of-band oracle is not configured"
                )
            return self._oob.evaluate_policy(
                invariant,
                trace,
                method_id=method_id,
            )
        return _unscoreable(
            "witness-signal",
            "QDL norm requires an explicit paired witness signal; "
            f"observed signals: {observed_signals or 'none'}",
        )

    def evaluate_pair(
        self,
        invariant: InvariantProjection,
        pair: ObservationPair,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
    ) -> PolicyVerdict:
        """Score a grounded response-path difference between a pair."""

        norm = _norm(invariant)
        if norm is None:
            return _unscoreable("content-delta", "invariant has no QDL norm fact")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return _unscoreable("content-delta", mismatch)
        if not pair.witness_path:
            return _unscoreable(
                "content-delta", "content-delta witness has no response path"
            )
        if response_is_incomplete(pair.control) or response_is_incomplete(
            pair.treatment
        ):
            return _unscoreable(
                "content-delta", "paired response evidence is incomplete"
            )

        grounded_fields = grounded_sink_fields(sink_types)
        control = path_witness(pair.control, pair.witness_path)
        treatment = path_witness(pair.treatment, pair.witness_path)
        if not control.present and not treatment.present:
            return _unscoreable(
                "content-delta",
                f"witness path {pair.witness_path!r} is absent from both responses",
            )
        if _only_echoed(
            pair.control,
            pair.witness_path,
            probe_fields=probe_fields,
            grounded_fields=grounded_fields,
        ) or _only_echoed(
            pair.treatment,
            pair.witness_path,
            probe_fields=probe_fields,
            grounded_fields=grounded_fields,
        ):
            return _unscoreable(
                "content-delta", "witness path is only an echoed request field"
            )

        changed = (control.present, control.values) != (
            treatment.present,
            treatment.values,
        )
        evidence_refs = (pair.control.observation_id, pair.treatment.observation_id)
        if changed:
            return PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale=(
                    "content-delta witness changed at response path "
                    f"{pair.witness_path!r} between control and treatment"
                ),
                evidence_refs=evidence_refs,
                model_id="content-delta",
                deterministic=True,
                grounded=True,
            )
        return PolicyVerdict(
            status=VerdictStatus.PASS,
            confidence=0.9,
            rationale=(
                "content-delta witness is stable at response path "
                f"{pair.witness_path!r} between control and treatment"
            ),
            evidence_refs=evidence_refs,
            model_id="content-delta",
            negative_scope=(
                "paired_control_response",
                "paired_treatment_response",
            ),
            deterministic=True,
            grounded=True,
        )

    def evaluate_known_content(
        self,
        invariant: InvariantProjection,
        observation: Observation,
        witness: KnownContentWitness,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
    ) -> PolicyVerdict:
        """Score operator-provided known content in one observation."""

        norm = _norm(invariant)
        if norm is None:
            return _unscoreable("known-content", "invariant has no QDL norm fact")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return _unscoreable("known-content", mismatch)
        if not observation.probe_marker:
            return _unscoreable(
                "known-content", "known-content observation has no candidate marker"
            )
        if response_is_incomplete(observation):
            return _unscoreable(
                "known-content", "known-content response evidence is incomplete"
            )
        if not observation.response_tree:
            rationale = "known-content witness has no complete full-response tree"
            return _unscoreable(
                "known-content",
                rationale,
                deficits=(
                    OracleDeficit(
                        kind="incomplete_negative_scope",
                        action_id=norm.action_id,
                        rationale=rationale,
                    ),
                ),
            )

        paths = known_content_paths(
            observation,
            witness,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        if paths:
            return PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale=(
                    "known-content witness matched response path(s): "
                    f"{_render_paths(paths)}"
                ),
                evidence_refs=(observation.observation_id,),
                model_id="known-content",
                deterministic=True,
                grounded=True,
            )
        return PolicyVerdict(
            status=VerdictStatus.PASS,
            confidence=0.9,
            rationale="known-content witness was not observed",
            evidence_refs=(observation.observation_id,),
            model_id="known-content",
            negative_scope=("response_tree",),
            deterministic=True,
            grounded=True,
        )

    def evaluate_known_content_pair(
        self,
        invariant: InvariantProjection,
        control: Observation,
        treatment: Observation,
        witness: KnownContentWitness,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
    ) -> PolicyVerdict:
        """Score known content appearing only in the treatment leg."""

        norm = _norm(invariant)
        if norm is None:
            return _unscoreable("known-content-delta", "invariant has no QDL norm fact")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return _unscoreable("known-content-delta", mismatch)
        if not treatment.probe_marker:
            return _unscoreable(
                "known-content-delta", "treatment has no candidate marker"
            )
        if response_is_incomplete(control) or response_is_incomplete(treatment):
            return _unscoreable(
                "known-content-delta", "paired response evidence is incomplete"
            )
        if not control.response_tree or not treatment.response_tree:
            rationale = (
                "known-content pair has no complete full-response tree for both legs"
            )
            return _unscoreable(
                "known-content-delta",
                rationale,
                deficits=(
                    OracleDeficit(
                        kind="incomplete_negative_scope",
                        action_id=norm.action_id,
                        rationale=rationale,
                    ),
                ),
            )

        control_paths = known_content_paths(
            control,
            witness,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        treatment_paths = known_content_paths(
            treatment,
            witness,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        evidence_refs = (control.observation_id, treatment.observation_id)
        if treatment_paths and not control_paths:
            return PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=1.0,
                rationale=(
                    "known-content witness appeared only in the treatment "
                    f"at path(s): {_render_paths(treatment_paths)}"
                ),
                evidence_refs=evidence_refs,
                model_id="known-content-delta",
                deterministic=True,
                grounded=True,
            )
        return PolicyVerdict(
            status=VerdictStatus.PASS,
            confidence=0.9,
            rationale="known-content witness did not appear only in the treatment",
            evidence_refs=evidence_refs,
            model_id="known-content-delta",
            negative_scope=(
                "paired_control_response",
                "paired_treatment_response",
            ),
            deterministic=True,
            grounded=True,
        )


def _norm(invariant: InvariantProjection) -> NormView | None:
    try:
        return NormView.from_invariant(invariant)
    except ValueError:
        return None


def _only_echoed(
    observation: Observation,
    path: str,
    *,
    probe_fields: tuple[str, ...],
    grounded_fields: frozenset[str],
) -> bool:
    paths = matching_paths(observation, path)
    if not paths:
        return False
    probe = frozenset(field.casefold() for field in probe_fields)
    return all(is_echo_path(leaf_path, probe, grounded_fields) for leaf_path in paths)


def _render_paths(paths: tuple[str, ...]) -> str:
    return ", ".join(repr(path) for path in paths)


def _unscoreable(
    model_id: str,
    rationale: str,
    *,
    deficits: tuple[OracleDeficit, ...] = (),
) -> PolicyVerdict:
    return PolicyVerdict(
        status=VerdictStatus.UNSCOREABLE,
        confidence=0.0,
        rationale=rationale,
        model_id=model_id,
        deterministic=True,
        grounded=False,
        deficits=deficits,
    )
