"""Signal-first deterministic witnesses for grammar-generated candidates.

Observation scoring first extracts every cheap runtime signal.  The primitive
oracles below remain class-free: they prove that a signal exists, not which
production vulnerability it belongs to.  Threat interpretation is supplied by
the QDL signal rule-pack in the formal layer.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    JsonValue,
    Observation,
    OracleDeficit,
    PolicyVerdict,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    action_alignment_rationale,
)
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.oracles.marker import (
    MarkerOracle,
    is_echo_path,
    response_is_incomplete,
)
from cloud_dast.verification.oracles.oob import OobOracle
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.witness import (
    KnownContentWitness,
    ObservationPair,
    WitnessSignal,
    extract_witness_signals,
)


@dataclass(frozen=True, slots=True)
class _PathWitness:
    present: bool
    values: tuple[JsonValue, ...]


class WitnessSignalOracle:
    """Score class-free witness signals with deterministic primitives."""

    def __init__(
        self,
        *,
        latency_oracle: LatencyOracle | None = None,
        marker_oracle: MarkerOracle | None = None,
        oob_oracle: OobOracle | None = None,
    ) -> None:
        self._latency = latency_oracle or LatencyOracle()
        self._marker = marker_oracle or MarkerOracle()
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
    ) -> tuple[WitnessSignal, ...]:
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
        signals: tuple[WitnessSignal, ...] | None = None,
    ) -> PolicyVerdict:
        """Score the primitive named by a QDL norm without sink-class dispatch."""

        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            norm = None
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
        mismatch = action_alignment_rationale(norm.action_id, method_id)
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

        grounded_fields = _grounded_sink_fields(sink_types)
        control = _path_witness(pair.control, pair.witness_path)
        treatment = _path_witness(pair.treatment, pair.witness_path)
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
        mismatch = action_alignment_rationale(norm.action_id, method_id)
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

        paths = _known_content_paths(
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
        mismatch = action_alignment_rationale(norm.action_id, method_id)
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

        control_paths = _known_content_paths(
            control,
            witness,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        treatment_paths = _known_content_paths(
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


def _action_id(method_id: str | None) -> str | None:
    if method_id is None:
        return None
    return method_id if method_id.startswith("action:") else f"action:{method_id}"


def _grounded_sink_fields(
    sink_types: dict[str, str] | None,
) -> frozenset[str]:
    return frozenset(
        name.casefold()
        for name, sink_type in (sink_types or {}).items()
        if sink_type.strip()
    )


def _response_values(observation: Observation) -> tuple[tuple[str, JsonValue], ...]:
    values = observation.response_tree
    if observation.output is not None:
        values += observation.output.fields
    return values


def _marker_signal(
    observation: Observation,
    action_id: str | None,
    *,
    probe_fields: tuple[str, ...],
    sink_types: dict[str, str] | None,
) -> WitnessSignal | None:
    marker = observation.probe_marker
    if not marker:
        return None
    probe = frozenset(field.casefold() for field in probe_fields)
    grounded_fields = _grounded_sink_fields(sink_types)
    paths = tuple(
        dict.fromkeys(
            path
            for path, value in _response_values(observation)
            if _value_contains(value, marker)
            and not is_echo_path(path, probe, grounded_fields)
        )
    )
    error_channel = marker in (observation.response_summary, observation.error_reason)
    if not paths and not error_channel:
        return None
    return WitnessSignal(
        kind="marker_echo",
        action_id=action_id,
        evidence_refs=(observation.observation_id,),
        paths=paths,
        marker=marker,
    )


def _content_delta_paths(
    control: Observation,
    treatment: Observation,
) -> tuple[str, ...]:
    control_values = _values_by_path(control)
    treatment_values = _values_by_path(treatment)
    return tuple(
        sorted(
            path
            for path in frozenset(control_values) | frozenset(treatment_values)
            if control_values.get(path) != treatment_values.get(path)
        )
    )


def _values_by_path(observation: Observation) -> dict[str, tuple[JsonValue, ...]]:
    values: dict[str, list[JsonValue]] = {}
    for path, value in _response_values(observation):
        values.setdefault(path, []).append(value)
    return {path: tuple(items) for path, items in values.items()}


def _matching_paths(
    observation: Observation,
    path: str,
) -> tuple[str, ...]:
    normalized = path.casefold().strip(".")
    return tuple(
        dict.fromkeys(
            leaf_path
            for leaf_path, _value in _response_values(observation)
            if _path_matches(leaf_path, normalized)
        )
    )


def _path_matches(leaf_path: str, witness_path: str) -> bool:
    normalized = leaf_path.casefold().strip(".")
    return normalized == witness_path or normalized.endswith(f".{witness_path}")


def _path_values(
    observation: Observation,
    path: str,
) -> tuple[JsonValue, ...]:
    normalized = path.casefold().strip(".")
    return tuple(
        value
        for leaf_path, value in _response_values(observation)
        if _path_matches(leaf_path, normalized)
    )


def _path_witness(
    observation: Observation,
    path: str,
) -> _PathWitness:
    values = _path_values(observation, path)
    return _PathWitness(present=bool(values), values=values)


def _only_echoed(
    observation: Observation,
    path: str,
    *,
    probe_fields: tuple[str, ...],
    grounded_fields: frozenset[str],
) -> bool:
    paths = _matching_paths(observation, path)
    if not paths:
        return False
    probe = frozenset(field.casefold() for field in probe_fields)
    return all(is_echo_path(leaf_path, probe, grounded_fields) for leaf_path in paths)


def _known_content_paths(
    observation: Observation,
    witness: KnownContentWitness,
    *,
    probe_fields: tuple[str, ...],
    sink_types: dict[str, str] | None,
) -> tuple[str, ...]:
    grounded_fields = _grounded_sink_fields(sink_types)
    probe = frozenset(field.casefold() for field in probe_fields)
    selected_paths = (
        _matching_paths(observation, witness.response_path)
        if witness.response_path
        else None
    )
    return tuple(
        dict.fromkeys(
            leaf_path
            for leaf_path, value in _response_values(observation)
            if (selected_paths is None or leaf_path in selected_paths)
            if not is_echo_path(leaf_path, probe, grounded_fields)
            and _value_equals(value, witness.content)
        )
    )


def _value_contains(value: JsonValue, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, tuple):
        return any(_value_contains(item, marker) for item in value)
    return False


def _value_equals(value: JsonValue, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, tuple):
        return any(_value_equals(item, expected) for item in value)
    return False


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
