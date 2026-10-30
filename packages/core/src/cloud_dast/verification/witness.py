"""Pure, class-free witness signals projected from bounded observations."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from cloud_dast.contracts import feedback
from cloud_dast.model import JsonValue, Observation

_INCOMPLETE_RESPONSE_PATHS = frozenset({"__truncated__", "not_available"})


@dataclass(frozen=True, slots=True)
class ObservationPair:
    """One grounded control/treatment response pair."""

    control: Observation
    treatment: Observation
    witness_path: str


@dataclass(frozen=True, slots=True)
class KnownContentWitness:
    """Operator-provided content expected in a response."""

    content: str
    response_path: str | None = None

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("known-content witness content must not be empty")


@dataclass(frozen=True, slots=True)
class PathWitness:
    """Presence and values observed at one response path."""

    present: bool
    values: tuple[JsonValue, ...]


def extract_witness_signals(
    trace: Sequence[Observation],
    *,
    method_id: str | None = None,
    probe_fields: tuple[str, ...] = (),
    sink_types: dict[str, str] | None = None,
    known_content: KnownContentWitness | None = None,
    oob_events: Sequence[object] = (),
) -> tuple[feedback.Signal, ...]:
    """Extract bounded evidence signals without classifying a vulnerability."""

    if not trace:
        return ()
    action_id = _action_id(method_id)
    signals: set[feedback.Signal] = set()
    for observation in trace:
        marker_signal = _marker_signal(
            observation,
            action_id,
            probe_fields=probe_fields,
            sink_types=sink_types,
        )
        if marker_signal is not None:
            signals.add(marker_signal)
        if known_content is not None:
            paths = known_content_paths(
                observation,
                known_content,
                probe_fields=probe_fields,
                sink_types=sink_types,
            )
            if paths:
                signals.add(
                    feedback.Signal(
                        kind="known_content",
                        action_id=action_id,
                        evidence_refs=(observation.observation_id,),
                        paths=paths,
                        content=known_content.content,
                    )
                )

    events_by_marker = {
        getattr(event, "correlation_id", ""): event
        for event in oob_events
        if getattr(event, "channel", None) == "oob"
    }
    for observation in trace:
        event = events_by_marker.get(observation.probe_marker or "")
        if event is None:
            continue
        signals.add(
            feedback.Signal(
                kind="oob_callback",
                action_id=action_id,
                evidence_refs=(
                    observation.observation_id,
                    getattr(event, "event_id", ""),
                ),
                marker=getattr(event, "correlation_id", None),
            )
        )

    control, treatment = trace[0], trace[-1]
    if len(trace) >= 2:
        if control.duration_ms is not None and treatment.duration_ms is not None:
            signals.add(
                feedback.Signal(
                    kind="latency_delta",
                    action_id=action_id,
                    evidence_refs=(
                        control.observation_id,
                        treatment.observation_id,
                    ),
                    delta_ms=treatment.duration_ms - control.duration_ms,
                )
            )
        paths = content_delta_paths(control, treatment)
        if paths:
            signals.add(
                feedback.Signal(
                    kind="content_delta",
                    action_id=action_id,
                    evidence_refs=(
                        control.observation_id,
                        treatment.observation_id,
                    ),
                    paths=paths,
                )
            )
    return tuple(sorted(signals, key=lambda signal: signal.signature))


def is_echo_path(
    path: str,
    probe_fields: frozenset[str],
    grounded_sink_fields: frozenset[str],
) -> bool:
    """Return whether a response path is only a request echo."""

    segments = tuple(
        segment.strip() for segment in path.casefold().split(".") if segment
    )
    if segments and segments[0] in {"request", "echo"}:
        return True
    if any(segment in grounded_sink_fields for segment in segments):
        return False
    return any(segment in probe_fields for segment in segments)


def response_is_incomplete(observation: Observation) -> bool:
    """Return whether response evidence contains an explicit incomplete path."""

    paths = {path for path, _ in observation.response_tree if _is_incomplete_path(path)}
    output = observation.output
    if output is not None:
        paths.update(name for name, _ in output.fields if _is_incomplete_path(name))
        paths.update(
            name
            for name in getattr(output, "field_names", ())
            if _is_incomplete_path(name)
        )
    return bool(paths)


def _is_incomplete_path(path: str) -> bool:
    return path in _INCOMPLETE_RESPONSE_PATHS or path.endswith(".not_available")


def grounded_sink_fields(sink_types: dict[str, str] | None) -> frozenset[str]:
    return frozenset(
        name.casefold()
        for name, sink_type in (sink_types or {}).items()
        if sink_type.strip()
    )


def content_delta_paths(
    control: Observation,
    treatment: Observation,
) -> tuple[str, ...]:
    control_values = values_by_path(control)
    treatment_values = values_by_path(treatment)
    return tuple(
        sorted(
            path
            for path in frozenset(control_values) | frozenset(treatment_values)
            if control_values.get(path) != treatment_values.get(path)
        )
    )


def known_content_paths(
    observation: Observation,
    witness: KnownContentWitness,
    *,
    probe_fields: tuple[str, ...],
    sink_types: dict[str, str] | None,
) -> tuple[str, ...]:
    grounded_fields = grounded_sink_fields(sink_types)
    probe = frozenset(field.casefold() for field in probe_fields)
    selected_paths = (
        matching_paths(observation, witness.response_path)
        if witness.response_path
        else None
    )
    return tuple(
        dict.fromkeys(
            leaf_path
            for leaf_path, value in response_values(observation)
            if (selected_paths is None or leaf_path in selected_paths)
            if not is_echo_path(leaf_path, probe, grounded_fields)
            and value_equals(value, witness.content)
        )
    )


def matching_paths(observation: Observation, path: str) -> tuple[str, ...]:
    normalized = path.casefold().strip(".")
    return tuple(
        dict.fromkeys(
            leaf_path
            for leaf_path, _value in response_values(observation)
            if path_matches(leaf_path, normalized)
        )
    )


def path_values(observation: Observation, path: str) -> tuple[JsonValue, ...]:
    normalized = path.casefold().strip(".")
    return tuple(
        value
        for leaf_path, value in response_values(observation)
        if path_matches(leaf_path, normalized)
    )


def path_witness(observation: Observation, path: str) -> PathWitness:
    values = path_values(observation, path)
    return PathWitness(present=bool(values), values=values)


def response_values(observation: Observation) -> tuple[tuple[str, JsonValue], ...]:
    values = observation.response_tree
    if observation.output is not None:
        values += observation.output.fields
    return values


def values_by_path(observation: Observation) -> dict[str, tuple[JsonValue, ...]]:
    values: dict[str, list[JsonValue]] = {}
    for path, value in response_values(observation):
        values.setdefault(path, []).append(value)
    return {path: tuple(items) for path, items in values.items()}


def path_matches(leaf_path: str, witness_path: str) -> bool:
    normalized = leaf_path.casefold().strip(".")
    return normalized == witness_path or normalized.endswith(f".{witness_path}")


def value_contains(value: JsonValue, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, tuple):
        return any(value_contains(item, marker) for item in value)
    return False


def value_equals(value: JsonValue, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, tuple):
        return any(value_equals(item, expected) for item in value)
    return False


def _action_id(method_id: str | None) -> str | None:
    if method_id is None:
        return None
    return method_id if method_id.startswith("action:") else f"action:{method_id}"


def _marker_signal(
    observation: Observation,
    action_id: str | None,
    *,
    probe_fields: tuple[str, ...],
    sink_types: dict[str, str] | None,
) -> feedback.Signal | None:
    marker = observation.probe_marker
    if not marker:
        return None
    probe = frozenset(field.casefold() for field in probe_fields)
    grounded_fields = grounded_sink_fields(sink_types)
    paths = tuple(
        dict.fromkeys(
            path
            for path, value in response_values(observation)
            if value_contains(value, marker)
            and not is_echo_path(path, probe, grounded_fields)
        )
    )
    error_channel = marker in (observation.response_summary, observation.error_reason)
    if not paths and not error_channel:
        return None
    return feedback.Signal(
        kind="marker_echo",
        action_id=action_id,
        evidence_refs=(observation.observation_id,),
        paths=paths,
        marker=marker,
    )


__all__ = [
    "KnownContentWitness",
    "ObservationPair",
    "PathWitness",
    "content_delta_paths",
    "extract_witness_signals",
    "grounded_sink_fields",
    "is_echo_path",
    "known_content_paths",
    "matching_paths",
    "path_matches",
    "path_values",
    "path_witness",
    "response_is_incomplete",
    "response_values",
    "value_contains",
    "value_equals",
    "values_by_path",
]
