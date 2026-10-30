"""Deterministic comparison of paired and aggregate differential evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from cloud_dast.model import (
    Observation,
    TransportStatus,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.verification.differential.report import (
    ConcurrencyEvidence,
    DiffReport,
    TimingEvidence,
)
from cloud_dast.verification.oracles import latency
from cloud_dast.verification.witness import response_is_incomplete


def compare_observations(
    action_id: str,
    control: Observation,
    treatment: Observation,
    *,
    latency_class_differs: bool = False,
) -> DiffReport | None:
    """Return a safe difference report for one paired observation.

    The comparator is a pure function over already captured evidence.  It
    compares full-fidelity response trees (falling back to the legacy
    whitelisted projection when no tree was captured) but retains only field
    names and equality booleans, so raw response values never reach the
    model-facing report.  Latency is intentionally not inferred from two raw
    durations; callers with repeated samples pass a robust class.
    """

    if response_is_incomplete(control) or response_is_incomplete(treatment):
        return None

    control_names = _shape_names(control)
    treatment_names = _shape_names(treatment)

    return DiffReport(
        action_id=action_id,
        control_observation_id=control.observation_id,
        treatment_observation_id=treatment.observation_id,
        outcome_differs=control.observed_outcome != treatment.observed_outcome,
        status_differs=control.transport_status != treatment.transport_status,
        fields_only_control=tuple(sorted(control_names - treatment_names)),
        fields_only_treatment=tuple(sorted(treatment_names - control_names)),
        value_differs=_value_differs(control, treatment),
        error_differs=control.error_reason != treatment.error_reason,
        latency_class_differs=latency_class_differs,
    )


def compare_timing_measurements(
    action_id: str,
    control_samples: Sequence[Observation],
    treatment_samples: Sequence[Observation],
    *,
    min_samples: int = 3,
) -> DiffReport | None:
    """Compare repeated control/treatment latency measurements.

    Each leg gets its own median/MAD baseline once it has enough measured
    durations.  A latency class differs when a majority of one leg's samples
    lies beyond the other leg's robust threshold.  Two isolated calls
    therefore cannot produce timing variance.
    """

    if not control_samples or not treatment_samples:
        return None
    if min_samples < 3:
        raise ValueError("timing comparison requires at least three samples")
    if any(
        response_is_incomplete(observation)
        for observation in (*control_samples, *treatment_samples)
    ):
        return None

    control_durations = _durations(control_samples)
    treatment_durations = _durations(treatment_samples)
    sufficient = (
        len(control_durations) >= min_samples
        and len(treatment_durations) >= min_samples
    )
    if sufficient:
        control_baseline = latency.Baseline.from_durations(
            action_id,
            control_durations,
            min_samples=min_samples,
        )
        treatment_baseline = latency.Baseline.from_durations(
            action_id,
            treatment_durations,
            min_samples=min_samples,
        )
        control = _representative(control_samples, control_baseline.median_ms)
        treatment = _representative(
            treatment_samples,
            treatment_baseline.median_ms,
        )
        class_differs = _latency_class_differs(
            control_baseline,
            treatment_baseline,
            control_durations,
            treatment_durations,
        )
        timing_evidence = _timing_evidence(
            control_baseline,
            treatment_baseline,
            len(control_durations),
            len(treatment_durations),
        )
    else:
        control = control_samples[0]
        treatment = treatment_samples[0]
        class_differs = False
        timing_evidence = _timing_evidence(
            None,
            None,
            len(control_durations),
            len(treatment_durations),
        )

    report = compare_observations(
        action_id,
        control,
        treatment,
        latency_class_differs=class_differs,
    )
    if report is None:
        return None
    return replace(report, timing_evidence=timing_evidence)


def compare_concurrency_measurements(
    action_id: str,
    probes: Sequence[Observation],
    *,
    read_before: Observation | None = None,
    read_after: Observation | None = None,
) -> DiffReport | None:
    """Compare one parallel probe batch and its optional state read-back.

    The comparator records aggregate outcome/status counts, the number of
    unique response digests, and whether the optional read-back changed.  It
    does not interpret the aggregate as a race class; variance remains an
    ``unexplained_variance`` question for grounding.
    """

    if not probes:
        return None
    if (read_before is None) != (read_after is None):
        raise ValueError("concurrency read-back requires both before and after legs")
    observations = (
        *probes,
        *(() if read_before is None else (read_before,)),
        *(() if read_after is None else (read_after,)),
    )
    if any(response_is_incomplete(observation) for observation in observations):
        return None

    outcome_counts = _outcome_counts(probes)
    status_counts = _status_counts(probes)
    unique_digests = len({_digest(observation) for observation in probes})
    state_readback = read_before is not None and read_after is not None

    if state_readback:
        control = read_before
        treatment = read_after
        state_report = compare_observations(
            action_id,
            control,
            treatment,
        )
        state_differs = state_report is not None and state_report.has_variance
    else:
        control = probes[0]
        treatment = _contrasting_probe(probes)
        state_differs = False

    report = compare_observations(action_id, control, treatment)
    if report is None:
        return None
    aggregate_differs = (
        len(outcome_counts) > 1
        or len(status_counts) > 1
        or unique_digests > 1
        or state_differs
    )
    concurrency_evidence = ConcurrencyEvidence(
        probes=len(probes),
        outcome_counts=outcome_counts,
        status_counts=status_counts,
        unique_response_digests=unique_digests,
        state_readback=state_readback,
        state_differs=state_differs,
    )
    return replace(
        report,
        aggregate_differs=aggregate_differs,
        concurrency_evidence=concurrency_evidence,
        dimensions=(),
    )


def _durations(samples: Sequence[Observation]) -> tuple[float, ...]:
    return tuple(
        observation.duration_ms
        for observation in samples
        if observation.duration_ms is not None
    )


def _representative(
    samples: Sequence[Observation],
    median_ms: float,
) -> Observation:
    measured = [
        observation for observation in samples if observation.duration_ms is not None
    ]
    return min(
        measured or samples,
        key=lambda observation: (
            abs((observation.duration_ms or 0.0) - median_ms),
            observation.observation_id,
        ),
    )


def _latency_class_differs(
    control: latency.Baseline,
    treatment: latency.Baseline,
    control_durations: Sequence[float],
    treatment_durations: Sequence[float],
) -> bool:
    treatment_above = sum(
        duration > control.threshold_ms for duration in treatment_durations
    )
    control_above = sum(
        duration > treatment.threshold_ms for duration in control_durations
    )
    return treatment_above * 2 >= len(treatment_durations) or control_above * 2 >= len(
        control_durations
    )


def _timing_evidence(
    control: latency.Baseline | None,
    treatment: latency.Baseline | None,
    control_samples: int,
    treatment_samples: int,
) -> TimingEvidence:
    return TimingEvidence(
        control_samples=control_samples,
        treatment_samples=treatment_samples,
        control_median_ms=None if control is None else control.median_ms,
        treatment_median_ms=None if treatment is None else treatment.median_ms,
        control_mad_ms=None if control is None else control.mad_ms,
        treatment_mad_ms=None if treatment is None else treatment.mad_ms,
    )


def _outcome_counts(
    probes: Sequence[Observation],
) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for observation in probes:
        value = observation.observed_outcome.value
        counts[value] = counts.get(value, 0) + 1
    return tuple(counts.items())


def _status_counts(
    probes: Sequence[Observation],
) -> tuple[tuple[TransportStatus | None, int], ...]:
    counts: dict[TransportStatus | None, int] = {}
    for observation in probes:
        value = observation.transport_status
        counts[value] = counts.get(value, 0) + 1
    return tuple(counts.items())


def _digest(observation: Observation) -> str:
    if observation.response_digest is not None:
        return observation.response_digest
    if observation.response_tree:
        return response_tree_digest(observation.response_tree)
    if observation.output is not None:
        return response_tree_digest(observation.output.fields)
    return "empty-response"


def _contrasting_probe(probes: Sequence[Observation]) -> Observation:
    first = probes[0]
    for observation in probes[1:]:
        if observation.observed_outcome != first.observed_outcome or (
            observation.transport_status != first.transport_status
        ):
            return observation
    for observation in probes[1:]:
        if _digest(observation) != _digest(first):
            return observation
    return probes[-1]


def _shape_names(observation: Observation) -> frozenset[str]:
    """Return observed response paths for one leg of the pair.

    Full-fidelity tree paths are authoritative when a tree was captured.
    Without a tree, the legacy union of forwarded and shape-only field names
    keeps observations from older codecs comparable.
    """

    if observation.response_tree:
        return frozenset(path for path, _ in observation.response_tree)
    output = observation.output
    if output is None:
        return frozenset()
    return frozenset({*(name for name, _ in output.fields), *output.field_names})


def _value_differs(
    control: Observation,
    treatment: Observation,
) -> tuple[str, ...]:
    """Return paths of common response leaves whose values differ.

    Every full-fidelity tree path participates in the comparison, so a
    variance outside the forwarded whitelist is still measured.  The legacy
    whitelisted-field comparison is merged in and deduplicated by path,
    keeping observations from tree-less codecs backward compatible.
    """

    differing: set[str] = set()
    control_tree = dict(control.response_tree)
    treatment_tree = dict(treatment.response_tree)
    if control_tree or treatment_tree:
        differing.update(
            path
            for path in control_tree.keys() & treatment_tree.keys()
            if control_tree[path] != treatment_tree[path]
        )
    control_output = control.output
    treatment_output = treatment.output
    if control_output is not None and treatment_output is not None:
        control_values = dict(control_output.fields)
        treatment_values = dict(treatment_output.fields)
        differing.update(
            name
            for name in control_values.keys() & treatment_values.keys()
            if control_values[name] != treatment_values[name]
        )
    return tuple(sorted(differing))
