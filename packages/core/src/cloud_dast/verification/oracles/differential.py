"""Deterministic state-change oracle for read-back and concurrency evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from cloud_dast.model import (
    AccessOutcome,
    Observation,
    VerdictStatus,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    action_alignment_rationale,
    actions_align,
)
from cloud_dast.verification.oracles.marker import response_is_incomplete
from cloud_dast.verification.oracles.policy_verdict import (
    OracleDeficit,
    PolicyVerdict,
)
from cloud_dast.verification.oracles.trace import ObservationTrace


@dataclass(frozen=True, slots=True)
class _FieldSnapshot:
    """One deterministic observation of a forbidden field."""

    values: tuple[tuple[str, object], ...]
    source: str
    complete: bool


class DifferentialOracle:
    """Compare a forbidden resource field across paired or concurrent evidence.

    The oracle is a verdict layer only: it consumes already captured
    observations and never re-executes or re-compares a pair.  A complete
    read-back trace is ``read-before → write → read-after``; a two-observation
    trace is accepted as an already paired before/after measurement.  A
    one-observation trace uses the write's explicit ``resource_state_before``/
    ``resource_state_after`` projection. Negative witnesses require complete
    snapshots; observed value changes remain positive on partial channels.
    Transport failures are recoverable only when another observation in the
    same sequence retains the field through ``response_tree`` or the trace's
    ``resource_state_before``/``resource_state_after`` channel.
    """

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            return self._unscoreable("invalid differential QDL norm")
        if norm is None or norm.primitive != "differential":
            return self._unscoreable("invariant is not a differential QDL norm")
        mismatch = action_alignment_rationale(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        if len(trace) not in {1, 2, 3}:
            return self._unscoreable(
                "differential QDL norm requires paired reads, a read-back "
                "trace, or one complete write state projection"
            )

        field = norm.forbidden_field
        if field is None:
            return self._unscoreable("differential QDL norm has no resource field")

        auth_failure = next(
            (observation for observation in trace if observation.auth_failed),
            None,
        )
        if auth_failure is not None:
            return self._unscoreable(
                "paired read-back contains an authentication failure: "
                f"{auth_failure.observation_id}"
            )

        if len(trace) == 1:
            before = _state_snapshot(trace[0], field, "before")
            after = _state_snapshot(trace[0], field, "after")
            if before is None or after is None:
                return self._unscoreable(
                    "differential QDL norm has no complete write state projection"
                )
        else:
            before = _observation_snapshot(trace[0], field, "before")
            after = _observation_snapshot(trace[-1], field, "after")
            if before is None and len(trace) == 3:
                before = _state_snapshot(trace[1], field, "before")
            if after is None and len(trace) == 3:
                after = _observation_snapshot(trace[1], field, "after")
        if before is None or after is None:
            transport_error = next(
                (
                    observation
                    for observation in trace
                    if _is_transport_error(observation)
                ),
                None,
            )
            if transport_error is not None:
                return self._unscoreable(
                    "paired read-back contains a transport error without "
                    f"recoverable state evidence: {transport_error.observation_id}"
                )
            return self._unscoreable(
                f"resource field {field!r} has no corresponding response_tree "
                "or resource-state leaf in both paired reads or the write "
                "state projection"
            )

        if len(trace) == 1:
            context = "from one write's state projection"
        elif any(_is_transport_error(observation) for observation in trace):
            context = "between paired reads with transport-error recovery"
        else:
            context = "between paired reads"
        return _compare_snapshots(
            field,
            before,
            after,
            evidence_refs=tuple(
                dict.fromkeys(observation.observation_id for observation in trace)
            ),
            context=context,
            model_id="differential",
        )

    def evaluate_concurrency_policy(
        self,
        invariant: InvariantProjection,
        *,
        read_before: Observation,
        probes: Sequence[Observation],
        read_after: Observation,
        method_id: str | None = None,
        min_successful_probes: int = 2,
    ) -> PolicyVerdict:
        """Score a changed norm against one already-executed probe batch.

        The caller supplies observations in execution order: read-before,
        concurrent probes, read-after.  This API is the concurrency witness;
        ``Observation`` does not carry wall-clock overlap.  At least two
        successful, method-aligned probes are required, so an isolated success
        cannot be reported as a race.  State recovery uses the same
        response-tree and trace-state channels as read-back.
        """

        if min_successful_probes < 2:
            raise ValueError("concurrency evidence requires at least two probes")
        if method_id is None:
            return self._unscoreable(
                "concurrency evidence requires a method id",
                model_id="differential-concurrency",
            )

        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            return self._unscoreable(
                "invalid differential QDL norm",
                model_id="differential-concurrency",
            )
        if norm is None or norm.primitive != "differential":
            return self._unscoreable(
                "invariant is not a differential QDL norm",
                model_id="differential-concurrency",
            )
        mismatch = action_alignment_rationale(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(
                mismatch,
                model_id="differential-concurrency",
            )

        field = norm.forbidden_field
        if field is None:
            return self._unscoreable(
                "differential QDL norm has no resource field",
                model_id="differential-concurrency",
            )

        probe_batch = tuple(probes)
        if not probe_batch:
            return self._unscoreable(
                "concurrency QDL norm has no probe observation",
                model_id="differential-concurrency",
            )
        if len({probe.observation_id for probe in probe_batch}) != len(probe_batch):
            return self._unscoreable(
                "concurrency probe observations must be distinct",
                model_id="differential-concurrency",
            )
        if any(not _observation_aligns(probe, method_id) for probe in probe_batch):
            return self._unscoreable(
                "concurrency probe trace is not aligned with the QDL method",
                model_id="differential-concurrency",
            )

        successful = tuple(probe for probe in probe_batch if _probe_completed(probe))
        if len(successful) < min_successful_probes:
            return self._unscoreable(
                "concurrency evidence has fewer than "
                f"{min_successful_probes} successful probes",
                model_id="differential-concurrency",
            )

        if read_before.auth_failed or read_after.auth_failed:
            return self._unscoreable(
                "concurrency read-back contains an authentication failure",
                model_id="differential-concurrency",
            )

        before = _observation_snapshot(read_before, field, "before")
        after = _observation_snapshot(read_after, field, "after")
        if before is None:
            before = _first_state_snapshot(probe_batch, field, "before")
        if after is None:
            after = _first_snapshot(reversed(probe_batch), field, "after")
        if before is None or after is None:
            transport_error = next(
                (
                    observation
                    for observation in (read_before, *probe_batch, read_after)
                    if _is_transport_error(observation)
                ),
                None,
            )
            if transport_error is not None:
                return self._unscoreable(
                    "concurrency read-back contains a transport error without "
                    f"recoverable state evidence: {transport_error.observation_id}",
                    model_id="differential-concurrency",
                )
            return self._unscoreable(
                f"resource field {field!r} has no corresponding response_tree "
                "or resource-state leaf in the concurrency read-back",
                model_id="differential-concurrency",
            )

        return _compare_snapshots(
            field,
            before,
            after,
            evidence_refs=(
                read_before.observation_id,
                *(probe.observation_id for probe in probe_batch),
                read_after.observation_id,
            ),
            context=(
                f"after {len(successful)} successful concurrent probes "
                "with transport-error recovery"
                if any(
                    _is_transport_error(observation)
                    for observation in (read_before, *probe_batch, read_after)
                )
                else f"after {len(successful)} successful concurrent probes"
            ),
            model_id="differential-concurrency",
        )

    @staticmethod
    def _unscoreable(
        rationale: str,
        *,
        model_id: str = "differential",
    ) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id=model_id,
            deterministic=True,
            grounded=False,
        )


def _first_snapshot(
    observations: Sequence[Observation] | reversed[Observation],
    field: str,
    phase: str,
) -> _FieldSnapshot | None:
    for observation in observations:
        snapshot = _observation_snapshot(observation, field, phase)
        if snapshot is not None:
            return snapshot
    return None


def _first_state_snapshot(
    observations: Sequence[Observation],
    field: str,
    phase: str,
) -> _FieldSnapshot | None:
    for observation in observations:
        snapshot = _state_snapshot(observation, field, phase)
        if snapshot is not None:
            return snapshot
    return None


def _state_snapshot(
    observation: Observation,
    field: str,
    phase: str,
) -> _FieldSnapshot | None:
    """Return only the explicit trace state channel for one observation."""

    if observation.trace is None:
        return None
    state_attr = f"resource_state_{phase}"
    for step in observation.trace.steps:
        if step.observation_id != observation.observation_id:
            continue
        state = getattr(step, state_attr)
        paths = _matching_paths(state, field)
        if paths:
            selected = dict(state)
            return _FieldSnapshot(
                values=tuple((path, selected[path]) for path in paths),
                source=state_attr,
                complete=not response_is_incomplete(
                    observation.model_copy(
                        update={"response_tree": state, "output": None}
                    )
                ),
            )
    return None


def _observation_snapshot(
    observation: Observation,
    field: str,
    phase: str,
) -> _FieldSnapshot | None:
    """Return the first generic channel that observes the field.

    The trace state channel is checked before response channels because it is
    the explicit resource snapshot.  Full-fidelity ``response_tree`` remains
    the primary response channel, followed by the safe output projections.
    """

    for values, source in _channels(observation, phase):
        paths = _matching_paths(values, field)
        if paths:
            selected = dict(values)
            return _FieldSnapshot(
                values=tuple((path, selected[path]) for path in paths),
                source=source,
                complete=source not in {"output_fields", "trace_response_fields"}
                and not response_is_incomplete(
                    observation.model_copy(
                        update={"response_tree": values, "output": None}
                    )
                ),
            )
    return None


def _channels(
    observation: Observation,
    phase: str,
) -> tuple[tuple[tuple[tuple[str, object], ...], str], ...]:
    state_attr = f"resource_state_{phase}"
    channels: list[tuple[tuple[tuple[str, object], ...], str]] = []
    if observation.trace is not None:
        for step in observation.trace.steps:
            if step.observation_id != observation.observation_id:
                continue
            state = getattr(step, state_attr)
            if state:
                channels.append((state, state_attr))
    if observation.response_tree:
        channels.append((observation.response_tree, "response_tree"))
    if observation.output is not None and observation.output.fields:
        channels.append((observation.output.fields, "output_fields"))
    if observation.trace is not None:
        for step in observation.trace.steps:
            if (
                step.observation_id == observation.observation_id
                and step.response is not None
                and step.response.fields
            ):
                channels.append((step.response.fields, "trace_response_fields"))
    return tuple(channels)


def _compare_snapshots(
    field: str,
    before: _FieldSnapshot,
    after: _FieldSnapshot,
    *,
    evidence_refs: tuple[str, ...],
    context: str,
    model_id: str,
) -> PolicyVerdict:
    before_values = dict(before.values)
    after_values = dict(after.values)
    before_paths = set(_matching_paths(before_values, field))
    after_paths = set(_matching_paths(after_values, field))
    common_paths = sorted(before_paths & after_paths)
    if not common_paths:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=(
                f"resource field {field!r} has no corresponding response_tree "
                "or resource-state leaf in both paired reads"
            ),
            model_id=model_id,
            deterministic=True,
            grounded=False,
        )

    changed_paths = tuple(
        sorted(
            (before_paths - after_paths if after.complete else set())
            | (after_paths - before_paths if before.complete else set())
            | {
                path
                for path in common_paths
                if before_values[path] != after_values[path]
            }
        )
    )
    source = f"before={before.source}, after={after.source}"
    if changed_paths:
        return PolicyVerdict(
            status=VerdictStatus.FAIL,
            confidence=1.0,
            rationale=(
                f"forbidden resource field {field!r} changed {context} at "
                f"response path(s): {_render_paths(changed_paths)} "
                f"(compared {_render_paths(tuple(common_paths))}; {source})"
            ),
            evidence_refs=evidence_refs,
            model_id=model_id,
            deterministic=True,
            grounded=True,
        )
    if not before.complete or not after.complete:
        rationale = (
            f"resource field {field!r} has an incomplete negative snapshot scope "
            f"({source})"
        )
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            evidence_refs=evidence_refs,
            model_id=model_id,
            deficits=(
                OracleDeficit(kind="incomplete_negative_scope", rationale=rationale),
            ),
            deterministic=True,
            grounded=False,
        )
    return PolicyVerdict(
        status=VerdictStatus.PASS,
        confidence=1.0,
        rationale=(
            f"forbidden resource field {field!r} was unchanged {context} at "
            f"response path(s): {_render_paths(tuple(common_paths))} ({source})"
        ),
        evidence_refs=evidence_refs,
        model_id=model_id,
        negative_scope=("before_snapshot", "after_snapshot"),
        deterministic=True,
        grounded=True,
    )


def _observation_aligns(observation: Observation, method_id: str | None) -> bool:
    if observation.trace is None:
        return method_id is None
    steps = tuple(
        step
        for step in observation.trace.steps
        if step.observation_id == observation.observation_id
    )
    return bool(steps) and all(
        actions_align(step.method_id, method_id) for step in steps
    )


def _probe_completed(observation: Observation) -> bool:
    if observation.auth_failed:
        return False
    if observation.trace is not None:
        return bool(observation.trace.steps) and all(
            step.status is AccessOutcome.ALLOWED for step in observation.trace.steps
        )
    return observation.observed_outcome is AccessOutcome.ALLOWED


def _is_transport_error(observation: Observation) -> bool:
    return observation.observed_outcome in {
        AccessOutcome.ERROR,
        AccessOutcome.UNKNOWN,
    } or bool(observation.error_reason)


def _matching_paths(
    values: dict[str, object] | tuple[tuple[str, object], ...],
    field: str,
) -> tuple[str, ...]:
    """Return exact or suffix matches for a response or state leaf path."""

    return tuple(
        path
        for path in sorted(dict(values))
        if path == field or path.endswith(f".{field}")
    )


def _render_paths(paths: tuple[str, ...]) -> str:
    return ", ".join(paths)
