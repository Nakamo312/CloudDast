"""Deterministic verification of a forbidden multi-step flow."""

from __future__ import annotations

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Observation,
    OracleDeficit,
    PolicyVerdict,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import normalize_action
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles.action_alignment import (
    actions_align,
    explain_mismatch,
)
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.projection import ObservationProjector
from cloud_dast.verification.witness import read_state


class Oracle:
    """Primitive P6: verify explicit state evidence for forbidden transitions.

    Successful calls alone cannot prove completion of a named flow.  The
    current trace interface carries no flow-to-terminal-state binding.
    """

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        action_id: str | None = None,
    ) -> PolicyVerdict:
        norm = NormView.from_invariant(invariant)
        if norm is None or norm.primitive != "sequence":
            return self._unscoreable("invariant is not a sequence QDL norm")
        if not trace:
            return self._unscoreable("sequence QDL norm has no observation")
        mismatch = explain_mismatch(norm.action_id, action_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        if norm.effect_name == "transition":
            return self._evaluate_transition(norm, trace, action_id)
        if norm.effect_name != "completed":
            return self._unscoreable(
                f"sequence QDL norm has unsupported effect {norm.effect_name!r}"
            )

        rationale = (
            "named flow has no grounded flow-state completion witness; "
            "action outcomes do not prove or refute completion"
        )
        return self._unscoreable(
            rationale,
            deficits=(
                OracleDeficit(
                    kind="partial_sequence",
                    action_id=action_id,
                    rationale=rationale,
                ),
            ),
        )

    def _evaluate_transition(
        self,
        norm: NormView,
        trace: ObservationTrace,
        action_id: str | None,
    ) -> PolicyVerdict:
        """Score one forbidden state transition against complete state evidence."""

        from_state = norm.from_state
        to_state = norm.to_state
        if from_state is None or to_state is None:
            return self._unscoreable("transition QDL norm is not state-grounded")

        projector = ObservationProjector()
        paired = _paired_transition(trace, action_id)
        if paired is not None:
            before, after, completed, evidence_refs = paired
            return _transition_verdict(
                from_state,
                to_state,
                violated=completed and before == from_state and after == to_state,
                exact_transition_observed=before == from_state and after == to_state,
                evidence_refs=evidence_refs,
            )

        observed: list[tuple[str, bool, str, str]] = []
        for observation in trace:
            step = _trace_step(observation, action_id)
            if (
                step is None
                or step.status in {AccessOutcome.ERROR, AccessOutcome.UNKNOWN}
                or observation.observed_outcome
                in {AccessOutcome.ERROR, AccessOutcome.UNKNOWN}
            ):
                continue
            transition = _projected_transition(projector, observation, step, action_id)
            if transition is None:
                continue
            before, after = transition
            observed.append(
                (
                    observation.observation_id,
                    step.status is AccessOutcome.ALLOWED
                    and not observation.auth_failed,
                    before,
                    after,
                )
            )

        if not observed:
            return self._unscoreable(
                "transition QDL norm has no complete before/after state evidence"
            )

        evidence_refs = tuple(dict.fromkeys(item[0] for item in observed))
        violated = any(
            completed and before == from_state and after == to_state
            for _observation_id, completed, before, after in observed
        )
        return _transition_verdict(
            from_state,
            to_state,
            violated=violated,
            exact_transition_observed=any(
                before == from_state and after == to_state
                for _observation_id, _completed, before, after in observed
            ),
            evidence_refs=evidence_refs,
        )

    @staticmethod
    def _unscoreable(
        rationale: str,
        *,
        deficits: tuple[OracleDeficit, ...] = (),
    ) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            model_id="sequence",
            deterministic=True,
            grounded=False,
            deficits=deficits,
        )


def _trace_step(
    observation: Observation,
    action_id: str | None,
) -> TraceStep | None:
    if observation.trace is None:
        return None
    return next(
        (
            step
            for step in observation.trace.steps
            if step.observation_id == observation.observation_id
            and (action_id is None or actions_align(step.method_id, action_id))
        ),
        None,
    )


def _projected_transition(
    projector: ObservationProjector,
    observation: Observation,
    step: TraceStep,
    action_id: str | None,
) -> tuple[str, str] | None:
    """Reuse the canonical runtime projection for one state transition."""

    method_id = normalize_action(action_id if action_id is not None else step.method_id)
    assert method_id is not None
    projected = projector.project(observation, method_id)
    for fact in projected.facts:
        if fact.predicate.name != "transition" or len(fact.args) != 3:
            continue
        before = atom_value(fact.args[1])
        after = atom_value(fact.args[2])
        if before is None or before == "unknown" or after is None:
            continue
        return before, after
    return None


def _paired_transition(
    trace: ObservationTrace,
    action_id: str | None,
) -> tuple[str, str, bool, tuple[str, ...]] | None:
    """Extract one transition from explicit before/after read evidence.

    The trace shape is the runtime boundary's contract, not a heuristic over
    arbitrary observations: a non-action read, one or more action probes, and
    a final non-action read.  This covers both read-back triples and complete
    concurrency batches.
    """

    if len(trace) < 3 or any(
        observation.observed_outcome in {AccessOutcome.ERROR, AccessOutcome.UNKNOWN}
        for observation in trace
    ):
        return None
    read_before, *action_observations, read_after = trace
    if (
        _trace_step(read_before, action_id) is not None
        or _trace_step(read_after, action_id) is not None
        or not action_observations
    ):
        return None
    aligned_actions = [
        observation
        for observation in action_observations
        if _trace_step(observation, action_id) is not None
    ]
    if not aligned_actions or any(
        step.status in {AccessOutcome.ERROR, AccessOutcome.UNKNOWN}
        for observation in aligned_actions
        if (step := _trace_step(observation, action_id)) is not None
    ):
        return None

    before = _projected_state(read_before)
    after = _projected_state(read_after)
    if before is None or after is None:
        return None
    completed = any(
        step.status is AccessOutcome.ALLOWED and not observation.auth_failed
        for observation in aligned_actions
        if (step := _trace_step(observation, action_id)) is not None
    )
    evidence_refs = tuple(
        dict.fromkeys(observation.observation_id for observation in trace)
    )
    return before, after, completed, evidence_refs


def _projected_state(observation: Observation) -> str | None:
    """Return the explicit after-state recorded for one observation."""

    step = _trace_step(observation, None)
    if step is None:
        return None
    return read_state(step.resource_state_after)


def _transition_verdict(
    from_state: str,
    to_state: str,
    *,
    violated: bool,
    exact_transition_observed: bool,
    evidence_refs: tuple[str, ...],
) -> PolicyVerdict:
    if violated:
        return PolicyVerdict(
            status=VerdictStatus.FAIL,
            confidence=1.0,
            rationale=f"forbidden transition completed: {from_state} -> {to_state}",
            evidence_refs=evidence_refs,
            model_id="sequence",
            deterministic=True,
            grounded=True,
        )

    rationale = (
        f"forbidden transition was observed but not completed: "
        f"{from_state} -> {to_state}"
        if exact_transition_observed
        else f"forbidden transition is absent from state evidence: "
        f"{from_state} -> {to_state}"
    )
    return PolicyVerdict(
        status=VerdictStatus.PASS,
        confidence=1.0,
        rationale=rationale,
        evidence_refs=evidence_refs,
        model_id="sequence",
        negative_scope=(
            ("state_before", "state_after", "action_outcome")
            if exact_transition_observed
            else ("state_before", "state_after")
        ),
        deterministic=True,
        grounded=True,
    )
