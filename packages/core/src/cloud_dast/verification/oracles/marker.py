from __future__ import annotations

from cloud_dast.model import (
    JsonValue,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import canonical_action_id, normalize_action
from cloud_dast.qdl.graph import Atom, reached
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.oracles.action_alignment import (
    action_alignment_rationale,
    actions_align,
)
from cloud_dast.verification.oracles.policy_verdict import (
    OracleDeficit,
    PolicyVerdict,
    WitnessRolePolicy,
)
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.projection import ObservationProjector


class MarkerOracle:
    """Primitive P5: verify a reached sink through explicit trace evidence.

    Response reflection and marker absence do not establish sink effects.
    """

    def __init__(
        self,
        *,
        adversarial_target: bool = False,
        witness_policy: WitnessRolePolicy | None = None,
    ) -> None:
        self._adversarial_target = adversarial_target
        self._policy = witness_policy or WitnessRolePolicy.load_default()

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        method_id: str | None = None,
        probe_fields: tuple[str, ...] = (),
        sink_types: dict[str, str] | None = None,
    ) -> PolicyVerdict:
        norm = NormView.from_invariant(invariant)
        if norm is None or norm.primitive != "marker":
            return self._unscoreable("invariant is not a marker QDL norm")
        mismatch = action_alignment_rationale(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        if not trace:
            return self._unscoreable("marker QDL norm has no observation")
        if not probe_fields:
            return self._unscoreable("marker QDL norm has no grounded probe fields")

        observation = trace[-1]
        if response_is_incomplete(observation):
            return self._unscoreable("target returned incomplete response evidence")
        marker = observation.probe_marker
        if not marker:
            return self._unscoreable(
                "marker observation has no non-empty candidate probe marker"
            )
        if self._adversarial_target:
            return self._unscoreable(
                "adversarial target policy does not trust in-band marker "
                "evidence without a corroborated witness",
                deficits=(
                    OracleDeficit(
                        kind="incomplete_negative_scope",
                        action_id=norm.action_id,
                        rationale="adversarial target requires a corroborated channel",
                    ),
                ),
            )

        # TraceStep.sinks_reached is the existing explicit effect channel.  The
        # projector is syntax-only, so first bind its step to this observation
        # and action instead of letting a caller relabel an unrelated trace.
        action = norm.action_id
        step = (
            next(
                (
                    step
                    for step in observation.trace.steps
                    if step.observation_id == observation.observation_id
                ),
                None,
            )
            if observation.trace is not None
            else None
        )
        if (
            step is not None
            and action is not None
            and actions_align(step.method_id, action)
            and step.scenario_id == observation.scenario_id
        ):
            method = normalize_action(action)
            assert method is not None
            projected = ObservationProjector().project(observation, method)
            if any(
                fact.predicate.name == "observed_reached"
                and reached(*fact.args)
                == reached(Atom(value=canonical_action_id(action)), norm.effect.args[1])
                for fact in projected.facts
            ):
                return PolicyVerdict(
                    status=VerdictStatus.FAIL,
                    confidence=1.0,
                    rationale="forbidden sink was reached through explicit trace evidence",
                    evidence_refs=(observation.observation_id,),
                    model_id="marker",
                    deterministic=True,
                    grounded=True,
                )

        grounded_fields = frozenset(field.casefold() for field in probe_fields)
        probe_sink_types = tuple(
            sink_type
            for field, sink_type in (sink_types or {}).items()
            if field.casefold() in grounded_fields
        )
        reflected = (
            any(
                _value_contains(value, marker) or _path_contains(path, marker)
                for path, value in _response_values(observation)
            )
            or marker in observation.response_summary
            or marker in (observation.error_reason or "")
        )
        candidate_only = bool(probe_sink_types) and all(
            self._policy.role_for(sink_type) == "candidate"
            for sink_type in probe_sink_types
        )
        rationale = (
            "candidate-tier marker reflection requires its dedicated structural oracle"
            if reflected and candidate_only
            else "marker reflection is not a grounded sink witness"
            if reflected
            else "marker absence has no complete negative sink witness scope"
        )
        return self._unscoreable(
            rationale,
            deficits=(
                OracleDeficit(
                    kind=(
                        "candidate_witness"
                        if reflected and candidate_only
                        else "echo_witness"
                        if reflected
                        else "incomplete_negative_scope"
                    ),
                    action_id=norm.action_id,
                    rationale=rationale,
                ),
            ),
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
            model_id="marker",
            deterministic=True,
            grounded=False,
            deficits=deficits,
        )


def _response_values(observation: Observation) -> tuple[tuple[str, JsonValue], ...]:
    values = observation.response_tree
    if observation.output is not None:
        values += observation.output.fields
    return values


def _value_contains(value: JsonValue, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, tuple):
        return any(_value_contains(item, marker) for item in value)
    return False


def _path_contains(path: str, marker: str) -> bool:
    return marker.casefold() in path.casefold()


def is_echo_path(
    path: str,
    probe_fields: frozenset[str],
    grounded_sink_fields: frozenset[str],
) -> bool:
    segments = tuple(
        segment.strip() for segment in path.casefold().split(".") if segment
    )
    if segments and segments[0] in {"request", "echo"}:
        return True
    if any(segment in grounded_sink_fields for segment in segments):
        return False
    return any(segment in probe_fields for segment in segments)


_INCOMPLETE_RESPONSE_PATHS = frozenset({"__truncated__", "not_available"})


def response_is_incomplete(observation: Observation) -> bool:
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
