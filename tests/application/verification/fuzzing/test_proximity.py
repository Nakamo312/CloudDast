from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    completed,
    denied,
    duration,
    external_call,
    has,
)
from cloud_dast.runtime.candidates.feedback import (
    goal_key,
    goal_proximity,
    invariant_effect,
)
from cloud_dast.verification.invariant_projection import InvariantProjection

GET = Atom(value="action:get")


def norm_invariant(effect) -> InvariantProjection:
    fact = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="norm:1"), effect),
    )
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm:1",
        statement="formal norm",
        severity=Severity.HIGH,
        norm_fact=fact,
    )


def observation(**kwargs) -> Observation:
    values = {
        "check_id": "check",
        "scenario_id": "scenario",
        "observed_outcome": AccessOutcome.ALLOWED,
        "response_summary": "ok",
    }
    values.update(kwargs)
    return Observation(**values)


def test_invariant_effect_and_goal_key() -> None:
    invariant = norm_invariant(denied(GET))
    effect = invariant_effect(invariant)

    assert effect is not None
    assert effect.name == "denied"
    assert goal_key(invariant) == "denied"


def test_goal_key_falls_back_without_norm_fact() -> None:
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="informal",
        severity=Severity.HIGH,
    )

    assert invariant_effect(invariant) is None
    assert goal_key(invariant) == "generic"


def test_violation_is_full_proximity() -> None:
    assert goal_proximity(denied(GET), None, VerdictStatus.FAIL) == 1.0


def test_missing_effect_or_observation_scores_zero() -> None:
    assert goal_proximity(None, observation(), VerdictStatus.UNSCOREABLE) == 0.0
    assert goal_proximity(denied(GET), None, VerdictStatus.UNSCOREABLE) == 0.0


def test_transport_failure_scores_zero() -> None:
    unknown = observation(observed_outcome=AccessOutcome.UNKNOWN)

    assert goal_proximity(denied(GET), unknown, VerdictStatus.UNSCOREABLE) == 0.0


def test_outcome_goal_ladder() -> None:
    error = observation(observed_outcome=AccessOutcome.ERROR)
    denied_obs = observation(observed_outcome=AccessOutcome.DENIED)

    assert goal_proximity(denied(GET), error, VerdictStatus.UNSCOREABLE) == 1 / 3
    assert goal_proximity(denied(GET), denied_obs, VerdictStatus.UNSCOREABLE) == 2 / 3


def test_response_field_goal_requires_output() -> None:
    effect = has(Atom(value="subject:attacker"), Atom(value="secret"))
    with_output = observation(output={"payload": "value"})

    assert goal_proximity(effect, observation(output=None), VerdictStatus.PASS) == 1 / 3
    assert goal_proximity(effect, with_output, VerdictStatus.PASS) == 2 / 3


def test_latency_goal_requires_duration() -> None:
    effect = duration(GET, Atom(value=100))

    assert (
        goal_proximity(effect, observation(duration_ms=None), VerdictStatus.PASS)
        == 1 / 3
    )
    assert (
        goal_proximity(effect, observation(duration_ms=120.5), VerdictStatus.PASS)
        == 2 / 3
    )


def test_oob_goal_requires_probe_marker() -> None:
    effect = external_call(GET, Atom(value="oob"))

    assert (
        goal_proximity(effect, observation(probe_marker=None), VerdictStatus.PASS)
        == 1 / 3
    )
    assert (
        goal_proximity(effect, observation(probe_marker="canary"), VerdictStatus.PASS)
        == 2 / 3
    )


def test_sequence_goal_requires_trace() -> None:
    effect = completed(Atom(value="flow:checkout"))

    assert goal_proximity(effect, observation(trace=None), VerdictStatus.PASS) == 1 / 3
    assert (
        goal_proximity(effect, observation(trace=ExecutionTrace()), VerdictStatus.PASS)
        == 2 / 3
    )
