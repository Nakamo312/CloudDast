"""Cumulative goal proximity over multi-step path traces."""

from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
    VerdictStatus,
)
from cloud_dast.qdl.graph import allowed
from cloud_dast.runtime.candidates.feedback import (
    DELIVERED_PROXIMITY,
    VIOLATION_PROXIMITY,
    WITNESS_PROXIMITY,
    goal_proximity,
    trace_proximity,
)


@pytest.fixture
def outcome_invariant() -> InvariantProjection:
    from cloud_dast.model import Severity
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate

    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="test",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm"), allowed(Atom(value="action:ship"))),
        ),
    )


def _observation(outcome: AccessOutcome = AccessOutcome.ALLOWED) -> Observation:
    return Observation(
        check_id=f"check-{outcome.value}",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


def test_single_step_path_degrades_to_goal_proximity(outcome_invariant) -> None:
    effect = outcome_invariant.norm_fact.args[1]  # type: ignore[index]
    observation = _observation()

    assert trace_proximity(
        effect, (observation,), VerdictStatus.FAIL, step_count=1
    ) == goal_proximity(effect, observation, VerdictStatus.FAIL)


def test_fail_climbs_to_full_violation(outcome_invariant) -> None:
    effect = outcome_invariant.norm_fact.args[1]  # type: ignore[index]

    assert (
        trace_proximity(
            effect,
            (_observation(), _observation(), _observation()),
            VerdictStatus.FAIL,
            step_count=3,
        )
        == VIOLATION_PROXIMITY
    )


def test_earlier_confirmed_steps_keep_the_branch_alive(outcome_invariant) -> None:
    """A dead current step on a progressed chain outranks a dead first step."""

    effect = outcome_invariant.norm_fact.args[1]  # type: ignore[index]
    unknown = _observation(AccessOutcome.UNKNOWN)

    # Chain of three: two earlier steps delivered, current call died.
    progressed = trace_proximity(
        effect,
        (_observation(), _observation(), unknown),
        VerdictStatus.UNSCOREABLE,
        step_count=3,
    )
    # Chain of three: nothing delivered yet.
    dead_start = trace_proximity(
        effect,
        (unknown,),
        VerdictStatus.UNSCOREABLE,
        step_count=3,
    )

    assert dead_start == 0.0
    assert progressed == pytest.approx(2 / 3)
    assert progressed > dead_start


def test_witness_progress_is_fractional_within_the_current_atom(
    outcome_invariant,
) -> None:
    effect = outcome_invariant.norm_fact.args[1]  # type: ignore[index]

    delivered = trace_proximity(
        effect,
        (_observation(), _observation()),
        VerdictStatus.UNSCOREABLE,
        step_count=3,
    )

    # One confirmed step plus the current WITNESS atom (an allowed outcome
    # establishes the outcome channel), over three steps.
    assert delivered == pytest.approx((1 + WITNESS_PROXIMITY) / 3)
    assert delivered < VIOLATION_PROXIMITY
    assert delivered > (1 + DELIVERED_PROXIMITY) / 3
