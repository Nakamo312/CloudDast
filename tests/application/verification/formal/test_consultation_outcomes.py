from __future__ import annotations

from itertools import product

import pytest

from cloud_dast.runtime.consultation.outcomes import (
    CONSULTATION_OUTCOMES,
    AttemptKey,
    OutcomePolicy,
    classify,
)


def _key(evidence: str = "obs-1") -> AttemptKey:
    return AttemptKey(
        scope="svc",
        work_item_id="work-item-1",
        evidence_signature=(evidence,),
    )


def test_outcome_alphabet_is_exactly_the_s33r_set() -> None:
    assert CONSULTATION_OUTCOMES == {
        "promoted",
        "parked",
        "rejected",
        "transient_error",
        "missing_evidence",
        "conflict",
    }


@pytest.mark.parametrize(
    ("observation", "expected"),
    [
        (
            dict(
                evidence_available=True,
                evidence_required=True,
                promoted=True,
            ),
            "promoted",
        ),
        (
            dict(
                evidence_available=True,
                evidence_required=True,
                promoted=False,
            ),
            "parked",
        ),
        (
            dict(
                evidence_available=True,
                evidence_required=False,
                promoted=False,
            ),
            "rejected",
        ),
        (
            dict(error=ValueError("infrastructure")),
            "rejected",
        ),
        (
            dict(error=RuntimeError("contract")),
            "transient_error",
        ),
        (
            dict(
                evidence_available=False,
                evidence_required=True,
            ),
            "missing_evidence",
        ),
        (
            dict(conflict=True, promoted=True),
            "conflict",
        ),
    ],
)
def test_every_outcome_has_one_deterministic_input(
    observation: dict,
    expected: str,
) -> None:
    assert classify(**observation) == expected
    assert classify(**observation) == expected


def test_classification_is_total_over_the_structured_alphabet() -> None:
    observations = (
        dict(
            conflict=conflict,
            error=error,
            evidence_available=evidence_available,
            evidence_required=evidence_required,
            promoted=promoted,
        )
        for conflict, error, evidence_available, evidence_required, promoted in product(
            (False, True),
            (None, ValueError("invalid contract"), RuntimeError("unavailable")),
            (False, True),
            (False, True),
            (False, True),
        )
    )

    assert {
        classify(**observation) for observation in observations
    } <= CONSULTATION_OUTCOMES


def test_policy_absorbs_outcomes_without_attempt_counts() -> None:
    policy = OutcomePolicy()
    observation = dict(
        evidence_available=True,
        evidence_required=True,
        promoted=False,
    )

    assert policy.should_dispatch(_key())
    assert policy.record(_key(), classify(**observation)) == "parked"

    for _ in range(100):
        assert policy.should_dispatch(_key()) is False
        assert policy.record(_key(), "promoted") == "parked"


def test_new_evidence_is_the_only_reopening_transition() -> None:
    policy = OutcomePolicy()
    policy.record(
        _key(),
        "transient_error",
    )

    assert policy.should_dispatch(_key()) is False
    assert policy.should_dispatch(_key("obs-2")) is True
    assert (
        policy.record(
            _key("obs-2"),
            "promoted",
        )
        == "promoted"
    )


def test_error_classification_uses_types_not_message_heuristics() -> None:
    assert classify() == "rejected"
    assert classify(error=ValueError("infrastructure")) == "rejected"
    assert classify(error=RuntimeError("contract")) == "transient_error"


def test_policy_does_not_depend_on_action_names_or_scheduling_order() -> None:
    policy = OutcomePolicy()
    first = AttemptKey("svc", "work-a", ("obs-1",))
    second = AttemptKey("svc", "work-b", ("obs-1",))
    observation = dict(
        evidence_available=True,
        evidence_required=True,
        promoted=False,
    )

    assert policy.record(first, classify(**observation)) == "parked"
    assert policy.record(second, classify(**observation)) == "parked"
    assert policy.states == {first: "parked", second: "parked"}


@pytest.mark.parametrize("invalid", ("invalid", None))
def test_invalid_outcome_does_not_absorb_an_attempt(invalid) -> None:
    policy = OutcomePolicy()

    with pytest.raises(ValueError, match="unknown consultation outcome"):
        policy.record(_key(), invalid)

    assert policy.should_dispatch(_key())
    assert policy.outcome_for(_key()) is None
    assert policy.record(_key(), "promoted") == "promoted"
    assert policy.record(_key(), invalid) == "promoted"
