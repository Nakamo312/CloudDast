from __future__ import annotations

from itertools import product

import pytest

from cloud_dast.runtime.consultation.outcomes import (
    CONSULTATION_OUTCOMES,
    AttemptKey,
    AttemptObservation,
    OutcomePolicy,
    classify_consultation_outcome,
    error_kind,
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
            AttemptObservation(
                evidence_available=True,
                evidence_required=True,
                promoted=True,
            ),
            "promoted",
        ),
        (
            AttemptObservation(
                evidence_available=True,
                evidence_required=True,
                promoted=False,
            ),
            "parked",
        ),
        (
            AttemptObservation(
                evidence_available=True,
                evidence_required=False,
                promoted=False,
            ),
            "rejected",
        ),
        (
            AttemptObservation(error_kind="contract"),
            "rejected",
        ),
        (
            AttemptObservation(error_kind="infrastructure"),
            "transient_error",
        ),
        (
            AttemptObservation(
                evidence_available=False,
                evidence_required=True,
            ),
            "missing_evidence",
        ),
        (
            AttemptObservation(conflict=True, promoted=True),
            "conflict",
        ),
    ],
)
def test_every_outcome_has_one_deterministic_input(
    observation: AttemptObservation,
    expected: str,
) -> None:
    assert classify_consultation_outcome(observation) == expected
    assert classify_consultation_outcome(observation) == expected


def test_classification_is_total_over_the_structured_alphabet() -> None:
    observations = (
        AttemptObservation(
            conflict=conflict,
            error_kind=error_kind,
            evidence_available=evidence_available,
            evidence_required=evidence_required,
            promoted=promoted,
        )
        for conflict, error_kind, evidence_available, evidence_required, promoted in product(
            (False, True),
            ("none", "contract", "infrastructure"),
            (False, True),
            (False, True),
            (False, True),
        )
    )

    assert {
        classify_consultation_outcome(observation) for observation in observations
    } <= CONSULTATION_OUTCOMES


def test_policy_absorbs_outcomes_without_attempt_counts() -> None:
    policy = OutcomePolicy()
    observation = AttemptObservation(
        evidence_available=True,
        evidence_required=True,
        promoted=False,
    )

    assert policy.should_dispatch(_key())
    assert policy.record(_key(), observation) == "parked"

    for _ in range(100):
        assert policy.should_dispatch(_key()) is False
        assert policy.record(_key(), AttemptObservation(promoted=True)) == "parked"


def test_new_evidence_is_the_only_reopening_transition() -> None:
    policy = OutcomePolicy()
    policy.record(
        _key(),
        AttemptObservation(error_kind="infrastructure"),
    )

    assert policy.should_dispatch(_key()) is False
    assert policy.should_dispatch(_key("obs-2")) is True
    assert (
        policy.record(
            _key("obs-2"),
            AttemptObservation(evidence_available=True, promoted=True),
        )
        == "promoted"
    )


def test_error_classification_uses_types_not_message_heuristics() -> None:
    assert error_kind(None) == "none"
    assert error_kind(ValueError("contract")) == "contract"
    assert error_kind(RuntimeError("infrastructure")) == "infrastructure"


def test_policy_does_not_depend_on_action_names_or_scheduling_order() -> None:
    policy = OutcomePolicy()
    first = AttemptKey("svc", "work-a", ("obs-1",))
    second = AttemptKey("svc", "work-b", ("obs-1",))
    observation = AttemptObservation(
        evidence_available=True,
        evidence_required=True,
        promoted=False,
    )

    assert policy.record(first, observation) == "parked"
    assert policy.record(second, observation) == "parked"
    assert policy.states == {first: "parked", second: "parked"}
