"""Tests for the B23 deficit cold-score arm."""

from __future__ import annotations

import pytest
from benchmarks.nsfy_bench.cold_score import (
    deficit_cold_score,
    rank_deficit_cold_scores,
)


def test_deficit_priority_preserves_the_campaign_critic_order() -> None:
    kinds = (
        "blocked_step",
        "missing_role",
        "missing_exposes",
        "response_semantics_ungrounded",
        "unexplained_variance",
        "missing_baseline",
        "fixture_type_deficit",
    )

    ordered = rank_deficit_cold_scores(
        deficit_cold_score(deficit_id=kind, deficit_kind=kind)
        for kind in reversed(kinds)
    )

    assert tuple(score.deficit_id for score in ordered) == kinds


def test_unknown_deficit_kind_is_lowest_priority() -> None:
    known = deficit_cold_score(
        deficit_id="fixture",
        deficit_kind="fixture_type_deficit",
    )
    unknown = deficit_cold_score(
        deficit_id="unknown",
        deficit_kind="novel-deficit",
    )

    assert unknown.priority == 99
    assert known.rank < unknown.rank


def test_evidence_tie_break_prefers_more_clues_and_observations() -> None:
    sparse = deficit_cold_score(
        deficit_id="sparse",
        deficit_kind="missing_role",
        clue_count=0,
        observation_count=0,
    )
    observed = deficit_cold_score(
        deficit_id="observed",
        deficit_kind="missing_role",
        clue_count=1,
        observation_count=2,
    )
    clue_rich = deficit_cold_score(
        deficit_id="clue-rich",
        deficit_kind="missing_role",
        clue_count=2,
        observation_count=1,
    )

    ordered = rank_deficit_cold_scores((sparse, observed, clue_rich))

    assert tuple(score.deficit_id for score in ordered) == (
        "clue-rich",
        "observed",
        "sparse",
    )


def test_identifier_is_the_final_deterministic_tie_break() -> None:
    first = deficit_cold_score(
        deficit_id="deficit:a",
        deficit_kind="missing_role",
        clue_count=2,
        observation_count=2,
    )
    second = deficit_cold_score(
        deficit_id="deficit:b",
        deficit_kind="missing_role",
        clue_count=2,
        observation_count=2,
    )

    assert first.rank < second.rank


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"deficit_id": "", "deficit_kind": "missing_role"},
            "deficit identifier must not be empty",
        ),
        (
            {
                "deficit_id": "deficit",
                "deficit_kind": "missing_role",
                "clue_count": -1,
            },
            "clue count must not be negative",
        ),
        (
            {
                "deficit_id": "deficit",
                "deficit_kind": "missing_role",
                "observation_count": -1,
            },
            "observation count must not be negative",
        ),
    ],
)
def test_deficit_cold_score_rejects_invalid_input(
    kwargs: dict[str, int | str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        deficit_cold_score(**kwargs)
