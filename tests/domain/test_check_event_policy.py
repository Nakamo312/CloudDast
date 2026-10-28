"""Replay admission is grounded in accepted field roles, not field names."""

from __future__ import annotations

import pytest

from cloud_dast.contracts.finding_examples import (
    is_replayable_check,
    replay_gaps,
)
from cloud_dast.model import Check


def _check(request: tuple[tuple[str, object], ...]) -> Check:
    return Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=request,
        identities=("attacker",),
    )


def test_order_id_replays_only_with_accepted_object_ref_role() -> None:
    check = _check((("order_id", "order-victim"),))

    assert not is_replayable_check(check)
    assert is_replayable_check(check, replayable_fields={"order_id"})


def test_session_id_without_role_fact_is_redacted_by_default() -> None:
    check = _check(
        (
            ("order_id", "order-victim"),
            ("session_id", "session-secret"),
        )
    )

    assert not is_replayable_check(
        check,
        replayable_fields={"order_id"},
    )
    assert replay_gaps(check, replayable_fields={"order_id"}) == ("session_id",)


def test_unknown_field_never_enters_replay() -> None:
    check = _check((("mystery", "value"),))

    assert not is_replayable_check(check, replayable_fields={"order_id"})
    assert replay_gaps(check, replayable_fields={"order_id"}) == ("mystery",)


def test_non_string_value_for_retained_field_is_a_replay_gap() -> None:
    check = _check((("order_id", 42),))

    assert not is_replayable_check(check, replayable_fields={"order_id"})
    assert replay_gaps(check, replayable_fields={"order_id"}) == ("order_id",)


def test_missing_roles_are_logged_as_deficits(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = _check((("session_id", "session-secret"),))

    with caplog.at_level(
        "WARNING",
        logger="cloud_dast.model.checks",
    ):
        assert not is_replayable_check(check)

    assert "method=get" in caplog.text
    assert "session_id" in caplog.text
