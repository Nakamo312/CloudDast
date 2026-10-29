"""Campaign-wide live-call budget for QDL execution."""

from __future__ import annotations

from typing import Literal

from cloud_dast.contracts.execution import LiveRequest

type CallKind = Literal["check", "setup", "diff_leg"]


class CallLimits:
    """Own every live call spent by ordinary checks, setup, and diff legs.

    ``max_checks`` is a campaign-wide limit on live calls, not on resulting
    observations.  A setup create and each differential leg are therefore
    counted even when they do not produce an ordinary path observation.
    """

    def __init__(self, max_checks: int | None) -> None:
        if max_checks is not None and max_checks < 0:
            raise ValueError("max_checks must be non-negative or None")
        self._max_checks = max_checks
        self._live_calls = 0
        self._setup_calls = 0
        self._diff_legs = 0
        self._round_calls = 0
        self._round_limit: int | None = None
        self._differential_cap: int | None = None
        self._differential_reserve = 0

    @classmethod
    def from_request(cls, request: LiveRequest) -> CallLimits:
        return cls(request.max_checks)

    @property
    def max_checks(self) -> int | None:
        return self._max_checks

    @property
    def checks(self) -> int:
        """All executed checks, including setup and differential legs."""

        return self._live_calls

    @property
    def live_calls(self) -> int:
        return self._live_calls

    @property
    def setup_calls(self) -> int:
        return self._setup_calls

    @property
    def diff_legs(self) -> int:
        return self._diff_legs

    @property
    def exhausted(self) -> bool:
        return self._max_checks is not None and self._live_calls >= self._max_checks

    def begin_ordinary_round(
        self,
        *,
        limit: int | None = None,
        reserve: int = 0,
    ) -> None:
        """Start one ordinary round, optionally protecting differential calls."""

        if limit is not None and limit < 0:
            raise ValueError("ordinary round limit must be non-negative or None")
        if reserve < 0:
            raise ValueError("differential reserve must be non-negative")
        self._round_calls = 0
        self._round_limit = limit
        self._differential_cap = None
        self._differential_reserve = reserve

    def begin_differential_round(self, *, reserve: int | None = None) -> None:
        """Start a differential round, optionally capping its total spend."""

        if reserve is not None and reserve < 0:
            raise ValueError("differential reserve must be non-negative or None")
        self._round_calls = 0
        self._round_limit = None
        self._differential_cap = reserve

    def end_round(self) -> None:
        """Clear per-round policy while preserving the protected reserve."""

        self._round_calls = 0
        self._round_limit = None
        self._differential_cap = None

    def release_differential_reserve(self) -> None:
        self._differential_reserve = 0

    def can_spend(self, required: int = 1) -> bool:
        """Return whether the current round can spend more live calls."""

        if required < 0:
            raise ValueError("required live calls must be non-negative")
        if (
            self._round_limit is not None
            and self._round_calls + required > self._round_limit
        ):
            return False
        if (
            self._differential_cap is not None
            and self._live_calls + required > self._differential_cap
        ):
            return False
        if self._differential_cap is None and self._differential_reserve:
            protected = self._live_calls + self._differential_reserve + required
            if self._max_checks is not None and protected > self._max_checks:
                return False
        return (
            self._max_checks is None or self._live_calls + required <= self._max_checks
        )

    def spend(self, count: int = 1, *, kind: CallKind = "check") -> None:
        """Record live calls after the transport boundary executed them."""

        if count < 0:
            raise ValueError("spent live calls must be non-negative")
        if count and not self.can_spend(count):
            raise RuntimeError(
                f"budget would exceed max_checks={self._max_checks} "
                f"live_calls={self._live_calls} count={count}"
            )
        self._live_calls += count
        self._round_calls += count
        if kind == "setup":
            self._setup_calls += count
        elif kind == "diff_leg":
            self._diff_legs += count
