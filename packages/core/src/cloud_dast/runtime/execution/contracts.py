"""Runtime prefilter result carrying live fuzz sessions."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.extensions import FuzzSession
from cloud_dast.model import Check


@dataclass(frozen=True, slots=True)
class PrefilterResult:
    """Whole-path preview; empty checks invalidate solutions, retaining sessions."""

    seeds: tuple[Check, ...]
    checks: tuple[Check, ...]
    sessions: tuple[FuzzSession | None, ...]
    status: str


__all__ = ["PrefilterResult"]
