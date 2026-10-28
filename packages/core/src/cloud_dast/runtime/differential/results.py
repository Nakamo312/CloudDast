"""Measurement records and partial results for differential execution."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.model import Check, Observation
from cloud_dast.verification.differential.report import DiffReport


@dataclass(frozen=True, slots=True)
class VarianceRecord:
    """One measured pair kept for variance grounding dispatch."""

    control: Observation
    treatment: Observation
    report: DiffReport
    control_check: Check | None = None
    treatment_check: Check | None = None


@dataclass(frozen=True, slots=True)
class PartialExecutionResult:
    """Evidence retained when a differential execution boundary fails."""

    checks: tuple[Check, ...]
    observations: tuple[Observation, ...]
    failed_checks: tuple[Check, ...] = ()


@dataclass(frozen=True, slots=True)
class PairPartialResult(PartialExecutionResult):
    """Completed legs of a partially executed control/treatment pair."""

    control: tuple[Check, Observation] | None = None
    treatment: tuple[Check, Observation] | None = None


@dataclass(frozen=True, slots=True)
class ReadBackPartialResult(PartialExecutionResult):
    """Completed legs of a partially executed read-back triple."""

    read_before: tuple[Check, Observation] | None = None
    write: tuple[Check, Observation] | None = None
    read_after: tuple[Check, Observation] | None = None


@dataclass(frozen=True, slots=True)
class ConcurrencyPartialResult(PartialExecutionResult):
    """Completed legs of a partially executed concurrency batch."""

    read_before: tuple[Check, Observation] | None = None
    read_after: tuple[Check, Observation] | None = None
    probes: tuple[tuple[Check, Observation], ...] = ()


class PartialExecutionError(ValueError):
    """A differential boundary failed after zero or more live calls."""

    def __init__(self, message: str, *, result: PartialExecutionResult) -> None:
        super().__init__(message)
        self.partial_result = result


__all__ = [
    "VarianceRecord",
    "ConcurrencyPartialResult",
    "PairPartialResult",
    "PartialExecutionError",
    "PartialExecutionResult",
    "ReadBackPartialResult",
]
