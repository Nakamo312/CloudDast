"""Runtime-neutral execution feedback contract."""

from dataclasses import dataclass

from cloud_dast.model import Check, Observation, VerdictStatus


@dataclass(frozen=True, slots=True)
class ExecutionFeedbackEntry:
    """One executed candidate and its deterministic outcome."""

    check: Check
    observation: Observation
    verdict: VerdictStatus
    grounded: bool = True
    proximity: float | None = None


@dataclass(frozen=True, slots=True)
class ExecutionFeedback:
    """Ordered feedback for a generator, oldest execution first."""

    entries: tuple[ExecutionFeedbackEntry, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.entries)


__all__ = ["ExecutionFeedback", "ExecutionFeedbackEntry"]
