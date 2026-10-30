"""Runtime-neutral execution feedback contract."""

from dataclasses import dataclass
from typing import Literal

from cloud_dast.model import Check, Observation, VerdictStatus

type SignalKind = Literal[
    "marker_echo",
    "latency_delta",
    "oob_callback",
    "content_delta",
    "known_content",
]


@dataclass(frozen=True, slots=True)
class Signal:
    """One class-free runtime signal with explicit evidence lineage."""

    kind: SignalKind
    action_id: str | None
    evidence_refs: tuple[str, ...]
    paths: tuple[str, ...] = ()
    marker: str | None = None
    delta_ms: float | None = None
    content: str | None = None

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise ValueError("witness signal must reference observation evidence")

    @property
    def signature(self) -> str:
        """Identify a deficit by kind and its paths, timing delta or marker."""

        if self.delta_ms is not None:
            return f"{self.kind}:{self.delta_ms}"
        if self.paths:
            return f"{self.kind}:{','.join(self.paths)}"
        if self.marker is not None:
            return f"{self.kind}:{self.marker}"
        return self.kind


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


__all__ = ["ExecutionFeedback", "ExecutionFeedbackEntry", "Signal", "SignalKind"]
