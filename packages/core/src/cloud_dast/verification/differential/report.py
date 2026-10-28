"""Deterministic difference report between two paired observations.

The report is the shared contract between the comparator (which measures a
control/treatment pair), the deficit classifier (which turns unexplained
variance into a grounding task), and the QDL projection (which persists
``paired``/``differs`` runtime facts).  It carries only safe dimensions —
field names, equality booleans, and bounded aggregate statistics; never raw
response values.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cloud_dast.model import TransportStatus

DIFFERENCE_DIMENSIONS: frozenset[str] = frozenset(
    {
        "aggregate",
        "outcome",
        "status",
        "fields",
        "value",
        "error",
        "latency",
    }
)
"""Closed dimension alphabet of the differential evidence constructor."""


@dataclass(frozen=True, slots=True)
class TimingEvidence:
    """Run-scoped robust latency statistics for a measured pair."""

    control_samples: int
    treatment_samples: int
    control_median_ms: float | None
    treatment_median_ms: float | None
    control_mad_ms: float | None
    treatment_mad_ms: float | None


@dataclass(frozen=True, slots=True)
class ConcurrencyEvidence:
    """Aggregate evidence for one parallel probe batch."""

    probes: int
    outcome_counts: tuple[tuple[str, int], ...]
    status_counts: tuple[tuple[TransportStatus | None, int], ...]
    unique_response_digests: int
    state_readback: bool
    state_differs: bool


@dataclass(frozen=True, slots=True)
class DiffReport:
    """Safe, deterministic comparison of one control/treatment pair."""

    action_id: str
    control_observation_id: str
    treatment_observation_id: str
    outcome_differs: bool = False
    status_differs: bool = False
    fields_only_control: tuple[str, ...] = ()
    fields_only_treatment: tuple[str, ...] = ()
    value_differs: tuple[str, ...] = ()
    error_differs: bool = False
    latency_class_differs: bool = False
    aggregate_differs: bool = False
    timing_evidence: TimingEvidence | None = None
    concurrency_evidence: ConcurrencyEvidence | None = None
    dimensions: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not self.dimensions:
            derived = [
                name
                for name, differs in (
                    ("outcome", self.outcome_differs),
                    ("status", self.status_differs),
                    (
                        "fields",
                        bool(self.fields_only_control or self.fields_only_treatment),
                    ),
                    ("value", bool(self.value_differs)),
                    ("error", self.error_differs),
                    ("latency", self.latency_class_differs),
                    ("aggregate", self.aggregate_differs),
                )
                if differs
            ]
            object.__setattr__(self, "dimensions", tuple(derived))
        unknown = set(self.dimensions) - DIFFERENCE_DIMENSIONS
        if unknown:
            raise ValueError(
                "unknown difference dimensions: " + ", ".join(sorted(unknown))
            )

    @property
    def has_variance(self) -> bool:
        """Return whether the pair differs in at least one dimension."""

        return bool(self.dimensions)

    @property
    def signature(self) -> str:
        """Return a stable discriminator for deficit deduplication."""

        parts = [
            f"{name}:{getattr(self, _DIMENSION_ATTRIBUTE[name])!r}"
            for name in self.dimensions
        ]
        if self.timing_evidence is not None:
            evidence = self.timing_evidence
            parts.append(
                "timing("
                f"samples={evidence.control_samples}/{evidence.treatment_samples},"
                f"median={evidence.control_median_ms}/{evidence.treatment_median_ms},"
                f"mad={evidence.control_mad_ms}/{evidence.treatment_mad_ms})"
            )
        if self.concurrency_evidence is not None:
            evidence = self.concurrency_evidence
            parts.append(
                "concurrency("
                f"probes={evidence.probes},"
                f"outcomes={evidence.outcome_counts},"
                f"statuses={_status_counts_text(evidence.status_counts)},"
                f"digests={evidence.unique_response_digests},"
                f"readback={evidence.state_readback},"
                f"state_differs={evidence.state_differs})"
            )
        return ";".join(parts) or "no-variance"


def _status_counts_text(
    counts: tuple[tuple[TransportStatus | None, int], ...],
) -> str:
    projected = tuple(
        (status.token if status is not None else None, count)
        for status, count in counts
    )
    return str(projected)


_DIMENSION_ATTRIBUTE: dict[str, str] = {
    "outcome": "outcome_differs",
    "status": "status_differs",
    "fields": "fields_only_treatment",
    "value": "value_differs",
    "error": "error_differs",
    "latency": "latency_class_differs",
    "aggregate": "aggregate_differs",
}


def diff_campaign_key(action_id: str, report: DiffReport) -> str:
    """Return a stable source key for one action/difference signature."""

    digest = hashlib.sha256(
        f"{action_id.removeprefix('action:')}|{report.signature}".encode("utf-8")
    ).hexdigest()
    return digest[:16]
