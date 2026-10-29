"""Deterministic ablation metrics over immutable run artifacts.

Metric calculation and repeat aggregation never execute checks or consult a
model.  A caller first freezes one finished run into
:class:`AblationRunArtifact`; both functions below are pure over that value.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from statistics import fmean, stdev

from cloud_dast.contracts.metrics import TokenUsageSnapshot


@dataclass(frozen=True, slots=True)
class AblationFindingArtifact:
    """One classified finding and its durable event timestamp."""

    finding_id: str
    occurred_at: datetime
    true_positive: bool


@dataclass(frozen=True, slots=True)
class AblationCoverageCellArtifact:
    """One stable coverage cell and its covered state in one snapshot."""

    cell_id: str
    covered: bool


@dataclass(frozen=True, slots=True)
class AblationPathArtifact:
    """Terminal path state used to identify a recovered blocked path."""

    path_id: str
    blocked_before: bool
    completed_after: bool


@dataclass(frozen=True, slots=True)
class AblationDeficitArtifact:
    """One campaign deficit and its final closure state."""

    deficit_id: str
    closed: bool


@dataclass(frozen=True, slots=True)
class AblationRunArtifact:
    """Immutable evidence for one finished ablation run."""

    started_at: datetime
    ended_at: datetime
    checks: int
    tokens: TokenUsageSnapshot
    expected_count: int
    findings: tuple[AblationFindingArtifact, ...] = ()
    coverage_before: tuple[AblationCoverageCellArtifact, ...] = ()
    coverage_after: tuple[AblationCoverageCellArtifact, ...] = ()
    paths: tuple[AblationPathArtifact, ...] = ()
    deficits: tuple[AblationDeficitArtifact, ...] = ()

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None or self.ended_at.tzinfo is None:
            raise ValueError("ablation run timestamps must be timezone-aware")
        if self.ended_at < self.started_at:
            raise ValueError("ablation run must end after it starts")
        if self.checks < 0:
            raise ValueError("check count must not be negative")
        if self.expected_count < 0:
            raise ValueError("expected finding count must not be negative")
        _validate_tokens(self.tokens)

        finding_ids = tuple(finding.finding_id for finding in self.findings)
        _validate_unique_ids(finding_ids, "finding")
        if (
            sum(finding.true_positive for finding in self.findings)
            > self.expected_count
        ):
            raise ValueError("true-positive count exceeds expected findings")
        for finding in self.findings:
            if finding.occurred_at.tzinfo is None:
                raise ValueError("finding timestamps must be timezone-aware")
            if not self.started_at <= finding.occurred_at <= self.ended_at:
                raise ValueError("finding timestamp is outside the run")

        _validate_unique_ids(
            (cell.cell_id for cell in self.coverage_before), "coverage cell"
        )
        _validate_unique_ids(
            (cell.cell_id for cell in self.coverage_after), "coverage cell"
        )
        _validate_unique_ids((path.path_id for path in self.paths), "path")
        _validate_unique_ids(
            (deficit.deficit_id for deficit in self.deficits), "deficit"
        )


@dataclass(frozen=True, slots=True)
class AblationRunMetrics:
    """Quality and efficiency metrics for one finished run."""

    tp_count: int
    fp_count: int
    fn_count: int
    precision: float
    recall: float
    f1: float
    time_to_first_finding_ms: float
    first_finding_censored: bool
    findings_per_check: float
    findings_per_token: float
    findings_per_second: float
    coverage_cells_closed: int
    blocked_paths_recovered: int
    deficit_closure_rate: float


@dataclass(frozen=True, slots=True)
class MetricDistribution:
    """Mean and sample standard deviation over repeat runs."""

    run_count: int
    mean: float
    std: float


@dataclass(frozen=True, slots=True)
class AblationRunSummary:
    """Mean±std aggregation of every ablation metric."""

    run_count: int
    tp_count: MetricDistribution
    fp_count: MetricDistribution
    fn_count: MetricDistribution
    precision: MetricDistribution
    recall: MetricDistribution
    f1: MetricDistribution
    time_to_first_finding_ms: MetricDistribution
    first_finding_censored_count: int
    findings_per_check: MetricDistribution
    findings_per_token: MetricDistribution
    findings_per_second: MetricDistribution
    coverage_cells_closed: MetricDistribution
    blocked_paths_recovered: MetricDistribution
    deficit_closure_rate: MetricDistribution


def calculate_ablation_metrics(artifact: AblationRunArtifact) -> AblationRunMetrics:
    """Calculate the R8 metrics from one immutable artifact.

    Efficiency metrics count true positives only, so false positives cannot
    improve an ablation result.  If a repeat finds no true positive, its
    time-to-first-finding value is the full wall-time budget and is explicitly
    marked censored; no failed repeat is silently dropped.
    """

    tp_count = sum(finding.true_positive for finding in artifact.findings)
    fp_count = len(artifact.findings) - tp_count
    fn_count = artifact.expected_count - tp_count
    precision = _ratio(tp_count, tp_count + fp_count, empty_value=1.0)
    recall = _ratio(tp_count, artifact.expected_count)
    f1_denominator = 2 * tp_count + fp_count + fn_count
    f1 = _ratio(2 * tp_count, f1_denominator)

    wall_time_ms = _elapsed_ms(artifact.started_at, artifact.ended_at)
    true_positive_times = [
        finding.occurred_at for finding in artifact.findings if finding.true_positive
    ]
    if true_positive_times:
        first_finding_ms = _elapsed_ms(
            artifact.started_at,
            min(true_positive_times),
        )
        first_finding_censored = False
    else:
        first_finding_ms = wall_time_ms
        first_finding_censored = True

    coverage_before = {cell.cell_id: cell.covered for cell in artifact.coverage_before}
    coverage_after = {cell.cell_id: cell.covered for cell in artifact.coverage_after}
    coverage_cells_closed = sum(
        not before_covered and coverage_after.get(cell_id, False)
        for cell_id, before_covered in coverage_before.items()
    )
    blocked_paths_recovered = sum(
        path.blocked_before and path.completed_after for path in artifact.paths
    )
    deficits_closed = sum(deficit.closed for deficit in artifact.deficits)

    return AblationRunMetrics(
        tp_count=tp_count,
        fp_count=fp_count,
        fn_count=fn_count,
        precision=precision,
        recall=recall,
        f1=f1,
        time_to_first_finding_ms=first_finding_ms,
        first_finding_censored=first_finding_censored,
        findings_per_check=_ratio(tp_count, artifact.checks),
        findings_per_token=_ratio(tp_count, artifact.tokens.total_tokens),
        findings_per_second=_ratio(tp_count, wall_time_ms / 1000),
        coverage_cells_closed=coverage_cells_closed,
        blocked_paths_recovered=blocked_paths_recovered,
        deficit_closure_rate=_ratio(deficits_closed, len(artifact.deficits)),
    )


def aggregate_ablation_metrics(
    metrics: Iterable[AblationRunMetrics],
) -> AblationRunSummary:
    """Aggregate repeat runs into mean±std for every metric."""

    runs = tuple(metrics)
    if not runs:
        raise ValueError("at least one ablation run is required")
    return AblationRunSummary(
        run_count=len(runs),
        tp_count=_distribution(run.tp_count for run in runs),
        fp_count=_distribution(run.fp_count for run in runs),
        fn_count=_distribution(run.fn_count for run in runs),
        precision=_distribution(run.precision for run in runs),
        recall=_distribution(run.recall for run in runs),
        f1=_distribution(run.f1 for run in runs),
        time_to_first_finding_ms=_distribution(
            run.time_to_first_finding_ms for run in runs
        ),
        first_finding_censored_count=sum(run.first_finding_censored for run in runs),
        findings_per_check=_distribution(run.findings_per_check for run in runs),
        findings_per_token=_distribution(run.findings_per_token for run in runs),
        findings_per_second=_distribution(run.findings_per_second for run in runs),
        coverage_cells_closed=_distribution(run.coverage_cells_closed for run in runs),
        blocked_paths_recovered=_distribution(
            run.blocked_paths_recovered for run in runs
        ),
        deficit_closure_rate=_distribution(run.deficit_closure_rate for run in runs),
    )


def _ratio(
    numerator: int | float,
    denominator: int | float,
    *,
    empty_value: float = 0.0,
) -> float:
    if denominator == 0:
        return empty_value
    return numerator / denominator


def _elapsed_ms(started_at: datetime, ended_at: datetime) -> float:
    return (ended_at - started_at).total_seconds() * 1000


def _distribution(values: Iterable[int | float]) -> MetricDistribution:
    samples = tuple(values)
    if not samples:
        raise ValueError("metric distribution requires at least one run")
    return MetricDistribution(
        run_count=len(samples),
        mean=fmean(samples),
        std=stdev(samples) if len(samples) > 1 else 0.0,
    )


def _validate_tokens(tokens: TokenUsageSnapshot) -> None:
    if any(
        value < 0
        for value in (
            tokens.input_tokens,
            tokens.cached_input_tokens,
            tokens.output_tokens,
            tokens.request_count,
        )
    ):
        raise ValueError("token usage must not be negative")
    if tokens.cached_input_tokens > tokens.input_tokens:
        raise ValueError("cached input tokens must not exceed input tokens")


def _validate_unique_ids(identifiers: Iterable[str], label: str) -> None:
    values = tuple(identifiers)
    if any(not value for value in values):
        raise ValueError(f"{label} identifiers must not be empty")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} identifiers must be unique")


__all__ = [
    "AblationCoverageCellArtifact",
    "AblationDeficitArtifact",
    "AblationFindingArtifact",
    "AblationPathArtifact",
    "AblationRunArtifact",
    "AblationRunMetrics",
    "AblationRunSummary",
    "MetricDistribution",
    "aggregate_ablation_metrics",
    "calculate_ablation_metrics",
]
