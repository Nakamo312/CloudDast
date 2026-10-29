from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cloud_dast.contracts.metrics import TokenUsageSnapshot
from cloud_dast_reporting import (
    AblationCoverageCellArtifact,
    AblationDeficitArtifact,
    AblationFindingArtifact,
    AblationPathArtifact,
    AblationRunArtifact,
    aggregate_ablation_metrics,
    calculate_ablation_metrics,
)

START = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def _artifact(
    *,
    with_true_positive: bool = True,
    findings: tuple[AblationFindingArtifact, ...] | None = None,
) -> AblationRunArtifact:
    default_findings = (
        AblationFindingArtifact(
            finding_id="fp",
            occurred_at=START + timedelta(seconds=2),
            true_positive=False,
        ),
        *(
            (
                AblationFindingArtifact(
                    finding_id="tp",
                    occurred_at=START + timedelta(seconds=4),
                    true_positive=True,
                ),
            )
            if with_true_positive
            else ()
        ),
    )
    selected_findings = default_findings if findings is None else findings
    return AblationRunArtifact(
        started_at=START,
        ended_at=START + timedelta(seconds=10),
        checks=10,
        tokens=TokenUsageSnapshot(input_tokens=60, output_tokens=40),
        expected_count=2,
        findings=selected_findings,
        coverage_before=(
            AblationCoverageCellArtifact("cell-a", False),
            AblationCoverageCellArtifact("cell-b", False),
            AblationCoverageCellArtifact("cell-c", True),
            AblationCoverageCellArtifact("cell-d", False),
        ),
        coverage_after=(
            AblationCoverageCellArtifact("cell-a", True),
            AblationCoverageCellArtifact("cell-b", True),
            AblationCoverageCellArtifact("cell-c", True),
            AblationCoverageCellArtifact("cell-d", False),
            AblationCoverageCellArtifact("cell-new", True),
        ),
        paths=(
            AblationPathArtifact("path-recovered", True, True),
            AblationPathArtifact("path-still-blocked", True, False),
            AblationPathArtifact("path-always-completed", False, True),
        ),
        deficits=(
            AblationDeficitArtifact("deficit-a", True),
            AblationDeficitArtifact("deficit-b", True),
            AblationDeficitArtifact("deficit-c", False),
            AblationDeficitArtifact("deficit-d", True),
        ),
    )


def test_calculates_all_ablation_metrics_from_one_artifact() -> None:
    metrics = calculate_ablation_metrics(_artifact())

    assert metrics.tp_count == 1
    assert metrics.fp_count == 1
    assert metrics.fn_count == 1
    assert metrics.precision == pytest.approx(0.5)
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.f1 == pytest.approx(0.5)
    assert metrics.time_to_first_finding_ms == pytest.approx(4000)
    assert metrics.first_finding_censored is False
    assert metrics.findings_per_check == pytest.approx(0.1)
    assert metrics.findings_per_token == pytest.approx(0.01)
    assert metrics.findings_per_second == pytest.approx(0.1)
    assert metrics.coverage_cells_closed == 2
    assert metrics.blocked_paths_recovered == 1
    assert metrics.deficit_closure_rate == pytest.approx(0.75)


def test_no_true_positive_uses_wall_time_as_censored_value() -> None:
    metrics = calculate_ablation_metrics(_artifact(with_true_positive=False))

    assert metrics.tp_count == 0
    assert metrics.fp_count == 1
    assert metrics.fn_count == 2
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.time_to_first_finding_ms == pytest.approx(10000)
    assert metrics.first_finding_censored is True
    assert metrics.findings_per_check == 0.0
    assert metrics.findings_per_token == 0.0
    assert metrics.findings_per_second == 0.0


def test_aggregate_repeats_reports_mean_and_sample_std() -> None:
    first = calculate_ablation_metrics(_artifact())
    second = calculate_ablation_metrics(
        _artifact(
            findings=(
                AblationFindingArtifact(
                    finding_id="tp",
                    occurred_at=START + timedelta(seconds=4),
                    true_positive=True,
                ),
            )
        )
    )

    summary = aggregate_ablation_metrics((first, second))

    assert summary.run_count == 2
    assert summary.tp_count.mean == pytest.approx(1.0)
    assert summary.tp_count.std == pytest.approx(0.0)
    assert summary.precision.mean == pytest.approx(0.75)
    assert summary.precision.std == pytest.approx(0.3535533905932738)
    assert summary.first_finding_censored_count == 0


def test_aggregate_rejects_no_runs() -> None:
    with pytest.raises(ValueError, match="at least one ablation run"):
        aggregate_ablation_metrics(())


def test_artifact_rejects_duplicate_finding_ids() -> None:
    finding = AblationFindingArtifact(
        finding_id="duplicate",
        occurred_at=START,
        true_positive=False,
    )

    with pytest.raises(ValueError, match="finding identifiers must be unique"):
        AblationRunArtifact(
            started_at=START,
            ended_at=START,
            checks=0,
            tokens=TokenUsageSnapshot(),
            expected_count=0,
            findings=(finding, finding),
        )
