from __future__ import annotations

from cloud_dast.model import (
    Finding,
    Severity,
)
from cloud_dast_reporting import (
    CampaignInfo,
    FindingSummaryGroup,
    ReportService,
    finding_summary,
)


def _finding(
    vulnerability_class: str,
    *,
    cwe: tuple[str, ...] = (),
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        observation_id="observation",
        invariant_id="invariant",
        method_id="method",
        scenario_id="scenario",
        severity=severity,
        title="Finding",
        description="Observed violation",
        remediation="Fix policy",
        vulnerability_class=vulnerability_class,
        cwe=cwe,
    )


def test_finding_summary_groups_class_cwe_and_severity() -> None:
    first = _finding(
        "authorization-policy-bypass",
        cwe=("CWE-639", "CWE-284", "CWE-639"),
    )
    second = _finding(
        "authorization-policy-bypass",
        cwe=("CWE-284", "CWE-639"),
    )
    third = _finding("ssrf", cwe=("CWE-918",))

    assert finding_summary((third, second, first)) == (
        FindingSummaryGroup(
            vulnerability_class="authorization-policy-bypass",
            cwe=("CWE-284", "CWE-639"),
            severity=Severity.HIGH,
            count=2,
        ),
        FindingSummaryGroup(
            vulnerability_class="ssrf",
            cwe=("CWE-918",),
            severity=Severity.HIGH,
            count=1,
        ),
    )


def test_finding_summary_orders_severity_descending_within_a_group() -> None:
    low = _finding("secret-exposure", cwe=("CWE-200",), severity=Severity.LOW)
    critical = _finding(
        "secret-exposure",
        cwe=("CWE-200",),
        severity=Severity.CRITICAL,
    )

    assert finding_summary((low, critical)) == (
        FindingSummaryGroup(
            vulnerability_class="secret-exposure",
            cwe=("CWE-200",),
            severity=Severity.CRITICAL,
            count=1,
        ),
        FindingSummaryGroup(
            vulnerability_class="secret-exposure",
            cwe=("CWE-200",),
            severity=Severity.LOW,
            count=1,
        ),
    )


def test_report_bundle_materializes_the_finding_summary() -> None:
    first = _finding("bola", cwe=("CWE-639",))
    second = _finding("bola", cwe=("CWE-639",))
    third = _finding("fla", cwe=("CWE-285",), severity=Severity.CRITICAL)

    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(third, first, second),
    )

    assert bundle.finding_summary == (
        FindingSummaryGroup("bola", ("CWE-639",), Severity.HIGH, 2),
        FindingSummaryGroup("fla", ("CWE-285",), Severity.CRITICAL, 1),
    )
    assert sum(group.count for group in bundle.finding_summary) == len(bundle.findings)
