from __future__ import annotations

from dataclasses import replace

from cloud_dast.model import Severity
from cloud_dast_reporting import (
    CampaignInfo,
    OwaspAxisScore,
    QdlCoverageCounts,
    QdlCoverageModel,
    QdlEffectCoverageItem,
    QdlFieldCoverageItem,
    QdlStateMachineCoverageModel,
    ReportService,
)
from cloud_dast_reporting.formats.html import HtmlReportRenderer
from cloud_dast_reporting.formats.html.radar import (
    canonical_owasp_api,
    owasp_radar_axes,
    owasp_radar_points,
)


def _bundle(finding, *findings, ground_truth=None):
    return ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(finding, *findings),
        owasp_ground_truth=ground_truth,
    )


def _coverage_model(
    cls: type[QdlCoverageModel] = QdlCoverageModel,
) -> QdlCoverageModel:
    field_cells = (
        QdlFieldCoverageItem(
            field_id="field:owner",
            field_name="owner",
            field_kind="input",
            semantic_role="privileged_attribute",
            primitive="differential",
            status="covered",
            deficit=None,
            rationale="observed",
            request_executed=True,
            oracle_witness_observed=True,
        ),
        QdlFieldCoverageItem(
            field_id="field:status",
            field_name="status",
            field_kind="output",
            semantic_role="state_transition",
            primitive="marker",
            status="unresolved",
            deficit="capability_blind",
            rationale="no witness",
            request_executed=True,
            oracle_witness_observed=False,
        ),
    )
    effect_cells = (
        QdlEffectCoverageItem(
            effect_id="effect:changed",
            effect_kind="changed",
            primitive="marker",
            status="unresolved",
            deficit="setup_blind",
            rationale="not observed",
        ),
    )
    return cls(
        service="orders",
        fields=QdlCoverageCounts(
            total=2,
            covered=1,
            unresolved=1,
            blind=0,
            not_applicable=0,
        ),
        effects=QdlCoverageCounts(
            total=1,
            covered=0,
            unresolved=1,
            blind=0,
            not_applicable=0,
        ),
        by_field_kind={
            "input": QdlCoverageCounts(
                total=1,
                covered=1,
                unresolved=0,
                blind=0,
                not_applicable=0,
            ),
            "output": QdlCoverageCounts(
                total=1,
                covered=0,
                unresolved=1,
                blind=0,
                not_applicable=0,
            ),
        },
        deficit_counts={"capability_blind": 1, "setup_blind": 1},
        field_cells=field_cells,
        effect_cells=effect_cells,
        gaps=(field_cells[1], effect_cells[0]),
        state_machine=QdlStateMachineCoverageModel(
            states=QdlCoverageCounts(
                total=2,
                covered=1,
                unresolved=1,
                blind=0,
                not_applicable=0,
            ),
            transitions=QdlCoverageCounts(
                total=1,
                covered=0,
                unresolved=1,
                blind=0,
                not_applicable=0,
            ),
            forbidden_states=QdlCoverageCounts(
                total=1,
                covered=0,
                unresolved=0,
                blind=1,
                not_applicable=0,
            ),
            initial_states=("draft",),
            reachable_states=("draft", "published"),
            mismatches=0,
        ),
    )


def _bundle_with_coverage(
    cls: type[QdlCoverageModel] = QdlCoverageModel,
):
    bundle = ReportService().bundle(campaign=CampaignInfo(service="orders"))
    return replace(bundle, coverage=_coverage_model(cls))


def test_radar_axes_come_from_class_catalog(finding) -> None:
    axes = owasp_radar_axes()

    assert [code for code, _title in axes] == [
        "API1:2023",
        "API2:2023",
        "API3:2023",
        "API4:2023",
        "API5:2023",
        "API6:2023",
        "API7:2023",
        "API8:2023",
        "API9:2023",
        "API10:2023",
    ]


def test_radar_uses_findings_share_without_ground_truth(finding) -> None:
    first = finding.model_copy(update={"owasp": ("API1",)})
    second = finding.model_copy(
        update={"finding_id": "finding-2", "owasp": ("API1", "API3")}
    )

    points = {point.code: point for point in owasp_radar_points(_bundle(first, second))}

    assert points["API1:2023"].value == 1.0
    assert points["API1:2023"].findings == 2
    assert points["API3:2023"].value == 0.5
    assert points["API6:2023"].value == 0.0


def test_radar_uses_ground_truth_recall_and_maps_2019_to_2023(
    finding,
) -> None:
    tagged = finding.model_copy(update={"owasp": ("API1", "API3")})
    ground_truth = (
        OwaspAxisScore("API1", expected=2, matched=1),
        OwaspAxisScore("API3:2019", expected=1, matched=1),
        OwaspAxisScore("API6:2019", expected=1, matched=0),
    )

    points = {
        point.code: point
        for point in owasp_radar_points(_bundle(tagged, ground_truth=ground_truth))
    }

    assert points["API1:2023"].value == 0.5
    assert points["API3:2023"].expected == 2
    assert points["API3:2023"].matched == 1
    assert points["API3:2023"].value == 0.5


def test_canonical_owasp_mapping_is_owned_by_renderer() -> None:
    assert canonical_owasp_api("API1") == (
        "API1:2023",
        "Broken Object Level Authorization",
    )
    assert canonical_owasp_api("API6:2019")[0] == "API3:2023"
    assert canonical_owasp_api("API7:2019")[0] == "API8:2023"


def test_html_report_is_self_contained_and_embeds_radar(finding) -> None:
    tagged = finding.model_copy(update={"owasp": ("API1", "API3")})
    report = HtmlReportRenderer().render(_bundle(tagged))

    assert report.startswith("<!doctype html>\n")
    assert "<script" not in report
    assert "<iframe" not in report
    assert 'src="' not in report
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in report
    assert "API1:2023" in report
    assert "Broken Object Level Authorization" in report
    assert "100.0%" in report


def test_html_report_marks_ground_truth_mode(finding) -> None:
    tagged = finding.model_copy(update={"owasp": ("API1",)})
    ground_truth = (OwaspAxisScore("API1", expected=2, matched=1),)

    report = HtmlReportRenderer().render(_bundle(tagged, ground_truth=ground_truth))

    assert "Ground truth is attached." in report
    assert "50.0%" in report
    assert "ground-truth recall" in report


def test_html_report_renders_finding_summary_grouping(finding) -> None:
    first = finding.model_copy(
        update={
            "finding_id": "finding-1",
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ("CWE-862", "CWE-284"),
        }
    )
    second = finding.model_copy(
        update={
            "finding_id": "finding-2",
            "vulnerability_class": "secret-exposure",
            "cwe": ("CWE-200",),
            "severity": Severity.CRITICAL,
        }
    )

    report = HtmlReportRenderer().render(_bundle(first, second))

    assert "Findings by class, CWE, and severity" in report
    assert (
        "<tr><td><code>authorization-policy-bypass</code></td>"
        '<td><span class="chip">CWE-284</span>'
        '<span class="chip">CWE-862</span></td>'
        "<td>high</td><td>1</td></tr>" in report
    )
    assert (
        "<tr><td><code>secret-exposure</code></td>"
        '<td><span class="chip">CWE-200</span></td>'
        "<td>critical</td><td>1</td></tr>" in report
    )


def test_html_report_escapes_untrusted_values(finding) -> None:
    dangerous = finding.model_copy(
        update={
            "title": "<script>alert('Cloud DAST')</script>",
            "description": "Injected <b>description</b>",
            "remediation": "Patch & verify",
        }
    )

    report = HtmlReportRenderer().render(_bundle(dangerous))

    assert "&lt;script&gt;" in report
    assert "&lt;b&gt;description&lt;/b&gt;" in report
    assert "Patch &amp; verify" in report
    assert "<script>alert(" not in report


def test_html_report_renders_qdl_field_and_effect_cells() -> None:
    report = HtmlReportRenderer().render(_bundle_with_coverage())

    assert "<summary>QDL coverage</summary>" in report
    assert '<th scope="col">Field</th>' in report
    assert (
        "<tr><td><code>owner</code></td><td>input</td>"
        "<td>privileged_attribute</td><td>differential</td>"
        "<td>covered</td><td>none</td><td>yes</td><td>no</td>"
        "<td>yes</td></tr>" in report
    )
    assert (
        "<tr><td><code>status</code></td><td>output</td>"
        "<td>state_transition</td><td>marker</td>"
        "<td>unresolved</td><td>capability blind</td>"
        "<td>yes</td><td>no</td><td>no</td></tr>" in report
    )
    assert '<th scope="col">Effect</th>' in report
    assert (
        "<tr><td><code>changed</code></td><td>marker</td>"
        "<td>unresolved</td><td>setup blind</td></tr>" in report
    )
    assert (
        "<tr><td><code>input</code></td><td>1</td><td>1</td>"
        "<td>0</td><td>0</td><td>0</td></tr>" in report
    )
    assert "<tr><td><code>capability blind</code></td><td>1</td></tr>" in report
    assert (
        "<tr><td><code>field</code></td><td><code>status</code></td>"
        "<td>marker</td><td>unresolved</td>"
        "<td>capability blind</td></tr>" in report
    )
    assert "<h3>State machine coverage</h3>" in report
    assert "<dt>Initial states</dt><dd>draft</dd>" in report


def test_html_report_does_not_access_legacy_qdl_coverage_fields() -> None:
    class LegacyFreeCoverage(QdlCoverageModel):
        def __getattribute__(self, name: str):
            if name in {"target", "cells"}:
                raise AssertionError(f"legacy coverage field accessed: {name}")
            return super().__getattribute__(name)

    report = HtmlReportRenderer().render(_bundle_with_coverage(LegacyFreeCoverage))

    assert "<summary>QDL coverage</summary>" in report
