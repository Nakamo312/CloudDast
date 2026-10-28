from __future__ import annotations

import json
from dataclasses import dataclass

from app.cli import _write_campaign_report

from cloud_dast.api import LiveResult
from cloud_dast.composition.profile import LiveSettings
from cloud_dast_reporting import CampaignMetricsSnapshot
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer


@dataclass
class _MetricsView:
    snapshot_value: CampaignMetricsSnapshot

    def snapshot(self) -> CampaignMetricsSnapshot:
        return self.snapshot_value


def test_campaign_report_writes_canonical_json(
    tmp_path,
    finding,
    allowed_observation,
    scenario_position,
) -> None:
    result = LiveResult(
        scenario=scenario_position,
        observations=(allowed_observation,),
        findings=(finding,),
        replayed_observations=(),
        replayed_findings=(),
    )
    settings = LiveSettings(
        service="orders",
        identity="attacker",
        principal_id="attacker",
        resource_id="resource",
        method_id=None,
        max_checks=None,
        event_log=None,
        event_log_dir=str(tmp_path),
        environment=None,
        timeout=1.0,
        safe_fields=(),
        progress="off",
        progress_color="never",
    )
    metrics = _MetricsView(
        CampaignMetricsSnapshot(total_checks=1, total_findings=1),
    )

    paths = _write_campaign_report(
        result,
        metrics,
        settings,
        str(tmp_path),
        MarkdownReportRenderer(),
    )

    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    assert paths["json"] == str(report_path)
    assert (tmp_path / "report.md").is_file()
    assert paths["sarif"] == str(sarif_path)
    assert sarif_path.is_file()
    assert paths["html"] == str(tmp_path / "report.html")
    assert (tmp_path / "report.html").is_file()
    assert (tmp_path / "owasp-donut.svg").is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["campaign"]["service"] == "orders"
    assert report["findings"][0]["finding_id"] == finding.finding_id
    assert report["metrics"]["checks"] == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
