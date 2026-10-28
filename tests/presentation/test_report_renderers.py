from __future__ import annotations

import json

from cloud_dast_reporting import CampaignInfo, ReportService
from cloud_dast_reporting.formats.charts import OwaspSvgRenderer
from cloud_dast_reporting.formats.html import HtmlReportRenderer
from cloud_dast_reporting.formats.json import JsonReportRenderer
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer
from cloud_dast_reporting.formats.sarif import SarifReportRenderer


def test_every_report_format_renders_the_same_bundle() -> None:
    bundle = ReportService().bundle(campaign=CampaignInfo(service="orders"))

    markdown = MarkdownReportRenderer().render(bundle)
    machine_report = json.loads(JsonReportRenderer().render(bundle))
    sarif = json.loads(SarifReportRenderer().render(bundle))
    svg = OwaspSvgRenderer().render(bundle)
    html_report = HtmlReportRenderer().render(bundle)

    assert markdown.startswith("# Cloud DAST report\n")
    assert machine_report["schema_version"] == 1
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"')
    assert html_report.startswith("<!doctype html>\n")
