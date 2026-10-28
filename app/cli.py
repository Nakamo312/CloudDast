"""Run a graph-backed live service workflow."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from app.assembly import make_live_container
from cloud_dast.api import LiveRequest, LiveResult
from cloud_dast.composition.live import check_live_prerequisites
from cloud_dast.composition.profile import (
    LiveSettings,
    apply_profile_environment,
    load_profile,
    parse_environment_flag,
    resolve_live_settings,
)
from cloud_dast.composition.runtime import CloudDastRuntime
from cloud_dast.infrastructure.observability import configure_logging
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast_reporting import (
    CampaignInfo,
    CampaignMetricsView,
    ReportRenderer,
    ReportService,
    owasp_distribution,
)
from cloud_dast_reporting.formats.charts import OwaspSvgRenderer
from cloud_dast_reporting.formats.console import make_progress_renderer
from cloud_dast_reporting.formats.html import HtmlReportRenderer
from cloud_dast_reporting.formats.json import JsonReportRenderer
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer
from cloud_dast_reporting.formats.sarif import SarifReportRenderer

logger = logging.getLogger("cloud_dast.cli")
_UNSAFE_SERVICE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    args = _parser().parse_args(argv)
    profile = load_profile(args.profile) if args.profile else None
    if profile is not None:
        apply_profile_environment(profile)
    if args.skip_llm_grounding:
        os.environ["CLOUD_DAST_SKIP_LLM_GROUNDING"] = "1"
    if args.force_llm_grounding:
        os.environ["CLOUD_DAST_SKIP_LLM_GROUNDING"] = "0"
    if args.refresh_grounding:
        os.environ["CLOUD_DAST_GROUNDING_CACHE"] = "0"

    skip_llm_grounding = _skip_llm_grounding()
    settings = resolve_live_settings(args, profile)
    logger.info(
        "run_started mode=live-workflow service=%s method_id=%s event_log=%s",
        settings.service,
        settings.method_id or "-",
        settings.event_log or os.environ.get("CLOUD_DAST_EVENT_LOG", "-"),
    )
    prerequisites = check_live_prerequisites(
        settings.identity,
        require_model=not skip_llm_grounding,
    )
    if not prerequisites.ready:
        logger.error(
            "run_prerequisites_missing missing=%s", ",".join(prerequisites.missing)
        )
        raise RuntimeError(
            "live prerequisites are missing: " + ", ".join(prerequisites.missing)
        )
    event_path = settings.event_log or os.environ.get(
        "CLOUD_DAST_EVENT_LOG", "cloud-dast-live-events.jsonl"
    )
    if not settings.event_log and not os.environ.get("CLOUD_DAST_EVENT_LOG"):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        event_path = str(
            Path(settings.event_log_dir)
            / (
                f"cloud-dast-live-{_sanitize_service_slug(settings.service)}-"
                f"{timestamp}.jsonl"
            )
        )
    container = make_live_container(
        event_path=event_path,
        timeout=settings.timeout,
        endpoint_environment=settings.environment,
        safe_fields=settings.safe_fields,
        require_model=not skip_llm_grounding,
        method_prefix_aliases=settings.method_prefix_aliases,
    )
    with container as app, app() as run:
        runtime = run.get(CloudDastRuntime)
        progress = make_progress_renderer(
            settings.progress,
            service=settings.service,
            color=settings.progress_color,
        )
        progress.attach(runtime.event_subscriber)
        metrics = run.get(CampaignMetrics)
        progress.set_metrics(metrics)
        runtime.pre_scan_advisories(settings.service)
        result = runtime.live_workflow.execute(
            LiveRequest(
                service=settings.service,
                principal_id=settings.principal_id,
                resource_id=settings.resource_id,
                method_id=settings.method_id,
                max_checks=settings.max_checks,
            )
        )
        payload = _build_payload(result, event_path)
        logger.info(
            "run_completed mode=live-workflow observations=%d findings=%d",
            len(result.observations),
            len(result.findings),
        )

    if args.report_dir:
        payload["report"] = _write_campaign_report(
            result,
            metrics,
            settings,
            args.report_dir,
            MarkdownReportRenderer(),
        )
    print(json.dumps(payload, ensure_ascii=False))
    return _exit_code(payload)


def _build_payload(result: LiveResult, event_path: str) -> dict[str, object]:
    """Build a compact machine-readable CLI result.

    A coverage matrix can contain thousands of cells.  It is rendered by the
    dashboard and remains reconstructable from the durable event log; the CLI
    must not dump it as one enormous JSON line.
    """

    return {
        "mode": "live-workflow",
        "scenario_id": result.scenario.scenario_id,
        "observations": len(result.observations),
        "findings": [finding.finding_id for finding in result.findings],
        "coverage": (
            result.coverage.summary.model_dump(mode="json")
            if result.coverage is not None
            else None
        ),
        "norm_coverage": [row.to_dict() for row in result.norm_coverage],
        "replayed_observations": len(result.replayed_observations),
        "replayed_findings": [
            finding.finding_id for finding in result.replayed_findings
        ],
        "event_log": event_path,
        "owasp": [
            {
                "category": slice_.category,
                "count": slice_.count,
                "ring_fraction": round(slice_.ring_fraction, 4),
            }
            for slice_ in owasp_distribution(result.findings)
        ],
    }


def _write_campaign_report(
    result: LiveResult,
    metrics: CampaignMetricsView,
    settings: LiveSettings,
    report_dir: str,
    report_renderer: ReportRenderer,
) -> dict[str, str]:
    """Write JSON, SARIF, HTML, markdown, and OWASP SVG report artifacts."""

    directory = Path(report_dir)
    directory.mkdir(parents=True, exist_ok=True)
    markdown_path = directory / "report.md"
    json_path = directory / "report.json"
    sarif_path = directory / "report.sarif"
    html_path = directory / "report.html"
    chart_path = directory / "owasp-donut.svg"
    coverage = result.coverage
    bundle = ReportService().bundle(
        campaign=CampaignInfo(
            service=settings.service,
            principal_id=settings.principal_id,
            resource_id=settings.resource_id,
            method_id=settings.method_id,
            max_checks=settings.max_checks,
            scenario_id=result.scenario.scenario_id,
            campaign_id=coverage.campaign_id if coverage is not None else None,
            run_id=coverage.run_id if coverage is not None else None,
            plan_hash=coverage.plan_hash if coverage is not None else "",
        ),
        findings=result.findings,
        observations=result.observations,
        metrics=metrics.snapshot(),
        coverage=coverage,
    )
    markdown = report_renderer.render(bundle)
    if isinstance(markdown, bytes):
        markdown_path.write_bytes(markdown)
    else:
        markdown_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(
        JsonReportRenderer().render(bundle),
        encoding="utf-8",
    )
    sarif_path.write_text(
        SarifReportRenderer().render(bundle),
        encoding="utf-8",
    )
    html_path.write_text(
        HtmlReportRenderer().render(bundle),
        encoding="utf-8",
    )
    chart_path.write_text(
        OwaspSvgRenderer().render(bundle),
        encoding="utf-8",
    )
    logger.info(
        "campaign_report_written json=%s markdown=%s sarif=%s html=%s owasp_chart=%s",
        json_path,
        markdown_path,
        sarif_path,
        html_path,
        chart_path,
    )
    return {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "sarif": str(sarif_path),
        "html": str(html_path),
        "owasp_chart": str(chart_path),
    }


def _sanitize_service_slug(service: str) -> str:
    return _UNSAFE_SERVICE_SLUG.sub("_", service)


def _exit_code(payload: dict[str, object]) -> int:
    if payload.get("mode") != "live-workflow":
        return 0
    if payload.get("findings"):
        return 1
    return 2 if payload.get("observations") == 0 else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        default=os.environ.get("CLOUD_DAST_PROFILE"),
        help="TOML launch profile (default: CLOUD_DAST_PROFILE)",
    )
    parser.add_argument("--method-id")
    parser.add_argument("--identity")
    parser.add_argument("--service")
    parser.add_argument(
        "--principal-id", help="Live graph principal; defaults to identity"
    )
    parser.add_argument("--resource-id")
    parser.add_argument("--max-checks", type=int)
    parser.add_argument("--event-log")
    parser.add_argument(
        "--report-dir",
        help=(
            "write report.json, report.md, report.sarif, report.html, and the "
            "OWASP SVG charts into this directory"
        ),
    )
    parser.add_argument(
        "--environment", help="Neo4j endpoint environment, e.g. preprod"
    )
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--safe-field", action="append", default=[])
    parser.add_argument(
        "--progress",
        choices=("auto", "live", "plain", "off"),
        default=None,
        help="console progress mode (default: auto)",
    )
    parser.add_argument(
        "--progress-color",
        choices=("auto", "always", "never"),
        default=None,
        help="console progress color mode (default: auto)",
    )
    grounding_mode = parser.add_mutually_exclusive_group()
    grounding_mode.add_argument(
        "--skip-llm-grounding",
        action="store_true",
        help="reuse persisted semantic facts and skip LLM grounding",
    )
    grounding_mode.add_argument(
        "--force-llm-grounding",
        action="store_true",
        help="run LLM grounding even if the environment skips it",
    )
    parser.add_argument(
        "--refresh-grounding",
        action="store_true",
        help="ignore the semantic grounding cache for this run",
    )
    return parser


def _skip_llm_grounding() -> bool:
    return parse_environment_flag("CLOUD_DAST_SKIP_LLM_GROUNDING")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
