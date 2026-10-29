from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.cli import (
    _build_payload,
    _exit_code,
    _sanitize_service_slug,
    _skip_llm_grounding,
    _write_campaign_report,
    main,
)

from cloud_dast.contracts.assessment import CoverageMatrix, FieldCoverageCell
from cloud_dast.contracts.execution import LiveResult
from cloud_dast.contracts.metrics import CampaignTimingSnapshot
from cloud_dast_reporting import (
    CampaignMetricsSnapshot,
    TokenUsageSnapshot,
)
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer


def test_live_cli_payload_contains_coverage_summary_not_full_matrix(
    scenario_position,
) -> None:
    result = LiveResult(
        scenario=scenario_position,
        observations=(),
        findings=(),
        replayed_observations=(),
        replayed_findings=(),
        coverage=CoverageMatrix(
            service="lockbox",
            fields=(
                FieldCoverageCell(
                    field_id='{"name":"input_field","args":[...]}',
                    field_name="secret_id",
                    field_kind="input",
                    semantic_role="object_ref",
                    primitive="outcome",
                    status="covered",
                ),
            ),
        ),
    )

    payload = _build_payload(result, "/tmp/cloud-dast-events.jsonl")

    assert payload["coverage"] == {
        "total": 1,
        "covered": 1,
        "not_applicable": 0,
        "unresolved": 0,
        "blind": 0,
    }
    assert "cells" not in payload["coverage"]


def test_live_cli_writes_markdown_report_from_campaign_bundle(
    tmp_path,
    finding,
    scenario_position,
) -> None:
    result = LiveResult(
        scenario=scenario_position,
        observations=(),
        findings=(
            finding.model_copy(
                update={
                    "cwe": ("CWE-639",),
                    "owasp": ("API1",),
                    "stride": ("E",),
                }
            ),
        ),
        replayed_observations=(),
        replayed_findings=(),
        coverage=None,
    )
    metrics = SimpleNamespace(
        snapshot=lambda: CampaignMetricsSnapshot(
            tokens=TokenUsageSnapshot(
                input_tokens=100,
                cached_input_tokens=40,
                output_tokens=20,
                request_count=2,
            ),
            timing=CampaignTimingSnapshot(wall_time=timedelta(minutes=1)),
        )
    )
    settings = SimpleNamespace(
        service="orders",
        principal_id="principal-attacker",
        resource_id="resource-1",
        method_id=None,
        max_checks=None,
    )

    payload = _write_campaign_report(
        result,
        metrics,
        settings,
        str(tmp_path),
        MarkdownReportRenderer(),
    )

    markdown = Path(payload["markdown"]).read_text(encoding="utf-8")
    html = Path(payload["html"]).read_text(encoding="utf-8")
    assert "- Input tokens: 100" in markdown
    assert "- Total tokens: 120" in markdown
    assert "- Wall time: 0:01:00" in markdown
    assert "- CWE: `CWE-639`" in markdown
    assert "- OWASP: `API1`" in markdown
    assert "- STRIDE: `E`" in markdown
    assert html.startswith("<!doctype html>\n")


def test_live_cli_exit_code_distinguishes_empty_execution() -> None:
    assert _exit_code({"mode": "live-workflow", "findings": (), "observations": 0}) == 2
    assert _exit_code({"mode": "live-workflow", "findings": (), "observations": 1}) == 0
    assert (
        _exit_code({"mode": "live-workflow", "findings": (1,), "observations": 1}) == 1
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("", False),
    ],
)
def test_live_cli_parses_skip_llm_grounding_flags(
    monkeypatch,
    value: str,
    expected: bool,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_SKIP_LLM_GROUNDING", value)

    assert _skip_llm_grounding() is expected


def test_live_cli_rejects_invalid_skip_llm_grounding_flag(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_SKIP_LLM_GROUNDING", "maybe")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_SKIP_LLM_GROUNDING"):
        _skip_llm_grounding()


@pytest.mark.parametrize(
    ("service", "expected"),
    [
        ("lockbox", "lockbox"),
        (
            "yandex.cloud.lockbox.v1.PayloadService",
            "yandex.cloud.lockbox.v1.PayloadService",
        ),
        ("../../etc/passwd", ".._.._etc_passwd"),
        ("C:\\temp\\events", "C_temp_events"),
    ],
)
def test_live_cli_sanitizes_service_slug(service: str, expected: str) -> None:
    assert _sanitize_service_slug(service) == expected


def test_live_cli_main_fails_fast_on_invalid_skip_llm_grounding_flag(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_SKIP_LLM_GROUNDING", "maybe")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_SKIP_LLM_GROUNDING"):
        main([])


def test_live_cli_runs_advisory_pre_scan_before_campaign(monkeypatch, tmp_path):
    events: list[str] = []

    class FakeWorkflow:
        def execute(self, request):
            events.append(f"campaign:{request.service}")
            return SimpleNamespace(observations=(), findings=())

    class FakeRuntime:
        event_subscriber = object()
        live_workflow = FakeWorkflow()

        def get(self, dependency):
            del dependency
            return self

        def pre_scan_advisories(self, service: str):
            events.append(f"pre-scan:{service}")
            return None

    class FakeRun:
        def __enter__(self):
            return FakeRuntime()

        def get(self, dependency):
            del dependency
            return FakeRuntime()

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    class FakeApp:
        def __call__(self):
            return FakeRun()

        def get(self, dependency):
            return object()

    class FakeContainer:
        def __enter__(self):
            return FakeApp()

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    class FakeProgress:
        def attach(self, subscriber):
            del subscriber

        def set_metrics(self, metrics):
            del metrics

    settings = SimpleNamespace(
        service="orders",
        method_id=None,
        principal_id="attacker",
        resource_id="resource",
        max_checks=None,
        event_log=str(tmp_path / "events.jsonl"),
        event_log_dir=str(tmp_path),
        environment=None,
        timeout=None,
        safe_fields=(),
        progress="off",
        progress_color="never",
        identity="attacker",
        method_prefix_aliases={},
    )

    monkeypatch.setattr(
        "app.cli.resolve_live_settings",
        lambda args, profile: settings,
    )
    monkeypatch.setattr(
        "app.cli.check_live_prerequisites",
        lambda identity, require_model: SimpleNamespace(ready=True),
    )
    monkeypatch.setattr(
        "app.cli.make_live_container",
        lambda **kwargs: FakeContainer(),
    )
    monkeypatch.setattr(
        "app.cli.make_progress_renderer",
        lambda *args, **kwargs: FakeProgress(),
    )
    monkeypatch.setattr(
        "app.cli._build_payload",
        lambda result, event_path: {
            "mode": "live-workflow",
            "observations": 1,
            "findings": [],
        },
    )

    assert main([]) == 0
    assert events == ["pre-scan:orders", "campaign:orders"]


def test_live_cli_keeps_default_event_log_inside_configured_directory(
    monkeypatch,
    tmp_path,
):
    captured_event_paths: list[str] = []

    class FakeWorkflow:
        def execute(self, request):
            del request
            return SimpleNamespace(observations=(), findings=())

    class FakeRuntime:
        event_subscriber = object()
        live_workflow = FakeWorkflow()

        def get(self, dependency):
            del dependency
            return self

        def pre_scan_advisories(self, service: str):
            del service
            return None

    class FakeRun:
        def __enter__(self):
            return FakeRuntime()

        def get(self, dependency):
            del dependency
            return FakeRuntime()

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    class FakeApp:
        def __call__(self):
            return FakeRun()

        def get(self, dependency):
            return object()

    class FakeContainer:
        def __enter__(self):
            return FakeApp()

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    class FakeProgress:
        def attach(self, subscriber):
            del subscriber

        def set_metrics(self, metrics):
            del metrics

    settings = SimpleNamespace(
        service="../../outside",
        method_id=None,
        principal_id="attacker",
        resource_id="resource",
        max_checks=None,
        event_log=None,
        event_log_dir=str(tmp_path),
        environment=None,
        timeout=None,
        safe_fields=(),
        progress="off",
        progress_color="never",
        identity="attacker",
        method_prefix_aliases={},
    )

    monkeypatch.delenv("CLOUD_DAST_EVENT_LOG", raising=False)
    monkeypatch.setattr(
        "app.cli.resolve_live_settings",
        lambda args, profile: settings,
    )
    monkeypatch.setattr(
        "app.cli.check_live_prerequisites",
        lambda identity, require_model: SimpleNamespace(ready=True),
    )

    def capture_event_path(**kwargs):
        captured_event_paths.append(kwargs["event_path"])
        return FakeContainer()

    monkeypatch.setattr(
        "app.cli.make_live_container",
        capture_event_path,
    )
    monkeypatch.setattr(
        "app.cli.make_progress_renderer",
        lambda *args, **kwargs: FakeProgress(),
    )
    monkeypatch.setattr(
        "app.cli._build_payload",
        lambda result, event_path: {
            "mode": "live-workflow",
            "observations": 1,
            "findings": [],
        },
    )

    assert main([]) == 0

    event_path = Path(captured_event_paths[0])
    assert event_path.parent == tmp_path
    assert event_path.name.startswith("cloud-dast-live-.._.._outside-")
    assert event_path.name.endswith(".jsonl")
