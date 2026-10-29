from __future__ import annotations

import json

import pytest

from cloud_dast.composition.run_provider import RunProvider
from cloud_dast.composition.runtime import CloudDastRuntime
from cloud_dast.infrastructure.advisory import AdvisoryPreScanService


class StaticFormalRepository:
    def load(self, source_id: str):
        raise AssertionError("formal repository must not be read during wiring")

    def load_merged(self, source_prefix: str):
        raise AssertionError("formal repository must not be read during wiring")


class FakeAdvisoryPreScan:
    def __init__(self) -> None:
        self.services: list[str] = []

    def pre_scan(self, service: str):
        self.services.append(service)
        return None


def test_run_provider_wires_disabled_advisory_pre_scan_by_default(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CLOUD_DAST_ADVISORY_PRESCAN", raising=False)

    service = RunProvider().advisory_pre_scan(StaticFormalRepository())

    assert isinstance(service, AdvisoryPreScanService)
    assert service.pre_scan("orders") is None


def test_enabled_advisory_pre_scan_requires_corpus_version(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ADVISORY_PRESCAN", "1")
    monkeypatch.setenv(
        "CLOUD_DAST_ADVISORY_SOURCES",
        json.dumps(
            [
                {
                    "kind": "osv",
                    "url": "https://api.osv.dev/v1/advisories",
                }
            ]
        ),
    )
    monkeypatch.setenv(
        "CLOUD_DAST_ADVISORY_PACKAGES",
        json.dumps(
            [
                {
                    "ecosystem": "pypi",
                    "name": "example",
                    "version": "1.5.0",
                }
            ]
        ),
    )
    monkeypatch.setenv(
        "CLOUD_DAST_ADVISORY_CACHE_DIR",
        str(tmp_path / "advisory-cache"),
    )

    with pytest.raises(RuntimeError, match="CORPUS_VERSION"):
        RunProvider().advisory_pre_scan(StaticFormalRepository())


def test_runtime_delegates_advisory_pre_scan() -> None:
    advisory = FakeAdvisoryPreScan()
    runtime = CloudDastRuntime(
        live_workflow=None,
        event_bus=None,
        event_subscriber=None,
        formal_ingestion=None,
        advisory_pre_scan=advisory,
    )

    assert runtime.pre_scan_advisories("orders") is None
    assert advisory.services == ["orders"]
