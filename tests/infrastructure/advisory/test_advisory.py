from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from cloud_dast.infrastructure.advisory import (
    AdvisoryPreScanService,
    AdvisoryResolver,
    AdvisorySource,
    FileAdvisoryCache,
    PackageVersion,
    project_affects,
)
from cloud_dast.infrastructure.advisory.cache import advisory_cache_key
from cloud_dast.infrastructure.advisory.parser import parse_advisory_payload
from cloud_dast.qdl.graph import Context


class FakeFetcher:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[AdvisorySource] = []

    def fetch(self, source: AdvisorySource) -> str:
        self.calls.append(source)
        return json.dumps(self.payload)


class RecordingFormalRepository:
    def __init__(self) -> None:
        self.saved: list[tuple[str, Any, Any]] = []

    def save(
        self,
        source_id: str,
        graph: Any,
        *,
        provenance: Any,
        adapter_version: str,
        mapping_report: Any,
    ) -> None:
        self.saved.append((source_id, graph, provenance))


def _osv_payload() -> dict[str, Any]:
    return {
        "id": "OSV-2026-1",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "2.0.0"},
                        ],
                    }
                ],
            }
        ],
    }


def _osv_source() -> AdvisorySource:
    return AdvisorySource(
        kind="osv",
        url="https://api.osv.dev/v1/advisories",
    )


def test_osv_records_project_only_affected_inventory_versions() -> None:
    records = parse_advisory_payload(_osv_source(), _osv_payload())
    graph = project_affects(
        records,
        (
            PackageVersion(
                ecosystem="pypi",
                name="example",
                version="1.5.0",
            ),
            PackageVersion(
                ecosystem="pypi",
                name="example",
                version="2.0.0",
            ),
            PackageVersion(
                ecosystem="pypi",
                name="other",
                version="1.5.0",
            ),
        ),
    )

    assert len(graph.facts) == 1
    fact = graph.facts[0]
    assert fact.context is Context.CONTRACT
    assert fact.predicate.name == "affects"
    assert fact.args[0].value == "pypi:example"
    assert fact.args[1].value == "1.5.0"


def test_osv_parser_preserves_multiple_events_as_disjoint_ranges() -> None:
    payload = {
        "id": "OSV-2026-2",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "2.0.0"},
                            {"introduced": "3.0.0"},
                            {"fixed": "4.0.0"},
                        ]
                    }
                ],
            }
        ],
    }

    records = parse_advisory_payload(_osv_source(), payload)
    graph = project_affects(
        records,
        (
            PackageVersion(ecosystem="pypi", name="example", version="2.5.0"),
            PackageVersion(ecosystem="pypi", name="example", version="3.5.0"),
        ),
    )

    assert [fact.args[1].value for fact in graph.facts] == ["3.5.0"]


def test_ghsa_and_nvd_payloads_normalize_version_bounds() -> None:
    ghsa = parse_advisory_payload(
        AdvisorySource(
            kind="ghsa",
            url="https://api.github.com/advisories",
        ),
        {
            "ghsa_id": "GHSA-1111-2222-3333",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "PIP", "name": "example"},
                    "vulnerable_version_range": ">= 1.0.0, < 2.0.0",
                }
            ],
        },
    )
    nvd = parse_advisory_payload(
        AdvisorySource(
            kind="nvd",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": (
                                                    "cpe:2.3:a:vendor:example:"
                                                    "1.0:*:*:*:*:*:*"
                                                ),
                                                "versionStartIncluding": "1.0",
                                                "versionEndExcluding": "2.0",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        },
    )

    assert ghsa[0].packages[0].ranges[0].introduced == "1.0.0"
    assert ghsa[0].packages[0].ranges[0].fixed == "2.0.0"
    assert nvd[0].packages[0].name == "a:vendor:example"
    assert nvd[0].packages[0].ranges[0].introduced == "1.0"
    assert nvd[0].packages[0].ranges[0].fixed == "2.0"


def test_advisory_source_allowlist_rejects_unrelated_hosts() -> None:
    with pytest.raises(ValidationError, match="not allowed"):
        AdvisorySource(kind="osv", url="https://example.com/advisories")


def test_resolver_reuses_versioned_cache(tmp_path) -> None:
    source = _osv_source()
    fetcher = FakeFetcher(_osv_payload())
    cache = FileAdvisoryCache(tmp_path)
    resolver = AdvisoryResolver(
        (source,),
        cache,
        fetcher,
        corpus_version="2026.10.20",
    )

    first = resolver.load()
    second = resolver.load()

    assert first.records == second.records
    assert len(fetcher.calls) == 1

    resolver = AdvisoryResolver(
        (source,),
        cache,
        fetcher,
        corpus_version="2026.10.21",
    )
    resolver.load()

    assert len(fetcher.calls) == 2


def test_cache_rejects_tampered_records(tmp_path) -> None:
    source = _osv_source()
    cache = FileAdvisoryCache(tmp_path)
    records = parse_advisory_payload(source, _osv_payload())
    cache.save(source, "2026.10.20", records)
    path = tmp_path / f"{advisory_cache_key(source, '2026.10.20')}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["records"][0]["advisory_id"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert cache.load(source, "2026.10.20") is None


def test_pre_scan_persists_source_tier_facts_before_campaign(tmp_path) -> None:
    repository = RecordingFormalRepository()
    service = AdvisoryPreScanService(
        repository,
        enabled=True,
        sources=(_osv_source(),),
        packages=(
            PackageVersion(
                ecosystem="pypi",
                name="example",
                version="1.5.0",
            ),
        ),
        corpus_version="2026.10.20",
        cache=FileAdvisoryCache(tmp_path),
        fetcher=FakeFetcher(_osv_payload()),
    )

    graph = service.pre_scan("orders")

    assert graph is not None
    assert len(graph.facts) == 1
    assert repository.saved[0][0] == "advisory:orders:2026.10.20"
    assert repository.saved[0][2]["source_kind"] == "advisory-corpus"
    assert repository.saved[0][2]["corpus_version"] == "2026.10.20"
