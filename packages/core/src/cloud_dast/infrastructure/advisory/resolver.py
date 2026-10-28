"""Pre-scan OSV, GHSA, and NVD advisories into source-tier QDL facts."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Self

from cloud_dast.infrastructure.advisory.cache import FileAdvisoryCache
from cloud_dast.infrastructure.advisory.models import (
    AFFECTS,
    AdvisoryRecord,
    AdvisorySource,
    PackageVersion,
)
from cloud_dast.infrastructure.advisory.parser import parse_advisory_payload
from cloud_dast.ports import FormalRepository
from cloud_dast.qdl.graph import Atom, Context, Fact, QdlGraph

ADVISORY_ADAPTER_VERSION = "advisory-resolver-v1"


class AdvisoryFetcher(Protocol):
    def fetch(self, source: AdvisorySource) -> str: ...


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


class HttpsAdvisoryFetcher:
    """The only component that downloads external advisory knowledge."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_NoRedirects())

    def fetch(self, source: AdvisorySource) -> str:
        request = urllib.request.Request(
            source.url,
            headers={
                "Accept": "application/json",
                "User-Agent": "cloud-dast-advisory/1",
            },
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                return response.read().decode("utf-8")
        except (OSError, UnicodeDecodeError, urllib.error.URLError) as error:
            raise RuntimeError(f"failed to fetch {source.kind} advisories") from error


@dataclass(frozen=True, slots=True)
class AdvisoryCorpus:
    """One deterministic corpus snapshot and its cache provenance."""

    records: tuple[AdvisoryRecord, ...]
    cache_hits: tuple[str, ...]
    fetched: tuple[str, ...]


class AdvisoryResolver:
    """Load a versioned corpus, preferring validated cache snapshots."""

    def __init__(
        self,
        sources: Iterable[AdvisorySource],
        cache: FileAdvisoryCache,
        fetcher: AdvisoryFetcher,
        *,
        corpus_version: str,
    ) -> None:
        self._sources = tuple(sources)
        self._cache = cache
        self._fetcher = fetcher
        self._corpus_version = corpus_version.strip()
        if not self._corpus_version:
            raise ValueError("advisory corpus_version must not be empty")
        identities = {(source.kind, source.url) for source in self._sources}
        if len(identities) != len(self._sources):
            raise ValueError("advisory sources must be unique")

    def load(self) -> AdvisoryCorpus:
        records_by_key: dict[str, AdvisoryRecord] = {}
        cache_hits: list[str] = []
        fetched: list[str] = []

        for source in self._sources:
            identity = f"{source.kind}:{source.url}"
            cached = self._cache.load(source, self._corpus_version)
            if cached is not None:
                cache_hits.append(identity)
                source_records = cached
            else:
                fetched.append(identity)
                source_records = parse_advisory_payload(
                    source,
                    self._fetcher.fetch(source),
                )
                self._cache.save(source, self._corpus_version, source_records)

            for record in source_records:
                records_by_key.setdefault(_record_key(record), record)

        return AdvisoryCorpus(
            records=tuple(records_by_key.values()),
            cache_hits=tuple(cache_hits),
            fetched=tuple(fetched),
        )


class AdvisoryPreScanService:
    """Materialize advisory facts before a campaign starts."""

    def __init__(
        self,
        repository: FormalRepository,
        *,
        enabled: bool = False,
        sources: Iterable[AdvisorySource] = (),
        packages: Iterable[PackageVersion] = (),
        corpus_version: str = "",
        cache: FileAdvisoryCache | None = None,
        fetcher: AdvisoryFetcher | None = None,
    ) -> None:
        self._repository = repository
        self._enabled = enabled
        self._packages = tuple(packages)
        self._corpus_version = corpus_version.strip()
        self._resolver = (
            AdvisoryResolver(
                sources,
                cache or FileAdvisoryCache("~/.cache/cloud-dast/advisory"),
                fetcher or HttpsAdvisoryFetcher(),
                corpus_version=self._corpus_version,
            )
            if enabled
            else None
        )

    @classmethod
    def from_environment(cls, repository: FormalRepository) -> Self:
        enabled = _parse_environment_flag("CLOUD_DAST_ADVISORY_PRESCAN")
        if not enabled:
            return cls(repository)

        sources = _sources_from_environment()
        packages = _packages_from_environment()
        corpus_version = os.environ.get(
            "CLOUD_DAST_ADVISORY_CORPUS_VERSION",
            "",
        ).strip()
        cache_dir = os.environ.get(
            "CLOUD_DAST_ADVISORY_CACHE_DIR",
            "~/.cache/cloud-dast/advisory",
        ).strip()
        if not corpus_version:
            raise RuntimeError(
                "CLOUD_DAST_ADVISORY_CORPUS_VERSION is required for pre-scan"
            )
        if not cache_dir:
            raise RuntimeError("CLOUD_DAST_ADVISORY_CACHE_DIR must not be empty")
        if not sources:
            raise RuntimeError("CLOUD_DAST_ADVISORY_SOURCES requires at least one")
        if not packages:
            raise RuntimeError("advisory package inventory must not be empty")

        return cls(
            repository,
            enabled=True,
            sources=sources,
            packages=packages,
            corpus_version=corpus_version,
            cache=FileAdvisoryCache(cache_dir),
        )

    def pre_scan(self, service: str) -> QdlGraph | None:
        """Load the corpus and persist its graph before campaign execution."""

        normalized_service = service.strip()
        if not normalized_service:
            raise ValueError("service must not be empty")
        if not self._enabled or self._resolver is None:
            return None

        corpus = self._resolver.load()
        graph = project_affects(corpus.records, self._packages)
        source_id = f"advisory:{normalized_service}:{self._corpus_version}"
        provenance: Mapping[str, Any] = {
            "service": normalized_service,
            "source_kind": "advisory-corpus",
            "corpus_version": self._corpus_version,
            "source_count": len(corpus.cache_hits) + len(corpus.fetched),
            "cache_hits": list(corpus.cache_hits),
            "fetched": list(corpus.fetched),
            "package_count": len(self._packages),
            "record_count": len(corpus.records),
        }
        mapping_report: Mapping[str, Any] = {
            "affected_fact_count": len(graph.facts),
            "cache_hits": list(corpus.cache_hits),
            "fetched": list(corpus.fetched),
        }
        self._repository.save(
            source_id,
            graph,
            provenance=provenance,
            adapter_version=ADVISORY_ADAPTER_VERSION,
            mapping_report=mapping_report,
        )
        return graph


def project_affects(
    records: Iterable[AdvisoryRecord],
    packages: Iterable[PackageVersion],
) -> QdlGraph:
    """Project matching package versions as contract-context ``affects`` facts."""

    facts: list[Fact] = []
    for package_version in packages:
        for record in records:
            for package in record.packages:
                if package.canonical_name != package_version.canonical_package:
                    continue
                if any(
                    version_range.matches(package_version.version)
                    for version_range in package.ranges
                ):
                    facts.append(
                        Fact(
                            context=Context.CONTRACT,
                            predicate=AFFECTS,
                            args=(
                                Atom(value=package.canonical_name),
                                Atom(value=package_version.version),
                            ),
                        )
                    )
    return QdlGraph(facts=tuple(facts))


def _record_key(record: AdvisoryRecord) -> str:
    return json.dumps(
        record.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
    )


def _parse_environment_flag(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if value in {"1", "true", "yes", "on", ""}:
        return value not in {"", "0", "false", "no", "off"}
    if value in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean flag")


def _sources_from_environment() -> tuple[AdvisorySource, ...]:
    raw = os.environ.get("CLOUD_DAST_ADVISORY_SOURCES", "").strip()
    if not raw:
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("CLOUD_DAST_ADVISORY_SOURCES must be JSON") from error
    if not isinstance(payload, list):
        raise RuntimeError("CLOUD_DAST_ADVISORY_SOURCES must be a JSON array")
    try:
        return tuple(AdvisorySource.model_validate(source) for source in payload)
    except ValueError as error:
        raise RuntimeError(f"invalid advisory source: {error}") from error


def _packages_from_environment() -> tuple[PackageVersion, ...]:
    inline = os.environ.get("CLOUD_DAST_ADVISORY_PACKAGES", "").strip()
    path = os.environ.get("CLOUD_DAST_ADVISORY_PACKAGE_FILE", "").strip()
    if inline and path:
        raise RuntimeError(
            "set either CLOUD_DAST_ADVISORY_PACKAGES or "
            "CLOUD_DAST_ADVISORY_PACKAGE_FILE, not both"
        )
    if path:
        try:
            inline = Path(path).expanduser().read_text(encoding="utf-8")
        except OSError as error:
            raise RuntimeError("cannot read advisory package inventory") from error
    if not inline:
        return ()
    try:
        payload = json.loads(inline)
    except json.JSONDecodeError as error:
        raise RuntimeError("advisory package inventory must be JSON") from error
    if not isinstance(payload, list):
        raise RuntimeError("advisory package inventory must be a JSON array")
    try:
        return tuple(PackageVersion.model_validate(item) for item in payload)
    except ValueError as error:
        raise RuntimeError(f"invalid advisory package: {error}") from error
