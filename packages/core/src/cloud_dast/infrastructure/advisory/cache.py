"""Versioned, content-addressed cache for normalized advisory records."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from cloud_dast.infrastructure.advisory.models import AdvisoryRecord, AdvisorySource

ADVISORY_CACHE_VERSION = 1
ADVISORY_NORMALIZER_VERSION = 1


class FileAdvisoryCache:
    """Persist one validated corpus snapshot per source and corpus version."""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory).expanduser()
        self._directory.mkdir(parents=True, exist_ok=True)

    def load(
        self,
        source: AdvisorySource,
        corpus_version: str,
    ) -> tuple[AdvisoryRecord, ...] | None:
        key = advisory_cache_key(source, corpus_version)
        path = self._directory / f"{key}.json"
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            records = tuple(
                AdvisoryRecord.model_validate(record) for record in payload["records"]
            )
        except (OSError, KeyError, TypeError, ValueError):
            return None
        expected_source = source.model_dump(mode="json")
        if (
            payload.get("cache_version") != ADVISORY_CACHE_VERSION
            or payload.get("normalizer_version") != ADVISORY_NORMALIZER_VERSION
            or payload.get("key") != key
            or payload.get("corpus_version") != corpus_version
            or payload.get("source") != expected_source
            or payload.get("records_hash") != _records_hash(records)
        ):
            return None
        return records

    def save(
        self,
        source: AdvisorySource,
        corpus_version: str,
        records: tuple[AdvisoryRecord, ...],
    ) -> None:
        key = advisory_cache_key(source, corpus_version)
        payload = {
            "cache_version": ADVISORY_CACHE_VERSION,
            "normalizer_version": ADVISORY_NORMALIZER_VERSION,
            "key": key,
            "corpus_version": corpus_version,
            "source": source.model_dump(mode="json"),
            "records_hash": _records_hash(records),
            "records": [record.model_dump(mode="json") for record in records],
        }
        temporary = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self._directory,
            prefix=f"{key}.",
            suffix=".tmp",
            delete=False,
        )
        try:
            with temporary:
                json.dump(payload, temporary, ensure_ascii=False, sort_keys=True)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary.name, self._directory / f"{key}.json")
        finally:
            if os.path.exists(temporary.name):
                os.unlink(temporary.name)


def advisory_cache_key(source: AdvisorySource, corpus_version: str) -> str:
    identity = {
        "cache_version": ADVISORY_CACHE_VERSION,
        "normalizer_version": ADVISORY_NORMALIZER_VERSION,
        "corpus_version": corpus_version,
        "source": source.model_dump(mode="json"),
    }
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _records_hash(records: tuple[AdvisoryRecord, ...]) -> str:
    canonical = json.dumps(
        [record.model_dump(mode="json") for record in records],
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
