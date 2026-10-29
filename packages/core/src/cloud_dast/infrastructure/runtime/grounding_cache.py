"""File-backed content-addressed cache for validated grounding graphs."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from cloud_dast.qdl.graph import Context, QdlGraph

_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CACHE_VERSION = 2


class FileGroundingCache:
    """Persist one JSON document per validated grounding result.

    Keys are SHA-256 digests produced by the application over the full cache
    identity (model namespace, prompt, response schema, input slice, and its
    invalidation inputs).  Rejecting any other key prevents path traversal and
    keeps the cache directory inspectable.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory).expanduser()
        self._directory.mkdir(parents=True, exist_ok=True)

    def load(self, key: str) -> QdlGraph | None:
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            graph = QdlGraph.model_validate(payload["graph"])
        except (OSError, KeyError, TypeError, ValueError):
            return None
        if (
            payload.get("cache_version") != _CACHE_VERSION
            or payload.get("key") != key
            or payload.get("graph_hash") != graph.content_hash
            or any(fact.context is not Context.PROPOSAL for fact in graph.facts)
            or any(
                literal.context is not Context.PROPOSAL
                for rule in graph.rules
                for literal in (*rule.body, *rule.head)
            )
        ):
            return None
        return graph

    def save(self, key: str, graph: QdlGraph) -> None:
        path = self._path(key)
        payload = {
            "cache_version": _CACHE_VERSION,
            "key": key,
            "graph_hash": graph.content_hash,
            "graph": graph.model_dump(mode="json"),
        }
        self._directory.mkdir(parents=True, exist_ok=True)
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
            os.replace(temporary.name, path)
        finally:
            if os.path.exists(temporary.name):
                os.unlink(temporary.name)

    def _path(self, key: str) -> Path:
        if not _KEY_PATTERN.fullmatch(key):
            raise ValueError("grounding cache key must be a sha-256 digest")
        return self._directory / f"{key}.json"
