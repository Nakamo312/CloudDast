"""SQLite persistence for immutable QDL projections.

Projection content is immutable and content-addressed. Each source separately
selects its current projection, so replay can reactivate earlier content
without duplicating it or losing history.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeVar

from cloud_dast.qdl.graph import Fact, QdlGraph, Rule, canonical_json
from cloud_dast.qdl.graph_ops import merge_graphs

_SCHEMA = """
CREATE TABLE IF NOT EXISTS qdl_fact (
    content_hash TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qdl_rule (
    content_hash TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qdl_issue (
    content_hash TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    canonical_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qdl_projection (
    projection_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    graph_hash TEXT NOT NULL,
    mapping_report_json TEXT NOT NULL,
    mapping_report_hash TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    provenance_hash TEXT NOT NULL,
    saved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qdl_source (
    source_id TEXT PRIMARY KEY,
    projection_id TEXT NOT NULL,
    FOREIGN KEY (projection_id) REFERENCES qdl_projection(projection_id)
);

CREATE TABLE IF NOT EXISTS projection_fact (
    projection_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (projection_id, content_hash),
    FOREIGN KEY (projection_id) REFERENCES qdl_projection(projection_id),
    FOREIGN KEY (content_hash) REFERENCES qdl_fact(content_hash)
);

CREATE TABLE IF NOT EXISTS projection_rule (
    projection_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (projection_id, content_hash),
    FOREIGN KEY (projection_id) REFERENCES qdl_projection(projection_id),
    FOREIGN KEY (content_hash) REFERENCES qdl_rule(content_hash)
);

CREATE TABLE IF NOT EXISTS projection_issue (
    projection_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (projection_id, content_hash),
    FOREIGN KEY (projection_id) REFERENCES qdl_projection(projection_id),
    FOREIGN KEY (content_hash) REFERENCES qdl_issue(content_hash)
);
"""

_ContentModel = TypeVar("_ContentModel", Fact, Rule)

_APPEND_ONLY_SOURCE_PREFIXES = (
    "accepted-batch:",
    "diff:",
    "observation:",
    "runtime:",
)


class SqliteFormalRepository:
    """Persist and restore immutable QDL graph projections in SQLite."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self._path,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        with self._connection:
            self._connection.executescript(_SCHEMA)
            # Legacy databases selected the last first-seen projection. Seed
            # missing pointers once; reopening must not undo a later replay.
            self._connection.execute(
                """
                INSERT OR IGNORE INTO qdl_source (source_id, projection_id)
                SELECT source_id, projection_id FROM qdl_projection
                WHERE rowid IN (
                    SELECT MAX(rowid) FROM qdl_projection GROUP BY source_id
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SqliteFormalRepository:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: Mapping[str, Any],
        adapter_version: str,
        mapping_report: Mapping[str, Any],
    ) -> None:
        """Save one adapter projection without replacing earlier versions."""

        _validate_identifier(source_id, "source_id")
        _validate_identifier(adapter_version, "adapter_version")
        _validate_mapping(provenance, "provenance")
        _validate_mapping(mapping_report, "mapping report")

        provenance_json = _canonical_json(provenance)
        mapping_report_json = _canonical_json(mapping_report)
        provenance_hash = _hash_json(provenance)
        mapping_report_hash = _hash_json(mapping_report)
        projection_id = _hash_json(
            {
                "adapter_version": adapter_version,
                "graph_hash": graph.content_hash,
                "mapping_report": mapping_report,
                "provenance": provenance,
                "source_id": source_id,
            }
        )

        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO qdl_projection (
                    projection_id,
                    source_id,
                    adapter_version,
                    graph_hash,
                    mapping_report_json,
                    mapping_report_hash,
                    provenance_json,
                    provenance_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    projection_id,
                    source_id,
                    adapter_version,
                    graph.content_hash,
                    mapping_report_json,
                    mapping_report_hash,
                    provenance_json,
                    provenance_hash,
                ),
            )

            for fact in graph.facts:
                content_json = canonical_json(fact)
                content_hash = _hash_text(content_json)
                self._connection.execute(
                    "INSERT OR IGNORE INTO qdl_fact VALUES (?, ?)",
                    (content_hash, content_json),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO projection_fact VALUES (?, ?)",
                    (projection_id, content_hash),
                )

            for rule in graph.rules:
                content_json = canonical_json(rule)
                content_hash = _hash_text(content_json)
                self._connection.execute(
                    "INSERT OR IGNORE INTO qdl_rule VALUES (?, ?)",
                    (content_hash, content_json),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO projection_rule VALUES (?, ?)",
                    (projection_id, content_hash),
                )

            for issue in _issue_rows(mapping_report):
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO qdl_issue (
                        content_hash,
                        issue_id,
                        code,
                        message,
                        canonical_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        issue["content_hash"],
                        issue["issue_id"],
                        issue["code"],
                        issue["message"],
                        issue["canonical_json"],
                    ),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO projection_issue VALUES (?, ?)",
                    (projection_id, issue["content_hash"]),
                )

            self._connection.execute(
                """
                INSERT INTO qdl_source (source_id, projection_id) VALUES (?, ?)
                ON CONFLICT(source_id) DO UPDATE SET projection_id = excluded.projection_id
                WHERE qdl_source.projection_id != excluded.projection_id
                """,
                (source_id, projection_id),
            )

    def load(self, source_id: str) -> QdlGraph:
        """Return the latest QDL graph saved for ``source_id``."""

        _validate_identifier(source_id, "source_id")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT projection_id
                FROM qdl_source
                WHERE source_id = ?
                """,
                (source_id,),
            ).fetchone()
            if row is None:
                return QdlGraph()
            projection_id = row["projection_id"]
            facts = self._load_content(
                projection_id,
                "qdl_fact",
                "projection_fact",
                Fact,
            )
            rules = self._load_content(
                projection_id,
                "qdl_rule",
                "projection_rule",
                Rule,
            )
        return QdlGraph(facts=facts, rules=rules)

    def load_merged(self, source_prefix: str) -> QdlGraph:
        """Merge projections under a prefix without logical deletion.

        Runtime, observation, and diff sources are bi-temporal: every saved
        projection remains available even when its logical ``source_id`` is
        reused.  In particular, a revised diff projection can omit runtime
        declarations such as ``is(reached(Action, Sink), Effect)``; selecting
        only the latest projection would turn that physical append into a
        logical deletion and make the merged graph non-monotonic.  These
        namespaces therefore contribute the union of all projections, while
        other namespaces retain their latest-projection semantics.
        """

        _validate_identifier(source_prefix, "source_prefix")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT p.source_id, p.projection_id,
                       s.projection_id AS current_projection_id
                FROM qdl_projection AS p
                JOIN qdl_source AS s ON s.source_id = p.source_id
                WHERE substr(p.source_id, 1, length(?)) = ? COLLATE BINARY
                ORDER BY p.source_id, p.projection_id
                """,
                (source_prefix, source_prefix),
            ).fetchall()

            graphs: list[QdlGraph] = []
            projection_ids = (
                row["projection_id"]
                for row in rows
                if row["source_id"].startswith(_APPEND_ONLY_SOURCE_PREFIXES)
                or row["projection_id"] == row["current_projection_id"]
            )
            for projection_id in projection_ids:
                facts = self._load_content(
                    projection_id,
                    "qdl_fact",
                    "projection_fact",
                    Fact,
                )
                rules = self._load_content(
                    projection_id,
                    "qdl_rule",
                    "projection_rule",
                    Rule,
                )
                graphs.append(QdlGraph(facts=facts, rules=rules))
        return merge_graphs(*graphs)

    def _load_content(
        self,
        projection_id: str,
        content_table: str,
        link_table: str,
        model: type[_ContentModel],
    ) -> tuple[_ContentModel, ...]:
        rows = self._connection.execute(
            f"""
            SELECT content.content_hash AS content_hash,
                   content.canonical_json AS canonical_json
            FROM {link_table} AS link
            JOIN {content_table} AS content
              ON content.content_hash = link.content_hash
            WHERE link.projection_id = ?
            ORDER BY content.canonical_json
            """,
            (projection_id,),
        ).fetchall()
        result = []
        for row in rows:
            if row["canonical_json"] is None:
                continue
            result.append(_restore(row, model))
        return tuple(result)


def _restore(row: Mapping[str, Any], model: type[_ContentModel]) -> _ContentModel:
    stored_json = row["canonical_json"]
    stored_hash = _hash_text(stored_json)
    if row["content_hash"] != stored_hash:
        raise ValueError("stored QDL content hash does not match canonical_json")
    return model.model_validate_json(stored_json)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_json(value: Mapping[str, Any]) -> str:
    return _hash_text(_canonical_json(value))


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must not be empty")


def _validate_mapping(value: Mapping[str, Any], name: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be strings")


def _issue_rows(mapping_report: Mapping[str, Any]) -> list[dict[str, str]]:
    issues = mapping_report.get("issues", ())
    if issues is None:
        return []
    if isinstance(issues, Mapping | str | bytes):
        raise ValueError("mapping report issues must be a sequence")
    if not isinstance(issues, Sequence):
        raise ValueError("mapping report issues must be a sequence")

    rows: list[dict[str, str]] = []
    for issue in issues:
        if not isinstance(issue, Mapping):
            raise ValueError("each mapping report issue must be a mapping")
        if any(not isinstance(key, str) for key in issue):
            raise ValueError("mapping report issue keys must be strings")
        code = issue.get("code")
        message = issue.get("message")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("mapping report issue code must not be empty")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("mapping report issue message must not be empty")
        issue_id = issue.get("issue_id", issue.get("id"))
        if issue_id is None:
            issue_id = _hash_json(issue)
        elif not isinstance(issue_id, str) or not issue_id.strip():
            raise ValueError("mapping report issue id must not be empty")
        content = dict(issue)
        content_hash = _hash_json(content)
        rows.append(
            {
                "issue_id": issue_id,
                "content_hash": content_hash,
                "code": code,
                "message": message,
                "canonical_json": _canonical_json(content),
            }
        )
    return rows
