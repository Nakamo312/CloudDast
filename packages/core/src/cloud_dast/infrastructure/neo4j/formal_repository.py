"""Neo4j persistence for immutable QDL projections.

The repository is append-only: it creates missing nodes and relationships with
``MERGE``, but never migrates or deletes earlier projections.  Facts and rules
are content-addressed, so a projection can be restored without flattening
custom predicate schemas to Neo4j-specific properties.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, TypeVar

from cloud_dast.infrastructure.neo4j.common.repository import Neo4jRepository
from cloud_dast.qdl.graph import Fact, QdlGraph, Rule, canonical_json

_SAVE_QUERY = """
    MERGE (source:QdlSource {
        source_id: $source_id,
        provenance_hash: $provenance_hash
    })
    ON CREATE SET source.provenance_json = $provenance_json
    MERGE (projection:QdlProjection {projection_id: $projection_id})
    ON CREATE SET projection.source_id = $source_id,
                  projection.adapter_version = $adapter_version,
                  projection.graph_hash = $graph_hash,
                  projection.mapping_report_json = $mapping_report_json,
                  projection.mapping_report_hash = $mapping_report_hash,
                  projection.created_at = timestamp()
    SET projection.saved_at = timestamp()
    MERGE (projection)-[:DERIVED_FROM]->(source)
    FOREACH (fact_item IN $facts |
        MERGE (fact:QdlFact {content_hash: fact_item.content_hash})
        ON CREATE SET fact.canonical_json = fact_item.canonical_json
        MERGE (fact)-[:DERIVED_FROM]->(source)
        MERGE (projection)-[:PRODUCED]->(fact)
    )
    FOREACH (rule_item IN $rules |
        MERGE (rule:QdlRule {content_hash: rule_item.content_hash})
        ON CREATE SET rule.canonical_json = rule_item.canonical_json
        MERGE (rule)-[:DERIVED_FROM]->(source)
        MERGE (projection)-[:PRODUCED]->(rule)
    )
    FOREACH (issue_item IN $issues |
        MERGE (issue:QdlIssue {content_hash: issue_item.content_hash})
        ON CREATE SET issue.issue_id = issue_item.issue_id,
                      issue.code = issue_item.code,
                      issue.message = issue_item.message,
                      issue.canonical_json = issue_item.canonical_json
        MERGE (projection)-[:HAS_ISSUE]->(issue)
    )
    RETURN projection.projection_id AS projection_id
"""

_LATEST_PROJECTION_QUERY = """
    MATCH (source:QdlSource {source_id: $source_id})
          <-[:DERIVED_FROM]-(projection:QdlProjection)
    RETURN projection.projection_id AS projection_id
    ORDER BY source.source_id, projection.saved_at DESC, projection.projection_id DESC
    LIMIT 1
"""

_FACTS_QUERY = """
    MATCH (:QdlProjection {projection_id: $projection_id})-[:PRODUCED]->(fact:QdlFact)
    RETURN fact.canonical_json AS canonical_json, fact.content_hash AS content_hash
    ORDER BY fact.content_hash
"""

_RULES_QUERY = """
    MATCH (:QdlProjection {projection_id: $projection_id})-[:PRODUCED]->(rule:QdlRule)
    RETURN rule.canonical_json AS canonical_json, rule.content_hash AS content_hash
    ORDER BY rule.content_hash
"""

_MERGED_PROJECTIONS_QUERY = """
    MATCH (source:QdlSource)
    WHERE source.source_id STARTS WITH $prefix
    MATCH (source)<-[:DERIVED_FROM]-(projection:QdlProjection)
    RETURN source.source_id AS source_id,
           projection.projection_id AS projection_id
    ORDER BY projection.saved_at DESC, projection.projection_id DESC
"""

_ContentModel = TypeVar("_ContentModel", Fact, Rule)
_APPEND_ONLY_SOURCE_PREFIXES = (
    "accepted-batch:",
    "diff:",
    "observation:",
    "runtime:",
)


class Neo4jFormalRepository(Neo4jRepository):
    """Persist and restore immutable QDL graph projections."""

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

        self._run(
            _SAVE_QUERY,
            source_id=source_id,
            provenance_hash=provenance_hash,
            provenance_json=provenance_json,
            projection_id=projection_id,
            adapter_version=adapter_version,
            graph_hash=graph.content_hash,
            mapping_report_json=mapping_report_json,
            mapping_report_hash=mapping_report_hash,
            facts=[
                {
                    "content_hash": fact.content_hash,
                    "canonical_json": canonical_json(fact),
                }
                for fact in graph.facts
            ],
            rules=[
                {
                    "content_hash": rule.content_hash,
                    "canonical_json": canonical_json(rule),
                }
                for rule in graph.rules
            ],
            issues=_issue_rows(mapping_report),
        )

    def load(self, source_id: str) -> QdlGraph:
        """Return the latest QDL graph saved for ``source_id``.

        An unknown source yields an empty graph rather than mixing facts from
        historical projections.
        """

        _validate_identifier(source_id, "source_id")
        projection = self._run_one(_LATEST_PROJECTION_QUERY, source_id=source_id)
        if projection is None:
            return QdlGraph()
        projection_id = str(projection["projection_id"])
        fact_rows = self._run(_FACTS_QUERY, projection_id=projection_id)
        rule_rows = self._run(_RULES_QUERY, projection_id=projection_id)
        facts = tuple(_restore(row, Fact) for row in fact_rows)
        rules = tuple(_restore(row, Rule) for row in rule_rows)
        return QdlGraph(facts=facts, rules=rules)

    def load_merged(self, source_prefix: str) -> QdlGraph:
        """Merge projections under a prefix without logical deletion.

        Bi-temporal source namespaces contribute every projection.  Other
        namespaces retain latest-projection semantics, matching SQLite.
        """

        _validate_identifier(source_prefix, "source_prefix")
        rows = self._run(_MERGED_PROJECTIONS_QUERY, prefix=source_prefix)
        latest_by_source: dict[str, str] = {}
        append_only_projection_ids: list[str] = []
        for row in rows:
            source_id = str(row["source_id"])
            projection_id = str(row["projection_id"])
            if source_id.startswith(_APPEND_ONLY_SOURCE_PREFIXES):
                append_only_projection_ids.append(projection_id)
                continue
            latest_by_source.setdefault(source_id, projection_id)

        unique: dict[str, Fact] = {}
        for projection_id in (
            *append_only_projection_ids,
            *latest_by_source.values(),
        ):
            for row in self._run(_FACTS_QUERY, projection_id=projection_id):
                if not row.get("canonical_json"):
                    continue
                fact = _restore(row, Fact)
                unique.setdefault(fact.content_hash, fact)
        return QdlGraph(facts=tuple(unique.values()))


def _row_json(row: Mapping[str, Any]) -> str:
    value = row.get("canonical_json")
    if not isinstance(value, str) or not value:
        raise ValueError("stored QDL content is missing canonical_json")
    return value


def _restore(row: Mapping[str, Any], model: type[_ContentModel]) -> _ContentModel:
    stored_json = _row_json(row)
    # Integrity is proven against the stored bytes exactly as they were
    # saved.  The returned model may then normalize to the current basis
    # (e.g. a legacy predicate definition coerced to its promoted built-in),
    # which intentionally changes the canonical form without invalidating
    # the stored content.
    stored_hash = hashlib.sha256(stored_json.encode("utf-8")).hexdigest()
    content_hash = row.get("content_hash")
    if content_hash != stored_hash:
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


def _hash_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


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
