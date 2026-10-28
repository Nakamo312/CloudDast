from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import pytest

from cloud_dast.infrastructure.neo4j.formal_repository import (
    _FACTS_QUERY,
    _LATEST_PROJECTION_QUERY,
    _MERGED_PROJECTIONS_QUERY,
    _RULES_QUERY,
    _SAVE_QUERY,
    Neo4jFormalRepository,
)
from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    PredicateSchema,
    QdlGraph,
    Rule,
    TermKind,
    Variable,
    canonical_json,
    input_field,
)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class FakeSession:
    """Small Neo4j double implementing the formal store's MERGE semantics."""

    def __init__(self) -> None:
        self.sources: dict[tuple[str, str], dict[str, Any]] = {}
        self.projections: dict[str, dict[str, Any]] = {}
        self.facts: dict[str, dict[str, Any]] = {}
        self.rules: dict[str, dict[str, Any]] = {}
        self.issues: dict[str, dict[str, Any]] = {}
        self.edges: set[tuple[str, str, str]] = set()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_after_projection = False
        self._clock = 0

    def run(self, query: str, **params: Any) -> FakeResult:
        self.calls.append((query, params))
        if query == _SAVE_QUERY:
            self._save_all(params)
        elif query == _LATEST_PROJECTION_QUERY:
            return FakeResult(self._latest_projection(params["source_id"]))
        elif query == _FACTS_QUERY:
            return FakeResult(self._content_rows(params["projection_id"], self.facts))
        elif query == _RULES_QUERY:
            return FakeResult(self._content_rows(params["projection_id"], self.rules))
        elif query == _MERGED_PROJECTIONS_QUERY:
            return FakeResult(self._merged_projections(params["prefix"]))
        return FakeResult([])

    def _save_all(self, params: dict[str, Any]) -> None:
        sources = dict(self.sources)
        projections = {
            projection_id: dict(projection)
            for projection_id, projection in self.projections.items()
        }
        facts = dict(self.facts)
        rules = dict(self.rules)
        issues = dict(self.issues)
        edges = set(self.edges)
        clock = self._clock + 1
        self._save_projection(params, sources, projections, edges, clock)
        if self.fail_after_projection:
            raise RuntimeError("simulated failure after projection write")
        self._save_content(params, "facts", facts, "QdlFact", edges)
        self._save_content(params, "rules", rules, "QdlRule", edges)
        self._save_issues(params, issues, edges)
        self.sources = sources
        self.projections = projections
        self.facts = facts
        self.rules = rules
        self.issues = issues
        self.edges = edges
        self._clock = clock

    def _save_projection(
        self,
        params: dict[str, Any],
        sources: dict[tuple[str, str], dict[str, Any]],
        projections: dict[str, dict[str, Any]],
        edges: set[tuple[str, str, str]],
        clock: int,
    ) -> None:
        source_key = (params["source_id"], params["provenance_hash"])
        sources.setdefault(
            source_key,
            {
                "source_id": params["source_id"],
                "provenance_hash": params["provenance_hash"],
                "provenance_json": params["provenance_json"],
            },
        )
        projection = projections.get(params["projection_id"])
        if projection is None:
            projection = {
                "projection_id": params["projection_id"],
                "source_id": params["source_id"],
                "adapter_version": params["adapter_version"],
                "graph_hash": params["graph_hash"],
                "mapping_report_json": params["mapping_report_json"],
                "mapping_report_hash": params["mapping_report_hash"],
                "created_at": clock,
                "saved_at": clock,
            }
            projections[params["projection_id"]] = projection
        else:
            projection["saved_at"] = clock
        edges.add(
            (
                f"projection:{params['projection_id']}",
                "DERIVED_FROM",
                f"source:{source_key}",
            )
        )

    def _save_content(
        self,
        params: dict[str, Any],
        key: str,
        nodes: dict[str, dict[str, Any]],
        label: str,
        edges: set[tuple[str, str, str]],
    ) -> None:
        source_key = (params["source_id"], params["provenance_hash"])
        projection_id = params["projection_id"]
        for item in params[key]:
            nodes.setdefault(item["content_hash"], dict(item))
            edges.add(
                (
                    f"{label.lower()}:{item['content_hash']}",
                    "DERIVED_FROM",
                    f"source:{source_key}",
                )
            )
            edges.add(
                (
                    f"projection:{projection_id}",
                    "PRODUCED",
                    f"{label.lower()}:{item['content_hash']}",
                )
            )

    def _save_issues(
        self,
        params: dict[str, Any],
        issues: dict[str, dict[str, Any]],
        edges: set[tuple[str, str, str]],
    ) -> None:
        projection_id = params["projection_id"]
        for item in params["issues"]:
            issues.setdefault(item["content_hash"], dict(item))
            edges.add(
                (
                    f"projection:{projection_id}",
                    "HAS_ISSUE",
                    f"issue:{item['content_hash']}",
                )
            )

    def _latest_projection(self, source_id: str) -> list[dict[str, Any]]:
        candidates = [
            projection
            for projection in self.projections.values()
            if projection["source_id"] == source_id
        ]
        if not candidates:
            return []
        latest = max(
            candidates,
            key=lambda projection: (
                projection["saved_at"],
                projection["projection_id"],
            ),
        )
        return [{"projection_id": latest["projection_id"]}]

    def _merged_projections(self, prefix: str) -> list[dict[str, Any]]:
        projections = [
            projection
            for projection in self.projections.values()
            if projection["source_id"].startswith(prefix)
        ]
        return [
            {
                "source_id": projection["source_id"],
                "projection_id": projection["projection_id"],
            }
            for projection in sorted(
                projections,
                key=lambda projection: (
                    projection["source_id"],
                    -projection["saved_at"],
                ),
            )
        ]

    def _content_rows(
        self,
        projection_id: str,
        nodes: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        hashes = {
            edge[2].rsplit(":", 1)[1]
            for edge in self.edges
            if edge[0] == f"projection:{projection_id}" and edge[1] == "PRODUCED"
        }
        return [
            {
                "canonical_json": nodes[node_hash]["canonical_json"],
                "content_hash": node_hash,
            }
            for node_hash in sorted(hashes)
            if node_hash in nodes
        ]


def make_factory(session: FakeSession):
    @contextmanager
    def factory():
        yield session

    return factory


def make_graph(suffix: str = "") -> QdlGraph:
    action = Atom(value=f"action:get_secret{suffix}")
    permission = Atom(value=f"permission:secret.get{suffix}")
    principal = Atom(value=f"principal:attacker{suffix}")
    custom_schema = PredicateSchema(
        name="field_type",
        arguments=(
            ArgumentSchema(name="field"),
            ArgumentSchema(
                name="type",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
            ),
        ),
    )
    facts = (
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_name("is"),
            args=(action, Atom(value="Action")),
        ),
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_name("is"),
            args=(permission, Atom(value="Permission")),
        ),
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_name("is"),
            args=(principal, Atom(value="Principal")),
        ),
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_schema(custom_schema),
            args=(
                input_field(action, Atom(value="request.role")),
                Atom(value="string"),
            ),
        ),
        Fact(
            context=Context.CONTRACT,
            predicate=Predicate.from_name("requires"),
            args=(action, permission),
        ),
    )
    rule = Rule(
        body=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Variable(name="Action"), Variable(name="ActionType")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Variable(name="Permission"), Variable(name="PermissionType")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Variable(name="Principal"), Variable(name="PrincipalType")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("requires"),
                args=(Variable(name="Action"), Variable(name="Permission")),
            ),
        ),
        head=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("may"),
                args=(
                    Variable(name="Principal"),
                    Variable(name="Action"),
                    Variable(name="Permission"),
                ),
            ),
        ),
    )
    return QdlGraph(facts=facts, rules=(rule,))


def mapping_report(suffix: str = "") -> dict[str, Any]:
    return {
        "mapped": 5,
        "issues": [
            {
                "issue_id": f"issue:unsupported{suffix}",
                "code": "unsupported_permission",
                "message": "Permission has no resource target",
                "path": "permissions[0]",
            }
        ],
    }


def provenance(suffix: str = "") -> dict[str, Any]:
    return {"service": "catalog", "contract_digest": f"digest-{suffix}"}


def save_graph(
    store: Neo4jFormalRepository,
    graph: QdlGraph,
    *,
    suffix: str = "",
    source_id: str = "contract:catalog",
) -> None:
    store.save(
        source_id,
        graph,
        provenance=provenance(suffix),
        adapter_version="1.2.3",
        mapping_report=mapping_report(suffix),
    )


def test_save_and_load_restore_custom_predicates_and_rules() -> None:
    graph = make_graph()
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, graph)
    restored = store.load("contract:catalog")

    assert restored == graph
    custom = next(
        fact for fact in restored.facts if fact.predicate.name == "field_type"
    )
    original = next(fact for fact in graph.facts if fact.predicate.name == "field_type")
    assert custom.predicate.definition == original.predicate.definition
    assert restored.rules == graph.rules
    assert store.load("contract:unknown") == QdlGraph()


def test_save_uses_required_schema_and_content_addressed_merge() -> None:
    graph = make_graph()
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, graph)
    save_graph(store, graph)

    queries = "\n".join(query for query, _ in session.calls)
    for label in ("QdlFact", "QdlRule", "QdlSource", "QdlProjection", "QdlIssue"):
        assert f":{label}" in queries
    for relation in ("DERIVED_FROM", "PRODUCED", "HAS_ISSUE"):
        assert relation in queries
    assert "MERGE (fact:QdlFact {content_hash: fact_item.content_hash})" in queries
    assert "MERGE (rule:QdlRule {content_hash: rule_item.content_hash})" in queries
    assert "DELETE" not in queries
    assert "CREATE INDEX" not in queries

    assert len(session.projections) == 1
    assert len(session.facts) == len(graph.facts)
    assert len(session.rules) == len(graph.rules)
    assert len(session.issues) == 1
    for fact in graph.facts:
        assert session.facts[fact.content_hash]["canonical_json"] == canonical_json(
            fact
        )
    for rule in graph.rules:
        assert session.rules[rule.content_hash]["canonical_json"] == canonical_json(
            rule
        )


def test_save_persists_provenance_adapter_version_report_and_issue() -> None:
    graph = make_graph()
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, graph)

    projection = next(iter(session.projections.values()))
    source = next(
        source
        for source in session.sources.values()
        if source["source_id"] == "contract:catalog"
    )
    assert projection["source_id"] == "contract:catalog"
    assert projection["adapter_version"] == "1.2.3"
    assert projection["graph_hash"] == graph.content_hash
    assert json.loads(source["provenance_json"]) == provenance()
    assert json.loads(projection["mapping_report_json"]) == mapping_report()
    issue_hash = next(iter(session.issues))
    assert session.issues[issue_hash] == {
        "issue_id": "issue:unsupported",
        "content_hash": issue_hash,
        "code": "unsupported_permission",
        "message": "Permission has no resource target",
        "canonical_json": json.dumps(
            {
                "issue_id": "issue:unsupported",
                "code": "unsupported_permission",
                "message": "Permission has no resource target",
                "path": "permissions[0]",
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    assert (
        f"projection:{projection['projection_id']}",
        "HAS_ISSUE",
        f"issue:{issue_hash}",
    ) in session.edges


def test_load_returns_latest_projection_and_keeps_history() -> None:
    first = make_graph("-1")
    second = make_graph("-2")
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, first, suffix="-1")
    save_graph(store, second, suffix="-2")
    restored = store.load("contract:catalog")

    assert restored == second
    assert len(session.projections) == 2
    assert set(session.facts) >= {fact.content_hash for fact in first.facts}
    assert set(session.rules) >= {rule.content_hash for rule in first.rules}
    assert all("DELETE" not in query for query, _ in session.calls)


def test_load_merged_keeps_latest_revision_for_non_append_sources() -> None:
    first = make_graph("-1")
    second = make_graph("-2")
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, first, suffix="-1", source_id="accepted:catalog")
    save_graph(store, second, suffix="-2", source_id="accepted:catalog")
    merged = store.load_merged("accepted:")

    assert {fact.content_hash for fact in merged.facts} == {
        fact.content_hash for fact in second.facts
    }


def test_load_merged_unions_accepted_batch_revisions() -> None:
    first = make_graph("-1")
    second = make_graph("-2")
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))
    source_id = "accepted-batch:orders:reactive:roles:action:get"

    save_graph(store, first, suffix="-1", source_id=source_id)
    save_graph(store, second, suffix="-2", source_id=source_id)
    merged = store.load_merged("accepted-batch:")

    assert {fact.content_hash for fact in merged.facts} == {
        fact.content_hash for fact in (*first.facts, *second.facts)
    }


def test_load_rejects_content_that_does_not_match_its_hash() -> None:
    graph = make_graph()
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))
    save_graph(store, graph)
    fact_hash = next(iter(session.facts))
    session.facts[fact_hash]["canonical_json"] = canonical_json(
        make_graph("-changed").facts[0]
    )

    with pytest.raises(ValueError, match="content hash does not match"):
        store.load("contract:catalog")


def test_save_uses_one_atomic_cypher_statement() -> None:
    graph = make_graph()
    session = FakeSession()
    store = Neo4jFormalRepository(make_factory(session))

    save_graph(store, graph)

    assert len(session.calls) == 1
    assert session.calls[0][0] == _SAVE_QUERY
    assert "FOREACH" in _SAVE_QUERY
    assert len(session.projections) == 1
    assert len(session.facts) == len(graph.facts)
    assert len(session.rules) == len(graph.rules)


def test_save_failure_does_not_publish_a_partial_projection() -> None:
    graph = make_graph()
    session = FakeSession()
    session.fail_after_projection = True
    store = Neo4jFormalRepository(make_factory(session))

    with pytest.raises(RuntimeError, match="simulated failure"):
        save_graph(store, graph)

    assert session.sources == {}
    assert session.projections == {}
    assert session.facts == {}
    assert session.rules == {}
    assert session.issues == {}
    assert session.edges == set()
