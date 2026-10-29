from __future__ import annotations

import pytest

from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
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
    input_field,
    reached,
)


def make_graph(suffix: str = "") -> QdlGraph:
    action = Atom(value=f"action:get{suffix}")
    permission = Atom(value=f"permission:read{suffix}")
    custom_schema = PredicateSchema(
        name="custom_field_type",
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
            predicate=Predicate.from_schema(custom_schema),
            args=(input_field(action, Atom(value="role")), Atom(value="string")),
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
                args=(Variable(name="Principal"), Variable(name="PrincipalType")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Variable(name="Permission"), Variable(name="PermissionType")),
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


def save_graph(
    repository: SqliteFormalRepository,
    graph: QdlGraph,
    *,
    source_id: str,
    provenance_suffix: str = "",
) -> None:
    repository.save(
        source_id,
        graph,
        provenance={"source_kind": "test", "digest": provenance_suffix},
        adapter_version="test-v1",
        mapping_report={
            "mapped": 1,
            "issues": [
                {
                    "issue_id": "issue:unsupported",
                    "code": "unsupported",
                    "message": "Unsupported mapping",
                }
            ],
        },
    )


def runtime_reached_graph(sink_name: str) -> QdlGraph:
    action = Atom(value="action:get")
    sink = Atom(value=f"sink:{sink_name}")
    effect = reached(action, sink)
    return QdlGraph(
        facts=(
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(sink, Atom(value="Sink")),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(effect, Atom(value="Effect")),
            ),
        )
    )


def test_save_and_load_restore_custom_predicates_and_rules(tmp_path) -> None:
    graph = make_graph()
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(repository, graph, source_id="contract:catalog")
        restored = repository.load("contract:catalog")

    assert restored == graph
    custom = next(
        fact for fact in restored.facts if fact.predicate.name == "custom_field_type"
    )
    original = next(
        fact for fact in graph.facts if fact.predicate.name == "custom_field_type"
    )
    assert custom.predicate.definition == original.predicate.definition
    assert restored.rules == graph.rules


def test_save_is_idempotent(tmp_path) -> None:
    graph = make_graph()
    path = tmp_path / "formal.sqlite3"
    with SqliteFormalRepository(path) as repository:
        save_graph(repository, graph, source_id="contract:catalog")
        save_graph(repository, graph, source_id="contract:catalog")

        with repository._connection:
            fact_count = repository._connection.execute(
                "SELECT COUNT(*) FROM qdl_fact"
            ).fetchone()[0]
            rule_count = repository._connection.execute(
                "SELECT COUNT(*) FROM qdl_rule"
            ).fetchone()[0]
            projection_count = repository._connection.execute(
                "SELECT COUNT(*) FROM qdl_projection"
            ).fetchone()[0]

    assert fact_count == len(graph.facts)
    assert rule_count == len(graph.rules)
    assert projection_count == 1


def test_load_returns_latest_projection(tmp_path) -> None:
    first = make_graph()
    second = make_graph(":v2")
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(
            repository, first, source_id="contract:catalog", provenance_suffix="1"
        )
        save_graph(
            repository, second, source_id="contract:catalog", provenance_suffix="2"
        )
        restored = repository.load("contract:catalog")

    assert restored == second


def test_load_merged_merges_latest_sources(tmp_path) -> None:
    first = make_graph(":one")
    second = make_graph(":two")
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(repository, first, source_id="accepted:one", provenance_suffix="1")
        save_graph(repository, second, source_id="accepted:two", provenance_suffix="2")
        merged = repository.load_merged("accepted:")

    assert {fact.content_hash for fact in merged.facts} == {
        fact.content_hash for fact in (*first.facts, *second.facts)
    }


def test_load_merged_keeps_latest_revision_for_non_runtime_sources(tmp_path) -> None:
    first = make_graph()
    second = make_graph(":v2")
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(
            repository, first, source_id="accepted:catalog", provenance_suffix="1"
        )
        save_graph(
            repository, second, source_id="accepted:catalog", provenance_suffix="2"
        )
        merged = repository.load_merged("accepted:")

    assert {fact.content_hash for fact in merged.facts} == {
        fact.content_hash for fact in second.facts
    }


@pytest.mark.parametrize(
    ("source_id", "prefix"),
    [
        ("diff:orders:campaign:runtime", "diff:"),
        ("observation:orders:check-1", "observation:"),
        ("runtime:orders:check-1", "runtime:"),
        (
            "accepted-batch:orders:reactive:alternatives:action-1",
            "accepted-batch:",
        ),
    ],
)
def test_load_merged_unions_append_only_source_revisions(
    tmp_path,
    source_id,
    prefix,
) -> None:
    old = runtime_reached_graph("sql")
    new = runtime_reached_graph("template")
    old_declaration = next(
        fact
        for fact in old.facts
        if fact.predicate.name == "is" and fact.args[0].kind == "struct"
    )
    new_declaration = next(
        fact
        for fact in new.facts
        if fact.predicate.name == "is" and fact.args[0].kind == "struct"
    )

    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(repository, old, source_id=source_id, provenance_suffix="1")
        save_graph(repository, new, source_id=source_id, provenance_suffix="2")
        save_graph(repository, new, source_id=source_id, provenance_suffix="2")

        with repository._connection:
            projection_rows = repository._connection.execute(
                """
                SELECT projection_id
                FROM qdl_projection
                WHERE source_id = ?
                ORDER BY rowid
                """,
                (source_id,),
            ).fetchall()

        assert len(projection_rows) == 2
        projection_fact_hashes = [
            {
                fact.content_hash
                for fact in repository._load_content(
                    row["projection_id"],
                    "qdl_fact",
                    "projection_fact",
                    Fact,
                )
            }
            for row in projection_rows
        ]
        revision_facts = next(
            hashes
            for hashes in projection_fact_hashes
            if new_declaration.content_hash in hashes
        )
        assert old_declaration.content_hash not in revision_facts

        merged = repository.load_merged(prefix)

    assert old_declaration.content_hash in {fact.content_hash for fact in merged.facts}


def test_projection_fact_links_are_persisted(tmp_path) -> None:
    graph = make_graph()
    with SqliteFormalRepository(tmp_path / "formal.sqlite3") as repository:
        save_graph(repository, graph, source_id="contract:catalog")
        with repository._connection:
            rows = repository._connection.execute(
                """
                SELECT p.projection_id, f.content_hash
                FROM qdl_projection AS p
                JOIN projection_fact AS pf ON pf.projection_id = p.projection_id
                JOIN qdl_fact AS f ON f.content_hash = pf.content_hash
                WHERE p.source_id = ?
                """,
                ("contract:catalog",),
            ).fetchall()

    assert {row["content_hash"] for row in rows} == {
        fact.content_hash for fact in graph.facts
    }
