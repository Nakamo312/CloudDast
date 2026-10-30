"""SQLite review regressions: source selection and literal namespaces."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.composition.app_provider import FileContractGraphRepository
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Variable,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.ingestion import ContractImporter


def graph(name: str) -> QdlGraph:
    action = Atom(value=canonical_action_id(name))
    declaration = Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("is"),
        args=(action, Atom(value="Action")),
    )
    variable = Variable(name="A")
    rule = Rule(
        body=(
            declaration.model_copy(update={"args": (variable, Atom(value="Action"))}),
        ),
        head=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("exposes"),
                args=(variable, action),
            ),
        ),
    )
    return QdlGraph(facts=(declaration,), rules=(rule,))


def save(repo, source, value, *, report=None):
    repo.save(
        source,
        value,
        provenance={"source_kind": "review-D1"},
        adapter_version="review-v1",
        mapping_report=report or {},
    )


def test_real_file_ingestion_reselects_previous_content(tmp_path):
    root = Path(__file__).resolve().parents[3]
    assert Path(cloud_dast.__file__).resolve().is_relative_to(root)
    path = tmp_path / "formal.sqlite"
    manifest = tmp_path / "contract.json"
    hashes = []
    with SqliteFormalRepository(path) as repo:
        for action in ("grpc:svc.A", "grpc:svc.B", "grpc:svc.A", "grpc:svc.A"):
            manifest.write_text(
                json.dumps(
                    {
                        "service": "svc",
                        "endpoints": [{"address": "127.0.0.1:1"}],
                        "methods": [
                            {
                                "method_id": action,
                                "service": "svc",
                                "name": "Get",
                                "input_type": "svc.Request",
                                "permissions": ["read"],
                                "resource_types": ["item"],
                            }
                        ],
                    }
                )
            )
            result = ContractImporter(
                FileContractGraphRepository(manifest), repo
            ).ingest("svc")
            hashes.append(result.graph_hash)
            assert repo.load("contract:svc").content_hash == result.graph_hash
        assert hashes[0] == hashes[2] == hashes[3] != hashes[1]
    with SqliteFormalRepository(path) as repo:
        assert repo.load("contract:svc").content_hash == hashes[-1]
        assert repo.load_merged("contract:").content_hash == hashes[-1]
    with sqlite3.connect(path) as db:
        assert sorted(
            r[0] for r in db.execute("SELECT graph_hash FROM qdl_projection")
        ) == sorted(hashes[:2])


@pytest.mark.parametrize(
    "source", ["contract:svc", "stand:svc", "accepted-batch:svc:one", "runtime:svc:one"]
)
def test_reselection_preserves_immutable_history_rules_and_provenance(tmp_path, source):
    path = tmp_path / "formal.sqlite"
    a, b = graph("A"), graph("B")
    with SqliteFormalRepository(path) as repo:
        save(repo, source, a)
        save(repo, source, b)
    with sqlite3.connect(path) as db:
        before = {
            table: db.execute(f"SELECT * FROM {table}").fetchall()
            for table in (
                "qdl_projection",
                "qdl_fact",
                "qdl_rule",
                "projection_fact",
                "projection_rule",
            )
        }
    with SqliteFormalRepository(path) as repo:
        save(repo, source, a)
        save(repo, source, a)
        assert repo.load(source) == a
        expected = (
            merge_graphs(a, b)
            if source.startswith(("accepted-batch:", "runtime:"))
            else a
        )
        assert repo.load_merged(source) == expected
    with sqlite3.connect(path) as db:
        for table, rows in before.items():
            assert db.execute(f"SELECT * FROM {table}").fetchall() == rows
        assert all(
            json.loads(row[6]) == {"source_kind": "review-D1"}
            for row in before["qdl_projection"]
        )


@pytest.mark.parametrize(
    "prefix,foreign",
    [
        ("accepted-batch:svc_a:", "accepted-batch:svcca:"),
        ("accepted-batch:svc%a:", "accepted-batch:svcANYa:"),
        ("accepted-batch:SvCa:", "accepted-batch:svca:"),
        ("proposal:svc_a:", "proposal:svcca:"),
        ("proposal:svc%a:", "proposal:svcANYa:"),
        ("proposal:SvCa:", "proposal:svca:"),
    ],
)
def test_prefix_is_literal_and_case_sensitive(tmp_path, prefix, foreign):
    own, other, exact = graph("own"), graph("foreign"), graph("exact")
    with SqliteFormalRepository(tmp_path / "formal.sqlite") as repo:
        save(repo, prefix + "one", own)
        save(repo, foreign + "one", other)
        save(repo, prefix, exact)
        assert repo.load_merged(prefix) == merge_graphs(own, exact)
        assert repo.load_merged(foreign) == other
        assert repo.load_merged(prefix + "absent") == QdlGraph()


def test_legacy_database_backfill_is_non_destructive_and_does_not_reset_selection(
    tmp_path,
):
    path = tmp_path / "legacy.sqlite"
    a, b = graph("A"), graph("B")
    with SqliteFormalRepository(path) as repo:
        save(repo, "contract:svc", a)
        save(repo, "contract:svc", b)
        save(repo, "stand:other", a)
    # Remove only new selection metadata to reproduce the pre-migration schema.
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE IF EXISTS qdl_source")
        history = db.execute("SELECT * FROM qdl_projection").fetchall()
    with SqliteFormalRepository(path) as repo:
        assert repo.load("contract:svc") == b
        assert repo.load("stand:other") == a
        save(repo, "contract:svc", a)
    with SqliteFormalRepository(path) as repo:
        assert repo.load("contract:svc") == a
        assert repo.load_merged("contract:") == a
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM qdl_projection").fetchall() == history


def test_failed_save_does_not_change_current_source(tmp_path):
    a, b = graph("A"), graph("B")
    with SqliteFormalRepository(tmp_path / "formal.sqlite") as repo:
        save(repo, "contract:svc", a)
        with pytest.raises(ValueError, match="code must not be empty"):
            save(repo, "contract:svc", b, report={"issues": [{"message": "invalid"}]})
        assert repo.load("contract:svc") == a
        assert repo.load_merged("contract:") == a


def test_connections_observe_committed_selection_and_adjacent_save_is_noop(tmp_path):
    path = tmp_path / "formal.sqlite"
    a, b = graph("A"), graph("B")
    with SqliteFormalRepository(path) as first, SqliteFormalRepository(path) as second:
        save(first, "contract:svc", a)
        assert second.load("contract:svc") == a
        save(second, "contract:svc", b)
        assert first.load("contract:svc") == b
        save(first, "contract:svc", a)
        assert second.load("contract:svc") == a
        before = first._connection.total_changes
        save(first, "contract:svc", a)
        assert first._connection.total_changes == before
