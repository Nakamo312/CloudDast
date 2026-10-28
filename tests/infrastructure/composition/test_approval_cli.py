"""CLI behavior for the explicit classification approval queue."""

from __future__ import annotations

import json
from contextlib import contextmanager

from cloud_dast.composition import approval_cli
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs


class Repository:
    def __init__(self, graphs: dict[str, QdlGraph]) -> None:
        self.graphs = dict(graphs)

    def load(self, source_id: str) -> QdlGraph:
        return self.graphs.get(source_id, QdlGraph())

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return merge_graphs(
            *(
                graph
                for source_id, graph in self.graphs.items()
                if source_id.startswith(source_prefix)
            )
        )

    def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
        self.graphs[source_id] = graph


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _repository() -> Repository:
    action = Atom(value="action:get")
    field = output_field(action, Atom(value="token"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="OutputField"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field, Atom(value="OutputField")), Context.PROPOSAL),
            _fact("has", (field, Atom(value="credential")), Context.PROPOSAL),
        )
    )
    return Repository(
        {
            "contract:orders": source,
            "proposal:orders:roles:b0": proposal,
        }
    )


def _patch_repository(monkeypatch, repository: Repository) -> None:
    monkeypatch.setattr(approval_cli, "make_session_factory", lambda: None)

    @contextmanager
    def open_repository(_session_factory):
        yield repository

    monkeypatch.setattr(approval_cli, "open_formal_repository", open_repository)


def test_approval_cli_lists_pending_classifications(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    repository = _repository()
    _patch_repository(monkeypatch, repository)
    audit_path = tmp_path / "approvals.jsonl"

    exit_code = approval_cli.main(
        ["--service", "orders", "--list", "--audit-log", str(audit_path)]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["mode"] == "list"
    assert len(payload["candidates"]) == 1
    assert payload["candidates"][0]["role"] == "credential"
    assert not audit_path.exists()


def test_approval_cli_approves_one_pending_classification(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    repository = _repository()
    _patch_repository(monkeypatch, repository)
    audit_path = tmp_path / "approvals.jsonl"
    fact_hash = next(
        fact.content_hash
        for graph in repository.graphs.values()
        for fact in graph.facts
        if fact.predicate.name == "has"
    )

    exit_code = approval_cli.main(
        [
            "--service",
            "orders",
            "--approve",
            fact_hash,
            "--operator",
            "ridrapsody",
            "--reason",
            "Owner confirmed the credential field.",
            "--audit-log",
            str(audit_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["mode"] == "approve"
    assert payload["fact_hash"] == fact_hash
    assert payload["promoted_facts"] > 0
    assert audit_path.exists()
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 1
