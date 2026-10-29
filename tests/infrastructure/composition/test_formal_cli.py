from __future__ import annotations

import os
from pathlib import Path

from cloud_dast.composition import formal_cli
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.ports import (
    ServiceGraphSlice,
)


class DummySessionFactory:
    def close(self) -> None:
        return None


class EmptyContractGraphRepository:
    def __init__(self, session_factory, method_spec) -> None:
        del session_factory
        self._method_spec = method_spec

    def load_slice(self, service: str) -> ServiceGraphSlice:
        return ServiceGraphSlice.from_methods(service, (self._method_spec,))


def test_formal_cli_persists_to_sqlite(
    tmp_path,
    monkeypatch,
    method_spec,
) -> None:
    monkeypatch.setattr(
        formal_cli,
        "make_session_factory",
        lambda: DummySessionFactory(),
    )
    monkeypatch.setattr(
        formal_cli,
        "Neo4jContractGraphRepository",
        lambda session_factory: EmptyContractGraphRepository(
            session_factory,
            method_spec,
        ),
    )
    monkeypatch.setenv("CLOUD_DAST_FORMAL_STORE", "sqlite")

    assert formal_cli.main(["--service", "lockbox"]) == 0

    repository_path = Path(os.environ["CLOUD_DAST_FORMAL_SQLITE_PATH"])
    with SqliteFormalRepository(repository_path) as repository:
        graph = repository.load("contract:lockbox")

    assert graph.facts or graph.rules
