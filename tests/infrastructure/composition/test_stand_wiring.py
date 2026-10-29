from __future__ import annotations

from contextlib import contextmanager

import pytest

from cloud_dast.composition.run_provider import select_stand_source
from cloud_dast.infrastructure.neo4j.stand_projection import Neo4jStandProjector
from cloud_dast.infrastructure.stand import FileStandSource


def test_select_stand_source_defaults_to_file(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "stand.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("CLOUD_DAST_STAND_SOURCE", raising=False)
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(path))

    source = select_stand_source(None)

    assert isinstance(source, FileStandSource)


def test_select_stand_source_uses_neo4j_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")

    @contextmanager
    def session_factory():
        yield object()

    source = select_stand_source(session_factory)

    assert isinstance(source, Neo4jStandProjector)


def test_select_stand_source_rejects_unknown_source(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "redis")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_STAND_SOURCE"):
        select_stand_source(None)
