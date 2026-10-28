from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

from cloud_dast.infrastructure.neo4j.stand_projection import (
    _BINDINGS_QUERY,
    _CLOUDS_QUERY,
    _FOLDERS_QUERY,
    _RESOURCES_QUERY,
)
from cloud_dast.infrastructure.stand import Neo4jStandExporter


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows


class FakeSession:
    def __init__(self) -> None:
        self._rows_by_query = {
            _BINDINGS_QUERY: [
                {
                    "principal_id": "victim",
                    "role_id": "viewer",
                    "scope_id": "secret-1",
                }
            ],
            _RESOURCES_QUERY: [
                {
                    "resource_id": "secret-1",
                    "resource_type": "lockbox.secret",
                    "folder_id": "folder-1",
                }
            ],
            _FOLDERS_QUERY: [{"folder_id": "folder-1", "cloud_id": "cloud-1"}],
            _CLOUDS_QUERY: [
                {"cloud_id": "cloud-1", "organization_id": "organization-1"}
            ],
        }

    def run(self, query: str) -> FakeResult:
        return FakeResult(self._rows_by_query[query])


def test_export_writes_the_neo4j_stand_as_json(tmp_path) -> None:
    session = FakeSession()

    @contextmanager
    def session_factory():
        yield session

    output = tmp_path / "exported" / "stand.json"
    snapshot = Neo4jStandExporter(session_factory).export("lockbox", output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == {
        "bindings": [{"subject": "victim", "role": "viewer", "scope": "secret-1"}],
        "resources": [{"resource": "secret-1", "resource_type": "lockbox.secret"}],
        "containments": [
            {"child": "secret-1", "parent": "folder-1"},
            {"child": "folder-1", "parent": "cloud-1"},
            {"child": "cloud-1", "parent": "organization-1"},
        ],
    }
    assert len(snapshot.containments) == 3
