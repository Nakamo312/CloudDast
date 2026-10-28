from __future__ import annotations

import json
import os
from pathlib import Path

from cloud_dast.composition import stand_cli
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository


def test_project_file_stand_to_sqlite(tmp_path, monkeypatch) -> None:
    stand_path = tmp_path / "stand.json"
    stand_path.write_text(
        json.dumps(
            {
                "bindings": [
                    {"subject": "victim", "role": "viewer", "scope": "secret-1"}
                ],
                "resources": [
                    {"resource": "secret-1", "resource_type": "lockbox.secret"}
                ],
                "containments": [{"child": "secret-1", "parent": "folder-1"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(stand_path))
    monkeypatch.setenv("CLOUD_DAST_FORMAL_STORE", "sqlite")

    assert stand_cli.main(["project", "--service", "lockbox"]) == 0

    repository_path = Path(os.environ["CLOUD_DAST_FORMAL_SQLITE_PATH"])
    with SqliteFormalRepository(repository_path) as repository:
        graph = repository.load("stand:lockbox")
    facts = {
        (fact.predicate.name, *(argument.value for argument in fact.args))
        for fact in graph.facts
    }

    assert (
        "binding",
        "principal:victim",
        "role:viewer",
        "resource:secret-1",
    ) in facts
