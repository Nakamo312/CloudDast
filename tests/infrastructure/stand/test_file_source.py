from __future__ import annotations

import json

import pytest

from cloud_dast.infrastructure.stand import FileStandSource
from cloud_dast.qdl.policy_projection import (
    PolicyBinding,
    PolicyContainment,
    PolicyResource,
    PolicySnapshot,
)


def write_stand(path) -> None:
    path.write_text(
        json.dumps(
            {
                "bindings": [
                    {"subject": "victim", "role": "viewer", "scope": "secret-1"}
                ],
                "resources": [
                    {"resource": "secret-1", "resource_type": "lockbox.secret"}
                ],
                "containments": [
                    {"child": "secret-1", "parent": "folder-1"},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_file_source_reads_a_generic_policy_snapshot(tmp_path) -> None:
    path = tmp_path / "stand.json"
    write_stand(path)

    snapshot = FileStandSource(path).snapshot("lockbox")

    assert snapshot == PolicySnapshot(
        bindings=(PolicyBinding("victim", "viewer", "secret-1"),),
        resources=(PolicyResource("secret-1", "lockbox.secret"),),
        containments=(PolicyContainment("secret-1", "folder-1"),),
    )


def test_file_source_uses_the_generic_policy_projector(tmp_path) -> None:
    path = tmp_path / "stand.json"
    write_stand(path)

    graph = FileStandSource(path).project("lockbox")
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
    assert ("is", "resource:secret-1", "Resource") in facts
    assert ("part", "resource:secret-1", "scope:folder-1") in facts


def test_file_source_rejects_malformed_json(tmp_path) -> None:
    path = tmp_path / "stand.json"
    path.write_text(
        '{"bindings": [{"subject": "", "role": "viewer", "scope": "secret-1"}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="policy binding subject must not be empty"):
        FileStandSource(path).snapshot("lockbox")
