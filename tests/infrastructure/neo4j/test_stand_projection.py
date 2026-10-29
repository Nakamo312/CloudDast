from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from cloud_dast.infrastructure.neo4j.stand_projection import (
    _BINDINGS_QUERY,
    _CLOUDS_QUERY,
    _FOLDERS_QUERY,
    _RESOURCES_QUERY,
    Neo4jStandProjector,
)
from cloud_dast.qdl.policy_projection import (
    PolicyBinding,
    PolicyContainment,
    PolicyResource,
    PolicySnapshot,
)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def data(self) -> list[dict[str, Any]]:
        return self._rows


class FakeSession:
    def __init__(self, rows_by_query: dict[str, list[dict[str, Any]]]) -> None:
        self._rows_by_query = rows_by_query

    def run(self, query: str) -> FakeResult:
        return FakeResult(self._rows_by_query.get(query, []))


def make_session() -> FakeSession:
    return FakeSession(
        {
            _BINDINGS_QUERY: [
                {
                    "principal_id": "victim",
                    "role_id": "lockbox.viewer",
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
            _FOLDERS_QUERY: [
                {"folder_id": "folder-1", "cloud_id": "cloud-1"},
            ],
            _CLOUDS_QUERY: [
                {"cloud_id": "cloud-1", "organization_id": "organization-1"},
            ],
        }
    )


def test_stand_projection_reads_a_generic_policy_snapshot() -> None:
    session = make_session()

    @contextmanager
    def session_factory():
        yield session

    snapshot = Neo4jStandProjector(session_factory).snapshot("lockbox")

    assert snapshot == PolicySnapshot(
        bindings=(PolicyBinding("victim", "lockbox.viewer", "secret-1"),),
        resources=(PolicyResource("secret-1", "lockbox.secret"),),
        containments=(
            PolicyContainment("secret-1", "folder-1"),
            PolicyContainment("folder-1", "cloud-1"),
            PolicyContainment("cloud-1", "organization-1"),
        ),
    )


def test_stand_projection_uses_the_generic_policy_projector() -> None:
    session = make_session()

    @contextmanager
    def session_factory():
        yield session

    graph = Neo4jStandProjector(session_factory).project("lockbox")
    facts = {
        (fact.predicate.name, *(argument.value for argument in fact.args))
        for fact in graph.facts
    }

    assert (
        "binding",
        "principal:victim",
        "role:lockbox.viewer",
        "resource:secret-1",
    ) in facts
    assert ("is", "principal:victim", "Subject") in facts
    assert ("is", "role:lockbox.viewer", "Role") in facts
    assert ("is", "resource:secret-1", "Resource") in facts
    assert ("is", "resource:secret-1", "Scope") in facts
    assert ("is", "resource:secret-1", "resource:lockbox.secret") in facts
    assert ("is", "resource:lockbox.secret", "ResourceType") in facts
    assert ("part", "resource:secret-1", "scope:folder-1") in facts
    assert ("part", "scope:folder-1", "scope:cloud-1") in facts
    assert ("part", "scope:cloud-1", "scope:organization-1") in facts
