from __future__ import annotations

from cloud_dast.qdl.graph import Context
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.secret_shapes import secret_shape_graph


def _evidence(leaves: list[tuple[str, object]]) -> EvidenceView:
    return EvidenceView(
        data={
            "response": {
                "leaves": [{"path": path, "value": value} for path, value in leaves]
            }
        },
        original_digest="digest",
        digest="digest",
        truncated=False,
    )


def test_secret_shape_classifies_observed_jwt_value() -> None:
    graph = secret_shape_graph(
        ("action:export",),
        _evidence(
            [
                ("token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.sig"),
                ("note", "benign text"),
            ]
        ),
    )

    assert graph is not None
    facts = graph.facts
    assert any(
        fact.context is Context.PROPOSAL
        and fact.predicate.name == "has"
        and fact.args[0].name == "output_field"
        and fact.args[0].args[1].value == "token"
        and fact.args[1].value == "credential"
        for fact in facts
    )
    assert not any(
        fact.predicate.name == "has" and fact.args[0].args[1].value == "note"
        for fact in facts
    )


def test_secret_shape_detects_private_key_hash_and_access_key() -> None:
    graph = secret_shape_graph(
        ("action:read",),
        _evidence(
            [
                ("key", "-----BEGIN RSA PRIVATE KEY-----"),
                ("hash", "$argon2id$v=19$salt"),
                ("aws", "AKIAIOSFODNN7EXAMPLE"),
            ]
        ),
    )

    assert graph is not None
    classified = {
        fact.args[0].args[1].value
        for fact in graph.facts
        if fact.predicate.name == "has"
    }
    assert classified == {"key", "hash", "aws"}


def test_secret_shape_requires_single_action_and_evidence() -> None:
    evidence = _evidence([("token", "eyJhbGciOiJIUzI1NiJ9.payload.sig")])

    assert secret_shape_graph(("action:a", "action:b"), evidence) is None
    assert secret_shape_graph(("action:a",), None) is None


def test_secret_shape_ignores_benign_values() -> None:
    graph = secret_shape_graph(
        ("action:read",),
        _evidence([("name", "plain value"), ("count", 7)]),
    )

    assert graph is None
