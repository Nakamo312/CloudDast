from __future__ import annotations

import json

import pytest

from cloud_dast.infrastructure.runtime.grounding_cache import FileGroundingCache
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph


def _build_graph() -> QdlGraph:
    action = Atom(value="action:get")
    return QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )


def test_file_grounding_cache_round_trips_valid_graph(tmp_path) -> None:
    cache = FileGroundingCache(tmp_path)
    key = "a" * 64
    graph = _build_graph()

    cache.save(key, graph)

    assert cache.load(key) == graph


def test_file_grounding_cache_returns_none_for_missing_key(tmp_path) -> None:
    cache = FileGroundingCache(tmp_path)

    assert cache.load("b" * 64) is None


def test_file_grounding_cache_rejects_non_digest_keys(tmp_path) -> None:
    cache = FileGroundingCache(tmp_path)

    with pytest.raises(ValueError, match="sha-256"):
        cache.load("../escape")

    with pytest.raises(ValueError, match="sha-256"):
        cache.save("../escape", _build_graph())


def test_file_grounding_cache_persists_version_key_and_graph_hash(
    tmp_path,
) -> None:
    cache = FileGroundingCache(tmp_path)
    key = "c" * 64
    graph = _build_graph()

    cache.save(key, graph)

    payload = json.loads((tmp_path / f"{key}.json").read_text(encoding="utf-8"))
    assert payload["cache_version"] == 2
    assert payload["key"] == key
    assert payload["graph_hash"] == graph.content_hash
    assert cache.load(key) == graph


def test_file_grounding_cache_discards_wrong_version_key_or_hash(
    tmp_path,
) -> None:
    cache = FileGroundingCache(tmp_path)
    key = "d" * 64
    graph = _build_graph()
    cache.save(key, graph)
    path = tmp_path / f"{key}.json"

    for field, value in (
        ("cache_version", 1),
        ("key", "e" * 64),
        ("graph_hash", "f" * 64),
    ):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload[field] = value
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert cache.load(key) is None


def test_file_grounding_cache_discards_accepted_facts(tmp_path) -> None:
    cache = FileGroundingCache(tmp_path)
    key = "1" * 64
    action = Atom(value="action:get")
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )

    cache.save(key, graph)

    assert cache.load(key) is None
