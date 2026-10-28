from __future__ import annotations

from pathlib import Path

from cloud_dast.infrastructure.events import JsonlExampleDatabase


def test_jsonl_example_database_persists_and_replays_values(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl.examples.jsonl"
    database = JsonlExampleDatabase(path)
    key = b"finding-key"
    value = b"finding-example"

    database.save(key, value)
    database.save(key, value)
    assert list(database.fetch(key)) == [value]

    reopened = JsonlExampleDatabase(path)
    assert list(reopened.fetch(key)) == [value]

    reopened.delete(key, value)
    assert list(reopened.fetch(key)) == []
    assert list(JsonlExampleDatabase(path).fetch(key)) == []


def test_jsonl_example_database_rejects_torn_tail(tmp_path: Path) -> None:
    path = tmp_path / "examples.jsonl"
    path.write_bytes(b'{"key":"00","value":"00"}\n{"key":"01"')

    database = JsonlExampleDatabase(path)
    assert list(database.fetch(b"\x01")) == []
