"""Export a live Neo4j stand into the versioned JSON format."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import TypeAdapter

from cloud_dast.infrastructure.neo4j.common.repository import SessionFactory
from cloud_dast.infrastructure.neo4j.stand_projection import Neo4jStandProjector
from cloud_dast.qdl.policy_projection import PolicySnapshot

_SNAPSHOT_ADAPTER = TypeAdapter(PolicySnapshot)


class Neo4jStandExporter:
    """Write the Neo4j stand snapshot as a git-diffable launch fixture."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._projector = Neo4jStandProjector(session_factory)

    def export(self, service: str, output: str | Path) -> PolicySnapshot:
        snapshot = self._projector.snapshot(service)
        payload = _SNAPSHOT_ADAPTER.dump_python(
            snapshot,
            mode="json",
            exclude_defaults=True,
        )
        payload.setdefault("bindings", [])
        payload.setdefault("resources", [])
        payload.setdefault("containments", [])
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return snapshot
