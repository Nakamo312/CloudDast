"""Run declarative state-machine-to-QDL ingestion."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

import yaml

from cloud_dast.infrastructure.neo4j.common.repository import make_session_factory
from cloud_dast.infrastructure.neo4j.formal_repository import Neo4jFormalRepository
from cloud_dast.qdl.state_machine_spec import (
    StateMachineSpecification,
)
from cloud_dast.verification.state_machine_ingestion import (
    StateMachineIngestionService,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    parser.add_argument("--specification", required=True, type=Path)
    parser.add_argument("--source-id")
    parser.add_argument(
        "--adapter-version",
        default="state-machine-v1",
    )
    args = parser.parse_args(argv)

    raw = yaml.safe_load(args.specification.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("state-machine specification must be a YAML mapping")
    specification = StateMachineSpecification.model_validate(raw)

    session_factory = make_session_factory()
    repository = Neo4jFormalRepository(session_factory)
    service = StateMachineIngestionService(
        repository,
        adapter_version=args.adapter_version,
    )

    try:
        result = service.ingest(
            args.service,
            specification,
            source_id=args.source_id,
        )
    finally:
        session_factory.close()

    print(
        json.dumps(
            {
                "service": result.service,
                "source_id": result.source_id,
                "graph_hash": result.graph_hash,
                "states": result.state_count,
                "actions": result.action_count,
                "transitions": result.transition_count,
                "forbidden_states": result.forbidden_state_count,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
