"""Project or export the stand policy snapshot."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from cloud_dast.composition.app_provider import open_formal_repository
from cloud_dast.composition.run_provider import select_stand_source
from cloud_dast.infrastructure.neo4j.common.repository import make_session_factory
from cloud_dast.infrastructure.stand import Neo4jStandExporter


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    if args.command == "export":
        return _export(args)
    return _project(args)


def _project(args: argparse.Namespace) -> int:
    store = os.environ.get("CLOUD_DAST_FORMAL_STORE", "sqlite").strip().lower()
    session_factory = (
        make_session_factory() if store == "neo4j" or args.source == "neo4j" else None
    )
    try:
        stand = select_stand_source(
            session_factory,
            source=args.source,
            stand_file=args.stand_file,
        )
        graph = stand.project(args.service)
        with open_formal_repository(session_factory) as repository:
            repository.save(
                f"stand:{args.service}",
                graph,
                provenance={"source_kind": "policy-projection"},
                adapter_version="policy-projection-v1",
                mapping_report={"mapped": len(graph.facts), "unmapped": 0},
            )
    finally:
        if session_factory is not None:
            session_factory.close()

    print(
        json.dumps(
            {
                "service": args.service,
                "source_id": f"stand:{args.service}",
                "facts": len(graph.facts),
            },
            sort_keys=True,
        )
    )
    return 0


def _export(args: argparse.Namespace) -> int:
    session_factory = make_session_factory()
    try:
        snapshot = Neo4jStandExporter(session_factory).export(
            args.service,
            args.output,
        )
    finally:
        session_factory.close()

    print(
        json.dumps(
            {
                "service": args.service,
                "output": str(args.output),
                "bindings": len(snapshot.bindings),
                "resources": len(snapshot.resources),
                "containments": len(snapshot.containments),
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    project = subparsers.add_parser(
        "project",
        help="project a stand source into the formal repository",
    )
    project.add_argument("--service", required=True)
    project.add_argument(
        "--source",
        choices=("file", "neo4j"),
        default=os.environ.get("CLOUD_DAST_STAND_SOURCE", "file"),
    )
    project.add_argument(
        "--stand-file",
        type=Path,
        default=Path(os.environ.get("CLOUD_DAST_STAND_FILE", "stand.json")),
    )

    export = subparsers.add_parser(
        "export",
        help="export a live Neo4j stand to JSON",
    )
    export.add_argument("--service", required=True)
    export.add_argument("--output", type=Path, default=Path("stand.json"))
    return parser


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
