"""Report, mark, or purge legacy pre-QDL threat-model data in Neo4j."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from cloud_dast.infrastructure.neo4j.common.repository import make_session_factory
from cloud_dast.infrastructure.neo4j.migration import LegacyThreatModelMigration


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mark-legacy",
        action="store_true",
        help="add a reversible Legacy label to every old-world node",
    )
    parser.add_argument(
        "--purge-legacy",
        action="store_true",
        help="detach and delete every node marked Legacy (destructive)",
    )
    args = parser.parse_args(argv)

    session_factory = make_session_factory()
    try:
        migration = LegacyThreatModelMigration(session_factory)
        if args.purge_legacy:
            purged = migration.purge_legacy()
            payload = {"action": "purge-legacy", "purged": purged}
        elif args.mark_legacy:
            marked = migration.mark_legacy()
            payload = {"action": "mark-legacy", "marked": marked}
        else:
            payload = {"action": "report", "legacy": migration.report()}
    finally:
        session_factory.close()
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
