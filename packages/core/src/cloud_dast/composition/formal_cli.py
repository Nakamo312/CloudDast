"""Run explicit contract-to-QDL ingestion."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from cloud_dast.composition.app_provider import open_formal_repository
from cloud_dast.composition.formal_ingestion import QdlIngestionService
from cloud_dast.composition.profile import load_classification_profile
from cloud_dast.infrastructure.neo4j.common.repository import make_session_factory
from cloud_dast.infrastructure.neo4j.contract_graph import (
    Neo4jContractGraphRepository,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    parser.add_argument("--source-id")
    parser.add_argument(
        "--adapter-version",
        default="contract-projection-v2",
    )
    parser.add_argument(
        "--classification-profile",
    )
    args = parser.parse_args(argv)

    session_factory = make_session_factory()
    contract_graph = Neo4jContractGraphRepository(session_factory)
    classification_profile = (
        load_classification_profile(args.classification_profile)
        if args.classification_profile
        else None
    )

    try:
        with open_formal_repository(session_factory) as formal_repository:
            service = QdlIngestionService(
                contract_graph,
                formal_repository,
                adapter_version=args.adapter_version,
                classification_profile=classification_profile,
            )
            result = service.ingest(args.service, source_id=args.source_id)
    finally:
        session_factory.close()
    print(
        json.dumps(
            {
                "service": result.service,
                "source_id": result.source_id,
                "graph_hash": result.graph_hash,
                "mapped": result.mapped,
                "unmapped": result.unmapped,
                "ambiguous": result.ambiguous,
                "conflict": result.conflict,
                "classification_mapped": result.classification_mapped,
                "classification_unmapped": result.classification_unmapped,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
