"""List and explicitly approve parked QDL classifications."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence

from cloud_dast.composition.app_provider import open_formal_repository
from cloud_dast.infrastructure.approval_audit import JsonlApprovalAuditLog
from cloud_dast.infrastructure.neo4j.common.repository import make_session_factory
from cloud_dast.runtime.grounding import AutoGroundingService


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.approve is not None and (not args.operator or not args.reason):
        parser.error("--approve requires --operator and --reason")

    session_factory = make_session_factory()
    with open_formal_repository(session_factory) as repository:
        audit_log = (
            JsonlApprovalAuditLog(args.audit_log) if args.approve is not None else None
        )
        grounding = AutoGroundingService(repository, approval_audit_log=audit_log)
        if args.list:
            candidates = grounding.list_classification_approval_queue(args.service)
            payload = {
                "mode": "list",
                "service": args.service,
                "candidates": [
                    {
                        "fact_hash": candidate.fact_hash,
                        "holder": candidate.holder,
                        "role": candidate.role,
                        "action_id": candidate.action_id,
                    }
                    for candidate in candidates
                ],
            }
        else:
            result = grounding.promote_parked_classification(
                args.service,
                args.approve,
                operator=args.operator,
                reason=args.reason,
            )
            payload = {
                "mode": "approve",
                "service": args.service,
                "fact_hash": result.fact_hash,
                "accepted_source_id": result.accepted_source_id,
                "accepted_graph_hash": result.accepted_graph_hash,
                "promoted_facts": result.promoted_facts,
                "audit_log": args.audit_log,
            }

    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--list",
        action="store_true",
        help="list pending protected-role classifications",
    )
    action.add_argument(
        "--approve",
        metavar="FACT_HASH",
        help="approve one pending classification by its content hash",
    )
    parser.add_argument("--operator", help="operator login making the approval")
    parser.add_argument("--reason", help="bounded human-readable approval reason")
    parser.add_argument(
        "--audit-log",
        default=os.environ.get(
            "CLOUD_DAST_APPROVAL_AUDIT_LOG",
            "cloud-dast-approvals.jsonl",
        ),
    )
    return parser


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
