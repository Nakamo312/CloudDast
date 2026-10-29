"""Assemble the canonical QDL graph for one live campaign."""

from __future__ import annotations

import logging
from threading import Lock

from cloud_dast.ports import FormalRepository
from cloud_dast.proposals import (
    ProposalPromotionRequest,
    ProposalPromotionResult,
    ThreatModelProposer,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.projection import planner_view
from cloud_dast.runtime.grounding.promotion import PromotionPolicy

logger = logging.getLogger("cloud_dast.formal.campaign_graphs")


class Assembler:
    """Load, ground, promote, and persist a campaign's formal graph.

    This service owns the durable formal-source lifecycle.  It deliberately
    does not select methods or bind scenarios; those are separate projections
    consumed by the live execution binder.
    """

    def __init__(
        self,
        formal_repository: FormalRepository,
        formal_threat_modeler: ThreatModelProposer | None,
        promotion_policy: PromotionPolicy,
    ) -> None:
        self._repository = formal_repository
        self._formal_threat_modeler = formal_threat_modeler
        self._promotion_policy = promotion_policy
        self._proposals: dict[str, QdlGraph | None] = {}
        self._proposal_lock = Lock()

    @property
    def formal_threat_modeler(self) -> ThreatModelProposer | None:
        """Return the optional model-backed formal proposal service."""

        return self._formal_threat_modeler

    def prepare(self, service: str) -> ProposalPromotionRequest | None:
        """Prepare one immutable request without promotion or persistence."""

        if self._formal_threat_modeler is None:
            return None
        with self._proposal_lock:
            if service in self._proposals:
                return None

        source = self._source(service, include_diff=False)
        proposal, created = self._get_proposal(service, source)
        if not created or proposal is None:
            return None
        return ProposalPromotionRequest(source=source, proposal=proposal)

    def load(self, service: str, *, formal_proposal: bool = True) -> QdlGraph:
        """Load the planner source and optionally include a formal proposal."""

        source = self._source(service)
        planner_source = planner_view(source)
        if not formal_proposal:
            return planner_source

        proposal, _ = self._get_proposal(service, source)
        if proposal is None:
            return planner_source

        graphs: list[QdlGraph] = [planner_source, proposal]
        promotion = self.commit(
            service, ProposalPromotionRequest(source=source, proposal=proposal)
        )
        if promotion.promoted:
            graphs.append(promotion.graph)
            logger.info(
                "formal_proposal_promotion service=%s promoted=%d "
                "semantic_facts=%d rejected=%d",
                service,
                len(promotion.promoted_norms),
                promotion.promoted_semantic_facts,
                len(promotion.rejected_norms),
            )
        return planner_view(merge_graphs(*graphs))

    def _get_proposal(
        self, service: str, source: QdlGraph
    ) -> tuple[QdlGraph | None, bool]:
        """Generate once per service; leave failed model calls retryable."""

        with self._proposal_lock:
            if service in self._proposals:
                return self._proposals[service], False
            proposal = self._propose(service, source)
            self._proposals[service] = proposal
            return proposal, True

    def commit(
        self, service: str, request: ProposalPromotionRequest
    ) -> ProposalPromotionResult:
        """Promote and persist one request admitted by its lifecycle owner."""

        result = self._promotion_policy.promote(request)
        if result.promoted:
            self.persist_promotion(service, result.graph)
        return result

    def persist_promotion(self, service: str, promoted: QdlGraph) -> None:
        """Persist promoted grounding as an append-only accepted batch."""

        source_id = f"accepted-batch:{service}:proposal:{promoted.content_hash}"
        self._repository.save(
            source_id,
            promoted,
            provenance={
                "source_kind": "proposal-promotion",
                "note": "explicit LLM semantic grounding promotion",
            },
            adapter_version="proposal-promotion-v1",
            mapping_report={"mapped": len(promoted.facts), "unmapped": 0},
        )
        logger.info(
            "formal_promotion_persisted service=%s facts=%d",
            service,
            len(promoted.facts),
        )

    def _source(self, service: str, *, include_diff: bool = True) -> QdlGraph:
        contract = self._repository.load(f"contract:{service}")
        state_machine = self._repository.load(f"state-machine:{service}")
        accepted = merge_graphs(
            self._repository.load(f"accepted:{service}"),
            self._repository.load_merged(f"accepted-batch:{service}:"),
        )
        stand = self._repository.load(f"stand:{service}")
        graphs = [contract, state_machine, accepted, stand]
        if include_diff:
            graphs.append(self._repository.load_merged(f"diff:{service}:"))
        return merge_graphs(*graphs)

    def _propose(self, service: str, source: QdlGraph) -> QdlGraph | None:
        if self._formal_threat_modeler is None:
            return None
        if not source.facts and not source.rules:
            return None
        result = self._formal_threat_modeler.propose(source)
        if result.proposal is None:
            logger.warning(
                "formal_threat_proposal_rejected service=%s attempts=%d issues=%s",
                service,
                result.attempts,
                [(issue.code, issue.message, issue.path) for issue in result.issues],
            )
        else:
            logger.info(
                "formal_threat_proposal_ready service=%s facts=%d prevents=%d "
                "rules=%d attempts=%d",
                service,
                len(result.proposal.facts),
                sum(
                    fact.predicate.name == "prevents" for fact in result.proposal.facts
                ),
                len(result.proposal.rules),
                result.attempts,
            )
        return result.proposal


__all__ = ["Assembler"]
