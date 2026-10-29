"""Load the immutable QDL source used by grounding components."""

from __future__ import annotations

import logging

from cloud_dast.ports import FormalRepository
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding.promotion import ProposalPromoter

logger = logging.getLogger("cloud_dast.runtime.grounding.source")


class Loader:
    """Own contract/stand/accepted-source loading for grounding flows."""

    def __init__(
        self,
        repository: FormalRepository,
        promotion: ProposalPromoter,
    ) -> None:
        self._repository = repository
        self._promotion = promotion

    def load(
        self,
        service: str,
        *,
        failure_log: str,
        include_accepted: bool = True,
    ) -> QdlGraph | None:
        """Return the current immutable source, or ``None`` on load failure."""

        try:
            contract = self._repository.load(f"contract:{service}")
            stand = self._repository.load(f"stand:{service}")
            if include_accepted:
                accepted = self._promotion.accepted_semantics(service)
                return merge_graphs(contract, stand, accepted)
            return merge_graphs(contract, stand)
        except Exception:  # noqa: BLE001 - grounding is best-effort
            logger.warning("%s service=%s", failure_log, service)
            return None


__all__ = ["Loader"]
