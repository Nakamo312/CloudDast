"""Asynchronous grounding lifecycle owned by the runtime composition."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from cloud_dast.ports import (
    FormalGrounder,
    FormalRepository,
    GroundingBatch,
    GroundingHandle,
    GroundingRunner,
    GroundingSink,
    GroundingTaskHandle,
)
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.promotion import (
    ProposalPromoter,
)
from cloud_dast.runtime.grounding.source import Loader

logger = logging.getLogger("cloud_dast.runtime.grounding.lifecycle")


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Injected capabilities used by asynchronous grounding lifecycle."""

    ingest_contract: Callable[[str], object] | None
    project_stand: Callable[[str], QdlGraph] | None
    axis_grounding: object | None
    formal_grounder: FormalGrounder | None
    skip_llm_grounding: bool
    formal_timeout: float
    formal_enabled: Callable[[], bool]
    promotion: ProposalPromoter
    source: Loader


class RunCoordinator:
    """Start, stream, and terminate one service's grounding worker."""

    def __init__(
        self,
        repository: FormalRepository,
        options: RunOptions,
    ) -> None:
        self._repository = repository
        self._ingest_contract = options.ingest_contract
        self._project_stand = options.project_stand
        self._axis_grounding = options.axis_grounding
        self._formal_grounder = options.formal_grounder
        self._skip_llm_grounding = options.skip_llm_grounding
        self._formal_timeout = options.formal_timeout
        self._formal_enabled = options.formal_enabled
        self._promotion = options.promotion
        self._source = options.source

    def start_grounded(
        self,
        service: str,
        runner: GroundingRunner,
    ) -> GroundingHandle | None:
        """Start background grounding and return its batch stream handle."""

        if self._ingest_contract is not None:
            try:
                self._ingest_contract(service)
            except Exception:  # noqa: BLE001 - grounding is best-effort
                logger.warning("auto_grounding_contract_failed service=%s", service)
        self._project_stand_if_configured(service)
        if self._skip_llm_grounding or self._axis_grounding is None:
            return None

        source = self._source.load(
            service,
            failure_log="auto_grounding_load_failed",
        )
        if source is None:
            return None
        cache_source = self._source.load(
            service,
            failure_log="auto_grounding_cache_load_failed",
            include_accepted=False,
        )
        if cache_source is None:
            return None
        return runner.start(
            lambda sink: self._run_grounded_worker(
                service,
                runner,
                source,
                cache_source,
                sink,
            )
        )

    def _run_grounded_worker(
        self,
        service: str,
        runner: GroundingRunner,
        source: QdlGraph,
        cache_source: QdlGraph,
        sink: GroundingSink,
    ) -> None:
        """Stream promoted axis batches and finish independently of formal work."""

        formal = self._start_formal_task(service, runner)
        sink.mark_enrichment("pending" if formal is not None else "not_started")
        self._detach_formal_result(service, formal, runner, sink)
        stream_factory = getattr(
            self._axis_grounding,
            "ground_staged_stream",
            None,
        )
        if stream_factory is None:
            stream_factory = self._axis_grounding.ground_stream
        for axis, batch_key, proposal in stream_factory(
            source,
            cache_source=cache_source,
        ):
            self._promote_axis_batch(
                service,
                source,
                axis,
                batch_key,
                proposal,
                sink,
            )
        sink.finish()

    def _detach_formal_result(
        self,
        service: str,
        formal: GroundingTaskHandle[int] | None,
        runner: GroundingRunner,
        sink: GroundingSink,
    ) -> None:
        """Publish a formal result on a detached runner-owned task."""

        if formal is None:
            return
        runner.start_task(lambda: self._publish_formal_result(service, formal, sink))

    def _start_formal_task(
        self,
        service: str,
        runner: GroundingRunner,
    ) -> GroundingTaskHandle[int] | None:
        """Start optional formal threat modeling when policy permits it."""

        formal_grounder = self._formal_grounder
        if formal_grounder is None or not self._formal_enabled():
            return None
        return runner.start_task(lambda: formal_grounder.ground(service))

    def _promote_axis_batch(
        self,
        service: str,
        source: QdlGraph,
        axis: str,
        batch_key: str,
        proposal: QdlGraph,
        sink: GroundingSink,
    ) -> None:
        """Promote and persist one best-effort axis batch."""

        try:
            promoted = self._promotion.promote(
                ProposalPromotionRequest(
                    evidence_fields=frozenset(), source=source, proposal=proposal
                ),
                proposal_source_id=f"proposal:{service}:{axis}:{batch_key}",
            )
            if promoted is None or not promoted.facts:
                return
            self._promotion.save_promoted_graph(
                f"accepted-batch:{service}:{axis}:{batch_key}",
                promoted,
                provenance={
                    "source_kind": "axis-grounding",
                    "axis": axis,
                },
                adapter_version="axis-grounding-v1",
                previous=source,
            )
        except Exception:  # noqa: BLE001 - batch is best-effort
            logger.warning(
                "grounding_batch_promotion_failed service=%s axis=%s batch=%s",
                service,
                axis,
                batch_key,
            )
            return
        sink.publish(
            GroundingBatch(
                axis=axis,
                batch_key=batch_key,
                fact_count=len(promoted.facts),
            )
        )

    def _publish_formal_result(
        self,
        service: str,
        formal: GroundingTaskHandle[int],
        sink: GroundingSink,
    ) -> None:
        """Publish detached formal grounding outcome without blocking campaign."""

        status = "committed"
        try:
            promoted_norms = formal.result(timeout=self._formal_timeout)
        except TimeoutError:
            logger.warning(
                "formal_grounding_timed_out service=%s timeout=%.1f",
                service,
                self._formal_timeout,
            )
            promoted_norms = 0
            status = "discarded"
        except Exception:  # noqa: BLE001 - formal is best-effort
            logger.warning("formal_grounding_failed service=%s", service)
            promoted_norms = 0
            status = "failed"
        if promoted_norms:
            try:
                sink.publish(
                    GroundingBatch(
                        axis="formal",
                        batch_key="threat-modeler",
                        fact_count=promoted_norms,
                    )
                )
            except Exception:  # noqa: BLE001 - detached publish is best-effort
                logger.warning("formal_grounding_publish_failed service=%s", service)
        sink.mark_enrichment(status)

    def _project_stand_if_configured(self, service: str) -> None:
        if self._project_stand is None:
            return
        try:
            stand = self._project_stand(service)
            self._repository.save(
                f"stand:{service}",
                stand,
                provenance={"source_kind": "policy-projection"},
                adapter_version="policy-projection-v1",
                mapping_report={"mapped": len(stand.facts), "unmapped": 0},
            )
        except Exception:  # noqa: BLE001 - grounding is best-effort
            logger.warning("auto_grounding_stand_failed service=%s", service)


__all__ = ["RunCoordinator", "RunOptions"]
