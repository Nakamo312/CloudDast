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
from cloud_dast.runtime.grounding.config import StartupGrounding
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
    startup: StartupGrounding | None
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
        self._startup = options.startup
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
        if self._skip_llm_grounding or self._startup is None:
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
        revision = runner.lifecycle_revision
        return runner.start(
            lambda sink: self._run_grounded_worker(
                service,
                runner,
                source,
                cache_source,
                sink,
                revision,
            )
        )

    def _run_grounded_worker(
        self,
        service: str,
        runner: GroundingRunner,
        source: QdlGraph,
        cache_source: QdlGraph,
        sink: GroundingSink,
        revision: int,
    ) -> None:
        """Stream promoted axis batches and finish independently of formal work."""

        self._start_formal(service, runner, revision, sink)
        for axis, batch_key, proposal in self._startup.ground_stream(
            source,
            cache_source=cache_source,
        ):
            with runner.commit(revision) as admitted:
                if not admitted:
                    break
                self._promote_axis_batch(
                    service,
                    source,
                    axis,
                    batch_key,
                    proposal,
                    sink,
                )
        sink.finish()

    def _start_formal(
        self, service: str, runner: GroundingRunner, revision: int, sink: GroundingSink
    ) -> None:
        """Prepare asynchronously and hand admission to the timed consumer."""

        grounder = self._formal_grounder
        if grounder is None or not self._formal_enabled():
            sink.mark_enrichment("not_started")
            return
        formal = runner.start_task(lambda: grounder.prepare(service))
        sink.mark_enrichment("pending")
        runner.start_task(
            lambda: self._publish_formal_result(
                service, formal, grounder, runner, revision, sink
            )
        )

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
        formal: GroundingTaskHandle[ProposalPromotionRequest | None],
        grounder: FormalGrounder,
        runner: GroundingRunner,
        revision: int,
        sink: GroundingSink,
    ) -> None:
        """Publish detached formal grounding outcome without blocking campaign."""

        status = "committed"
        try:
            request = formal.result(timeout=self._formal_timeout)
            promoted_norms = 0
            with runner.commit(revision) as admitted:
                if not admitted:
                    status = "discarded"
                elif request is not None:
                    promoted_norms = len(
                        grounder.commit(service, request).promoted_norms
                    )
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
