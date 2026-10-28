"""Consultation waves and model-backed reactive work-item execution."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from cloud_dast.model.events import (
    DomainEvent,
    EventScope,
)
from cloud_dast.ports import GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.consultation.calls import Invoker
from cloud_dast.runtime.consultation.commit import Committer
from cloud_dast.runtime.consultation.context import (
    Callbacks,
)
from cloud_dast.runtime.consultation.evidence import (
    key as make_key,
)
from cloud_dast.runtime.consultation.evidence import (
    observation_for_work_item,
)
from cloud_dast.runtime.consultation.outcomes import (
    OutcomePolicy,
)
from cloud_dast.runtime.consultation.wave import BatchRunner
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
)
from cloud_dast.runtime.execution.state import CampaignAccumulator

logger = logging.getLogger("cloud_dast.runtime.consultation")


class Coordinator(BatchRunner, Invoker, Committer):
    """Own consultation admission, execution, and outcome lifecycle."""

    def __init__(self, callbacks: Callbacks) -> None:
        self._grounding = callbacks.grounding
        self._grounding_runner = callbacks.grounding_runner
        self._batch_timeout = callbacks.batch_timeout
        self._reactive_max_workers = callbacks.reactive_max_workers
        self._latency_oracle = callbacks.latency_oracle
        self._event_bus = callbacks.event_bus
        self._metrics = callbacks.metrics
        self._evidence_gate = callbacks.evidence_gate
        self._consultation_outcomes = OutcomePolicy()

    @property
    def consultation_outcomes(self) -> OutcomePolicy:
        return self._consultation_outcomes

    def work_item_ready(
        self,
        service: str,
        work_item: WorkItem,
        accumulator: CampaignAccumulator,
    ) -> bool:
        """Return whether this evidence signature can consume a model slot."""

        observation = observation_for_work_item(work_item, accumulator)
        identity = make_key(service, work_item, observation)
        return self._consultation_outcomes.should_dispatch(identity)

    def _require_grounding_runner(self) -> GroundingRunner:
        if self._grounding_runner is None:
            raise RuntimeError("reactive grounding runner is unavailable")
        return self._grounding_runner

    def _load_source(self, service: str, *, failure_log: str) -> QdlGraph | None:
        """Load the current source through the grounding service contract."""

        if self._grounding is None:
            return None
        return self._grounding.load_source(service, failure_log=failure_log)

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)

    @staticmethod
    def _merge_wave_graph(
        base_graph: QdlGraph | None,
        outcomes: Mapping[str, WorkItemGrounding],
    ) -> QdlGraph | None:
        """Return the pre-wave graph plus every promoted wave outcome."""

        promoted = [
            outcome.result
            for outcome in outcomes.values()
            if outcome.promoted and outcome.result is not None
        ]
        if not promoted:
            return base_graph
        return merge_graphs(base_graph or QdlGraph(), *promoted)
