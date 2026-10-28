"""Evidence gate for model-backed reactive consultations."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass

from cloud_dast.api import LiveRequest
from cloud_dast.model.events import ComponentInvoked, DomainEvent, EventScope
from cloud_dast.ports import EventPublisher, FormalRepository
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.consultation.outcomes import ConsultationOutcome
from cloud_dast.runtime.deficits import (
    Deficit,
    evidence_deficit,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItem,
    WorkItemGrounding,
)
from cloud_dast.verification.evidence_facts import supports_dataflows
from cloud_dast.verification.slices import (
    SiblingAction,
    SiblingActionSlice,
    build_sibling_action_slice,
)

logger = logging.getLogger("cloud_dast.runtime.evidence_gate")

_EVIDENCE_GATE_COMPONENT = "evidence_gate:observation_required"


@dataclass(frozen=True, slots=True)
class EvidenceDeficitRecord:
    """One live-evidence gap recorded instead of a model guess."""

    service: str
    deficit: Deficit
    source_kind: str
    source_consultation_id: str
    sibling_actions: tuple[SiblingAction, ...] = ()
    sibling_slice_hash: str = ""


class Gate:
    """Own evidence sufficiency, parking, and deterministic evidence slices."""

    def __init__(
        self,
        *,
        formal_repository: FormalRepository | None,
        event_bus: EventPublisher | None,
    ) -> None:
        self._formal_repository = formal_repository
        self._event_bus = event_bus
        self._evidence_deficits: dict[
            tuple[str, tuple[str, ...]], EvidenceDeficitRecord
        ] = {}

    @property
    def evidence_deficits(
        self,
    ) -> dict[tuple[str, tuple[str, ...]], EvidenceDeficitRecord]:
        return self._evidence_deficits

    def _publish(self, event: DomainEvent, scope: EventScope | None) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(scope.apply(event) if scope is not None else event)

    def record_work_item(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        deficits: DeficitQueue,
        *,
        scope: EventScope | None = None,
        record_outcome: Callable[..., ConsultationOutcome],
    ) -> None:
        """Replace one evidence-less observation work item with evidence needs.

        Response-semantics and variance consultations are designed around live
        evidence; dataflows consultations additionally accept a declared
        sink/reaches fact as graph evidence.  Every deficit covered by the
        popped work item is closed without a model attempt; an
        ``evidence_deficit`` with no consultation mapping takes its place
        in the queue, and the deterministic sibling-action neighbourhood of
        the action is attached from current QDL facts — never from model
        questions.  One gate decision is published for the whole coalesced
        work item.

        The parked record is built by ``deficits.evidence_deficit`` (S21
        v2): the subgoal is preserved and only the consultation axis is
        withdrawn, so the gap can never reach a model.
        """

        self.publish_invocation(work_item, scope)
        record_outcome(
            request,
            work_item,
            WorkItemGrounding(work_item.work_item_id),
            deficits,
            scope=scope,
            component=_EVIDENCE_GATE_COMPONENT,
            kind="gate",
            evidence_available=False,
        )
        sibling_slice = self.sibling_action_slice(request, work_item.action)
        for deficit in work_item.deficits:
            parked = evidence_deficit(deficit)
            deficits.close_key(deficit.work_item_key)
            deficits.add((parked,))
            self._evidence_deficits[(request.service, parked.key)] = (
                EvidenceDeficitRecord(
                    service=request.service,
                    deficit=parked,
                    source_kind=deficit.predicate_class,
                    source_consultation_id=deficit.consultation_id,
                    sibling_actions=sibling_slice.siblings,
                    sibling_slice_hash=sibling_slice.slice_hash,
                )
            )
            logger.info(
                "evidence_deficit_recorded service=%s action=%s source_class=%s "
                "source_deficit_id=%s evidence_deficit_id=%s siblings=%d",
                request.service,
                deficit.action,
                deficit.predicate_class,
                deficit.consultation_id,
                parked.consultation_id,
                len(sibling_slice.siblings),
            )

    def publish_invocation(
        self,
        work_item: WorkItem,
        scope: EventScope | None,
    ) -> None:
        """Publish the evidence gate's input telemetry for one gated item.

        The gate is a deciding component, not a producer: its output is an
        admission decision over the work item it was offered.  The digest
        is content-based (axis, action, deficit and signature identity),
        so identical gate inputs deduplicate and distinct deficits stay
        distinct.
        """

        if self._event_bus is None:
            return
        digest_source = "|".join(
            (
                work_item.axis or "",
                work_item.action,
                *sorted(work_item.deficit_ids),
                *sorted(work_item.missing_fact_signature),
                *sorted(work_item.evidence_signature),
                work_item.graph_snapshot,
            )
        )
        self._publish(
            ComponentInvoked(
                component=_EVIDENCE_GATE_COMPONENT,
                kind="gate",
                input_digest=hashlib.sha256(digest_source.encode("utf-8")).hexdigest(),
                input_completeness={
                    "deficits": len(work_item.deficit_ids),
                    "missing_facts": len(work_item.missing_fact_signature),
                    "evidence_refs": len(work_item.evidence_signature),
                },
                invocation_id=f"{_EVIDENCE_GATE_COMPONENT}:{work_item.work_item_id}:0",
                correlation_id=work_item.work_item_id,
            ),
            scope,
        )

    def allows_dataflows(self, request: LiveRequest, action: str) -> bool:
        """Admit dataflow consultation only with declared action-bound context."""

        graph = self._evidence_slice_graph(request)
        return graph is not None and supports_dataflows(graph, action)

    def sibling_action_slice(
        self,
        request: LiveRequest,
        action: str,
    ) -> SiblingActionSlice:
        """Build the deterministic sibling neighbourhood for one action."""

        graph = self._evidence_slice_graph(request)
        if graph is None:
            return SiblingActionSlice(action="")
        return build_sibling_action_slice(graph, action=action)

    def _evidence_slice_graph(self, request: LiveRequest) -> QdlGraph | None:
        """Load the current merged QDL facts for sibling slicing."""

        if self._formal_repository is None:
            return None
        service = request.service
        try:
            return merge_graphs(
                self._formal_repository.load(f"contract:{service}"),
                self._formal_repository.load(f"stand:{service}"),
                self._formal_repository.load(f"accepted:{service}"),
                self._formal_repository.load_merged(f"accepted-batch:{service}:"),
                self._formal_repository.load_merged(f"diff:{service}:"),
            )
        except Exception:  # noqa: BLE001 - deterministic context is best-effort
            logger.warning("evidence_slice_graph_unavailable service=%s", service)
            return None
