"""Worker-only proposal preparation; no queue or promotion mutations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_dast.consultation import bind_consultation_telemetry
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import EventScope
from cloud_dast.ports import EventPublisher
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.deficits import Deficit, consultation_context
from cloud_dast.runtime.deficits.work_items import WorkItem
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.verification.evidence import View
from cloud_dast.verification.slices import SiblingActionSlice

if TYPE_CHECKING:
    from cloud_dast.runtime.grounding import BatchFlow


@dataclass(frozen=True, slots=True)
class PlannedItem:
    """Immutable inputs prepared for one worker call."""

    work_item: WorkItem
    observation: Observation | None
    check: Check | None
    evidence: View | None
    siblings: SiblingActionSlice | None
    variance: VarianceRecord | None


class Invoker:
    """Prepare model proposals from immutable owner-bound inputs."""

    def __init__(
        self,
        grounding: BatchFlow | None,
        event_bus: EventPublisher | None,
        variance: DifferentialFlow | None,
    ) -> None:
        self._batches = grounding
        self._variance = variance
        self._event_bus = event_bus

    def invoke(
        self,
        request: LiveRequest,
        item: PlannedItem,
        *,
        source: QdlGraph,
        scope: EventScope | None = None,
    ) -> AxisResult | Exception | None:
        """Run only the model proposal on a worker, with owner-bound inputs."""

        work_item = item.work_item
        try:
            with bind_consultation_telemetry(
                self._event_bus,
                scope,
                deficit_id=work_item.work_item_id,
                work_item_id=work_item.work_item_id,
                deficit_ids=work_item.deficit_ids,
            ):
                if work_item.axis == "variance":
                    record = item.variance
                    if record is None:
                        return None
                    return self._variance.prepare_batch(
                        PairInput(
                            source=source,
                            action_id=work_item.action,
                            control=record.control,
                            treatment=record.treatment,
                            report=record.report,
                            control_check=record.control_check,
                            treatment_check=record.treatment_check,
                            evidence=item.evidence,
                        )
                    )
                return self._prepare(
                    request,
                    work_item.representative,
                    source=source,
                    observation=item.observation,
                    check=item.check,
                    evidence=item.evidence,
                    sibling_slice=item.siblings,
                )
        except Exception as error:
            return error

    def _prepare(
        self,
        request: LiveRequest,
        deficit: Deficit,
        *,
        source: QdlGraph,
        observation,
        check: Check | None,
        evidence: View | None,
        sibling_slice: SiblingActionSlice | None = None,
    ) -> AxisResult | None:
        """Prepare the proposal selected by the existing consultation routing."""

        if deficit.axis == "alternatives":
            context = dict(deficit.context)
            return self._batches.prepare_branch(
                source,
                deficit.action,
                observation=observation,
                check=check,
                evidence=evidence,
                sibling_slice=sibling_slice,
                effect_hint=context.get("effect", ""),
                blocked_reason=context.get("reason", ""),
            )
        return self._batches.prepare_reactive(
            source,
            deficit.axis,
            (deficit.action,),
            context=consultation_context(deficit),
            observation=observation,
            check=check,
            evidence=evidence,
        )
