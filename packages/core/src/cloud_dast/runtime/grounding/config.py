"""Configuration value object for the axis grounding engine."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Mapping, Protocol

from cloud_dast.consultation import (
    ConsultationBudget,
    ConsultationDispatcher,
    ConsultationOutcome,
    ConsultationRequest,
)
from cloud_dast.contracts.axes import Axis
from cloud_dast.contracts.proposals import FormalModelOutputValidator
from cloud_dast.ports import (
    AxisGroundingDispatcher,
    CampaignMetricsRecorder,
    GroundingCache,
    GroundingRunner,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import DEFAULT_SLICE_BUDGET, SliceBudget


class StartupGrounding(Protocol):
    """Produce startup proposals without requiring reactive consultation."""

    def ground_stream(
        self,
        graph: QdlGraph,
        *,
        cache_source: QdlGraph | None = None,
        evidence: EvidenceView | None = None,
    ) -> Iterator[tuple[str, str, QdlGraph]]: ...


class ReactiveGrounding(Protocol):
    """Prepare live-evidence proposals without a startup scheduler or cache."""

    def ground_reactive(
        self,
        axis: Axis,
        action_ids: tuple[str, ...],
        graph: QdlGraph,
        **values: object,
    ) -> AxisResult: ...

    def ground_alternatives(
        self,
        graph: QdlGraph,
        blocked_action: str,
        **values: object,
    ) -> AxisResult: ...

    def ground_variance(
        self,
        graph: QdlGraph,
        action_id: str,
        **values: object,
    ) -> AxisResult: ...

    def dispatch_consultation(
        self, request: ConsultationRequest
    ) -> ConsultationOutcome: ...


@dataclass(frozen=True, slots=True)
class GrounderOptions:
    """Shared immutable settings; startup and reactive owners consume their own fields."""

    validator: FormalModelOutputValidator | None = None
    batch_size: int = 8
    max_workers: int = 4
    metrics: CampaignMetricsRecorder | None = None
    cache: GroundingCache | None = None
    cache_namespace: str = ""
    axis_timeout: float | None = 300.0
    slice_budget: SliceBudget = DEFAULT_SLICE_BUDGET
    consultation_budget: ConsultationBudget | None = None
    task_runner: GroundingRunner | None = None
    consultation: ConsultationDispatcher | None = None
    grounding_dispatcher: AxisGroundingDispatcher | None = None

    @classmethod
    def from_legacy(
        cls,
        options: GrounderOptions | None,
        values: Mapping[str, object],
    ) -> GrounderOptions:
        """Normalize constructor input into one immutable options object."""

        if options is not None:
            if values:
                raise TypeError("pass either options or individual grounder options")
            return options
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(values) - known)
        if unknown:
            raise TypeError("unknown grounder options: " + ", ".join(unknown))
        return cls(**values)


__all__ = ["GrounderOptions", "StartupGrounding", "ReactiveGrounding"]
