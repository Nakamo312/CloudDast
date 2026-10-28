"""Configuration value object for the axis grounding engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from cloud_dast.consultation import ConsultationBudget, ConsultationDispatcher
from cloud_dast.contracts.proposals import FormalModelOutputValidator
from cloud_dast.ports import (
    ApprovalAuditLog,
    AxisGroundingDispatcher,
    CampaignMetricsRecorder,
    FormalGrounder,
    GroundingCache,
    GroundingRunner,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.evidence import MeasuredEvidencePolicy
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast.verification.slices import DEFAULT_SLICE_BUDGET, SliceBudget


@dataclass(frozen=True, slots=True)
class GrounderOptions:
    """Injected policies and resources used by :class:`Grounder`."""

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


@dataclass(frozen=True, slots=True)
class ServiceOptions:
    """Injected policies and adapters used by the grounding facade."""

    ingest_contract: Callable[[str], object] | None = None
    project_stand: Callable[[str], QdlGraph] | None = None
    axis_grounding: object | None = None
    formal_grounder: FormalGrounder | None = None
    skip_llm_grounding: bool = False
    formal_timeout: float = 600.0
    promotion_policy: PromotionPolicy | None = None
    measured_evidence_policy: MeasuredEvidencePolicy | None = None
    approval_audit_log: ApprovalAuditLog | None = None

    @classmethod
    def from_legacy(
        cls,
        options: ServiceOptions | None,
        values: Mapping[str, object],
    ) -> ServiceOptions:
        """Normalize facade construction into one immutable options object."""

        if options is not None:
            if values:
                raise TypeError("pass either options or individual service options")
            return options
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(values) - known)
        if unknown:
            raise TypeError("unknown grounding service options: " + ", ".join(unknown))
        return cls(**values)


__all__ = ["GrounderOptions", "ServiceOptions"]
