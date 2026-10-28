"""Immutable call inputs shared by grounding implementations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cloud_dast.model import Check, Observation
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import SiblingActionSlice


@dataclass(frozen=True, slots=True)
class ReactiveCall:
    """Inputs for one evidence-backed reactive axis call."""

    axis: str
    action_ids: tuple[str, ...]
    graph: QdlGraph
    context_extra: Mapping[str, Any] | None = None
    observation: Observation | None = None
    check: Check | None = None
    oob_events: Sequence[EvidenceEvent] = ()
    evidence: EvidenceView | None = None
    cache_source: QdlGraph | None = None


@dataclass(frozen=True, slots=True)
class BranchCall:
    """Inputs for one bounded alternative-action consultation."""

    graph: QdlGraph
    blocked_action: str
    observation: Observation | None = None
    check: Check | None = None
    oob_events: Sequence[EvidenceEvent] = ()
    evidence: EvidenceView | None = None
    effect_hint: str = ""
    blocked_reason: str = ""
    sibling_slice: SiblingActionSlice | None = None


@dataclass(frozen=True, slots=True)
class PairInput:
    """Inputs for one measured control/treatment variance call."""

    source: QdlGraph
    action_id: str
    control: Observation
    treatment: Observation
    report: DiffReport
    control_check: Check | None = None
    treatment_check: Check | None = None
    oob_events: Sequence[EvidenceEvent] = ()
    evidence: EvidenceView | None = None


__all__ = ["BranchCall", "PairInput", "ReactiveCall"]
