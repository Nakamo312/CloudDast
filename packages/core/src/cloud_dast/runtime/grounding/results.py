"""Shared result contract for startup and reactive grounding calls."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.proposals import ClassificationPromotionContext
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.validation import ValidationIssue


@dataclass(frozen=True, slots=True)
class AxisResult:
    """One grounding result from one ``(axis, batch)`` call."""

    axis: str
    graph: QdlGraph | None
    issue_count: int
    action_count: int
    cache_hit: bool = False
    uncertainties: tuple[tuple[str, str], ...] = ()
    batch_key: str = ""
    observation_ids: tuple[str, ...] = ()
    issues: tuple[ValidationIssue, ...] = ()
    classification_context: ClassificationPromotionContext | None = None


__all__ = ["AxisResult"]
