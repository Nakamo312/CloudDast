"""Pure result and identity projections for axis grounding."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from cloud_dast.consultation import ConsultationOutcome, intersect_grounded_proposals
from cloud_dast.contracts.proposals import FormalUncertainty
from cloud_dast.ports import _bound_model_log_value
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.validation import ValidationIssue
from cloud_dast.runtime.grounding.axes.filtering import (
    _filter_grounding_graph,
    _filter_response_semantics_facts,
    _response_semantics_graph,
)
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView
from cloud_dast.verification.slices import BoundedSlice

logger = logging.getLogger("cloud_dast.runtime.grounding.parallel")

__all__ = [
    "batch_key",
    "build_axis_result",
    "intersect_axis_batch_proposals",
    "log_grounding_uncertainties",
    "proposals",
    "uncertainty_items",
    "uncertainty_pairs",
]


def log_grounding_uncertainties(
    axis: str,
    action_ids: tuple[str, ...],
    uncertainties: Sequence[tuple[str, str]],
) -> None:
    """Log self-reported model questions without failing the call."""

    if not uncertainties:
        return
    logger.info(
        "grounding_uncertainties axis=%s actions=%d items=%s",
        axis,
        len(action_ids),
        _bound_model_log_value(uncertainties[:3]),
    )


def build_axis_result(
    axis: str,
    action_ids: tuple[str, ...],
    slice_: BoundedSlice,
    *,
    evidence: EvidenceView | None,
    proposal: QdlGraph | None,
    issue_count: int,
    uncertainties: tuple[tuple[str, str], ...],
    validation_issues: Sequence[ValidationIssue] | None = None,
    invalid_reason: str = "",
    raw_response: str = "",
    require_response_grounding: bool = False,
) -> AxisResult:
    """Apply shared axis and response-evidence boundaries to one proposal."""

    issues = tuple(validation_issues or ())
    if proposal is not None:
        proposal, filter_issues = _filter_grounding_graph(
            axis,
            proposal,
            has_evidence=evidence is not None,
        )
        issues = (*issues, *filter_issues)
        issue_count += len(filter_issues)
    if proposal is not None:
        if axis == "response_semantics":
            proposal, response_issues = _response_semantics_graph(
                proposal,
                slice_.graph,
                action_ids,
                evidence=evidence,
            )
            issues = (*issues, *response_issues)
            issue_count += len(response_issues)
        elif require_response_grounding:
            proposal, response_issues = _filter_response_semantics_facts(
                proposal,
                slice_.graph,
                action_ids,
                evidence,
            )
            issues = (*issues, *response_issues)
            issue_count += len(response_issues)
    if proposal is None or not proposal.facts:
        if issues:
            logger.warning(
                "axis_grounding_invalid axis=%s actions=%d issues=%s raw_response=%s",
                axis,
                len(action_ids),
                _bound_model_log_value(
                    [
                        (issue.code, issue.message[:120], issue.path)
                        for issue in issues[:3]
                    ]
                ),
                _bound_model_log_value(raw_response),
            )
        else:
            logger.warning(
                "axis_grounding_invalid axis=%s actions=%d reason=%s",
                axis,
                len(action_ids),
                invalid_reason or "empty proposal",
            )
        return AxisResult(
            axis,
            None,
            issue_count,
            len(action_ids),
            uncertainties=uncertainties,
            issues=issues,
        )
    return AxisResult(
        axis,
        proposal,
        issue_count,
        len(action_ids),
        uncertainties=uncertainties,
        issues=issues,
    )


def intersect_axis_batch_proposals(
    proposals: Iterable[tuple[str, str, QdlGraph]],
) -> tuple[QdlGraph, ...]:
    """Intersect repetitions within one axis/batch family only."""

    grouped: dict[tuple[str, str], list[QdlGraph]] = {}
    for axis, batch_key_value, proposal in proposals:
        grouped.setdefault((axis, batch_key_value), []).append(proposal)
    return tuple(
        intersect_grounded_proposals(group)
        for _key, group in sorted(
            grouped.items(),
            key=lambda item: (item[0][0], item[0][1]),
        )
    )


def proposals(
    results: Sequence[AxisResult],
) -> list[tuple[str, str, QdlGraph]]:
    """Convert valid axis results into persistable batch proposals."""

    return [
        (result.axis, result.batch_key, result.graph)
        for result in results
        if result.graph is not None
    ]


def uncertainty_items(payload: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Decode self-reported model uncertainties without failing the call."""

    raw = payload.get("uncertainties") or ()
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    items: list[tuple[str, str]] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        try:
            uncertainty = FormalUncertainty.model_validate(dict(entry))
        except ValidationError:
            continue
        items.append((uncertainty.field, uncertainty.question))
    return items


def uncertainty_pairs(
    outcome: ConsultationOutcome,
) -> tuple[tuple[str, str], ...]:
    """Convert consultation uncertainties into axis result pairs."""

    return tuple(
        (uncertainty.field, uncertainty.question)
        for uncertainty in outcome.uncertainties
    )


def batch_key(axis: str, batch: tuple[str, ...]) -> str:
    """Return the stable identity of one axis/action batch."""

    payload = "|".join((axis, *batch))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
