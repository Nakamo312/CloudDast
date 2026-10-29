"""Prepare and commit reactive and branch grounding batches."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import replace

from cloud_dast.model import (
    Check,
)
from cloud_dast.proposals import (
    ClassificationPromotionContext,
    ProposalPromotionRequest,
)
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import append_supersession
from cloud_dast.runtime.grounding.config import ReactiveGrounding
from cloud_dast.runtime.grounding.promotion import (
    Activity,
    ProposalPromoter,
)
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView, evidence_response_fields
from cloud_dast.verification.slices import SiblingActionSlice

logger = logging.getLogger("cloud_dast.runtime.grounding")


class BatchFlow:
    """Own preparation, admission, and persistence of grounding batches."""

    def __init__(
        self,
        reactive: ReactiveGrounding | None,
        promotion: ProposalPromoter,
        *,
        skip_llm_grounding: bool = False,
    ) -> None:
        self._reactive = reactive
        self._skip_llm_grounding = skip_llm_grounding
        self.promotion = promotion

    @property
    def reactive_capable(self) -> bool:
        """Whether reactive axis batches can run for this service."""

        return not self._skip_llm_grounding and self._reactive is not None

    def prepare_reactive(
        self,
        source: QdlGraph,
        axis: str,
        action_ids: tuple[str, ...],
        *,
        context: Mapping[str, object] | None = None,
        observation=None,
        check: Check | None = None,
        evidence: EvidenceView | None = None,
    ) -> AxisResult | None:
        """Return a validated proposal against the owner's immutable wave graph."""

        if not self.reactive_capable or not action_ids:
            return None
        classification_context = (
            ClassificationPromotionContext.from_mapping(context)
            if axis == "classification"
            else None
        )
        result = self._reactive.ground_reactive(
            axis,
            action_ids,
            source,
            context_extra=context,
            observation=observation,
            check=check,
            evidence=evidence,
        )

        if (
            result is not None
            and result.classification_context is None
            and classification_context is not None
        ):
            result = replace(
                result,
                classification_context=classification_context.with_evidence_refs(
                    result.observation_ids
                ),
            )
        return result

    def commit(
        self,
        service: str,
        source: QdlGraph,
        axis: str,
        action_ids: tuple[str, ...],
        result: AxisResult,
        *,
        sibling_slice: SiblingActionSlice | None = None,
        evidence: EvidenceView | None = None,
        previous: QdlGraph | None = None,
    ) -> QdlGraph | None:
        """Admit and persist one reactive or pinned-neighbourhood proposal."""

        branch = sibling_slice is not None
        if branch and (axis, len(action_ids)) != ("alternatives", 1):
            raise ValueError(
                "branch admission requires one blocked alternatives action"
            )
        identity = action_ids[0] if branch else "+".join(action_ids)
        batch_key = (
            f"alternatives:{identity}"
            if branch
            else f"{axis}:{'+'.join(sorted(action_ids))}"
        )
        self.promotion.park_secret_shapes(
            f"proposal:{service}:reactive:{batch_key}:secret-shapes",
            action_ids,
            evidence,
            evidence_refs=frozenset(result.observation_ids),
        )
        if result.graph is None or not result.graph.facts:
            return None
        scope_actions = (
            (sibling_slice.action, *(item.action for item in sibling_slice.siblings))
            if sibling_slice is not None
            else ()
            if axis == "fixture"
            else action_ids
        )
        deficit_id = f"blocked:{identity}" if branch else f"reactive:{axis}:{identity}"
        promoted = self.promotion.promote(
            ProposalPromotionRequest(
                source=source,
                proposal=result.graph,
                evidence_fields=frozenset(evidence_response_fields(evidence)),
                action_ids=scope_actions,
                evidence_refs=frozenset(result.observation_ids),
                runtime_evidence_exempt_predicates=frozenset({"refers_to", "targets"})
                if axis == "fixture"
                else frozenset(),
                classification_context=None
                if branch
                else result.classification_context,
            ),
            proposal_source_id=f"proposal:{service}:reactive:{batch_key}",
            activity=Activity(
                component=f"consultation:{axis}",
                invocation_id=f"consultation:{deficit_id}:0",
                correlation_id=deficit_id,
            ),
        )
        if promoted is None:
            return None
        persisted = self._save(
            service,
            axis,
            action_ids,
            batch_key,
            promoted,
            evidence_refs=frozenset(result.observation_ids),
            previous=previous if previous is not None else source,
            branch=branch,
        )
        if branch:
            logger.info(
                "branch_grounding_promoted service=%s action=%s facts=%d",
                service,
                identity,
                len(promoted.facts),
            )
        else:
            logger.info(
                "reactive_grounding_promoted service=%s axis=%s actions=%d facts=%d",
                service,
                axis,
                len(action_ids),
                len(promoted.facts),
            )
        return persisted

    def prepare_branch(
        self,
        source: QdlGraph,
        action: str,
        *,
        sibling_slice: SiblingActionSlice,
        observation=None,
        check: Check | None = None,
        evidence: EvidenceView | None = None,
        effect_hint: str = "",
        blocked_reason: str = "",
    ) -> AxisResult | None:
        """Return alternatives in the same bounded neighbourhood used at commit."""

        if not self.reactive_capable:
            return None
        return self._reactive.ground_alternatives(
            source,
            action,
            observation=observation,
            check=check,
            evidence=evidence,
            effect_hint=effect_hint,
            blocked_reason=blocked_reason,
            sibling_slice=sibling_slice,
        )

    def _save(
        self,
        service: str,
        axis: str,
        action_ids: tuple[str, ...],
        batch_key: str,
        promoted: QdlGraph,
        *,
        evidence_refs: frozenset[str],
        previous: QdlGraph,
        branch: bool,
    ) -> QdlGraph:
        """Persist batch provenance without changing supersession ordering."""

        persisted = promoted if branch else append_supersession(promoted, previous)
        provenance: dict[str, object] = (
            {"source_kind": "branch-grounding", "action": action_ids[0]}
            if branch
            else {
                "source_kind": "reactive-grounding",
                "axis": axis,
                "actions": list(action_ids),
            }
        )
        provenance["evidence_refs"] = sorted(evidence_refs)
        saved, _source_id = self.promotion.save_promoted_graph(
            f"accepted-batch:{service}:reactive:{batch_key}",
            persisted,
            provenance=provenance,
            adapter_version="branch-grounding-v1"
            if branch
            else "reactive-grounding-v1",
            previous=previous if branch else None,
        )
        return append_supersession(promoted, previous) if branch else saved
