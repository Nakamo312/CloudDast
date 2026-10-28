"""Runtime-managed automatic model grounding before planning.

Every campaign start re-runs the deterministic projections (contract,
stand) and — behind its explicit flag — the LLM semantic layer.  All
operations are idempotent and content-addressed, so re-running is always
safe: unchanged sources produce identical facts that merge to themselves.
No manual CLI rituals before a run.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from cloud_dast.consultation import (
    ConsultationRequest,
    ConsultationResult,
)
from cloud_dast.model import (
    Check,
    Observation,
)
from cloud_dast.ports import (
    FormalRepository,
    GroundingHandle,
    GroundingRunner,
)
from cloud_dast.proposals import ProposalPromotionRequest
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.classification import (
    ApprovalFlow,
    ApprovalResult,
    ParkedClassification,
    promotion_context,
)
from cloud_dast.runtime.grounding.config import ServiceOptions
from cloud_dast.runtime.grounding.consultation import DispatchFlow
from cloud_dast.runtime.grounding.evidence import MeasuredEvidencePolicy
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator, RunOptions
from cloud_dast.runtime.grounding.projection import (
    append_supersession as _append_supersession,
)
from cloud_dast.runtime.grounding.promotion import (
    Activity,
    ProposalPromoter,
)
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.state import (
    ConsultationLedger,
    LeadLifecycle,
    ParkedLeadState,
)
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence import EvidenceView, evidence_response_fields
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast.verification.slices import SiblingActionSlice

logger = logging.getLogger("cloud_dast.runtime.grounding")
_SUPERSESSION_PREDICATES = frozenset({"causes", "has"})
_CAUSES_SUPERSESSION_EFFECTS = frozenset({"reached", "duration"})
_HAS_SUPERSESSION_ROLE_FAMILIES = (frozenset({"setup_value", "setup_skip"}),)


class AutoGroundingService:
    """Bring the model for one service up to date before planning.

    Set ``skip_llm_grounding=True`` (or the environment variable
    ``CLOUD_DAST_SKIP_LLM_GROUNDING=1``) to reuse already-persisted
    semantic facts from previous runs.  Deterministic projections
    (contract, stand) still run — they are cheap and idempotent.
    Production passes the shared ``PromotionPolicy`` from composition; the
    policy, not the model, decides which proposal facts become accepted.
    """

    def __init__(
        self,
        repository: FormalRepository,
        *,
        options: ServiceOptions | None = None,
        **values: object,
    ) -> None:
        settings = ServiceOptions.from_legacy(options, values)
        ingest_contract = settings.ingest_contract
        project_stand = settings.project_stand
        axis_grounding = settings.axis_grounding
        formal_grounder = settings.formal_grounder
        skip_llm_grounding = settings.skip_llm_grounding
        formal_timeout = settings.formal_timeout
        promotion_policy = settings.promotion_policy
        measured_evidence_policy = settings.measured_evidence_policy
        approval_audit_log = settings.approval_audit_log
        if formal_timeout <= 0:
            raise ValueError("formal_timeout must be positive")
        self._repository = repository
        self._axis_grounding = axis_grounding
        self._skip_llm_grounding = skip_llm_grounding
        self._promotion_policy = promotion_policy or PromotionPolicy(enabled=False)
        self._measured_evidence_policy = (
            measured_evidence_policy or MeasuredEvidencePolicy()
        )
        self._lead_lifecycle = LeadLifecycle()
        self._consultation_ledger = ConsultationLedger()
        self._promotion = ProposalPromoter(
            repository,
            promotion_policy=self._promotion_policy,
            lead_lifecycle=self._lead_lifecycle,
        )
        self._source = Loader(repository, self._promotion)
        self._consultation = DispatchFlow(
            axis_grounding,
            self._promotion,
            self._source,
            self._consultation_ledger,
            reactive_capable=lambda: self.reactive_capable,
        )
        self._classification = ApprovalFlow(
            repository,
            self._promotion,
            approval_audit_log,
        )
        self._lifecycle = RunCoordinator(
            repository,
            RunOptions(
                ingest_contract=ingest_contract,
                project_stand=project_stand,
                axis_grounding=axis_grounding,
                formal_grounder=formal_grounder,
                skip_llm_grounding=skip_llm_grounding,
                formal_timeout=formal_timeout,
                formal_enabled=lambda: (
                    self._promotion_policy.enabled
                    and not self._promotion_policy.exhausted
                ),
                promotion=self._promotion,
                source=self._source,
            ),
        )
        self._variance = DifferentialFlow(
            repository,
            self._promotion,
            axis_grounding,
            self._measured_evidence_policy,
            reactive_capable=lambda: self.reactive_capable,
            source=self._source,
        )

    def start_grounded(
        self,
        service: str,
        runner: GroundingRunner,
    ) -> GroundingHandle | None:
        """Start background grounding through the lifecycle owner."""

        return self._lifecycle.start_grounded(service, runner)

    def load_parked_proposals(self, service: str) -> QdlGraph:
        """Merge every latest parked proposal source for one service."""

        return self._promotion.load_parked_proposals(service)

    def parked_lead_states(self) -> tuple[ParkedLeadState, ...]:
        """Return the minimal deduplicated lead lifecycle state."""

        return self._promotion.parked_lead_states()

    def list_classification_approval_queue(
        self, service: str
    ) -> tuple[ParkedClassification, ...]:
        """Return pending protected-role classifications in stable order."""
        return self._classification.list_approval_queue(service)

    def promote_parked_classification(
        self,
        service: str,
        fact_hash: str,
        *,
        operator: str,
        reason: str,
    ) -> ApprovalResult:
        """Promote exactly one operator-reviewed parked classification.

        The operator supplies missing classification provenance, not execution
        authority.  The selected fact still passes the deterministic promotion
        boundary; its action must exist in the source graph and its supporting
        declarations must be self-contained.  No lead norm from the parked graph
        is included, so approval cannot turn an LLM hypothesis directly into a
        finding or an executable norm.
        """

        return self._classification.approve(
            service,
            fact_hash,
            operator=operator,
            reason=reason,
        )

    @property
    def reactive_capable(self) -> bool:
        """Whether reactive axis batches can run for this service."""

        return not self._skip_llm_grounding and self._axis_grounding is not None

    def prepare_reactive_batch(
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
        return self._axis_grounding.ground_reactive(
            axis,
            action_ids,
            source,
            context_extra=context,
            observation=observation,
            check=check,
            evidence=evidence,
        )

    def commit_reactive_batch(
        self,
        service: str,
        source: QdlGraph,
        axis: str,
        action_ids: tuple[str, ...],
        result: AxisResult,
        *,
        context: Mapping[str, object] | None = None,
        evidence: EvidenceView | None = None,
        previous: QdlGraph | None = None,
    ) -> QdlGraph | None:
        """Promote and persist one admitted result on the campaign owner."""

        batch_key = f"{axis}:{'+'.join(sorted(action_ids))}"
        self._promotion.park_secret_shapes(
            f"proposal:{service}:reactive:{batch_key}:secret-shapes",
            action_ids,
            evidence,
            evidence_refs=frozenset(result.observation_ids),
        )
        deficit_id = f"reactive:{axis}:{'+'.join(action_ids)}"
        fixture_axis = axis == "fixture"
        classification_context = result.classification_context
        if classification_context is None and axis == "classification":
            classification_context = promotion_context(
                context,
                evidence_refs=result.observation_ids,
            )
        if result.graph is None or not result.graph.facts:
            return None
        promoted = self._promotion.promote(
            ProposalPromotionRequest(
                source=source,
                proposal=result.graph,
                evidence_fields=frozenset(evidence_response_fields(evidence)),
                action_ids=() if fixture_axis else action_ids,
                evidence_refs=frozenset(result.observation_ids),
                runtime_evidence_exempt_predicates=frozenset({"refers_to", "targets"})
                if fixture_axis
                else frozenset(),
                classification_context=classification_context,
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
        persisted = self._save_reactive_promotion(
            service,
            axis,
            action_ids,
            batch_key,
            promoted,
            evidence_refs=frozenset(result.observation_ids),
            previous=previous if previous is not None else source,
        )
        logger.info(
            "reactive_grounding_promoted service=%s axis=%s actions=%d facts=%d",
            service,
            axis,
            len(action_ids),
            len(promoted.facts),
        )
        return persisted

    def prepare_branch_batch(
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
        return self._axis_grounding.ground_alternatives(
            source,
            action,
            observation=observation,
            check=check,
            evidence=evidence,
            effect_hint=effect_hint,
            blocked_reason=blocked_reason,
            sibling_slice=sibling_slice,
        )

    def commit_branch_batch(
        self,
        service: str,
        source: QdlGraph,
        action: str,
        result: AxisResult,
        *,
        sibling_slice: SiblingActionSlice,
        evidence: EvidenceView | None = None,
        previous: QdlGraph | None = None,
    ) -> QdlGraph | None:
        """Apply an admitted alternatives proposal through the shared policy."""

        action_ids = (
            sibling_slice.action,
            *(sibling.action for sibling in sibling_slice.siblings),
        )
        batch_key = f"alternatives:{action}"
        self._promotion.park_secret_shapes(
            f"proposal:{service}:reactive:{batch_key}:secret-shapes",
            (action,),
            evidence,
            evidence_refs=frozenset(result.observation_ids),
        )
        deficit_id = f"blocked:{action}"
        if result.graph is None or not result.graph.facts:
            return None
        promoted = self._promotion.promote(
            ProposalPromotionRequest(
                source=source,
                proposal=result.graph,
                evidence_fields=frozenset(evidence_response_fields(evidence)),
                action_ids=action_ids,
                evidence_refs=frozenset(result.observation_ids),
            ),
            proposal_source_id=f"proposal:{service}:reactive:{batch_key}",
            activity=Activity(
                component="consultation:alternatives",
                invocation_id=f"consultation:{deficit_id}:0",
                correlation_id=deficit_id,
            ),
        )
        if promoted is None:
            return None
        persisted = self._save_branch_promotion(
            service,
            action,
            batch_key,
            promoted,
            evidence_refs=frozenset(result.observation_ids),
            previous=previous if previous is not None else source,
        )
        logger.info(
            "branch_grounding_promoted service=%s action=%s facts=%d",
            service,
            action,
            len(promoted.facts),
        )
        return persisted

    def _save_reactive_promotion(
        self,
        service: str,
        axis: str,
        action_ids: tuple[str, ...],
        batch_key: str,
        promoted: QdlGraph,
        evidence_refs: frozenset[str] = frozenset(),
        previous: QdlGraph | None = None,
    ) -> QdlGraph:
        """Persist one promoted reactive batch and return persisted facts."""

        persisted = _append_supersession(promoted, previous)
        self._promotion.save_promoted_graph(
            f"accepted-batch:{service}:reactive:{batch_key}",
            promoted,
            provenance={
                "source_kind": "reactive-grounding",
                "axis": axis,
                "actions": list(action_ids),
                "evidence_refs": sorted(evidence_refs),
            },
            adapter_version="reactive-grounding-v1",
            previous=previous,
        )
        return persisted

    def _save_branch_promotion(
        self,
        service: str,
        action: str,
        batch_key: str,
        promoted: QdlGraph,
        evidence_refs: frozenset[str] = frozenset(),
        previous: QdlGraph | None = None,
    ) -> QdlGraph:
        """Persist one promoted branch-grounding batch."""

        self._promotion.save_promoted_graph(
            f"accepted-batch:{service}:reactive:{batch_key}",
            promoted,
            provenance={
                "source_kind": "branch-grounding",
                "action": action,
                "evidence_refs": sorted(evidence_refs),
            },
            adapter_version="branch-grounding-v1",
            previous=previous,
        )
        return _append_supersession(promoted, previous)

    def load_source(
        self,
        service: str,
        *,
        failure_log: str,
    ) -> QdlGraph | None:
        """Load the current contract, stand, and accepted semantics."""

        return self._source.load(service, failure_log=failure_log)

    def ground_consultation(
        self,
        service: str,
        request: ConsultationRequest,
    ) -> ConsultationResult:
        """Dispatch one typed consultation and promote it deterministically.

        The consultation dispatcher validates the model response and returns
        a proposal (or UNSCOREABLE); promotion is the existing deterministic
        policy over the current merged source, never the model.  Persisted
        provenance carries the full consultation audit record.

        S32R belief revision applies before dispatch: once one consultation
        identity has absorbed an evidence set, a repeat request is admitted
        only when it carries a new observation.  A vacuous repeat preserves
        the existing lead and returns UNSCOREABLE without another model call.
        """

        return self._consultation.run(service, request)

    def persist_measured_evidence(
        self,
        service: str,
        action_id: str,
        control: Observation,
        treatment: Observation,
        report: DiffReport,
        *,
        control_check: Check | None = None,
        treatment_check: Check | None = None,
    ) -> QdlGraph | None:
        """Persist deterministic canary-echo evidence without promoting it."""
        return self._variance.persist_measured_evidence(
            service,
            action_id,
            control,
            treatment,
            report,
            control_check=control_check,
            treatment_check=treatment_check,
        )

    def prepare_variance_batch(
        self,
        request: PairInput,
    ) -> AxisResult | None:
        """Return a variance proposal; measured evidence is already owned by workflow."""
        return self._variance.prepare_batch(request)

    def commit_variance_batch(
        self,
        service: str,
        source: QdlGraph,
        action_id: str,
        report: DiffReport,
        result: AxisResult,
        *,
        evidence: EvidenceView,
    ) -> QdlGraph | None:
        """Promote and persist one admitted measured-variance proposal."""
        return self._variance.commit_batch(
            service,
            source,
            action_id,
            report,
            result,
            evidence=evidence,
        )
