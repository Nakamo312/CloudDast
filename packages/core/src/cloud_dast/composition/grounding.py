"""Run-scoped assembly of independent grounding owners."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from dishka import Provider as DishkaProvider
from dishka import provide

from cloud_dast.composition.scopes import RunScope
from cloud_dast.ports import ApprovalAuditLog, FormalGrounder, FormalRepository
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.classification import ApprovalFlow
from cloud_dast.runtime.grounding.config import ReactiveGrounding, StartupGrounding
from cloud_dast.runtime.grounding.consultation import DispatchFlow
from cloud_dast.runtime.grounding.evidence import MeasuredEvidencePolicy
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator, RunOptions
from cloud_dast.runtime.grounding.promotion import ProposalPromoter
from cloud_dast.runtime.grounding.runtime import BatchFlow
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.state import ConsultationLedger, LeadLifecycle
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.verification.promotion import PromotionPolicy


@dataclass(frozen=True, slots=True)
class ServiceOptions:
    """Assembly settings for grounding policies and capabilities."""

    ingest_contract: Callable[[str], object] | None = None
    project_stand: Callable[[str], QdlGraph] | None = None
    startup: StartupGrounding | None = None
    reactive: ReactiveGrounding | None = None
    formal_grounder: FormalGrounder | None = None
    skip_llm_grounding: bool = False
    formal_timeout: float = 600.0
    promotion_policy: PromotionPolicy | None = None
    measured_evidence_policy: MeasuredEvidencePolicy | None = None
    approval_audit_log: ApprovalAuditLog | None = None

    def __post_init__(self) -> None:
        if self.formal_timeout <= 0:
            raise ValueError("formal_timeout must be positive")
        object.__setattr__(
            self,
            "promotion_policy",
            self.promotion_policy or PromotionPolicy(enabled=False),
        )


class Provider(DishkaProvider):
    """Wire grounding owners with one shared promotion boundary per run."""

    @provide(scope=RunScope)
    def lead_lifecycle(self) -> LeadLifecycle:
        return LeadLifecycle()

    @provide(scope=RunScope)
    def consultation_ledger(self) -> ConsultationLedger:
        return ConsultationLedger()

    @provide(scope=RunScope)
    def proposal_promoter(
        self,
        repository: FormalRepository,
        settings: ServiceOptions,
        lead_lifecycle: LeadLifecycle,
    ) -> ProposalPromoter:
        return ProposalPromoter(
            repository,
            promotion_policy=settings.promotion_policy,
            lead_lifecycle=lead_lifecycle,
        )

    @provide(scope=RunScope)
    def loader(
        self, repository: FormalRepository, promoter: ProposalPromoter
    ) -> Loader:
        return Loader(repository, promoter)

    @provide(scope=RunScope)
    def batch_flow(
        self, settings: ServiceOptions, promoter: ProposalPromoter
    ) -> BatchFlow:
        return BatchFlow(
            settings.reactive,
            promoter,
            skip_llm_grounding=settings.skip_llm_grounding,
        )

    @provide(scope=RunScope)
    def run_coordinator(
        self,
        repository: FormalRepository,
        settings: ServiceOptions,
        promoter: ProposalPromoter,
        loader: Loader,
    ) -> RunCoordinator:
        policy = settings.promotion_policy
        return RunCoordinator(
            repository,
            RunOptions(
                ingest_contract=settings.ingest_contract,
                project_stand=settings.project_stand,
                startup=settings.startup,
                formal_grounder=settings.formal_grounder,
                skip_llm_grounding=settings.skip_llm_grounding,
                formal_timeout=settings.formal_timeout,
                formal_enabled=lambda: policy.enabled and not policy.exhausted,
                promotion=promoter,
                source=loader,
            ),
        )

    @provide(scope=RunScope)
    def differential_flow(
        self,
        repository: FormalRepository,
        settings: ServiceOptions,
        promoter: ProposalPromoter,
        loader: Loader,
        batches: BatchFlow,
    ) -> DifferentialFlow:
        return DifferentialFlow(
            repository,
            promoter,
            settings.reactive,
            settings.measured_evidence_policy or MeasuredEvidencePolicy(),
            reactive_capable=lambda: batches.reactive_capable,
            source=loader,
        )

    @provide(scope=RunScope)
    def dispatch_flow(
        self,
        settings: ServiceOptions,
        promoter: ProposalPromoter,
        loader: Loader,
        batches: BatchFlow,
        ledger: ConsultationLedger,
    ) -> DispatchFlow:
        return DispatchFlow(
            settings.reactive,
            promoter,
            loader,
            ledger,
            reactive_capable=lambda: batches.reactive_capable,
        )

    @provide(scope=RunScope)
    def approval_flow(
        self,
        repository: FormalRepository,
        settings: ServiceOptions,
        promoter: ProposalPromoter,
    ) -> ApprovalFlow:
        return ApprovalFlow(repository, promoter, settings.approval_audit_log)
