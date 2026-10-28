"""Dependency assembly for the live path execution coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from cloud_dast.extensions import (
    FindingShrinkerFactory,
    FuzzSessionFactory,
    SymbolicPrefilter,
)
from cloud_dast.model.events import DomainEvent
from cloud_dast.ports import (
    EventPublisher,
    EventStore,
    FindingExampleStore,
    FormalRepository,
)
from cloud_dast.runtime.campaign.round import (
    Runner,
    RunnerDeps,
)
from cloud_dast.runtime.candidates.session import StepCandidateRunner
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.evidence_projection import Projection
from cloud_dast.runtime.evidence_reuse import Reuse
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.execution.evidence import PathSignature
from cloud_dast.runtime.execution.prefilter import SymbolicPathPrefilter
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.terminal import Callbacks, PathTerminalizer
from cloud_dast.runtime.finding_shrinking import FindingShrinkCoordinator
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.observation_effects import Publisher
from cloud_dast.runtime.observation_recording import Coordinator
from cloud_dast.runtime.readback_reevaluation import Reevaluation
from cloud_dast.verification.evaluation import ObservationEvaluator
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.oracles.grounded import GroundedOutcomeOracle
from cloud_dast.verification.oracles.primitive_router import PrimitiveOracleRouter
from cloud_dast.verification.projection import ObservationProjector


@dataclass(frozen=True, slots=True)
class BoundPathRunnerOptions:
    """Optional adapters used by the live path execution owner."""

    grounded_oracle: GroundedOutcomeOracle | None = None
    primitive_oracle: PrimitiveOracleRouter | None = None
    formal_repository: FormalRepository | None = None
    observation_projector: ObservationProjector | None = None
    fuzz_session_factory: FuzzSessionFactory | None = None
    finding_shrinker_factory: FindingShrinkerFactory | None = None
    example_database: FindingExampleStore | None = None
    symbolic_prefilter: SymbolicPrefilter | None = None
    metrics: CampaignMetrics | None = None

    @classmethod
    def from_legacy(
        cls,
        options: BoundPathRunnerOptions | None,
        values: dict[str, object],
    ) -> BoundPathRunnerOptions:
        if options is not None:
            if values:
                raise TypeError("pass either options or individual runner options")
            return options
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(values) - known)
        if unknown:
            raise TypeError("unknown runner options: " + ", ".join(unknown))
        return cls(**values)


class RunnerAssembly:
    """Build injected runtime services without owning their behavior."""

    def _initialize_core(
        self,
        checker: Checker,
        event_bus: EventPublisher,
        event_store: EventStore,
        settings: BoundPathRunnerOptions,
    ) -> None:
        self._checker = checker
        self._event_bus = event_bus
        self._events = event_store
        self._primitive_oracle = settings.primitive_oracle or PrimitiveOracleRouter(
            grounded_oracle=settings.grounded_oracle
        )
        self._norm_compiler = NormCompiler()
        self._observation_projector = (
            settings.observation_projector or ObservationProjector()
        )
        self._fuzz_session_factory = settings.fuzz_session_factory
        self._finding_shrinker_factory = settings.finding_shrinker_factory
        self._example_database = settings.example_database
        self._metrics = settings.metrics
        self._path_definitions: dict[str, QdlExecutionPath] = {}
        self._event_consumer_id = f"path-runner:{uuid4().hex}"
        self._projected_events: list[DomainEvent] = []

    def _initialize_observation_services(
        self,
        settings: BoundPathRunnerOptions,
    ) -> None:
        self._evidence_projection = Projection(
            events=self._refresh_event_projection,
            path_lookup=self._path_definitions.get,
            checks=lambda: self._checker.checks,
            formal_repository=settings.formal_repository,
            observation_projector=self._observation_projector,
        )
        self._evidence_signature = PathSignature(
            self._evidence_projection.observed_graph,
        ).build
        self._finding_shrinking = FindingShrinkCoordinator(
            factory=settings.finding_shrinker_factory,
            example_database=settings.example_database,
            execute_check=self._execute_check_with_budget,
            classify_observation=self._evaluator.evaluate,
        )
        self._observation_effects = Publisher(
            publish=self._publish,
            evidence_projection=self._evidence_projection,
            executed_check_identities=self._executed_check_identities,
        )
        self._observation_recording = Coordinator(
            classify_observation=self._evaluator.evaluate,
            executed_check_identities=self._executed_check_identities,
            publish_effects=self._observation_effects.publish_observation,
            service_checks=lambda: self._checker.checks,
            metrics=settings.metrics,
        )
        self._evidence_reuse = Reuse(
            refresh_events=self._refresh_event_projection,
            observed_graph=self._evidence_projection.observed_graph,
            set_coupling_context=self._checker.set_coupling_context,
            generate_pair_checks=self._checker.generate_pair_checks,
            resolve_check=self._checker.resolve_check,
            publish_step_event=self._observation_effects.publish_step_event,
        )
        self._differential = ProbeExecutor(
            self._checker,
            self._event_bus,
        )

    def _initialize_candidate_services(
        self,
        settings: BoundPathRunnerOptions,
    ) -> None:
        self._step_candidates = StepCandidateRunner(
            fuzz_session_factory=settings.fuzz_session_factory,
            symbolic_prefilter=settings.symbolic_prefilter,
            publish=self._publish,
            execute_step_with_budget=self._execute_step_with_budget,
            execute_check_with_budget=self._execute_check_with_budget,
            path_scoped_step=self._path_scoped_step,
            checks_for_step=lambda context: context.prefiltered.checks[
                context.step_index
            ],
        )
        self._path_prefilter = SymbolicPathPrefilter(
            symbolic_prefilter=settings.symbolic_prefilter,
            preview_path=self._step_candidates.preview_path,
            generate_checks=lambda step: self._checker.generate_pair_checks(
                step.plan,
                step.method,
                step.invariant,
                step.scenario,
                strategy=step.plan.generator,
            ),
            publish=self._publish,
        )
        self._evaluator = ObservationEvaluator(
            primitive_oracle=self._primitive_oracle,
            observation_projector=self._observation_projector,
            build_evidence_key=ProbeExecutor.build_evidence_key,
            norm_compiler=self._norm_compiler,
        )

    def _initialize_round_services(self) -> None:
        self._readback_reevaluation = Reevaluation(
            norm_compiler=self._norm_compiler,
            build_evidence_key=ProbeExecutor.build_evidence_key,
            classify_observation=self._evaluator.evaluate,
            trace_for_step=self._evaluator.trace_for_step,
            publish_step_event=self._observation_effects.publish_step_event,
        )
        self._path_terminal = PathTerminalizer(
            Callbacks(
                publish=self._publish,
                refresh_events=self._refresh_event_projection,
                path_definitions=lambda: self._path_definitions,
                metrics=self._metrics,
                evidence_signature=self._evidence_signature,
            )
        )
        self._campaign_round = Runner(
            RunnerDeps(
                reset_checks=self._checker.reset_checks,
                refresh_events=self._refresh_event_projection,
                register_paths=lambda paths: self._path_definitions.update(
                    {path.path_id: path for path in paths}
                ),
                initialize_intents=self._initialize_intent_states,
                mark_executing=self._mark_path_executing,
                has_finding_examples=self._has_finding_examples,
                skip_evaluated_path=self._path_terminal.skip_evaluated_path,
                execute_path=self._execute_path,
                publish_scheduler_terminal_events=(
                    self._path_terminal.publish_scheduler_terminal_events
                ),
                publish_missing_terminal_path_events=(
                    self._path_terminal.publish_missing_terminal_path_events
                ),
                service_checks=lambda: self._checker.checks,
                evidence_signature=self._evidence_signature,
                reconsider_paths=self._path_terminal.reconsider_paths,
            )
        )


__all__ = ["RunnerAssembly", "BoundPathRunnerOptions"]
