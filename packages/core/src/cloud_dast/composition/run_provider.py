from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from dishka import Provider, alias, provide
from hypothesis.database import InMemoryExampleDatabase

import cloud_dast.composition.runtime as runtime_composition
from cloud_dast.candidates import TemplateGenerator
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.grounding import ServiceOptions
from cloud_dast.composition.profile import (
    classification_profile_from_environment,
    parse_environment_flag,
)
from cloud_dast.composition.scopes import AppScope, RunScope
from cloud_dast.config import DEFAULT_MAX_PROMOTED_NORMS, MAX_SEMANTIC_FACTS
from cloud_dast.contracts.payload_proposals import MAX_PAYLOAD_CORPUS_DELTA_ITEMS
from cloud_dast.extensions import (
    DefaultGeneratorCatalog,
    DefaultGeneratorPolicy,
    DefaultGeneratorSelector,
    ExtensionRegistry,
    FindingShrinkerFactory,
    FuzzSession,
    FuzzSessionFactory,
    FuzzSessionRequest,
    GeneratorCatalogPort,
    GeneratorPolicy,
    GeneratorSelectorPort,
    PayloadCorpusSource,
    PayloadStrategyCompiler,
    RequestSolver,
    SymbolicGenerator,
    SymbolicPrefilter,
    TestCaseGenerator,
)
from cloud_dast.infrastructure.advisory import AdvisoryPreScanService
from cloud_dast.infrastructure.events import EventBus, JsonlEventStore
from cloud_dast.infrastructure.events.jsonl_example_database import (
    JsonlExampleDatabase,
)
from cloud_dast.infrastructure.neo4j.common.repository import SessionFactory
from cloud_dast.infrastructure.neo4j.live.scenario_repository import (
    Neo4jScenarioRepository,
)
from cloud_dast.infrastructure.neo4j.stand_projection import Neo4jStandProjector
from cloud_dast.infrastructure.runtime import (
    FileGroundingCache,
    JsonlEvidenceChannel,
    MemoryEvidenceChannel,
    OobCollaborator,
    ThreadedGroundingRunner,
)
from cloud_dast.infrastructure.stand import FileStandSource
from cloud_dast.model import (
    EndpointLayer,
    MethodSpec,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.model.checks import scenario_id_for
from cloud_dast.model.events import (
    CheckCompleted,
    ComponentInvoked,
    ComponentOutput,
    ComponentSkipped,
    CoverageUpdated,
    DiffPairComputed,
    DownstreamDecision,
    EvidenceRecorded,
    FactVerified,
    FindingRaised,
    IntentProposed,
    InvestigationActionExecuted,
    PhaseChanged,
    QdlPathEvaluated,
    QdlStepEvaluated,
    canonical_action_id,
    normalize_principal,
)
from cloud_dast.ports import (
    ContractGraphRepository,
    EventPublisher,
    EventStore,
    EvidenceChannel,
    FindingExampleStore,
    FormalRepository,
    GroundingRunner,
    Guardrail,
    MethodRepository,
    ModelClient,
    OobEvaluator,
    OobUrlFactory,
    ReportPublisher,
    ScenarioRepository,
    StandSource,
    Target,
)
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import Atom
from cloud_dast.qdl.policy_projection import (
    GenericPolicyProjector,
)
from cloud_dast.qdl.reasoning import QdlSubgoal, derivable
from cloud_dast.qdl.threat_compiler import (
    ThreatIntentCompiler,
)
from cloud_dast.runtime import oob
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign import (
    BoundPathRunner,
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.grounding import BatchFlow
from cloud_dast.runtime.grounding.lifecycle import RunCoordinator
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.grounding.variance import DifferentialFlow
from cloud_dast.runtime.ingestion import ContractImporter
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.planning import IncrementalQdlPlanner, QdlPlanner
from cloud_dast.verification.differential.contracts import (
    IsolatedStandPolicy,
)
from cloud_dast.verification.oracles import (
    FieldExposureOracle,
    GroundedOutcomeOracle,
    LatencyBaseline,
    LatencyOracle,
    MarkerOracle,
    PrimitiveOracleRouter,
    SequenceOracle,
    WitnessSignalOracle,
)
from cloud_dast.verification.oracles import oob as verification_oob
from cloud_dast.verification.projection import ObservationProjector


def select_stand_source(
    session_factory: SessionFactory | None = None,
    *,
    source: str | None = None,
    stand_file: Path | None = None,
) -> StandSource:
    """Select the configured stand source without coupling callers to adapters."""

    selected = (
        (
            source
            if source is not None
            else os.environ.get("CLOUD_DAST_STAND_SOURCE", "file")
        )
        .strip()
        .lower()
    )
    if selected == "file":
        return FileStandSource(_configured_stand_file(stand_file))
    if selected == "neo4j":
        if session_factory is None:
            raise RuntimeError("the neo4j stand source requires a session factory")
        return Neo4jStandProjector(session_factory)
    raise RuntimeError("CLOUD_DAST_STAND_SOURCE must be one of: file, neo4j")


def _configured_stand_file(stand_file: Path | None = None) -> Path:
    return stand_file or Path(os.environ.get("CLOUD_DAST_STAND_FILE", "stand.json"))


def select_scenario_repository(
    session_factory: SessionFactory | None = None,
    *,
    source: str | None = None,
    stand_file: Path | None = None,
) -> ScenarioRepository:
    """Select the configured scenario repository without coupling callers."""

    selected = (
        (
            source
            if source is not None
            else os.environ.get("CLOUD_DAST_STAND_SOURCE", "file")
        )
        .strip()
        .lower()
    )
    if selected == "file":
        return FileScenarioRepository(_configured_stand_file(stand_file))
    if selected == "neo4j":
        if session_factory is None:
            raise RuntimeError(
                "the neo4j scenario repository requires a session factory"
            )
        return Neo4jScenarioRepository(session_factory)
    raise RuntimeError("CLOUD_DAST_STAND_SOURCE must be one of: file, neo4j")


class FileScenarioRepository:
    """Resolve file scenarios through the same QDL policy as stand ingestion.

    Positive may proves the requested decision. A completed solve can also
    prove its absence inside an explicit source completeness scope. Outside
    that service/subject/action/resource scope, missing may remains unknown.
    """

    def __init__(self, stand_file: Path) -> None:
        self._snapshot = FileStandSource(stand_file).snapshot("")
        self._policy = GenericPolicyProjector(self._snapshot).project("")

    def get_scenario(
        self,
        principal_id: str,
        resource_id: str,
        method: MethodSpec | None = None,
        *,
        method_id: str | None = None,
        scope_relation: ScopeRelation | None = None,
        binding_level: str | None = None,
        resource_state: str = "existing",
        identity_class: str = "attacker",
        addressing_mode: str = "direct",
    ) -> ScenarioPosition | None:
        principal = Atom(value=f"principal:{normalize_principal(principal_id)}")
        if not derivable(
            QdlSubgoal("is", (principal, Atom(value="Subject"))), self._policy
        ):
            return None

        authorized = False
        permissions_known = False
        resources = self._stand_resources(resource_id, method)
        if method is not None and resources:
            try:
                decisions = ClingoEngine().derive_may_triples(self._policy)
            except RuntimeError:
                decisions = None
            if decisions is not None:
                authorized = (
                    principal.value,
                    canonical_action_id(method.method_id),
                    f"resource:{resource_id.removeprefix('resource:')}",
                ) in decisions
                complete = any(
                    scope.service == method.service
                    and f"principal:{scope.subject}" == principal.value
                    and f"action:{scope.action}"
                    == canonical_action_id(method.method_id)
                    and resource_id.removeprefix("resource:") in scope.resources
                    for scope in self._snapshot.completeness
                )
                permissions_known = authorized or complete
        profile = ScenarioProfile(
            scope_relation=scope_relation or ScopeRelation.SAME_FOLDER,
            binding_level=binding_level or "resource",
            endpoint_layer=method.layer if method is not None else EndpointLayer.PUBLIC,
            resource_state=resource_state,
            identity_class=identity_class,
            addressing_mode=addressing_mode,
        )
        scenario_id = scenario_id_for(
            principal_id=principal_id,
            resource_id=resource_id,
            method_id=method.method_id if method is not None else method_id,
            profile=profile,
        )
        return ScenarioPosition(
            scenario_id=scenario_id,
            profile=profile,
            stand=StandState(
                resources=resources,
                principals=(
                    PrincipalRef(
                        principal_id=principal_id,
                        principal_type=(
                            "service_account" if identity_class == "service" else "user"
                        ),
                    ),
                ),
                effective_permissions=method.permissions if authorized else frozenset(),
                permissions_known=permissions_known,
            ),
        )

    def _stand_resources(
        self,
        resource_id: str,
        method: MethodSpec | None,
    ) -> tuple[ResourceRef, ...]:
        """Bind declared instances to the exact policy-query identity and type.

        Only declared, compatible resources can inherit this permission proof.
        """

        return tuple(
            ResourceRef(
                service=resource.service or (method.service if method else ""),
                resource_type=resource.resource_type,
                resource_id=resource.resource,
            )
            for resource in self._snapshot.resources
            if resource.resource == resource_id.removeprefix("resource:")
            and resource.resource_type is not None
            and (
                method is None
                or not method.resource_types
                or resource.resource_type in method.resource_types
            )
        )


def _latency_oracle_from_environment() -> LatencyOracle:
    raw = os.environ.get("CLOUD_DAST_LATENCY_BASELINES", "").strip()
    if not raw:
        return LatencyOracle()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("CLOUD_DAST_LATENCY_BASELINES must be JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("CLOUD_DAST_LATENCY_BASELINES must map method IDs to data")

    baselines = {}
    for method_id, row in payload.items():
        durations = (
            row
            if isinstance(row, list)
            else row.get("durations_ms")
            if isinstance(row, dict)
            else None
        )
        if not isinstance(durations, list):
            raise RuntimeError(
                f"latency baseline for {method_id} requires durations_ms"
            )
        baselines[method_id] = LatencyBaseline.from_durations(
            method_id, tuple(float(value) for value in durations)
        )
    return LatencyOracle(baselines)


def _skip_llm_grounding_from_environment() -> bool:
    return parse_environment_flag("CLOUD_DAST_SKIP_LLM_GROUNDING")


def _positive_int_from_environment(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _grounding_batch_size_from_environment() -> int:
    return _positive_int_from_environment("CLOUD_DAST_GROUNDING_BATCH_SIZE", 8)


def _grounding_workers_from_environment() -> int:
    return _positive_int_from_environment("CLOUD_DAST_GROUNDING_WORKERS", 4)


def _reactive_workers_from_environment() -> int:
    return _positive_int_from_environment("CLOUD_DAST_REACTIVE_WORKERS", 4)


def _grounding_cache_enabled_from_environment() -> bool:
    return parse_environment_flag("CLOUD_DAST_GROUNDING_CACHE", default=True)


def _reactive_budget_from_environment() -> int | None:
    raw = os.environ.get("CLOUD_DAST_REACTIVE_BUDGET", "8").strip()
    if raw.lower() == "all":
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "CLOUD_DAST_REACTIVE_BUDGET must be 'all' or a non-negative integer"
        ) from error
    if value < 0:
        raise RuntimeError(
            "CLOUD_DAST_REACTIVE_BUDGET must be 'all' or a non-negative integer"
        )
    return value


def _grounding_cache_dir_from_environment() -> Path:
    raw = os.environ.get(
        "CLOUD_DAST_GROUNDING_CACHE_DIR",
        "~/.cache/cloud-dast/grounding",
    ).strip()
    if not raw:
        raise RuntimeError("CLOUD_DAST_GROUNDING_CACHE_DIR must not be empty")
    return Path(raw).expanduser()


def _grounding_cache_namespace_from_environment() -> str:
    return json.dumps(
        {
            "adapter": "axis-grounding-v1",
            "model_id": os.environ.get("CLOUD_DAST_MODEL_ID", ""),
            "model_api": os.environ.get("CLOUD_DAST_MODEL_API", ""),
            "reasoning_effort": os.environ.get(
                "CLOUD_DAST_MODEL_REASONING_EFFORT",
                "",
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _fuzz_max_checks_from_environment() -> int:
    return _positive_int_from_environment("CLOUD_DAST_FUZZ_MAX_CHECKS", 3)


def _promote_formal_proposals_from_environment() -> bool:
    return parse_environment_flag("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS")


def _max_semantic_facts() -> int:
    return _positive_int_from_environment(
        "CLOUD_DAST_MAX_PROMOTED_SEMANTIC_FACTS",
        MAX_SEMANTIC_FACTS,
    )


def _max_payload_delta_items() -> int:
    return _positive_int_from_environment(
        "CLOUD_DAST_MAX_PAYLOAD_CORPUS_DELTA_ITEMS",
        MAX_PAYLOAD_CORPUS_DELTA_ITEMS,
    )


def select_promotion_policy() -> PromotionPolicy:
    """Build the one environment-gated promotion boundary for a run."""

    return PromotionPolicy(
        enabled=_promote_formal_proposals_from_environment(),
        max_norms=_max_promoted_norms_from_environment(),
        max_semantic_facts=_max_semantic_facts(),
        max_payload_delta_items=_max_payload_delta_items(),
    )


def _diff_mode_from_environment() -> bool:
    return parse_environment_flag("CLOUD_DAST_DIFF_MODE")


def _max_promoted_norms_from_environment() -> int | None:
    raw = os.environ.get(
        "CLOUD_DAST_MAX_PROMOTED_NORMS",
        str(DEFAULT_MAX_PROMOTED_NORMS),
    ).strip()
    if raw.lower() in {"all", "none"}:
        if raw.lower() == "none":
            raise RuntimeError("CLOUD_DAST_MAX_PROMOTED_NORMS must be positive or all")
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "CLOUD_DAST_MAX_PROMOTED_NORMS must be a positive integer or all"
        ) from error
    if value <= 0:
        raise RuntimeError(
            "CLOUD_DAST_MAX_PROMOTED_NORMS must be a positive integer or all"
        )
    return value


def _max_formal_actions_from_environment() -> int | None:
    raw = os.environ.get("CLOUD_DAST_MAX_FORMAL_ACTIONS", "12").strip()
    if raw.lower() == "all":
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "CLOUD_DAST_MAX_FORMAL_ACTIONS must be a positive integer or all"
        ) from error
    if value <= 0:
        raise RuntimeError(
            "CLOUD_DAST_MAX_FORMAL_ACTIONS must be a positive integer or all"
        )
    return value


class NullReportPublisher:
    """Keep the core composition standalone when reporting is not installed."""

    def publish_plan(self, execution, *, max_checks, scope) -> None:
        del execution, max_checks, scope

    def publish_coverage(self, coverage, *, scope) -> None:
        del coverage, scope


class RunProvider(Provider):
    """Wire one live run.

    Provider methods are runtime facts.  The S22R documentation test projects
    this wiring; prose must follow it rather than describe a parallel
    architecture.
    """

    oob_evaluator = alias(oob.Coordinator, provides=OobEvaluator)

    def __init__(
        self,
        model_client: ModelClient | None = None,
        extension_registry: ExtensionRegistry | None = None,
        report_publisher_factory: Callable[[EventPublisher], ReportPublisher]
        | None = None,
    ) -> None:
        super().__init__()
        self._model_client = model_client
        self._extensions = extension_registry or ExtensionRegistry.discover()
        self._report_publisher_factory = report_publisher_factory

    @provide(scope=RunScope)
    def promotion_policy(self) -> PromotionPolicy:
        return select_promotion_policy()

    @provide(scope=RunScope)
    def template_generator(self) -> TemplateGenerator:
        return TemplateGenerator()

    @provide(scope=RunScope)
    def payload_corpus(self) -> PayloadCorpusSource | None:
        factory = self._extensions.payload_corpus_factory
        return factory() if factory is not None else None

    @provide(scope=RunScope, provides=TestCaseGenerator)
    def test_case_generator(
        self,
        generator_catalog: GeneratorCatalogPort,
    ) -> TestCaseGenerator:
        return generator_catalog.one_shot()

    @provide(scope=RunScope)
    def minimal_seed_generator(
        self, template_generator: TemplateGenerator
    ) -> TestCaseGenerator:
        factory = self._extensions.minimal_seed_generator_factory
        return (
            factory(template_generator) if factory is not None else template_generator
        )

    @provide(scope=RunScope)
    def symbolic_generator(
        self, template_generator: TemplateGenerator
    ) -> SymbolicGenerator:
        """The symbolic strategy must produce solver-derived candidates."""

        factory = self._extensions.symbolic_generator_factory
        return (
            factory(template_generator) if factory is not None else template_generator
        )

    @provide(scope=RunScope, provides=RequestSolver)
    def grammar_request_solver(self) -> RequestSolver | None:
        """Expose the optional symbolic implementation through a core port."""

        return self._extensions.request_solver

    @provide(scope=RunScope)
    def fuzzing_generator(
        self,
        minimal_seed_generator: TestCaseGenerator,
        payload_compiler: PayloadStrategyCompiler | None = None,
        request_solver: RequestSolver = None,
    ) -> TestCaseGenerator | None:
        factory = self._extensions.fuzzing_generator_factory
        if factory is None:
            return None
        return factory(
            minimal_seed_generator,
            payload_compiler=payload_compiler,
            request_solver=request_solver,
        )

    @provide(scope=RunScope)
    def payload_compiler(
        self,
        payload_corpus: PayloadCorpusSource | None,
    ) -> PayloadStrategyCompiler | None:
        factory = self._extensions.payload_compiler_factory
        if factory is None:
            return None
        return factory(payload_corpus)

    @provide(scope=RunScope)
    def textual_generator(
        self, template_generator: TemplateGenerator
    ) -> TestCaseGenerator:
        factory = self._extensions.textual_generator_factory
        return (
            factory(template_generator) if factory is not None else template_generator
        )

    @provide(scope=RunScope)
    def generator_bandit(self) -> Any:
        factory = self._extensions.generator_policy_factory
        if factory is None:
            return DefaultGeneratorPolicy()
        return factory(seed=int(os.environ.get("CLOUD_DAST_GENERATOR_SEED", "0")))

    @provide(scope=RunScope, provides=GeneratorPolicy)
    def generator_policy(self) -> GeneratorPolicy:
        """Share one filtered strategy policy across adaptive sessions."""

        return self.generator_bandit()

    @provide(scope=RunScope)
    def generator_selector(
        self,
        template_generator: TemplateGenerator,
        symbolic_generator: SymbolicGenerator,
        fuzzing_generator: TestCaseGenerator | None,
        textual_generator: TestCaseGenerator,
        generator_policy: GeneratorPolicy,
        payload_corpus: PayloadCorpusSource | None,
        payload_compiler: PayloadStrategyCompiler | None = None,
        request_solver: RequestSolver = None,
    ) -> GeneratorSelectorPort:
        if (
            payload_compiler is None
            and self._extensions.payload_compiler_factory is not None
        ):
            payload_compiler = self._extensions.payload_compiler_factory(payload_corpus)
        generators: dict[str, TestCaseGenerator] = {
            "template": template_generator,
            "textual": textual_generator,
        }
        if self._extensions.symbolic_generator_factory is not None:
            generators["symbolic"] = symbolic_generator
        if fuzzing_generator is not None:
            generators["fuzzing"] = fuzzing_generator
        if self._extensions.llm_generator_factory is not None:
            generators["llm"] = self._extensions.llm_generator_factory(
                self._model_client,
                template_generator,
            )
        if (
            self._extensions.grammar_generator_factory is not None
            and payload_compiler is not None
        ):
            generators["grammar"] = self._extensions.grammar_generator_factory(
                template_generator,
                payload_compiler=payload_compiler,
                request_solver=request_solver,
            )
        configured_default = os.environ.get("CLOUD_DAST_GENERATOR", "template")
        default = configured_default if configured_default in generators else "template"
        factory = self._extensions.generator_selector_factory
        if factory is not None:
            return factory(
                generators=generators,
                default=default,
                policy=generator_policy,
            )
        return DefaultGeneratorSelector(template_generator)

    @provide(scope=RunScope)
    def generator_catalog(
        self,
        generator_selector: GeneratorSelectorPort,
        oob_urls: OobUrlFactory,
        payload_corpus: PayloadCorpusSource | None,
    ) -> GeneratorCatalogPort:
        """Expose one QDL-aware extension boundary to all consumers."""

        factory = self._extensions.generator_catalog_factory
        if factory is not None:
            return factory(
                generator_selector,
                oob_urls=oob_urls,
                payload_corpus=payload_corpus,
            )
        return DefaultGeneratorCatalog(generator_selector)

    @provide(scope=RunScope)
    def grounded_outcome_oracle(self) -> GroundedOutcomeOracle:
        return GroundedOutcomeOracle()

    @provide(scope=RunScope)
    def field_exposure_oracle(self) -> FieldExposureOracle:
        return FieldExposureOracle()

    @provide(scope=RunScope)
    def latency_oracle(self) -> LatencyOracle:
        return _latency_oracle_from_environment()

    @provide(scope=RunScope)
    def marker_oracle(self) -> MarkerOracle:
        return MarkerOracle()

    @provide(scope=RunScope)
    def sequence_oracle(self) -> SequenceOracle:
        return SequenceOracle()

    @provide(scope=RunScope, provides=EvidenceChannel)
    def evidence_channel(self, event_store: EventStore) -> EvidenceChannel:
        explicit_path = os.environ.get("CLOUD_DAST_EVIDENCE_LOG", "").strip()
        if explicit_path:
            return JsonlEvidenceChannel(explicit_path)
        if isinstance(event_store, JsonlEventStore):
            sidecar = event_store.path.with_name(
                event_store.path.name + ".evidence.jsonl",
            )
            return JsonlEvidenceChannel(sidecar)
        return MemoryEvidenceChannel()

    @provide(scope=RunScope, provides=FindingExampleStore)
    def finding_example_store(self, event_store: EventStore) -> FindingExampleStore:
        """Persist finding examples beside the JSONL event log."""

        explicit_path = os.environ.get("CLOUD_DAST_EXAMPLE_DATABASE", "").strip()
        if explicit_path:
            return JsonlExampleDatabase(explicit_path)
        if isinstance(event_store, JsonlEventStore):
            return JsonlExampleDatabase(
                event_store.path.with_name(
                    event_store.path.name + ".examples.jsonl",
                )
            )
        return InMemoryExampleDatabase()

    @provide(scope=RunScope, provides=OobUrlFactory)
    def oob_url_factory(self, events: EvidenceChannel) -> Iterator[OobUrlFactory]:
        collaborator = OobCollaborator(events)
        try:
            yield collaborator
        finally:
            collaborator.stop()

    @provide(scope=RunScope)
    def oob_oracle(self) -> verification_oob.Oracle:
        return verification_oob.Oracle()

    @provide(scope=RunScope)
    def oob_coordinator(
        self, events: EvidenceChannel, oracle: verification_oob.Oracle
    ) -> oob.Coordinator:
        return oob.Coordinator(
            events,
            oracle,
            wait_seconds=float(os.environ.get("CLOUD_DAST_OOB_WAIT_SECONDS", "1.0")),
        )

    @provide(scope=RunScope)
    def observation_projector(
        self, oob_events: EvidenceChannel
    ) -> ObservationProjector:
        return ObservationProjector(oob_events)

    @provide(scope=RunScope)
    def witness_oracle(
        self,
        latency_oracle: LatencyOracle,
        marker_oracle: MarkerOracle,
        oob_evaluator: OobEvaluator,
    ) -> WitnessSignalOracle:
        return WitnessSignalOracle(
            latency_oracle=latency_oracle,
            marker_oracle=marker_oracle,
            oob_oracle=oob_evaluator,
        )

    @provide(scope=RunScope)
    def primitive_oracle_router(
        self,
        grounded_outcome_oracle: GroundedOutcomeOracle,
        field_exposure_oracle: FieldExposureOracle,
        sequence_oracle: SequenceOracle,
        witness_oracle: WitnessSignalOracle,
    ) -> PrimitiveOracleRouter:
        return PrimitiveOracleRouter(
            grounded_oracle=grounded_outcome_oracle,
            field_oracle=field_exposure_oracle,
            sequence_oracle=sequence_oracle,
            witness_oracle=witness_oracle,
        )

    @provide(scope=RunScope)
    def scenario_checker(
        self,
        target: Target,
        test_case_generator: TestCaseGenerator,
        guardrail: Guardrail,
        event_bus: EventPublisher,
    ) -> Checker:
        return Checker(
            target,
            test_case_generator,
            guardrail,
            event_bus,
            readback_stand_policy=IsolatedStandPolicy(),
        )

    @provide(scope=RunScope, provides=GroundingRunner)
    def grounding_runner(self) -> ThreadedGroundingRunner:
        return ThreadedGroundingRunner()

    @provide(scope=RunScope)
    def workflow_options(
        self,
        latency_oracle: LatencyOracle,
        scenario_repository: ScenarioRepository,
        formal_repository: FormalRepository,
        event_bus: EventPublisher,
        campaign_metrics: CampaignMetrics,
        grounding_runner: GroundingRunner,
        report_publisher: ReportPublisher,
    ) -> LiveWorkflowOptions:
        return LiveWorkflowOptions(
            reactive_budget=_reactive_budget_from_environment(),
            latency_oracle=latency_oracle,
            diff_mode=_diff_mode_from_environment(),
            scenario_repository=scenario_repository,
            formal_repository=formal_repository,
            event_bus=event_bus,
            report_publisher=report_publisher,
            metrics=campaign_metrics,
            grounding_runner=grounding_runner,
            reactive_max_workers=_reactive_workers_from_environment(),
        )

    @provide(scope=RunScope)
    def live_workflow(
        self,
        scenario_binder: ScenarioBinder,
        path_runner: BoundPathRunner,
        finding_evaluator: FindingEvaluator,
        oob_coordinator: oob.Coordinator,
        grounding: BatchFlow,
        lifecycle: RunCoordinator,
        source: Loader,
        variance: DifferentialFlow,
        options: LiveWorkflowOptions,
    ) -> LiveWorkflow:
        return runtime_composition.assemble_workflow(
            scenario_binder,
            path_runner,
            finding_evaluator,
            oob_collector=oob_coordinator,
            grounding=grounding,
            lifecycle=lifecycle,
            source=source,
            variance=variance,
            options=options,
        )

    @provide(scope=RunScope)
    def formal_ingestion_service(
        self,
        contract_graph: ContractGraphRepository,
        formal_repository: FormalRepository,
    ) -> ContractImporter:
        return ContractImporter(
            contract_graph,
            formal_repository,
            classification_profile=classification_profile_from_environment(),
        )

    @provide(scope=RunScope)
    def advisory_pre_scan(
        self,
        formal_repository: FormalRepository,
    ) -> AdvisoryPreScanService:
        """Wire the only external advisory-knowledge boundary."""

        return AdvisoryPreScanService.from_environment(formal_repository)

    @provide(scope=AppScope, provides=ScenarioRepository)
    def scenario_repository(
        self, session_factory: SessionFactory
    ) -> ScenarioRepository:
        return select_scenario_repository(session_factory)

    @provide(scope=RunScope)
    def planner(self) -> QdlPlanner:
        """Own the mutable QDL snapshot cache for exactly one campaign run."""

        return IncrementalQdlPlanner()

    @provide(scope=RunScope)
    def scenario_binder(
        self,
        method_repository: MethodRepository,
        scenario_repository: ScenarioRepository,
        formal_repository: FormalRepository,
        promotion_policy: PromotionPolicy,
        qdl_planner: QdlPlanner,
    ) -> ScenarioBinder:
        return ScenarioBinder(
            method_repository,
            scenario_repository,
            formal_repository,
            qdl_planner=qdl_planner,
            formal_threat_modeler=(
                self._extensions.threat_modeler_factory(
                    self._model_client,
                    max_actions=_max_formal_actions_from_environment(),
                )
                if self._model_client is not None
                and self._extensions.threat_modeler_factory is not None
                and not _skip_llm_grounding_from_environment()
                else None
            ),
            promotion_policy=promotion_policy,
            threat_compiler=ThreatIntentCompiler(),
        )

    @provide(scope=RunScope)
    def stand_source(self, session_factory: SessionFactory) -> StandSource:
        return select_stand_source(session_factory)

    @provide(scope=RunScope)
    def grounding_settings(
        self,
        formal_repository: FormalRepository,
        contract_graph_repository: ContractGraphRepository,
        campaign_metrics: CampaignMetrics,
        scenario_binder: ScenarioBinder,
        promotion_policy: PromotionPolicy,
        stand_source: StandSource,
        grounding_runner: GroundingRunner,
    ) -> ServiceOptions:
        """Deterministic + parallel LLM grounding on every campaign start."""

        model_id = os.environ.get("CLOUD_DAST_MODEL_ID", "").strip() or "none"
        if _skip_llm_grounding_from_environment():
            model_id = f"{model_id} (grounding skipped)"
        campaign_metrics.set_model_id(model_id)

        ingestion = ContractImporter(
            contract_graph_repository,
            formal_repository,
            classification_profile=classification_profile_from_environment(),
        )
        startup = None
        reactive = None
        if (
            self._model_client is not None
            and self._extensions.axis_grounding_factory is not None
            and self._extensions.consultation_factory is not None
        ):
            from cloud_dast.runtime.grounding.config import GrounderOptions
            from cloud_dast.runtime.grounding.reactive import Followup
            from cloud_dast.runtime.grounding.startup import Bootstrap

            grounder_options = GrounderOptions(
                batch_size=_grounding_batch_size_from_environment(),
                max_workers=_grounding_workers_from_environment(),
                metrics=campaign_metrics,
                cache=(
                    FileGroundingCache(_grounding_cache_dir_from_environment())
                    if _grounding_cache_enabled_from_environment()
                    else None
                ),
                cache_namespace=_grounding_cache_namespace_from_environment(),
                task_runner=grounding_runner,
                grounding_dispatcher=self._extensions.axis_grounding_factory(
                    self._model_client,
                    metrics=campaign_metrics,
                ),
                consultation=self._extensions.consultation_factory(self._model_client),
            )

            startup = Bootstrap(options=grounder_options)
            reactive = Followup(options=grounder_options)

        return ServiceOptions(
            ingest_contract=ingestion.ingest,
            project_stand=stand_source.project,
            startup=startup,
            reactive=reactive,
            formal_grounder=scenario_binder.formal_grounder,
            skip_llm_grounding=_skip_llm_grounding_from_environment(),
            promotion_policy=promotion_policy,
        )

    @provide(scope=RunScope)
    def fuzz_session_factory(
        self,
        generator_catalog: GeneratorCatalogPort,
        generator_policy: GeneratorPolicy,
        guardrail: Guardrail,
        payload_corpus: PayloadCorpusSource | None,
        example_database: FindingExampleStore,
        promotion_policy: PromotionPolicy,
    ) -> FuzzSessionFactory:
        """Create an adaptive fuzz session for every QDL execution step."""

        max_checks = _fuzz_max_checks_from_environment()
        # The adaptive fuzz loop is deterministic between saturation points.
        # The LLM strategy remains available to other workflows, but this
        # session calls a model only through the entropy hook below.
        generators = generator_catalog.session_generators(exclude=("llm",))

        seed_enrichment = (
            self._extensions.seed_enrichment_factory(
                self._extensions.consultation_factory(self._model_client),
                store=payload_corpus,
                promotion_policy=promotion_policy,
            )
            if self._model_client is not None
            and payload_corpus is not None
            and self._extensions.seed_enrichment_factory is not None
            and self._extensions.consultation_factory is not None
            else None
        )

        def factory(request: FuzzSessionRequest) -> FuzzSession | None:
            if self._extensions.fuzz_session_factory is None:
                return None
            return self._extensions.fuzz_session_factory(
                request,
                generators=generators,
                policy=generator_policy,
                guardrail=guardrail,
                max_checks=max_checks,
                example_database=example_database,
                seed_enrichment=seed_enrichment,
            )

        return factory

    @provide(scope=RunScope)
    def bound_path_runner(
        self,
        checker: Checker,
        event_projection: EventProjection,
        grounded_outcome_oracle: GroundedOutcomeOracle,
        primitive_oracle_router: PrimitiveOracleRouter,
        formal_repository: FormalRepository,
        fuzz_session_factory: FuzzSessionFactory,
        example_database: FindingExampleStore,
        campaign_metrics: CampaignMetrics,
        observation_projector: ObservationProjector,
        symbolic_prefilter: SymbolicPrefilter = None,
        finding_shrinker_factory: FindingShrinkerFactory = None,
    ) -> BoundPathRunner:
        return assemble_runner(
            checker,
            event_projection,
            grounded_oracle=grounded_outcome_oracle,
            primitive_oracle=primitive_oracle_router,
            formal_repository=formal_repository,
            observation_projector=observation_projector,
            fuzz_session_factory=fuzz_session_factory,
            finding_shrinker_factory=finding_shrinker_factory,
            example_database=example_database,
            symbolic_prefilter=symbolic_prefilter,
            metrics=campaign_metrics,
        )

    @provide(scope=RunScope)
    def finding_shrinker_factory(
        self,
        request_solver: RequestSolver = None,
    ) -> FindingShrinkerFactory:
        """Create bounded witness shrinkers through the optional fuzzing package."""

        if self._extensions.finding_shrinker_factory is None:
            return None  # type: ignore[return-value]

        def factory(*, seed, plan, method, invariant):
            return self._extensions.finding_shrinker_factory(
                seed=seed,
                plan=plan,
                method=method,
                invariant=invariant,
                request_solver=request_solver,
            )

        return factory

    @provide(scope=RunScope)
    def campaign_metrics(self) -> CampaignMetrics:
        return CampaignMetrics()

    @provide(scope=RunScope)
    def symbolic_prefilter(self) -> SymbolicPrefilter:
        factory = self._extensions.symbolic_prefilter_factory
        return factory() if factory is not None else None  # type: ignore[return-value]

    @provide(scope=RunScope)
    def event_projection(
        self,
        event_bus: EventPublisher,
        event_store: EventStore,
    ) -> EventProjection:
        return EventProjection(event_bus, event_store)

    @provide(scope=RunScope)
    def finding_evaluator(self, event_projection: EventProjection) -> FindingEvaluator:
        return FindingEvaluator(event_projection)

    @provide(scope=RunScope, provides=ReportPublisher)
    def report_publisher(self, event_bus: EventPublisher) -> ReportPublisher:
        """Return the optional reporting adapter, or a standalone no-op."""

        if self._report_publisher_factory is None:
            return NullReportPublisher()
        return self._report_publisher_factory(event_bus)

    @provide(scope=RunScope, provides=EventPublisher)
    def event_bus(
        self,
        event_store: EventStore,
        campaign_metrics: CampaignMetrics,
    ) -> EventBus:
        bus = EventBus()
        component_event_types = (
            ComponentInvoked,
            ComponentSkipped,
            ComponentOutput,
            DownstreamDecision,
        )
        for event_type in (
            CheckCompleted,
            *component_event_types,
            EvidenceRecorded,
            CoverageUpdated,
            DiffPairComputed,
            FactVerified,
            FindingRaised,
            IntentProposed,
            InvestigationActionExecuted,
            PhaseChanged,
            QdlStepEvaluated,
            QdlPathEvaluated,
        ):
            bus.subscribe(event_type, event_store.append)
        for event_type in component_event_types:
            bus.subscribe(event_type, campaign_metrics.record_component_event)
        return bus

    @provide(scope=RunScope)
    def runtime(
        self,
        live_workflow: LiveWorkflow,
        event_bus: EventPublisher,
        formal_ingestion_service: ContractImporter,
        advisory_pre_scan: AdvisoryPreScanService,
        campaign_metrics: CampaignMetrics,
    ) -> runtime_composition.CloudDastRuntime:
        return runtime_composition.CloudDastRuntime(
            live_workflow=live_workflow,
            event_bus=event_bus,
            event_subscriber=event_bus,
            formal_ingestion=formal_ingestion_service,
            advisory_pre_scan=advisory_pre_scan,
        )
