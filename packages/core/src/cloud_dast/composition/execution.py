"""Assemble the run-scoped live execution graph from explicit capabilities."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

from cloud_dast.contracts.plan import QdlExecutionPath
from cloud_dast.extensions import (
    FindingShrinkerFactory,
    FuzzSessionFactory,
    SymbolicPrefilter,
)
from cloud_dast.model import Observation
from cloud_dast.ports import (
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
from cloud_dast.runtime.execution.calls import execute as execute_call_fn
from cloud_dast.runtime.execution.evidence import PathSignature
from cloud_dast.runtime.execution.paths import Executor, scope_step
from cloud_dast.runtime.execution.prefilter import SymbolicPathPrefilter
from cloud_dast.runtime.execution.runner import BoundPathRunner, EventProjection
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.execution.terminal import Callbacks, PathTerminalizer
from cloud_dast.runtime.finding_shrinking import FindingShrinkCoordinator
from cloud_dast.runtime.metrics import CampaignMetrics
from cloud_dast.runtime.observation_effects import Publisher
from cloud_dast.runtime.observation_recording import Coordinator
from cloud_dast.runtime.readback_reevaluation import Reevaluation
from cloud_dast.verification.evaluation import ObservationEvaluator
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.oracles import grounded, primitive_router
from cloud_dast.verification.projection import ObservationProjector


@dataclass(frozen=True, slots=True)
class BoundPathRunnerOptions:
    """Optional adapters used by the live path execution owner."""

    grounded_oracle: grounded.Oracle | None = None
    primitive_oracle: primitive_router.Oracle | None = None
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


def assemble_runner(
    checker: Checker,
    events: EventProjection,
    options: BoundPathRunnerOptions | None = None,
    **legacy_options: object,
) -> BoundPathRunner:
    """Build one execution graph without storing assembly state on its runner."""

    settings = BoundPathRunnerOptions.from_legacy(options, legacy_options)
    event_bus = events.publisher
    execute_call = partial(execute_call_fn, checker, event_bus)
    primitive_oracle = settings.primitive_oracle or primitive_router.Oracle(
        grounded_oracle=settings.grounded_oracle
    )
    compiler = NormCompiler()
    projector = settings.observation_projector or ObservationProjector()
    paths: dict[str, QdlExecutionPath] = {}
    candidates, prefilter = _assemble_candidates(
        checker, events, execute_call, settings
    )
    evaluator = ObservationEvaluator(
        primitive_oracle=primitive_oracle,
        observation_projector=projector,
        build_evidence_key=ProbeExecutor.build_evidence_key,
        norm_compiler=compiler,
    )
    evidence = Projection(
        events=events.refresh,
        path_lookup=paths.get,
        checks=lambda: checker.checks,
        find_check=checker.find,
        formal_repository=settings.formal_repository,
        observation_projector=projector,
    )
    signature = PathSignature(evidence.observed_graph).build
    shrinking, effects, recorder, reuse = _assemble_observations(
        checker, events, execute_call, settings, evaluator, evidence
    )
    differential = ProbeExecutor(checker, event_bus)
    readback = Reevaluation(
        norm_compiler=compiler,
        build_evidence_key=ProbeExecutor.build_evidence_key,
        classify_observation=evaluator.evaluate,
        publish_step_event=effects.publish_step_event,
    )
    terminal = PathTerminalizer(
        Callbacks(
            publish=events.publish,
            refresh_events=events.refresh,
            path_definitions=lambda: paths,
            metrics=settings.metrics,
            evidence_signature=signature,
        )
    )
    executor = Executor(
        checker, evidence, reuse, prefilter, candidates, recorder, shrinking, terminal
    )
    round_runner = _assemble_round(checker, events, paths, terminal, executor, settings)
    return BoundPathRunner(
        checker,
        events,
        terminal,
        round_runner,
        differential,
        readback,
    )


def _assemble_candidates(
    checker: Checker,
    events: EventProjection,
    execute_call: Callable[..., Observation | None],
    settings: BoundPathRunnerOptions,
) -> tuple[StepCandidateRunner, SymbolicPathPrefilter]:
    """Bind candidate sources and prefiltering to the same live-call boundary."""

    candidates = StepCandidateRunner(
        fuzz_session_factory=settings.fuzz_session_factory,
        symbolic_prefilter=settings.symbolic_prefilter,
        publish=events.publish,
        execute_step_with_budget=execute_call,
        execute_check_with_budget=execute_call,
        path_scoped_step=scope_step,
        latest_check=lambda: checker.latest,
        metrics=settings.metrics,
    )
    prefilter = SymbolicPathPrefilter(
        symbolic_prefilter=settings.symbolic_prefilter,
        preview_path=candidates.preview_path,
        generate_checks=lambda step: checker.generate_pair_checks(
            step.plan,
            step.method,
            step.invariant,
            step.scenario,
            strategy=step.plan.generator,
        ),
        publish=events.publish,
    )
    return candidates, prefilter


def _assemble_observations(
    checker: Checker,
    events: EventProjection,
    execute_call: Callable[..., Observation | None],
    settings: BoundPathRunnerOptions,
    evaluator: ObservationEvaluator,
    evidence: Projection,
) -> tuple[FindingShrinkCoordinator, Publisher, Coordinator, Reuse]:
    """Share interpretation and evidence callbacks without a parent runner."""

    shrinking = FindingShrinkCoordinator(
        factory=settings.finding_shrinker_factory,
        example_database=settings.example_database,
        execute_check=execute_call,
        classify_observation=evaluator.evaluate,
    )
    effects = Publisher(
        publish=events.publish,
        evidence_projection=evidence,
        executed_check_identities=checker.identities_for,
    )
    recorder = Coordinator(
        classify_observation=evaluator.evaluate,
        executed_check_identities=checker.identities_for,
        publish_effects=effects.bind,
        latest_check=lambda: checker.latest,
        metrics=settings.metrics,
    )
    reuse = Reuse(
        refresh_events=events.refresh,
        observed_graph=evidence.observed_graph,
        set_coupling_context=checker.set_coupling_context,
        generate_pair_checks=checker.generate_pair_checks,
        resolve_check=checker.resolve_check,
        publish_step_event=effects.publish_step_event,
    )
    return shrinking, effects, recorder, reuse


def _assemble_round(
    checker: Checker,
    events: EventProjection,
    paths: dict[str, QdlExecutionPath],
    terminal: PathTerminalizer,
    executor: Executor,
    settings: BoundPathRunnerOptions,
) -> Runner:
    """Connect campaign sequencing to its actual execution and policy owners."""

    return Runner(
        RunnerDeps(
            reset_checks=checker.reset_checks,
            refresh_events=events.refresh,
            register_paths=lambda added: paths.update(
                {path.path_id: path for path in added}
            ),
            skip_evaluated_path=terminal.skip_evaluated_path,
            execute_path=executor.execute,
            publish_scheduler_terminal_events=terminal.publish_scheduler_terminal_events,
            publish_missing_terminal_path_events=terminal.publish_missing_terminal_path_events,
            service_checks=lambda: checker.checks,
            reconsider_paths=terminal.reconsider_paths,
        ),
        metrics=settings.metrics,
        example_database=settings.example_database,
    )
