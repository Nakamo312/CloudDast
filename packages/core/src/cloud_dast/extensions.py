"""Stable specifications implemented by optional core extensions."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import entry_points
from importlib.util import find_spec
from types import MappingProxyType
from typing import Any, Protocol

from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.grammar import GrammarConstraint, GrammarSolution
from cloud_dast.contracts.payloads import PayloadCorpus
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    Check,
    MethodSpec,
    Observation,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.proposals import ThreatModelProposer
from cloud_dast.qdl.graph import QdlGraph, Struct
from cloud_dast.qdl.state_machine import (
    INSUFFICIENT_TRACE_EVIDENCE,
    LEARNED_TRANSITION_CONFLICT,
    STATE_SEMANTICS_DEFICIT,
    state_semantics_deficit_fact,
)
from cloud_dast.verification.invariant_projection import InvariantProjection


class FuzzSession(Protocol):
    """Adaptive candidate session supplied by an optional fuzzing extension."""

    @property
    def stopped(self) -> bool: ...

    @property
    def current_strategy(self) -> str | None: ...

    def preview(self) -> Check | None: ...

    def next(self) -> Check | None: ...

    def record(
        self,
        check: Check,
        verdict: VerdictStatus,
        *,
        grounded: bool = True,
        proximity: float | None = None,
        observation: Observation | None = None,
        solver_prefiltered: bool = False,
    ) -> None: ...


class FuzzSessionFactory(Protocol):
    """Create one local fuzz session for a QDL execution step."""

    def __call__(self, request: FuzzSessionRequest) -> FuzzSession | None: ...


class PayloadCorpusSource(Protocol):
    """Read-only payload knowledge supplied to candidate generators."""

    @property
    def corpus(self) -> PayloadCorpus: ...


class PayloadStrategyCompiler(Protocol):
    """Compile QDL-grounded payload facts into candidate strategies."""

    def compile(
        self,
        sink_types: Iterable[str],
        dialects: Iterable[str],
        *,
        marker_placeholder: str = "",
    ) -> Any: ...


class RequestSolver(Protocol):
    """Solve QDL field constraints without exposing a solver implementation."""

    def __call__(
        self,
        request: Mapping[str, Any],
        method: MethodSpec,
        couplings: Sequence[Any],
        constraints: Sequence[GrammarConstraint],
    ) -> GrammarSolution: ...


@dataclass(frozen=True, slots=True)
class ShrinkResult:
    """Result of a bounded finding-witness shrinking session."""

    check: Check
    steps: int


class FindingShrinker(Protocol):
    """Bounded candidate minimizer supplied by the fuzzing extension."""

    @property
    def result(self) -> ShrinkResult: ...

    def next(self) -> Check | None: ...

    def record(self, check: Check, *, reproduced: bool) -> None: ...

    def discard(self, check: Check) -> None: ...


class FindingShrinkerFactory(Protocol):
    """Create a minimizer without exposing its search implementation to core."""

    def __call__(
        self,
        *,
        seed: Check,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
    ) -> FindingShrinker: ...


@dataclass(frozen=True, slots=True)
class FuzzSessionRequest:
    """Minimal immutable input for one per-step adaptive session.

    The runtime owns the full QDL execution step. Extensions receive only the
    stable facts needed to scope local search, not campaign orchestration or
    private execution state.
    """

    step_id: str
    goal_id: str | None
    plan: VerificationPlan
    method: MethodSpec
    invariant: InvariantProjection
    scenario: ScenarioPosition


@dataclass(frozen=True, slots=True)
class SeedEnrichmentResult:
    """Result returned by the optional entropy-point enrichment hook."""

    continued: bool
    reason: str
    additional_checks: int = 0


class SaturatedHistory(Protocol):
    """Stable evidence view passed from fuzzing to entropy enrichment."""

    action_id: str
    invariant_id: str
    scenario_id: str
    sink_types: tuple[tuple[str, str], ...]
    source_graph: object

    @property
    def digest(self) -> str: ...

    def to_model_dict(self) -> dict[str, object]: ...


class SeedEnrichmentHook(Protocol):
    """Optional model-facing hook used after local candidate saturation."""

    def enrich(self, history: SaturatedHistory) -> SeedEnrichmentResult: ...


class TestCaseGenerator(Protocol):
    """Generate QDL-bound checks through the common extension contract."""

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        """Generate checks while preserving the QDL binding and feedback hook."""
        ...


class GeneratorSelectorPort(Protocol):
    """Core-facing strategy selection port."""

    @property
    def strategies(self) -> tuple[str, ...]: ...

    @property
    def generators(self) -> Mapping[str, TestCaseGenerator]: ...

    def select(
        self,
        strategy: str | None = None,
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
    ) -> TestCaseGenerator: ...

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]: ...


class GeneratorCatalogPort(Protocol):
    """Core-facing view shared by one-shot and per-step fuzz sessions."""

    @property
    def strategies(self) -> tuple[str, ...]: ...

    def one_shot(self) -> TestCaseGenerator: ...

    def session_generators(
        self,
        *,
        exclude: Iterable[str] = (),
    ) -> Mapping[str, TestCaseGenerator]: ...


class GeneratorPolicy(Protocol):
    """Choose and score generator strategies without exposing policy state."""

    def choose(
        self,
        strategies: tuple[str, ...],
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
    ) -> str: ...

    def update(
        self,
        strategy: str,
        reward: float,
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
        verdict: VerdictStatus | None = None,
    ) -> None: ...


class DefaultGeneratorPolicy:
    """Deterministic core fallback when no adaptive extension is installed.

    Campaign runtime owns the policy contract, not a search algorithm.  The
    fuzzing extension supplies the adaptive bandit through composition; this
    fallback keeps the standalone core executable and deliberately performs
    no learning.
    """

    def choose(
        self,
        strategies: tuple[str, ...],
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
    ) -> str:
        del goal_key, action_id
        if not strategies:
            raise ValueError("generator policy requires at least one strategy")
        return strategies[0]

    def update(
        self,
        strategy: str,
        reward: float,
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
        verdict: VerdictStatus | None = None,
    ) -> None:
        del strategy, reward, goal_key, action_id, verdict


class DefaultGeneratorSelector:
    """Single-strategy selector used by a standalone core installation."""

    def __init__(
        self,
        generator: TestCaseGenerator,
        *,
        name: str = "template",
    ) -> None:
        self._name = name
        self._generators = {name: generator}

    @property
    def strategies(self) -> tuple[str, ...]:
        return (self._name,)

    @property
    def generators(self) -> Mapping[str, TestCaseGenerator]:
        return MappingProxyType(self._generators)

    def select(
        self,
        strategy: str | None = None,
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
    ) -> TestCaseGenerator:
        del goal_key, action_id
        selected = self._name if strategy is None else strategy
        if selected != self._name:
            raise ValueError(f"unknown generator strategy {selected!r}")
        return self._generators[self._name]

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        return self.select(plan.generator).generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )

    def update(
        self,
        strategy: str,
        verdict: object,
        *,
        goal_key: str = "generic",
        action_id: str | None = None,
    ) -> None:
        del strategy, verdict, goal_key, action_id


class DefaultGeneratorCatalog:
    """Expose the standalone selector through the same session boundary."""

    def __init__(self, selector: DefaultGeneratorSelector) -> None:
        self._selector = selector

    @property
    def strategies(self) -> tuple[str, ...]:
        return self._selector.strategies

    def one_shot(self) -> TestCaseGenerator:
        return self._selector

    def session_generators(
        self,
        *,
        exclude: Iterable[str] = (),
    ) -> Mapping[str, TestCaseGenerator]:
        excluded = frozenset(exclude)
        return MappingProxyType(
            {
                name: generator
                for name, generator in self._selector.generators.items()
                if name not in excluded
            }
        )


class SymbolicPrefilter(Protocol):
    """Optional solver boundary used before live request execution."""

    def prefilter(
        self, check: Check, plan: VerificationPlan, method: MethodSpec
    ) -> object:
        """Return a solver decision for one candidate."""
        ...

    def prefilter_sequence(
        self,
        checks: tuple[Check, ...],
        bindings: tuple[tuple[VerificationPlan, MethodSpec], ...],
    ) -> object:
        """Return a solver decision for a complete execution path."""
        ...


class SymbolicGenerator(TestCaseGenerator, Protocol):
    """Optional solver-backed candidate generator supplied by an extension."""


@dataclass(slots=True)
class ExtensionRegistry:
    """Composition-neutral registry of optional implementations.

    Core owns the contracts and this registry only owns *references to
    factories*.  Concrete packages register themselves at the application
    boundary; no core service imports a concrete fuzzing, solver, or LLM
    implementation.  The registry is deliberately mutable during assembly and
    becomes effectively immutable once Dishka providers are constructed.
    """

    payload_corpus_factory: Callable[[], PayloadCorpusSource] | None = None
    payload_compiler_factory: Callable[..., PayloadStrategyCompiler] | None = None
    minimal_seed_generator_factory: Callable[..., TestCaseGenerator] | None = None
    textual_generator_factory: Callable[..., TestCaseGenerator] | None = None
    generator_policy_factory: Callable[..., GeneratorPolicy] | None = None
    generator_selector_factory: Callable[..., Any] | None = None
    generator_catalog_factory: Callable[..., Any] | None = None
    fuzzing_generator_factory: Callable[..., TestCaseGenerator] | None = None
    grammar_generator_factory: Callable[..., TestCaseGenerator] | None = None
    symbolic_generator_factory: Callable[..., SymbolicGenerator] | None = None
    llm_generator_factory: Callable[..., TestCaseGenerator] | None = None
    request_solver: RequestSolver | None = None
    consultation_factory: Callable[..., Any] | None = None
    axis_grounding_factory: Callable[..., Any] | None = None
    threat_modeler_factory: Callable[..., ThreatModelProposer] | None = None
    fuzz_session_factory: Callable[..., FuzzSession] | None = None
    seed_enrichment_factory: Callable[..., SeedEnrichmentHook] | None = None
    finding_shrinker_factory: Callable[..., FindingShrinker] | None = None
    symbolic_prefilter_factory: Callable[[], SymbolicPrefilter] | None = None
    automata_learning_factory: Callable[..., AutomataLearningPort] | None = None
    load_payload_corpus: Callable[[], Any] | None = None
    max_payload_delta_items: int = 64

    def register(self, **implementations: Any) -> None:
        """Register one extension's implementations by contract name."""

        for name, implementation in implementations.items():
            if not hasattr(self, name):
                raise ValueError(f"unknown Cloud DAST extension: {name}")
            if implementation is not None:
                setattr(self, name, implementation)

    @classmethod
    def discover(cls) -> ExtensionRegistry:
        """Discover installed optional packages without importing them eagerly.

        The string module names are plugin identifiers, not core dependencies:
        a missing package is a valid standalone-core configuration.  Explicit
        callers may construct and pass a registry instead, which is what the
        application assembly should do in production.
        """

        discovered = cls.from_entry_points()
        if discovered is not None:
            return discovered

        registry = cls()
        for module_name in (
            "cloud_dast_fuzzing.plugin",
            "cloud_dast_automata.plugin",
            "cloud_dast_symbolic.plugin",
            "cloud_dast_llm.plugin",
        ):
            if find_spec(module_name) is None:
                continue
            module = import_module(module_name)
            register = getattr(module, "register", None)
            if register is None:
                raise RuntimeError(f"extension {module_name} has no register()")
            register(registry)
        return registry

    @classmethod
    def from_entry_points(cls) -> ExtensionRegistry | None:
        """Load registered extensions without naming concrete packages in core."""

        registered = tuple(entry_points(group="cloud_dast.extensions"))
        if not registered:
            return None
        registry = cls()
        for entry in sorted(registered, key=lambda item: item.name):
            entry.load()(registry)
        return registry


PROBE_MARKER_PLACEHOLDER = "{probe_marker}"
OOB_URL_PLACEHOLDER = "{oob_url}"


def runtime_placeholder(plan: VerificationPlan, invariant: InvariantProjection) -> str:
    """Return the transport placeholder required by a grounded probe norm.

    This is part of the public extension surface: candidate generators need the
    stable placeholder contract, but must not depend on verification views or
    application internals.  The accepted QDL effect remains the source of
    truth.
    """

    if not plan.probe_fields or invariant.norm_fact is None:
        return ""
    if len(invariant.norm_fact.args) != 2:
        return ""
    effect = invariant.norm_fact.args[1]
    if not isinstance(effect, Struct):
        return ""
    if effect.name == "reached":
        return PROBE_MARKER_PLACEHOLDER
    if effect.name == "external_call":
        return OOB_URL_PLACEHOLDER
    return ""


class AutomataLearningPort(Protocol):
    """Learn a deterministic state-machine proposal from observed QDL traces."""

    def learn(self, graph: QdlGraph) -> QdlGraph:
        """Return a proposal-context QDL graph or a state-semantics deficit."""
        ...


__all__ = [
    "FuzzSession",
    "FuzzSessionFactory",
    "FuzzSessionRequest",
    "DefaultGeneratorPolicy",
    "DefaultGeneratorCatalog",
    "DefaultGeneratorSelector",
    "GeneratorCatalogPort",
    "GeneratorSelectorPort",
    "PayloadCorpusSource",
    "PayloadStrategyCompiler",
    "FindingShrinker",
    "FindingShrinkerFactory",
    "GeneratorPolicy",
    "SaturatedHistory",
    "SeedEnrichmentHook",
    "SeedEnrichmentResult",
    "ShrinkResult",
    "TestCaseGenerator",
    "SymbolicPrefilter",
    "SymbolicGenerator",
    "ExtensionRegistry",
    "OOB_URL_PLACEHOLDER",
    "PROBE_MARKER_PLACEHOLDER",
    "runtime_placeholder",
    "RequestSolver",
    "AutomataLearningPort",
    "INSUFFICIENT_TRACE_EVIDENCE",
    "LEARNED_TRANSITION_CONFLICT",
    "STATE_SEMANTICS_DEFICIT",
    "state_semantics_deficit_fact",
]
