"""Registration entry point for the adaptive fuzzing extension."""

from __future__ import annotations

from cloud_dast.extensions import ExtensionRegistry, FuzzSessionRequest
from cloud_dast_fuzzing.corpus import (
    PayloadCorpusCompiler,
    PayloadCorpusStore,
    load_payload_corpus,
)
from cloud_dast_fuzzing.corpus.enrichment import SeedEnrichmentConsultant
from cloud_dast_fuzzing.session import FuzzSession


def build_fuzz_session(request: FuzzSessionRequest, **kwargs):
    """Adapt the core per-step request to the concrete fuzz session."""

    return FuzzSession(
        plan=request.plan,
        method=request.method,
        invariant=request.invariant,
        scenario=request.scenario,
        **kwargs,
    )


from cloud_dast_fuzzing.shrinking import FindingShrinker
from cloud_dast_fuzzing.strategies import (
    FailingStrategyFilter,
    FuzzingGenerator,
    GeneratorBandit,
    GeneratorCatalog,
    GeneratorSelector,
    GrammarGenerator,
    MinimalSeedGenerator,
    TextualGenerator,
)


def build_generator_policy(*, seed: int = 0):
    """Build the adaptive policy without exposing it to core runtime."""

    return FailingStrategyFilter(GeneratorBandit(seed=seed))


def build_generator_selector(*, generators, default, policy):
    """Assemble concrete strategies at the extension boundary."""

    return GeneratorSelector(generators, default=default, policy=policy)


def build_generator_catalog(selector, *, oob_urls=None, payload_corpus=None):
    """Decorate all selected strategies through one extension-owned catalog."""

    return GeneratorCatalog(
        selector,
        oob_urls=oob_urls,
        payload_corpus=payload_corpus,
    )


def register(registry: ExtensionRegistry) -> None:
    """Expose concrete fuzzing implementations through core contracts only."""

    registry.register(
        payload_corpus_factory=lambda: PayloadCorpusStore(load_payload_corpus()),
        payload_compiler_factory=PayloadCorpusCompiler,
        minimal_seed_generator_factory=MinimalSeedGenerator,
        textual_generator_factory=TextualGenerator,
        generator_policy_factory=build_generator_policy,
        generator_selector_factory=build_generator_selector,
        generator_catalog_factory=build_generator_catalog,
        fuzzing_generator_factory=FuzzingGenerator,
        grammar_generator_factory=GrammarGenerator,
        fuzz_session_factory=build_fuzz_session,
        seed_enrichment_factory=SeedEnrichmentConsultant,
        finding_shrinker_factory=FindingShrinker,
        load_payload_corpus=load_payload_corpus,
    )


__all__ = [
    "build_fuzz_session",
    "build_generator_catalog",
    "build_generator_policy",
    "build_generator_selector",
    "register",
]
