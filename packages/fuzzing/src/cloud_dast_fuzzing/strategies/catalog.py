"""One application-owned extension boundary for QDL-aware generators."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from cloud_dast.contracts.payloads import PayloadCorpus
from cloud_dast.extensions import PayloadCorpusSource, TestCaseGenerator
from cloud_dast.ports import OobUrlFactory
from cloud_dast_fuzzing.strategies.goal_payload import (
    GoalPayloadGenerator,
)
from cloud_dast_fuzzing.strategies.selector import GeneratorSelector


class GeneratorCatalog:
    """Expose one consistent QDL-aware view of all generator extensions.

    The selector owns strategy choice; this catalog owns the cross-cutting
    ``GoalPayloadGenerator`` decoration.  One-shot and adaptive paths therefore
    cannot accidentally diverge in seed hints, probe markers, OOB URLs or
    feedback forwarding.
    """

    def __init__(
        self,
        selector: GeneratorSelector,
        *,
        oob_urls: OobUrlFactory | None = None,
        payload_corpus: PayloadCorpus | PayloadCorpusSource | None = None,
    ) -> None:
        self._selector = selector
        self._oob_urls = oob_urls
        self._payload_corpus = payload_corpus

    @property
    def strategies(self) -> tuple[str, ...]:
        return self._selector.strategies

    def one_shot(self) -> TestCaseGenerator:
        """Return the selected generator with QDL payload decoration."""

        return self._decorate(self._selector)

    def session_generators(
        self,
        *,
        exclude: Iterable[str] = (),
    ) -> Mapping[str, TestCaseGenerator]:
        """Return all adaptive generators through the same extension boundary."""

        excluded = frozenset(exclude)
        return MappingProxyType(
            {
                strategy: self._decorate(generator)
                for strategy, generator in self._selector.generators.items()
                if strategy not in excluded
            }
        )

    def _decorate(self, generator: TestCaseGenerator) -> TestCaseGenerator:
        return GoalPayloadGenerator(
            generator,
            oob_urls=self._oob_urls,
            payload_corpus=self._payload_corpus,
        )


__all__ = ["GeneratorCatalog"]
