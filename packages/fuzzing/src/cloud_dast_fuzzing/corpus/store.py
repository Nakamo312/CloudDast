"""Thread-safe campaign store for a growing payload corpus and its audit trail."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace

from cloud_dast.contracts.payload_proposals import (
    PayloadCorpusDelta,
    PayloadCorpusGuardrail,
    merge_payload_corpus_delta,
)
from cloud_dast.contracts.payloads import (
    PayloadCorpus,
)
from cloud_dast.extensions import PayloadCorpusSource
from cloud_dast_fuzzing.corpus.corpus import DEFAULT_PAYLOAD_CORPUS


@dataclass(frozen=True, slots=True)
class PayloadCorpusAuditRecord:
    """Full provenance for one attempted corpus enrichment."""

    record_id: str
    deficit_id: str
    action: str
    status: str
    reason: str
    history_digest: str
    proposal_digest: str
    prompt_hash: str
    graph_slice_hash: str
    model_version: str
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    latency_ms: float
    depth: int
    base_corpus_version: str
    next_corpus_version: str = ""
    promoted_productions: tuple[str, ...] = ()
    promoted_slot_alternatives: tuple[str, ...] = ()
    promoted_items: int = 0
    rejected: tuple[str, ...] = ()
    delta: PayloadCorpusDelta | None = None


class PayloadCorpusStore(PayloadCorpusSource):
    """Hold the current corpus, merge promoted deltas, and retain every attempt."""

    def __init__(self, corpus: PayloadCorpus | None = None) -> None:
        self._corpus = corpus if corpus is not None else DEFAULT_PAYLOAD_CORPUS
        self._audit: list[PayloadCorpusAuditRecord] = []
        self._lock = threading.RLock()

    @property
    def corpus(self) -> PayloadCorpus:
        with self._lock:
            return self._corpus

    @property
    def audit_trail(self) -> tuple[PayloadCorpusAuditRecord, ...]:
        with self._lock:
            return tuple(self._audit)

    def record(
        self,
        audit: PayloadCorpusAuditRecord,
        *,
        delta: PayloadCorpusDelta | None = None,
        guardrail: PayloadCorpusGuardrail | None = None,
    ) -> bool:
        """Record an attempt and, when supplied, atomically merge its delta."""

        with self._lock:
            merged: PayloadCorpus | None = None
            if delta is not None:
                try:
                    merged = merge_payload_corpus_delta(
                        self._corpus,
                        delta,
                        guardrail,
                    )
                except ValueError as error:
                    audit = replace(
                        audit,
                        status="rejected",
                        reason=str(error),
                        next_corpus_version=self._corpus.corpus_version,
                        promoted_items=0,
                        promoted_productions=(),
                        promoted_slot_alternatives=(),
                    )
                    self._audit.append(audit)
                    return False

            if merged is not None:
                audit = replace(audit, next_corpus_version=merged.corpus_version)
                self._corpus = merged
            else:
                audit = replace(
                    audit,
                    next_corpus_version=self._corpus.corpus_version,
                )
            self._audit.append(audit)
            return merged is not None


def payload_corpus_snapshot(
    source: PayloadCorpus | PayloadCorpusSource,
) -> PayloadCorpus:
    """Return the current immutable corpus behind a static or live source."""

    if isinstance(source, PayloadCorpus):
        return source
    return source.corpus


__all__ = [
    "PayloadCorpusAuditRecord",
    "PayloadCorpusSource",
    "PayloadCorpusStore",
    "payload_corpus_snapshot",
]
