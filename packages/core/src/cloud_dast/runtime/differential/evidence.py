"""Store campaign-local differential execution evidence."""

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple, TypeVar

from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    ReadBackResult,
)

EvidenceKeyT = TypeVar("EvidenceKeyT", bound=tuple[str, ...])
EvidenceEntry = tuple[EvidenceKeyT, ReadBackResult]
ConcurrencyEntry = tuple[EvidenceKeyT, ConcurrencyResult]


class MeasurementKey(NamedTuple):
    """Stable identity of one read-back or concurrency measurement."""

    method_id: str
    scenario_id: str
    resource_id: str
    invariant_id: str


class Store[EvidenceKeyT]:
    """Keep read-back and concurrency measurements for one campaign.

    The store is deliberately an in-memory workflow component.  It owns no
    transport, event, or repository concerns; the caller decides when a
    campaign starts and therefore when to discard this instance.

    Both namespaces use last-write-wins semantics, matching the existing
    runner-local evidence dictionaries.  Iterators are snapshots and sorted
    by the tuple-like evidence key, so consumers cannot observe later writes
    or mutate the store through an iterator.
    """

    def __init__(self) -> None:
        self._readbacks: dict[EvidenceKeyT, ReadBackResult] = {}
        self._concurrency: dict[EvidenceKeyT, ConcurrencyResult] = {}

    def put_readback(self, key: EvidenceKeyT, result: ReadBackResult) -> None:
        """Store or replace one read-back measurement."""

        self._readbacks[key] = result

    def get_readback(self, key: EvidenceKeyT) -> ReadBackResult | None:
        """Return a read-back measurement, if one was stored for ``key``."""

        return self._readbacks.get(key)

    def iter_readbacks(self) -> Iterator[EvidenceEntry[EvidenceKeyT]]:
        """Iterate over a stable, key-ordered read-back snapshot."""

        return iter(tuple(sorted(self._readbacks.items())))

    def clear_readbacks(self) -> None:
        """Discard all read-back measurements."""

        self._readbacks.clear()

    def put_concurrency(
        self,
        key: EvidenceKeyT,
        result: ConcurrencyResult,
    ) -> None:
        """Store or replace one concurrency measurement."""

        self._concurrency[key] = result

    def get_concurrency(self, key: EvidenceKeyT) -> ConcurrencyResult | None:
        """Return a concurrency measurement, if one was stored for ``key``."""

        return self._concurrency.get(key)

    def iter_concurrency(self) -> Iterator[ConcurrencyEntry[EvidenceKeyT]]:
        """Iterate over a stable, key-ordered concurrency snapshot."""

        return iter(tuple(sorted(self._concurrency.items())))

    def clear_concurrency(self) -> None:
        """Discard all concurrency measurements."""

        self._concurrency.clear()

    def clear(self) -> None:
        """Discard every differential measurement in the campaign."""

        self.clear_readbacks()
        self.clear_concurrency()


# Descriptive aliases keep the public API aligned with the stored contract
# names while retaining the concise methods used by the workflow integration.
DifferentialEvidence = Store
