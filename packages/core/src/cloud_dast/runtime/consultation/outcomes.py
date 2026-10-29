"""Deterministic consultation-outcome automaton for reactive grounding.

S33R separates *what a consultation produced* from *how often it was tried*.
One consultation identity is a finite-state automaton keyed by scope, work-item
identity, and evidence signature.  Every recorded outcome is absorbing for
that key; only a new evidence signature creates a fresh automaton instance.

Formally, let ``O`` be the six outcome states and let ``ready`` be the single
non-terminal state.  The structured input alphabet carries conflict, error
kind, evidence availability, evidence requirement, and promotion.  A fixed
total precedence order maps every input to exactly one outcome:
``conflict > contract error > infrastructure error > missing evidence >
promotion > evidence-required parking > rejection``.  The transition function
is therefore total and deterministic, and no attempt counter participates in
the decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from pydantic import ValidationError

__all__ = [
    "CONSULTATION_OUTCOMES",
    "AttemptKey",
    "ConsultationOutcome",
    "OutcomePolicy",
    "classify",
]

type ConsultationOutcome = Literal[
    "promoted",
    "parked",
    "rejected",
    "transient_error",
    "missing_evidence",
    "conflict",
]

CONSULTATION_OUTCOMES: frozenset[str] = frozenset(
    {
        "promoted",
        "parked",
        "rejected",
        "transient_error",
        "missing_evidence",
        "conflict",
    }
)

_CONTRACT_ERRORS: tuple[type[BaseException], ...] = (
    ValidationError,
    TypeError,
    ValueError,
)


@dataclass(frozen=True, slots=True)
class AttemptKey:
    """One consultation identity for a fixed evidence signature."""

    scope: str
    work_item_id: str
    evidence_signature: tuple[str, ...]


def classify(
    *,
    conflict: bool = False,
    error: BaseException | None = None,
    evidence_available: bool = True,
    evidence_required: bool = False,
    promoted: bool = False,
) -> ConsultationOutcome:
    """Classify the committed result using the fixed precedence order."""

    if conflict:
        return "conflict"
    if isinstance(error, _CONTRACT_ERRORS):
        return "rejected"
    if error is not None:
        return "transient_error"
    if not evidence_available:
        return "missing_evidence"
    if promoted:
        return "promoted"
    if evidence_required:
        return "parked"
    return "rejected"


class OutcomePolicy:
    """Absorbing outcome automaton without retry counters.

    A missing key is the ``ready`` state.  ``record`` performs the only
    non-identity transition and then the outcome is absorbing.  A changed
    evidence signature changes the key, which is the sole reopening rule and
    keeps this policy aligned with the S32R lead lifecycle.
    """

    def __init__(self) -> None:
        self._states: dict[AttemptKey, ConsultationOutcome] = {}

    def should_dispatch(self, key: AttemptKey) -> bool:
        """Return whether this evidence-signed consultation is still ready."""

        return key not in self._states

    def record(
        self,
        key: AttemptKey,
        outcome: ConsultationOutcome,
    ) -> ConsultationOutcome:
        """Record one absorbing outcome for a fixed consultation key."""

        recorded = self._states.get(key)
        if recorded is not None:
            return recorded
        if outcome not in CONSULTATION_OUTCOMES:
            raise ValueError(f"unknown consultation outcome: {outcome!r}")
        self._states[key] = outcome
        return outcome

    def outcome_for(self, key: AttemptKey) -> ConsultationOutcome | None:
        """Return the recorded outcome for one key, if any."""

        return self._states.get(key)

    @property
    def states(self) -> Mapping[AttemptKey, ConsultationOutcome]:
        """Return a read-only view of the outcome states."""

        return MappingProxyType(self._states)
