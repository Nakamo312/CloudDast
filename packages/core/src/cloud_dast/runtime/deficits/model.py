"""Immutable runtime deficit contracts.

The value object is deliberately independent from queue mutation and from the
detectors that derive deficits from QDL or execution evidence.  The legacy
``runtime.deficits`` module re-exports it while remaining the constructor and
derivation facade.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.qdl.graph import canonical_json
from cloud_dast.runtime.planning import QdlSubgoal

PredicateClass = str
DeficitAxis = str
DeficitKey = tuple[str, ...]

CONSULTATION_DEFICIT_KIND = "consultation_deficit"
RESPONSE_SEMANTICS_AXIS = "response_semantics"


def _context_value(deficit: Deficit, name: str) -> str | None:
    return next((value for key, value in deficit.context if key == name), None)


@dataclass(frozen=True, slots=True)
class Deficit:
    """One unprovable QDL subgoal that blocks verification."""

    subgoal: QdlSubgoal
    predicate_class: PredicateClass
    axis: DeficitAxis | None
    action: str
    context: tuple[tuple[str, str], ...] = ()

    @property
    def is_consultation_deficit(self) -> bool:
        return _context_value(self, "deficit_kind") == CONSULTATION_DEFICIT_KIND

    @property
    def key(self) -> DeficitKey:
        parts = [self.predicate_class, *self.subgoal.key]
        if self.predicate_class == "prevents":
            diff = _context_value(self, "diff")
            if diff is not None:
                parts.append(diff)
        elif self.predicate_class == "exposes" and self.axis == RESPONSE_SEMANTICS_AXIS:
            fields = _context_value(self, "fields")
            if fields is not None:
                parts.append(fields)
        return tuple(parts)

    @property
    def consultation_id(self) -> str:
        return "|".join(self.key)

    @property
    def work_item_key(self) -> DeficitKey:
        parts = [self.predicate_class, self.axis or "", self.action]
        if self.predicate_class == "has" and self.axis in {
            "input_roles",
            "output_roles",
        }:
            parts.append(canonical_json(self.subgoal.args[0]))
        elif self.predicate_class == "causes" and len(self.subgoal.args) > 1:
            parts.append(canonical_json(self.subgoal.args[1]))
        elif self.axis == "classification":
            classification_term = _context_value(self, "classification_term")
            if classification_term is not None:
                parts.append(classification_term)
        elif self.predicate_class == "prevents":
            diff = _context_value(self, "diff")
            if diff is not None:
                parts.append(diff)
        return tuple(parts)


__all__ = [
    "CONSULTATION_DEFICIT_KIND",
    "Deficit",
    "DeficitAxis",
    "DeficitKey",
    "PredicateClass",
    "RESPONSE_SEMANTICS_AXIS",
]
