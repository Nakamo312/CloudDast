"""Shared axis vocabulary for reactive deficit consultations."""

from __future__ import annotations

from typing import Literal

LLM_AXES: frozenset[str] = frozenset(
    {
        "alternatives",
        "dataflows",
        "exposures",
        "fixture",
        "response_semantics",
        "roles",
        "state",
        "variance",
        "classification",
    }
)
DETERMINISTIC_AXES: frozenset[str] = frozenset({"availability"})


Axis = Literal[
    "roles",
    "norms",
    "dataflows",
    "exposures",
    "authentication",
    "availability",
    # Reactive custom labels.  They are never startup axes: alternatives
    # response semantics, and variance have dedicated grounding methods and
    # use dedicated reactive methods.
    "alternatives",
    "response_semantics",
    "variance",
    # S21 v2 predicate-class axes: a refers_to deficit routes to fixture
    # typing and a transition deficit routes to state-machine semantics.
    "fixture",
    "state",
    # Reactive classification axis: the term to classify is named by one
    # violated norm, so it is never a startup action-batch axis.
    "classification",
]

SEMANTIC_AXES: tuple[Axis, ...] = (
    "roles",
    "dataflows",
    "exposures",
    "authentication",
    "availability",
)
NORMS_AXIS: Axis = "norms"


__all__ = ["Axis", "SEMANTIC_AXES", "NORMS_AXIS", "DETERMINISTIC_AXES", "LLM_AXES"]
