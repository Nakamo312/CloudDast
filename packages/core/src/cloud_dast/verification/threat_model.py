"""Read-only threat-model projections owned by the core verifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cloud_dast.qdl.graph import Atom, Struct

type StrideCategory = Literal["S", "T", "R", "I", "D", "E"]


@dataclass(frozen=True, slots=True)
class StrideView:
    """One STRIDE row projected from QDL.

    This is a read model, not a second source of truth. Categories are
    derived from semantic-role and causal facts already present in the graph.
    """

    action: Atom
    field: Struct | None = None
    role: str | None = None
    effect: Struct | None = None
    categories: tuple[StrideCategory, ...] = ()


__all__ = ["StrideCategory", "StrideView"]
