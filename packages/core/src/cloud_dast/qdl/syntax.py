"""Surface syntax nodes for the bounded, human-readable QDL DSL.

The surface tree deliberately does not contain :class:`Fact` or
:class:`QdlGraph`.  Parsing is therefore safe to use for model output and the
compiler remains the only boundary that creates semantic graph objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A source location suitable for a model-facing diagnostic."""

    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True, slots=True)
class SurfaceTerm:
    """One syntax-level atom, variable, or structural term."""

    kind: str
    value: Any = None
    name: str | None = None
    args: tuple[SurfaceTerm, ...] = ()
    span: SourceSpan | None = None


@dataclass(frozen=True, slots=True)
class SurfaceFact:
    """A predicate application before schema and reference validation."""

    predicate: str
    args: tuple[SurfaceTerm, ...]
    context: str
    span: SourceSpan | None = None


@dataclass(frozen=True, slots=True)
class SurfaceRule:
    """A Datalog rule written as ``head :- body, ...``."""

    head: SurfaceFact
    body: tuple[SurfaceFact, ...]
    context: str
    span: SourceSpan | None = None


@dataclass(frozen=True, slots=True)
class SurfaceUncertainty:
    """A question that must remain outside the semantic graph."""

    field: str
    question: str
    span: SourceSpan | None = None


@dataclass(frozen=True, slots=True)
class SurfaceMetadata:
    """Optional source/provenance metadata carried beside the graph."""

    source: str | None = None
    provenance: str | None = None
    extra: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class SurfaceDocument:
    """Parsed QDL DSL document."""

    facts: tuple[SurfaceFact, ...] = ()
    rules: tuple[SurfaceRule, ...] = ()
    uncertainties: tuple[SurfaceUncertainty, ...] = ()
    metadata: SurfaceMetadata = field(default_factory=SurfaceMetadata)
    source: str = ""


__all__ = [
    "SourceSpan",
    "SurfaceDocument",
    "SurfaceFact",
    "SurfaceMetadata",
    "SurfaceRule",
    "SurfaceTerm",
    "SurfaceUncertainty",
]
