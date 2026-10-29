"""Transport-neutral grammar contracts shared with generation extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from cloud_dast.model.evidence import JsonValue


class _GrammarPlan(Protocol):
    """Structural input needed to project grammar facts from a plan."""

    grammar_formats: tuple[tuple[str, str], ...]
    grammar_constraints: tuple[tuple[str, str, JsonValue], ...]
    grammar_dialects: tuple[tuple[str, str], ...]
    sink_types: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class GrammarConstraint:
    """One bounded value constraint projected onto a method field."""

    field: str
    operator: str
    value: JsonValue


@dataclass(frozen=True, slots=True)
class GrammarFieldRule:
    """All executable grammar facts for one field."""

    field: str
    formats: tuple[str, ...] = ()
    constraints: tuple[GrammarConstraint, ...] = ()
    sink_types: tuple[str, ...] = ()
    dialects: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GrammarFacts:
    """A deterministic, action-scoped projection of grammar facts."""

    fields: tuple[GrammarFieldRule, ...] = ()

    @classmethod
    def from_plan(cls, plan: _GrammarPlan) -> GrammarFacts:
        """Project grammar facts already grounded in an execution plan."""

        formats: dict[str, set[str]] = {}
        for field, format_name in plan.grammar_formats:
            formats.setdefault(field, set()).add(format_name)
        constraints: dict[str, list[GrammarConstraint]] = {}
        for field, operator, value in plan.grammar_constraints:
            constraints.setdefault(field, []).append(
                GrammarConstraint(field=field, operator=operator, value=value)
            )
        dialects: dict[str, set[str]] = {}
        for field, dialect in plan.grammar_dialects:
            dialects.setdefault(field, set()).add(dialect)
        sink_types: dict[str, set[str]] = {}
        for field, sink_type in plan.sink_types:
            sink_types.setdefault(field, set()).add(sink_type)
        return cls(
            fields=tuple(
                GrammarFieldRule(
                    field=field,
                    formats=tuple(sorted(formats.get(field, ()))),
                    constraints=tuple(constraints.get(field, ())),
                    dialects=tuple(sorted(dialects.get(field, ()))),
                    sink_types=tuple(sorted(sink_types.get(field, ()))),
                )
                for field in sorted(
                    formats.keys()
                    | constraints.keys()
                    | dialects.keys()
                    | sink_types.keys()
                )
            )
        )


@dataclass(frozen=True, slots=True)
class GrammarSolution:
    """Solver result returned to a strategy compiler through a public port."""

    request: dict[str, JsonValue]
    status: Literal["sat", "unsat", "unknown", "deferred", "no-constraints"]
    dropped_couplings: bool = False


__all__ = [
    "GrammarConstraint",
    "GrammarFacts",
    "GrammarFieldRule",
    "GrammarSolution",
]
