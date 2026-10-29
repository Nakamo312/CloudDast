"""Canonical renderer from QDL semantic graphs to the surface DSL."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from cloud_dast.qdl.compiler import CompilationMetadata
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    QdlGraph,
    Rule,
    Struct,
    Term,
    Variable,
)

_SAFE_ATOM = re.compile(r"^[A-Za-z_][A-Za-z0-9_:.\-/]*$")
_CONTEXT_ORDER = {
    Context.CONTRACT: 0,
    Context.PROPOSAL: 1,
    Context.ACCEPTED: 2,
    Context.RUNTIME: 3,
    Context.REPORT: 4,
}


def render_qdl(
    graph: QdlGraph,
    *,
    metadata: CompilationMetadata | None = None,
) -> str:
    """Render a graph deterministically so it can be fed back to a model."""

    lines: list[str] = []
    if metadata is not None and (
        metadata.source is not None or metadata.provenance is not None or metadata.extra
    ):
        lines.append("meta:")
        if metadata.source is not None:
            lines.append(f"  source: {_quote(metadata.source)}")
        if metadata.provenance is not None:
            lines.append(f"  provenance: {_quote(metadata.provenance)}")
        for key, value in metadata.extra:
            lines.append(f"  {key}: {_quote(value)}")

    statements: dict[Context, list[str]] = defaultdict(list)
    for fact in graph.facts:
        statements[fact.context].append(_render_fact(fact))
    for rule in graph.rules:
        context = _rule_context(rule)
        statements[context].append(_render_rule(rule))

    for context in sorted(statements, key=lambda item: _CONTEXT_ORDER[item]):
        if lines:
            lines.append("")
        lines.append(f"{context.value}:")
        lines.extend(f"  {statement}" for statement in statements[context])

    if metadata is not None and metadata.uncertainties:
        if lines:
            lines.append("")
        lines.append("uncertainty:")
        lines.extend(
            f"  uncertainty({_quote(field)}, {_quote(question)})"
            for field, question in metadata.uncertainties
        )
    return "\n".join(lines) + ("\n" if lines else "")


def _render_fact(fact: Fact) -> str:
    return f"{fact.predicate.name}({', '.join(_render_term(arg) for arg in fact.args)})"


def _render_rule(rule: Rule) -> str:
    # The semantic validator intentionally permits exactly one head literal.
    # Do not emit a surface form that the parser would interpret differently if
    # a malformed/legacy model bypassed that invariant.
    if len(rule.head) != 1:
        raise ValueError("QDL renderer requires exactly one rule head literal")
    head = _render_fact(rule.head[0])
    body = ", ".join(_render_fact(fact) for fact in rule.body)
    return f"{head} :- {body}"


def _rule_context(rule: Rule) -> Context:
    contexts = {fact.context for fact in (*rule.body, *rule.head)}
    return min(contexts, key=lambda item: _CONTEXT_ORDER[item])


def _render_term(term: Term) -> str:
    if isinstance(term, Variable):
        # Variables are explicit in the surface language.  Bare identifiers
        # are atoms (including ``Action`` and ``Norm``), so omitting ``$``
        # would change the meaning on a render/parse round trip.
        return f"${term.name}"
    if isinstance(term, Atom):
        if isinstance(term.value, bool):
            return "true" if term.value else "false"
        if isinstance(term.value, int):
            return str(term.value)
        return (
            str(term.value)
            if _SAFE_ATOM.fullmatch(str(term.value))
            else _quote(str(term.value))
        )
    if isinstance(term, Struct):
        return f"{term.name}({', '.join(_render_term(arg) for arg in term.args)})"
    raise TypeError(f"unsupported QDL term {type(term).__name__}")


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


__all__ = ["render_qdl"]
