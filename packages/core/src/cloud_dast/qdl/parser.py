"""Bounded parsers for textual QDL terms, facts, and surface documents.

The parser owns syntax only.  The legacy term/fact functions return the
parsed term mappings; ``parse_document`` returns a surface AST.
Predicate allowlisting and graph construction remain in the QDL compiler
boundary and ``qdl.compiler``.
"""

from __future__ import annotations

import re
from typing import Any

from lark import Lark, Transformer, v_args
from lark.exceptions import UnexpectedInput, VisitError

from cloud_dast.qdl.diagnostics import Diagnostic
from cloud_dast.qdl.syntax import (
    SourceSpan,
    SurfaceDocument,
    SurfaceFact,
    SurfaceMetadata,
    SurfaceRule,
    SurfaceTerm,
    SurfaceUncertainty,
)

_GRAMMAR = r"""
?start: term
?term: struct
     | ESCAPED_STRING        -> double_string
     | SINGLE_STRING          -> single_string
     | SIGNED_INT             -> integer
     | TRUE                   -> true
     | FALSE                  -> false
     | BARE                   -> bare

struct: BARE "(" [term ("," term)*] ")"

BARE: /[^(),\s]+/
SINGLE_STRING.3: /'([^'\\]|\\.)*'/
TRUE.3: "true"
FALSE.3: "false"

%import common.ESCAPED_STRING
%import common.SIGNED_INT
%import common.WS
%ignore WS
"""


class _TermTransformer(Transformer[Any, dict[str, Any]]):
    """Convert the Lark tree into the existing Pydantic wire shape."""

    def struct(self, items: list[Any]) -> dict[str, Any]:
        name = str(items[0])
        return {"kind": "struct", "name": name, "args": list(items[1:])}

    def double_string(self, items: list[Any]) -> dict[str, Any]:
        return {
            "kind": "atom",
            "literal_type": "string",
            "value": _decode_string(str(items[0])),
        }

    def single_string(self, items: list[Any]) -> dict[str, Any]:
        return {
            "kind": "atom",
            "literal_type": "string",
            "value": _decode_single(str(items[0])),
        }

    def integer(self, items: list[Any]) -> dict[str, Any]:
        return {
            "kind": "atom",
            "literal_type": "integer",
            "value": int(str(items[0])),
        }

    def true(self, _items: list[Any]) -> dict[str, Any]:
        return {"kind": "atom", "literal_type": "boolean", "value": True}

    def false(self, _items: list[Any]) -> dict[str, Any]:
        return {"kind": "atom", "literal_type": "boolean", "value": False}

    def bare(self, items: list[Any]) -> dict[str, Any]:
        return {
            "kind": "atom",
            "literal_type": "string",
            "value": str(items[0]),
        }


_PARSER = Lark(_GRAMMAR, parser="lalr", maybe_placeholders=False)

_SURFACE_GRAMMAR = r"""
?start: rule | fact
rule: fact ":-" fact ("," fact)*
fact: BARE "(" [term ("," term)*] ")"
?term: struct
     | VARIABLE          -> variable
     | ESCAPED_STRING    -> double_string
     | SINGLE_STRING     -> single_string
     | SIGNED_INT        -> integer
     | TRUE              -> true
     | FALSE             -> false
     | BARE              -> bare

struct: BARE "(" [term ("," term)*] ")"

VARIABLE: /\$[A-Za-z_][A-Za-z0-9_]*/
BARE: /(?!:-)[^(),\s]+/
SINGLE_STRING.3: /'([^'\\]|\\.)*'/
TRUE.3: "true"
FALSE.3: "false"

%import common.ESCAPED_STRING
%import common.SIGNED_INT
%import common.WS
%ignore WS
"""


@v_args(meta=True)
class _SurfaceTransformer(Transformer[Any, SurfaceTerm | SurfaceFact | SurfaceRule]):
    """Build syntax nodes while retaining Lark's source span."""

    def fact(self, meta: Any, items: list[Any]) -> SurfaceFact:
        return SurfaceFact(
            predicate=str(items[0]),
            args=tuple(items[1:]),
            context="proposal",
            span=SourceSpan(
                line=int(meta.line),
                column=int(meta.column),
                end_line=int(meta.end_line),
                end_column=int(meta.end_column),
            ),
        )

    def rule(self, meta: Any, items: list[Any]) -> SurfaceRule:
        head, *body = items
        return SurfaceRule(
            head=head,
            body=tuple(body),
            context="proposal",
            span=SourceSpan(
                line=int(meta.line),
                column=int(meta.column),
                end_line=int(meta.end_line),
                end_column=int(meta.end_column),
            ),
        )

    def struct(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return SurfaceTerm(
            kind="struct",
            name=str(items[0]),
            args=tuple(items[1:]),
            span=SourceSpan(
                line=int(meta.line),
                column=int(meta.column),
                end_line=int(meta.end_line),
                end_column=int(meta.end_column),
            ),
        )

    def double_string(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, _decode_string(str(items[0])))

    def single_string(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, _decode_single(str(items[0])))

    def integer(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, int(str(items[0])))

    def true(self, meta: Any, _items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, True)

    def false(self, meta: Any, _items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, False)

    def bare(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return self._atom(meta, str(items[0]))

    def variable(self, meta: Any, items: list[Any]) -> SurfaceTerm:
        return SurfaceTerm(
            kind="variable",
            value=str(items[0]).removeprefix("$"),
            span=SourceSpan(
                line=int(meta.line),
                column=int(meta.column),
                end_line=int(meta.end_line),
                end_column=int(meta.end_column),
            ),
        )

    @staticmethod
    def _atom(meta: Any, value: Any) -> SurfaceTerm:
        return SurfaceTerm(
            kind="atom",
            value=value,
            span=SourceSpan(
                line=int(meta.line),
                column=int(meta.column),
                end_line=int(meta.end_line),
                end_column=int(meta.end_column),
            ),
        )


_SURFACE_PARSER = Lark(
    _SURFACE_GRAMMAR,
    parser="lalr",
    maybe_placeholders=False,
    propagate_positions=True,
)
_SECTION_RE = re.compile(
    r"^(contract|proposal|accepted|runtime|report|meta|metadata|uncertainty|uncertainties)\s*:$",
    re.IGNORECASE,
)
_CONTEXT_SECTIONS = {"contract", "proposal", "accepted", "runtime", "report"}


def parse_term(text: str, *, max_length: int | None = None) -> dict[str, Any] | None:
    """Parse one QDL term into a bounded mapping for a caller-owned schema."""

    if not isinstance(text, str) or not text.strip():
        return None
    if max_length is not None and len(text) > max_length:
        return None
    try:
        tree = _PARSER.parse(text.strip())
        value = _TermTransformer().transform(tree)
    except (UnexpectedInput, VisitError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) and value.get("kind") else None


def parse_fact(
    text: str,
    *,
    max_length: int | None = None,
) -> dict[str, Any] | None:
    """Parse ``predicate(term, ...)`` into a FormalFact-compatible mapping."""

    term = parse_term(text, max_length=max_length)
    if term is None or term.get("kind") != "struct":
        return None
    return {
        "context": "proposal",
        "predicate": term["name"],
        "args": term["args"],
    }


def parse_document(
    text: str,
    *,
    max_length: int | None = 65_536,
) -> tuple[SurfaceDocument | None, tuple[Diagnostic, ...]]:
    """Parse a bounded QDL document into a syntax tree and diagnostics.

    The document format is intentionally controlled: sections are explicit,
    each fact or rule occupies one line, and all semantic validation is left
    to ``qdl.compiler``.  The legacy ``parse_term``/``parse_fact`` functions
    remain unchanged for wire-compatible model responses.
    """

    if not isinstance(text, str) or not text.strip():
        return None, (Diagnostic("empty", "QDL document is empty"),)
    if max_length is not None and len(text) > max_length:
        return None, (
            Diagnostic("size", f"QDL document exceeds {max_length} characters"),
        )

    diagnostics: list[Diagnostic] = []
    facts: list[SurfaceFact] = []
    rules: list[SurfaceRule] = []
    uncertainties: list[SurfaceUncertainty] = []
    metadata: dict[str, str] = {}
    extra_metadata: list[tuple[str, str]] = []
    section: str | None = None
    lines = text.splitlines()

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SECTION_RE.match(stripped)
        if match is not None:
            section = match.group(1).lower()
            if section == "metadata":
                section = "meta"
            if section == "uncertainties":
                section = "uncertainty"
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*\s*:", stripped):
            diagnostics.append(
                Diagnostic(
                    "section",
                    f"unknown QDL section {stripped[:-1].strip()!r}",
                    SourceSpan(line_number, len(raw_line) - len(raw_line.lstrip()) + 1),
                )
            )
            section = None
            continue
        if section is None:
            diagnostics.append(
                Diagnostic(
                    "section_required",
                    "a QDL document statement must be inside a named section",
                    SourceSpan(line_number, 1),
                )
            )
            continue
        leading = len(raw_line) - len(raw_line.lstrip())
        if section == "meta":
            _parse_metadata_line(
                stripped,
                line_number,
                leading + 1,
                metadata,
                extra_metadata,
                diagnostics,
            )
            continue
        if section == "uncertainty":
            _parse_uncertainty_line(
                stripped, line_number, leading + 1, uncertainties, diagnostics
            )
            continue
        if section not in _CONTEXT_SECTIONS:
            diagnostics.append(
                Diagnostic(
                    "section",
                    f"unknown QDL section {section!r}",
                    SourceSpan(line_number, leading + 1),
                )
            )
            continue
        statement = _parse_surface_statement(
            stripped, line_number, leading + 1, diagnostics
        )
        if isinstance(statement, SurfaceRule):
            head = SurfaceFact(
                statement.head.predicate,
                statement.head.args,
                section,
                statement.head.span,
            )
            body = tuple(
                SurfaceFact(item.predicate, item.args, section, item.span)
                for item in statement.body
            )
            rules.append(
                SurfaceRule(
                    head=head,
                    body=body,
                    context=section,
                    span=statement.span,
                )
            )
            continue
        if isinstance(statement, SurfaceFact):
            facts.append(
                SurfaceFact(
                    statement.predicate,
                    statement.args,
                    section,
                    statement.span,
                )
            )

    document = SurfaceDocument(
        facts=tuple(facts),
        rules=tuple(rules),
        uncertainties=tuple(uncertainties),
        metadata=SurfaceMetadata(
            source=metadata.get("source"),
            provenance=metadata.get("provenance"),
            extra=tuple(extra_metadata),
        ),
        source=text,
    )
    return document, tuple(diagnostics)


def _parse_surface_statement(
    text: str,
    line: int,
    column: int,
    diagnostics: list[Diagnostic],
) -> SurfaceFact | SurfaceRule | None:
    if not text:
        diagnostics.append(
            Diagnostic(
                "statement",
                "expected a predicate application",
                SourceSpan(line, column),
            )
        )
        return None
    try:
        value = _SurfaceTransformer().transform(_SURFACE_PARSER.parse(text))
    except (UnexpectedInput, VisitError, ValueError, TypeError) as error:
        error_line = getattr(error, "line", 1) or 1
        error_column = getattr(error, "column", 1) or 1
        diagnostics.append(
            Diagnostic(
                "syntax",
                "invalid predicate application; expected predicate(arg, ...)",
                SourceSpan(line + error_line - 1, column + error_column - 1),
            )
        )
        return None
    if not isinstance(value, (SurfaceFact, SurfaceRule)):
        diagnostics.append(
            Diagnostic(
                "syntax",
                "expected a predicate application or rule",
                SourceSpan(line, column),
            )
        )
        return None
    shifted = _shift_span(value.span, line, column)
    if isinstance(value, SurfaceFact):
        return SurfaceFact(
            value.predicate,
            tuple(_shift_term(term, line, column) for term in value.args),
            value.context,
            shifted,
        )
    head = SurfaceFact(
        value.head.predicate,
        tuple(_shift_term(term, line, column) for term in value.head.args),
        value.head.context,
        _shift_span(value.head.span, line, column),
    )
    body = tuple(
        SurfaceFact(
            item.predicate,
            tuple(_shift_term(term, line, column) for term in item.args),
            item.context,
            _shift_span(item.span, line, column),
        )
        for item in value.body
    )
    return SurfaceRule(head=head, body=body, context=value.context, span=shifted)


def _shift_span(span: SourceSpan | None, line: int, column: int) -> SourceSpan:
    if span is None:
        return SourceSpan(line, column)
    return SourceSpan(
        line + span.line - 1,
        column + span.column - 1,
        line + (span.end_line or span.line) - 1,
        column + (span.end_column or span.column) - 1,
    )


def _shift_term(term: SurfaceTerm, line: int, column: int) -> SurfaceTerm:
    return SurfaceTerm(
        kind=term.kind,
        value=term.value,
        name=term.name,
        args=tuple(_shift_term(arg, line, column) for arg in term.args),
        span=_shift_span(term.span, line, column),
    )


def _parse_surface_fact(
    text: str,
    line: int,
    column: int,
    diagnostics: list[Diagnostic],
) -> SurfaceFact | None:
    """Parse a fact-only line used by metadata side channels."""

    value = _parse_surface_statement(text, line, column, diagnostics)
    if isinstance(value, SurfaceFact):
        return value
    if isinstance(value, SurfaceRule):
        diagnostics.append(
            Diagnostic(
                "syntax", "uncertainty expects one predicate application", value.span
            )
        )
    return None


def _parse_metadata_line(
    text: str,
    line: int,
    column: int,
    metadata: dict[str, str],
    extra: list[tuple[str, str]],
    diagnostics: list[Diagnostic],
) -> None:
    if ":" not in text:
        diagnostics.append(
            Diagnostic(
                "metadata", "metadata expects key: value", SourceSpan(line, column)
            )
        )
        return
    key, raw_value = (part.strip() for part in text.split(":", 1))
    value = parse_term(raw_value)
    if value is None or value.get("kind") != "atom":
        diagnostics.append(
            Diagnostic(
                "metadata", "metadata value must be a scalar", SourceSpan(line, column)
            )
        )
        return
    scalar = str(value["value"])
    if key in {"source", "provenance"}:
        metadata[key] = scalar
    else:
        extra.append((key, scalar))


def _parse_uncertainty_line(
    text: str,
    line: int,
    column: int,
    uncertainties: list[SurfaceUncertainty],
    diagnostics: list[Diagnostic],
) -> None:
    fact = _parse_surface_fact(text, line, column, diagnostics)
    if fact is None:
        return
    if fact.predicate != "uncertainty" or len(fact.args) != 2:
        diagnostics.append(
            Diagnostic(
                "uncertainty",
                "uncertainty expects uncertainty(field, question)",
                fact.span,
            )
        )
        return
    if any(
        term.kind != "atom" or not isinstance(term.value, str) for term in fact.args
    ):
        diagnostics.append(
            Diagnostic(
                "uncertainty",
                "uncertainty field and question must be strings",
                fact.span,
            )
        )
        return
    uncertainties.append(
        SurfaceUncertainty(fact.args[0].value, fact.args[1].value, fact.span)
    )


def _decode_string(value: str) -> str:
    """Decode a JSON-style quoted string without evaluating Python syntax."""

    import json

    return str(json.loads(value))


def _decode_single(value: str) -> str:
    inner = value[1:-1]
    return inner.replace("\\'", "'").replace("\\\\", "\\")


__all__ = ["parse_document", "parse_fact", "parse_term"]
