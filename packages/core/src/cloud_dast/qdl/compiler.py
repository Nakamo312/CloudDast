"""Compile the human-facing QDL DSL into the canonical semantic graph."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from cloud_dast.qdl.diagnostics import Diagnostic, QdlCompileError
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Term,
    Variable,
)
from cloud_dast.qdl.parser import parse_document
from cloud_dast.qdl.syntax import (
    SurfaceDocument,
    SurfaceFact,
    SurfaceTerm,
)


@dataclass(frozen=True, slots=True)
class CompilationMetadata:
    """Metadata and non-semantic questions carried beside a compiled graph."""

    source: str | None = None
    provenance: str | None = None
    extra: tuple[tuple[str, str], ...] = ()
    uncertainties: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class CompilationResult:
    """A graph plus all diagnostics needed to repair the source."""

    graph: QdlGraph | None
    diagnostics: tuple[Diagnostic, ...] = ()
    metadata: CompilationMetadata = CompilationMetadata()
    document: SurfaceDocument | None = None

    @property
    def valid(self) -> bool:
        return self.graph is not None and not self.diagnostics

    def raise_for_errors(self) -> QdlGraph:
        """Return the graph or raise a model-facing structured error."""

        if not self.valid:
            raise QdlCompileError(self.diagnostics)
        assert self.graph is not None
        return self.graph


class QdlCompiler:
    """Compile surface syntax without promoting proposal facts."""

    def compile(self, source: str | SurfaceDocument) -> CompilationResult:
        """Parse, type-check, and validate one bounded QDL document."""

        if isinstance(source, str):
            document, parse_diagnostics = parse_document(source)
        else:
            document, parse_diagnostics = source, ()
        if document is None:
            return CompilationResult(None, parse_diagnostics)

        diagnostics = list(parse_diagnostics)
        facts: list[Fact] = []
        rules: list[Rule] = []
        for index, surface_fact in enumerate(document.facts):
            fact = self._fact(surface_fact, diagnostics, path=f"facts[{index}]")
            if fact is not None:
                facts.append(fact)
        for index, surface_rule in enumerate(document.rules):
            head = self._fact(
                surface_rule.head,
                diagnostics,
                path=f"rules[{index}].head",
            )
            body = tuple(
                fact
                for body_index, surface_fact in enumerate(surface_rule.body)
                if (
                    fact := self._fact(
                        surface_fact,
                        diagnostics,
                        path=f"rules[{index}].body[{body_index}]",
                    )
                )
                is not None
            )
            if head is not None and len(body) == len(surface_rule.body):
                try:
                    rules.append(Rule(body=body, head=(head,)))
                except (ValidationError, ValueError, TypeError) as error:
                    diagnostics.append(
                        Diagnostic(
                            "semantic",
                            _validation_message(error),
                            surface_rule.span,
                            f"rules[{index}]",
                        )
                    )

        metadata = CompilationMetadata(
            source=document.metadata.source,
            provenance=document.metadata.provenance,
            extra=document.metadata.extra,
            uncertainties=tuple(
                (item.field, item.question) for item in document.uncertainties
            ),
        )
        if diagnostics:
            return CompilationResult(None, tuple(diagnostics), metadata, document)
        try:
            graph = QdlGraph(facts=tuple(facts), rules=tuple(rules))
        except (ValidationError, ValueError, TypeError) as error:
            diagnostics.append(
                Diagnostic(
                    "graph",
                    _validation_message(error),
                )
            )
            return CompilationResult(None, tuple(diagnostics), metadata, document)
        return CompilationResult(graph, (), metadata, document)

    def _fact(
        self,
        surface: SurfaceFact,
        diagnostics: list[Diagnostic],
        *,
        path: str,
    ) -> Fact | None:
        try:
            context = Context(surface.context)
            predicate = Predicate.from_name(surface.predicate)
            args = tuple(self._term(term) for term in surface.args)
            return Fact(context=context, predicate=predicate, args=args)
        except (ValueError, ValidationError, TypeError, KeyError) as error:
            diagnostics.append(
                Diagnostic(
                    "semantic",
                    _validation_message(error),
                    surface.span,
                    path,
                )
            )
            return None

    def _term(self, term: SurfaceTerm) -> Term:
        if term.kind == "atom":
            return Atom(value=term.value)
        if term.kind == "variable":
            return Variable(name=str(term.value))
        if term.kind == "struct" and term.name is not None:
            return Struct(
                name=term.name, args=tuple(self._term(arg) for arg in term.args)
            )
        raise ValueError(f"unsupported QDL surface term kind {term.kind!r}")


def compile_qdl(source: str | SurfaceDocument) -> CompilationResult:
    """Convenience wrapper around :class:`QdlCompiler`."""

    return QdlCompiler().compile(source)


def _validation_message(error: Exception) -> str:
    if isinstance(error, ValidationError):
        errors = error.errors()
        if errors:
            return str(errors[0].get("msg", str(error)))
    return str(error)


__all__ = [
    "CompilationMetadata",
    "CompilationResult",
    "QdlCompiler",
    "compile_qdl",
]
