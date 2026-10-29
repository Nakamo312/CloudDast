"""Structured diagnostics emitted by the QDL surface compiler."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.qdl.syntax import SourceSpan


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One syntax, type, reference, or graph validation error."""

    code: str
    message: str
    span: SourceSpan | None = None
    path: str = ""

    def format(self) -> str:
        """Render a compact message suitable for an LLM repair prompt."""

        location = ""
        if self.span is not None:
            location = f"line {self.span.line}, column {self.span.column}: "
        suffix = f" [{self.path}]" if self.path else ""
        return f"{location}{self.message}{suffix}"


class QdlCompileError(ValueError):
    """Raised by the strict compile helper when diagnostics are present."""

    def __init__(self, diagnostics: tuple[Diagnostic, ...]):
        self.diagnostics = diagnostics
        message = "QDL compilation failed: " + "; ".join(
            diagnostic.format() for diagnostic in diagnostics
        )
        super().__init__(message)


__all__ = ["Diagnostic", "QdlCompileError"]
