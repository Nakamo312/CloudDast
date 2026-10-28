"""Public QDL language boundary.

The semantic graph remains the source of truth.  Surface parsing and rendering
are exposed here as a deliberately small compiler boundary; implementation
modules do not need to be imported by callers that only consume the language.
"""

from cloud_dast.qdl.compiler import (
    CompilationMetadata,
    CompilationResult,
    QdlCompiler,
    compile_qdl,
)
from cloud_dast.qdl.diagnostics import Diagnostic, QdlCompileError
from cloud_dast.qdl.parser import parse_document, parse_fact, parse_term
from cloud_dast.qdl.renderer import render_qdl
from cloud_dast.qdl.syntax import (
    SourceSpan,
    SurfaceDocument,
    SurfaceFact,
    SurfaceMetadata,
    SurfaceRule,
    SurfaceTerm,
    SurfaceUncertainty,
)

__all__ = [
    "CompilationMetadata",
    "CompilationResult",
    "Diagnostic",
    "QdlCompileError",
    "QdlCompiler",
    "SourceSpan",
    "SurfaceDocument",
    "SurfaceFact",
    "SurfaceMetadata",
    "SurfaceRule",
    "SurfaceTerm",
    "SurfaceUncertainty",
    "compile_qdl",
    "parse_document",
    "parse_fact",
    "parse_term",
    "render_qdl",
]
