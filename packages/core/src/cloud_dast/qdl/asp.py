"""Central QDL <-> ASP term encoding.

The encoder deliberately keeps string atoms as ordinary ASP strings and wraps
non-string atoms in tagged constructors.  This preserves QDL literal types in
Clingo and prevents ``Atom(1.5, float)`` and ``Atom("1.5", string)`` from
collapsing into the same solver term.
"""

from __future__ import annotations

import clingo

from cloud_dast.qdl.graph import Atom, Struct, Term, Variable

_INTEGER_TAG = "qdl_int"
_FLOAT_TAG = "qdl_float"
_BOOLEAN_TAG = "qdl_bool"
_TAGS = frozenset({_INTEGER_TAG, _FLOAT_TAG, _BOOLEAN_TAG})


def asp_string(value: str) -> str:
    """Render a QDL string as a Clingo string literal.

    Clingo accepts literal control characters in string atoms, but rejects NUL.
    Newlines are escaped for readability because Clingo supports ``\\n``.
    """

    if "\0" in value:
        raise ValueError("ASP string atom contains NUL")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def encode_atom(atom: Atom) -> str:
    """Encode one typed QDL atom as a distinct ASP term."""

    if atom.literal_type == "string":
        return asp_string(str(atom.value))
    if atom.literal_type == "integer":
        return f"{_INTEGER_TAG}({asp_string(str(atom.value))})"
    if atom.literal_type == "float":
        return f"{_FLOAT_TAG}({asp_string(str(atom.value))})"
    if atom.literal_type == "boolean":
        rendered = "true" if atom.value else "false"
        return f"{_BOOLEAN_TAG}({asp_string(rendered)})"
    raise TypeError(f"unsupported QDL atom type: {atom.literal_type}")


def decode_term(symbol: clingo.Symbol) -> Term:
    """Decode a Clingo symbol produced by :func:`encode_atom`/``Struct``.

    String atoms are represented by Clingo strings, integers by numbers, and
    non-string atoms by the tagged constructors above.  Any other function
    application is a QDL ``Struct``.
    """

    if symbol.type == clingo.SymbolType.String:
        return Atom(value=symbol.string, literal_type="string")
    if symbol.type == clingo.SymbolType.Number:
        return Atom(value=symbol.number, literal_type="integer")
    if symbol.type != clingo.SymbolType.Function:
        raise TypeError(f"unsupported Clingo symbol: {symbol!s}")

    if symbol.name in _TAGS and len(symbol.arguments) == 1:
        argument = symbol.arguments[0]
        if argument.type != clingo.SymbolType.String:
            raise TypeError(f"malformed tagged atom: {symbol!s}")
        value = argument.string
        if symbol.name == _INTEGER_TAG:
            return Atom(value=int(value), literal_type="integer")
        if symbol.name == _FLOAT_TAG:
            return Atom(value=float(value), literal_type="float")
        if value not in {"true", "false"}:
            raise TypeError(f"malformed boolean atom: {symbol!s}")
        return Atom(value=value == "true", literal_type="boolean")

    return Struct(
        name=symbol.name,
        args=tuple(decode_term(argument) for argument in symbol.arguments),
    )


__all__ = ["asp_string", "decode_term", "encode_atom"]


def encode_term(term: Term) -> str:
    if isinstance(term, Variable):
        return term.name
    if isinstance(term, Atom):
        return encode_atom(term)
    if isinstance(term, Struct):
        arguments = ", ".join(encode_term(argument) for argument in term.args)
        return f"{term.name}({arguments})"
    raise TypeError(f"unsupported QDL term: {type(term).__name__}")
