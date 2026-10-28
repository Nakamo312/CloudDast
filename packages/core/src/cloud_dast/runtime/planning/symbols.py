"""Low-level Clingo symbol decoding and stable path identities."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

import clingo

from cloud_dast.qdl.engine import CLOSURE_PREDICATES, path_nodes
from cloud_dast.qdl.graph import Context


def _symbol_value(symbol: clingo.Symbol) -> str:
    if symbol.type == clingo.SymbolType.String:
        return symbol.string
    if symbol.type == clingo.SymbolType.Number:
        return str(symbol.number)
    return str(symbol)


def _closure_symbols(
    symbols: tuple[clingo.Symbol, ...],
) -> set[tuple[Context, str, str, str]]:
    """Decode closure atoms from one Clingo model."""

    pairs: set[tuple[Context, str, str, str]] = set()
    for symbol in symbols:
        if symbol.type != clingo.SymbolType.Function:
            continue
        if symbol.name not in CLOSURE_PREDICATES or len(symbol.arguments) != 3:
            continue
        context_value = _symbol_value(symbol.arguments[0])
        try:
            context = Context(context_value)
        except ValueError:
            continue
        pairs.add(
            (
                context,
                symbol.name,
                _symbol_value(symbol.arguments[1]),
                _symbol_value(symbol.arguments[2]),
            )
        )
    return pairs


def _walk_symbols(
    symbols: tuple[clingo.Symbol, ...],
) -> set[tuple[Context, tuple[str, ...]]]:
    """Decode all bounded walks, preserving repeated action occurrences."""

    walks: set[tuple[Context, tuple[str, ...]]] = set()
    for symbol in symbols:
        if symbol.type != clingo.SymbolType.Function:
            continue
        if symbol.name != "_qdl_walk" or len(symbol.arguments) != 5:
            continue
        context_value = _symbol_value(symbol.arguments[0])
        try:
            context = Context(context_value)
        except ValueError:
            continue
        source = _symbol_value(symbol.arguments[1])
        depth = symbol.arguments[4].number
        if depth == 0:
            nodes: tuple[str, ...] = (source,)
        else:
            decoded = path_nodes(symbol.arguments[3])
            if decoded is None:
                continue
            nodes = (source, *decoded)
        walks.add((context, nodes))
    return walks


def _path_id(
    kind: str,
    context: Context,
    nodes: Iterable[str],
    *,
    extra: str = "",
) -> str:
    payload = json.dumps(
        {
            "kind": kind,
            "context": context.value,
            "nodes": tuple(nodes),
            "extra": extra,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"qdl-{kind}-{digest}"
