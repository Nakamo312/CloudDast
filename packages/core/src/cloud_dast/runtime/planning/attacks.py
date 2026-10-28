"""Decode Clingo attack walks and reveal relations into QDL views."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping

import clingo

from cloud_dast.qdl.asp import decode_term
from cloud_dast.qdl.engine import path_nodes
from cloud_dast.qdl.graph import Context, QdlGraph, Struct, canonical_json
from cloud_dast.qdl.reasoning import QdlAttackPath, QdlRevealEdge
from cloud_dast.runtime.planning.symbols import _path_id, _symbol_value, _walk_symbols


def declared_action_ids(graph: QdlGraph, context: Context) -> frozenset[str]:
    """Return action identifiers declared in one QDL context.

    This is the contract-level action universe used by executable smoke
    coverage.  It contains only ``is(Action, ...)`` declarations and never
    infers an action from a causal edge or a method name.
    """

    return graph.declared_identifiers("Action", contexts=(context,))


def _effect_edges(
    symbols: tuple[clingo.Symbol, ...],
) -> dict[tuple[Context, str, str], tuple[Struct, ...]]:
    """Decode Clingo's effect-carrying attack edges."""

    edges: dict[tuple[Context, str, str], set[Struct]] = defaultdict(set)
    for symbol in symbols:
        if symbol.type != clingo.SymbolType.Function:
            continue
        if symbol.name != "_qdl_effect_edge" or len(symbol.arguments) != 4:
            continue
        context_value = _symbol_value(symbol.arguments[0])
        try:
            context = Context(context_value)
        except ValueError:
            continue
        source = _symbol_value(symbol.arguments[1])
        target = _symbol_value(symbol.arguments[2])
        effect = decode_term(symbol.arguments[3])
        if not isinstance(effect, Struct):
            continue
        edges[(context, source, target)].add(effect)

    return {
        key: tuple(sorted(effects, key=canonical_json))
        for key, effects in edges.items()
    }


def _reveal_edges(
    symbols: tuple[clingo.Symbol, ...],
    contexts: tuple[Context, ...],
) -> tuple[QdlRevealEdge, ...]:
    """Decode reveal edges in the selected execution contexts."""

    edges: set[QdlRevealEdge] = set()
    for symbol in symbols:
        if symbol.type != clingo.SymbolType.Function:
            continue
        if symbol.name != "_qdl_reveal_edge" or len(symbol.arguments) != 5:
            continue
        context_value = _symbol_value(symbol.arguments[0])
        try:
            context = Context(context_value)
        except ValueError:
            continue
        if context not in contexts:
            continue
        create_action = _symbol_value(symbol.arguments[1])
        observe_action = _symbol_value(symbol.arguments[2])
        resource_type = _symbol_value(symbol.arguments[3])
        witness = decode_term(symbol.arguments[4])
        if not isinstance(witness, Struct):
            continue
        edges.add(
            QdlRevealEdge(
                context=context,
                create_action=create_action,
                observe_action=observe_action,
                resource_type=resource_type,
                witness=witness,
            )
        )
    return tuple(
        sorted(
            edges,
            key=lambda edge: (
                edge.context.value,
                edge.create_action,
                edge.observe_action,
                edge.resource_type,
                canonical_json(edge.witness),
            ),
        )
    )


def _attack_paths_from_symbols(
    graph: QdlGraph,
    symbols: tuple[clingo.Symbol, ...],
    contexts: tuple[Context, ...],
    trusted_contexts: tuple[Context, ...],
) -> tuple[QdlAttackPath, ...]:
    """Build deterministic bounded paths from derived effect/reveal edges."""

    trusted_actions = graph.declared_identifiers("Action", contexts=trusted_contexts)
    actions = {
        context: trusted_actions
        if context in trusted_contexts
        else declared_action_ids(graph, context)
        for context in contexts
    }
    effect_edges = _effect_edges(symbols)
    # All derived dependencies are edges, but only causes/requires carries
    # causal obligations. In particular reveal must not invent requires(create).
    # Retain component contexts even when selecting accepted-only final walks.
    for symbol in symbols:
        if symbol.name == "_qdl_edge" and len(symbol.arguments) == 3:
            context, source, target = map(_symbol_value, symbol.arguments)
            effect_edges.setdefault((Context(context), source, target), ())

    walk_effects = {
        (context, nodes): _attack_edge_effects(
            effect_edges, context, nodes, trusted_contexts
        )
        for context, nodes in _walk_symbols(symbols)
    }
    walk_effects.update(_and_walk_effects(symbols, trusted_contexts))
    supported = {
        (Context(_symbol_value(symbol.arguments[0])), path_nodes(symbol.arguments[1]))
        for symbol in symbols
        if symbol.name == "_qdl_supported_walk" and len(symbol.arguments) == 2
    }
    paths: dict[tuple[Context, tuple[str, ...]], QdlAttackPath] = {}
    for (context, nodes), edge_effects in sorted(walk_effects.items()):
        source, target = nodes[0], nodes[-1]
        context_actions = actions.get(context, frozenset())
        if source not in context_actions:
            continue
        if target not in context_actions:
            continue
        if edge_effects is None:
            continue
        key = (context, nodes)
        paths.setdefault(
            key,
            QdlAttackPath(
                path_id=_path_id(
                    "attack",
                    context,
                    nodes,
                    extra=canonical_json(edge_effects),
                ),
                context=context,
                actions=nodes,
                edge_effects=edge_effects,
                supported=(context, nodes) in supported,
            ),
        )

    return tuple(
        sorted(paths.values(), key=lambda path: (path.context.value, path.actions))
    )


def _and_walk_effects(
    symbols: tuple[clingo.Symbol, ...],
    trusted_contexts: tuple[Context, ...],
) -> dict[tuple[Context, tuple[str, ...]], tuple[tuple[Struct, ...], ...] | None]:
    """Decode prospective conjunctions with only immediate causal gates.

    A sibling producer may precede an independent call without proving effects
    needed by the eventual goal. Each consumer's own requires remain strict at
    invocation; a nominal plan never upgrades a future effect into evidence.
    """

    effects = _effect_edges(symbols)
    decoded = {}
    for symbol in symbols:
        if symbol.name != "_qdl_and_walk" or len(symbol.arguments) != 3:
            continue
        context = Context(_symbol_value(symbol.arguments[0]))
        nodes = path_nodes(symbol.arguments[1])
        if nodes is None:
            continue
        for source, target in zip(nodes, nodes[1:]):
            # The conjunction itself grounds sibling ordering. Only existing
            # causes/requires edges may add a gate for this adjacent pair.
            effects.setdefault((context, source, target), ())
        decoded[(context, nodes)] = _attack_edge_effects(
            effects, context, nodes, trusted_contexts
        )
    return decoded


def _attack_edge_effects(
    effect_edges: Mapping[tuple[Context, str, str], tuple[Struct, ...]],
    context: Context,
    actions: tuple[str, ...],
    trusted_contexts: tuple[Context, ...],
) -> tuple[tuple[Struct, ...], ...] | None:
    """Return real causal obligations for each edge, including value-only edges."""

    edges: list[tuple[Struct, ...]] = []
    for source, target in zip(actions, actions[1:]):
        # Accepted paths may include contract-only edges. Edge facts retain
        # their own context; only this execution view combines their effects.
        edge_contexts = trusted_contexts if context is Context.ACCEPTED else (context,)
        effects = tuple(
            sorted(
                {
                    effect
                    for edge_context in edge_contexts
                    for effect in effect_edges.get((edge_context, source, target), ())
                },
                key=canonical_json,
            )
        )
        if not any(
            (edge_context, source, target) in effect_edges
            for edge_context in edge_contexts
        ):
            return None
        edges.append(effects)
    return tuple(edges)
