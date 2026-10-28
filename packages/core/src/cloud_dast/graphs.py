"""Deterministic directed-graph helpers shared by core and extensions."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence

import networkx as nx

Edges = Mapping[str, Iterable[str]]
Components = tuple[tuple[str, ...], ...]
Rank = Callable[[str], tuple[int, ...]]


def _build_graph(nodes: Sequence[str], edges: Edges) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(sorted(nodes))
    graph.add_edges_from(
        (node, target)
        for node in sorted(nodes)
        for target in sorted(set(edges.get(node, ())))
    )
    return graph


def strongly_connected_components(nodes: Sequence[str], edges: Edges) -> Components:
    """Return SCCs in the old Tarjan-compatible deterministic order."""

    graph = _build_graph(nodes, edges)
    postorder = {
        node: index for index, node in enumerate(nx.dfs_postorder_nodes(graph))
    }
    return tuple(
        tuple(
            nx.dfs_preorder_nodes(
                graph.subgraph(component),
                source=max(component, key=postorder.__getitem__),
            )
        )
        for component in nx.strongly_connected_components(graph)
    )


def wave_layers(nodes: Sequence[str], edges: Edges, rank: Rank) -> Components:
    """Layer nodes into deterministic parallel waves over a blocking DAG."""

    if not nodes:
        return ()
    graph = _build_graph(nodes, edges)
    components = strongly_connected_components(nodes, edges)
    condensed = nx.condensation(graph, [set(component) for component in components])
    for source, target in condensed.edges():
        condensed[source][target]["wave_weight"] = len(components[source])

    depths: dict[int, int] = {}
    for component in nx.topological_sort(condensed):
        subgraph = condensed.subgraph(nx.ancestors(condensed, component) | {component})
        path = nx.dag_longest_path(subgraph, weight="wave_weight")
        depths[component] = sum(
            subgraph[u][v]["wave_weight"] for u, v in zip(path, path[1:])
        )

    wave_of = {
        node: depths[index] + position
        for index, component in enumerate(components)
        for position, node in enumerate(sorted(component, key=rank))
    }
    waves: list[list[str]] = [[] for _ in range(max(wave_of.values()) + 1)]
    for node, wave_index in wave_of.items():
        waves[wave_index].append(node)
    return tuple(tuple(sorted(wave, key=rank)) for wave in waves)


__all__ = ["strongly_connected_components", "wave_layers"]
