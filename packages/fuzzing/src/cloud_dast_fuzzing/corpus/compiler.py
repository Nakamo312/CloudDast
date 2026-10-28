"""Compile declarative payload productions into Hypothesis strategies."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

from hypothesis import assume
from hypothesis import strategies as st

from cloud_dast.contracts.payloads import (
    MAX_PAYLOAD_RECURSION_LEAVES,
    PAYLOAD_MARKER_TOKEN,
    PayloadAlternative,
    PayloadCondition,
    PayloadCorpus,
    PayloadNode,
    PayloadProduction,
    PayloadReference,
    PayloadSlot,
    PayloadTerminal,
)
from cloud_dast.extensions import PayloadCorpusSource
from cloud_dast.graphs import strongly_connected_components
from cloud_dast_fuzzing.corpus.corpus import DEFAULT_PAYLOAD_CORPUS
from cloud_dast_fuzzing.corpus.store import payload_corpus_snapshot

_ChildStrategy = Callable[[str], st.SearchStrategy[str]]


class PayloadCorpusCompiler:
    """Compile versioned payload data without evaluating model prose."""

    def __init__(
        self,
        corpus: PayloadCorpus | PayloadCorpusSource | None = None,
    ) -> None:
        self._source: PayloadCorpus | PayloadCorpusSource
        if corpus is None:
            self._source = DEFAULT_PAYLOAD_CORPUS
        else:
            self._source = corpus

    @property
    def corpus(self) -> PayloadCorpus:
        return payload_corpus_snapshot(self._source)

    def compile(
        self,
        sink_types: Iterable[str],
        dialects: Iterable[str],
        *,
        marker_placeholder: str = "",
    ) -> st.SearchStrategy[str] | None:
        productions = self.corpus.productions_for(sink_types, dialects)
        if not productions:
            return None
        strategies = tuple(
            self.compile_production(
                production,
                marker_placeholder,
                dialects=dialects,
            )
            for production in productions
        )
        return strategies[0] if len(strategies) == 1 else st.one_of(*strategies)

    def compile_production(
        self,
        production: PayloadProduction,
        marker_placeholder: str = "",
        *,
        dialects: Iterable[str] | None = None,
    ) -> st.SearchStrategy[str]:
        if production.root is None:
            return self._compile_template_production(production, marker_placeholder)
        selected_dialects = (
            tuple(dialects)
            if dialects is not None and tuple(dialects)
            else production.dialects
        )
        return _compile_grammar_production(
            production,
            marker_placeholder=marker_placeholder,
            dialects=selected_dialects,
        )

    def _compile_template_production(
        self,
        production: PayloadProduction,
        marker_placeholder: str,
    ) -> st.SearchStrategy[str]:
        strategies: dict[str, st.SearchStrategy[str]] = {}
        for slot in production.slots:
            strategies[slot.name] = self.compile_slot(slot, marker_placeholder)

        def render(**values: str) -> str:
            return production.template.format(**values)  # type: ignore[union-attr]

        return st.builds(render, **strategies)

    @staticmethod
    def compile_slot(
        slot: PayloadSlot,
        marker_placeholder: str = "",
    ) -> st.SearchStrategy[str]:
        alternatives = (
            slot.marker_alternatives
            if marker_placeholder and slot.marker_alternatives
            else slot.payload_alternatives
        )
        if not alternatives:
            raise ValueError(
                f"payload slot has no "
                f"{'marker' if marker_placeholder else 'payload'} alternative"
            )
        if marker_placeholder:
            alternatives = tuple(
                value.replace(PAYLOAD_MARKER_TOKEN, marker_placeholder)
                for value in alternatives
            )
        scalar = st.sampled_from(alternatives)
        if slot.repeat_min == 1 and slot.repeat_max == 1:
            return scalar
        return st.builds(
            lambda alternative, count: alternative * count,
            scalar,
            st.integers(min_value=slot.repeat_min, max_value=slot.repeat_max),
        )


def _compile_grammar_production(
    production: PayloadProduction,
    *,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> st.SearchStrategy[str]:
    nodes = {node.name: node for node in production.nodes}
    compiled: dict[str, st.SearchStrategy[str]] = {}
    graph = {
        name: tuple(
            sorted(
                element.node
                for alternative in node.alternatives
                for element in alternative.elements
                if isinstance(element, PayloadReference)
            )
        )
        for name, node in nodes.items()
    }
    for component in strongly_connected_components(sorted(nodes), graph):
        if len(component) == 1 and not _node_references_itself(nodes[component[0]]):
            name = component[0]
            compiled[name] = _compile_plain_node(
                nodes[name],
                nodes,
                compiled,
                marker_placeholder=marker_placeholder,
                dialects=dialects,
            )
        else:
            compiled.update(
                _compile_recursive_component(
                    component,
                    nodes,
                    compiled,
                    marker_placeholder=marker_placeholder,
                    dialects=dialects,
                ),
            )
    return compiled[production.root or ""]


def _compile_plain_node(
    node: PayloadNode,
    nodes: Mapping[str, PayloadNode],
    compiled: Mapping[str, st.SearchStrategy[str]],
    *,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> st.SearchStrategy[str]:
    del nodes

    def child_strategy(name: str) -> st.SearchStrategy[str]:
        return compiled[name]

    alternatives = tuple(
        _compile_alternative(
            alternative,
            child_strategy,
            marker_placeholder=marker_placeholder,
            dialects=dialects,
        )
        for alternative in node.alternatives
    )
    return st.one_of(*alternatives)


def _compile_recursive_component(
    component: tuple[str, ...],
    nodes: Mapping[str, PayloadNode],
    compiled: Mapping[str, st.SearchStrategy[str]],
    *,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> dict[str, st.SearchStrategy[str]]:
    internal = set(component)

    def external_child(name: str) -> st.SearchStrategy[str]:
        if name in internal:
            raise ValueError(f"payload grammar component is not recursive: {name}")
        return compiled[name]

    base_alternatives = tuple(
        _compile_tagged_alternative(
            node.name,
            alternative,
            external_child,
            marker_placeholder=marker_placeholder,
            dialects=dialects,
        )
        for name in component
        for node in (nodes[name],)
        for alternative in node.alternatives
        if not _alternative_references_component(alternative, internal)
    )
    if not base_alternatives:
        raise ValueError("payload grammar component has no non-recursive base")
    base = st.one_of(*base_alternatives)

    def extend(
        recursive: st.SearchStrategy[tuple[str, str]],
    ) -> st.SearchStrategy[tuple[str, str]]:
        def child_strategy(name: str) -> st.SearchStrategy[str]:
            if name in internal:
                return recursive.filter(
                    lambda value, expected=name: value[0] == expected
                ).map(lambda value: value[1])
            return compiled[name]

        recursive_alternatives = tuple(
            _compile_tagged_alternative(
                node.name,
                alternative,
                child_strategy,
                marker_placeholder=marker_placeholder,
                dialects=dialects,
            )
            for name in component
            for node in (nodes[name],)
            for alternative in node.alternatives
            if _alternative_references_component(alternative, internal)
        )
        if not recursive_alternatives:
            return st.nothing()
        return st.one_of(*recursive_alternatives)

    component_strategy = st.recursive(
        base,
        extend,
        max_leaves=MAX_PAYLOAD_RECURSION_LEAVES,
    )
    return {
        name: component_strategy.filter(
            lambda value, expected=name: value[0] == expected
        ).map(lambda value: value[1])
        for name in component
    }


def _compile_tagged_alternative(
    node_name: str,
    alternative: PayloadAlternative,
    child_strategy: _ChildStrategy,
    *,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> st.SearchStrategy[tuple[str, str]]:
    strategy = _compile_alternative(
        alternative,
        child_strategy,
        marker_placeholder=marker_placeholder,
        dialects=dialects,
    )
    return strategy.map(lambda value, name=node_name: (name, value))


def _compile_alternative(
    alternative: PayloadAlternative,
    child_strategy: _ChildStrategy,
    *,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> st.SearchStrategy[str]:
    @st.composite
    def strategy(draw: st.DrawFn) -> str:
        prefix = ""
        chunks: list[str] = []
        for element in alternative.elements:
            if isinstance(element, PayloadTerminal):
                values = _terminal_values(
                    element,
                    prefix=prefix,
                    marker_placeholder=marker_placeholder,
                    dialects=dialects,
                )
                if not values:
                    assume(False)
                    return ""
                value = draw(st.sampled_from(values))
            else:
                child = child_strategy(element.node)
                if element.repeat_min == 1 and element.repeat_max == 1:
                    value = draw(child)
                else:
                    count = draw(
                        st.integers(
                            min_value=element.repeat_min,
                            max_value=element.repeat_max,
                        ),
                    )
                    value = "".join(draw(child) for _ in range(count))
            chunks.append(value)
            prefix += value
        return "".join(chunks)

    return strategy()


def _terminal_values(
    element: PayloadTerminal,
    *,
    prefix: str,
    marker_placeholder: str,
    dialects: tuple[str, ...],
) -> tuple[str, ...]:
    marker_alternatives = tuple(
        alternative
        for alternative in element.alternatives
        if PAYLOAD_MARKER_TOKEN in alternative.value
    )
    plain_alternatives = tuple(
        alternative
        for alternative in element.alternatives
        if PAYLOAD_MARKER_TOKEN not in alternative.value
    )
    if marker_placeholder:
        selected = marker_alternatives or plain_alternatives
    else:
        selected = plain_alternatives or marker_alternatives
    valid = tuple(
        alternative
        for alternative in selected
        if _condition_matches(
            alternative.condition,
            prefix=prefix,
            dialects=dialects,
        )
    )
    if not valid:
        return ()
    values = tuple(alternative.value for alternative in valid)
    if marker_placeholder:
        return tuple(
            value.replace(PAYLOAD_MARKER_TOKEN, marker_placeholder) for value in values
        )
    return tuple(value.replace(PAYLOAD_MARKER_TOKEN, "") for value in values)


def _condition_matches(
    condition: PayloadCondition | None,
    *,
    prefix: str,
    dialects: tuple[str, ...],
) -> bool:
    if condition is None:
        return True
    selected_dialects = set(dialects)
    if condition.dialects and not selected_dialects.intersection(condition.dialects):
        return False
    if condition.prefix_contains and not any(
        token in prefix for token in condition.prefix_contains
    ):
        return False
    if condition.prefix_not_contains and any(
        token in prefix for token in condition.prefix_not_contains
    ):
        return False
    return True


def _node_references_itself(node: PayloadNode) -> bool:
    return any(
        isinstance(element, PayloadReference) and element.node == node.name
        for alternative in node.alternatives
        for element in alternative.elements
    )


def _alternative_references_component(
    alternative: PayloadAlternative,
    component: set[str],
) -> bool:
    return any(
        isinstance(element, PayloadReference) and element.node in component
        for element in alternative.elements
    )


__all__ = ["PayloadCorpusCompiler"]
