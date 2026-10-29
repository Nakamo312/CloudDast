"""Validated declarative payload-grammar models.

This module contains only immutable grammar data and pure rendering helpers.
Loading YAML, version migration and mutable audit storage remain outside the
domain model.
"""

from __future__ import annotations

from collections.abc import Iterable
from string import Formatter
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

PAYLOAD_MARKER_TOKEN = "{marker}"
MAX_PAYLOAD_TERMINAL_LENGTH = 128
MAX_PAYLOAD_SLOT_ALTERNATIVES = 8
MAX_PAYLOAD_REPEAT = 8
MAX_PAYLOAD_NODES = 8
MAX_PAYLOAD_ELEMENTS = 8
MAX_PAYLOAD_RECURSION_LEAVES = 16

_Terminal = Annotated[
    str,
    StringConstraints(max_length=MAX_PAYLOAD_TERMINAL_LENGTH),
]
_ConditionToken = Annotated[
    str,
    StringConstraints(min_length=1, max_length=32),
]


class PayloadSlot(BaseModel):
    """One named terminal with bounded repetition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    alternatives: tuple[_Terminal, ...] = Field(
        min_length=1,
        max_length=MAX_PAYLOAD_SLOT_ALTERNATIVES,
    )
    repeat_min: int = Field(default=1, ge=1, le=MAX_PAYLOAD_REPEAT)
    repeat_max: int = Field(default=1, ge=1, le=MAX_PAYLOAD_REPEAT)

    @model_validator(mode="after")
    def validate_slot(self) -> PayloadSlot:
        if not self.name or not self.name.isidentifier():
            raise ValueError("payload slot names must be non-empty identifiers")
        if not self.alternatives:
            raise ValueError("payload slots must contain alternatives")
        if len(set(self.alternatives)) != len(self.alternatives):
            raise ValueError("payload slot alternatives must be unique")
        if self.repeat_min < 1 or self.repeat_max < self.repeat_min:
            raise ValueError("payload slot repetition bounds are invalid")
        for value in self.alternatives:
            residual = value.replace(PAYLOAD_MARKER_TOKEN, "")
            if "{" in residual or "}" in residual:
                raise ValueError("payload alternatives cannot contain format braces")
        return self

    @property
    def marker_alternatives(self) -> tuple[str, ...]:
        return tuple(
            value for value in self.alternatives if PAYLOAD_MARKER_TOKEN in value
        )

    @property
    def payload_alternatives(self) -> tuple[str, ...]:
        return tuple(
            value for value in self.alternatives if PAYLOAD_MARKER_TOKEN not in value
        )


class PayloadCondition(BaseModel):
    """Conditions for one terminal alternative.

    Prefix conditions are scoped to the alternative currently being expanded.
    A dialect condition is matched against the dialects selected by the
    deterministic compiler.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dialects: tuple[str, ...] = Field(default=(), max_length=8)
    prefix_contains: tuple[_ConditionToken, ...] = Field(default=(), max_length=8)
    prefix_not_contains: tuple[_ConditionToken, ...] = Field(default=(), max_length=8)


class PayloadTerminalAlternative(BaseModel):
    """One terminal value and its optional context condition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: _Terminal
    condition: PayloadCondition | None = None

    @model_validator(mode="after")
    def validate_terminal_alternative(self) -> PayloadTerminalAlternative:
        residual = self.value.replace(PAYLOAD_MARKER_TOKEN, "")
        if "{" in residual or "}" in residual:
            raise ValueError("payload terminals cannot contain format braces")
        return self


class PayloadTerminal(BaseModel):
    """A terminal element with context-aware alternatives."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["terminal"] = "terminal"
    alternatives: tuple[PayloadTerminalAlternative, ...] = Field(
        min_length=1,
        max_length=MAX_PAYLOAD_SLOT_ALTERNATIVES,
    )


class PayloadReference(BaseModel):
    """A bounded reference to another grammar node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["reference"] = "reference"
    node: str = Field(min_length=1, max_length=64)
    repeat_min: int = Field(default=1, ge=1, le=MAX_PAYLOAD_REPEAT)
    repeat_max: int = Field(default=1, ge=1, le=MAX_PAYLOAD_REPEAT)

    @model_validator(mode="after")
    def validate_reference(self) -> PayloadReference:
        if not self.node.isidentifier():
            raise ValueError("payload reference names must be identifiers")
        if self.repeat_max < self.repeat_min:
            raise ValueError("payload reference repetition bounds are invalid")
        return self


PayloadElement = Annotated[
    Union[PayloadTerminal, PayloadReference],
    Field(discriminator="kind"),
]


class PayloadAlternative(BaseModel):
    """One ordered expansion of a grammar node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    elements: tuple[PayloadElement, ...] = Field(
        min_length=1,
        max_length=MAX_PAYLOAD_ELEMENTS,
    )


class PayloadNode(BaseModel):
    """One named node in a recursive payload grammar."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    alternatives: tuple[PayloadAlternative, ...] = Field(
        min_length=1,
        max_length=MAX_PAYLOAD_SLOT_ALTERNATIVES,
    )

    @model_validator(mode="after")
    def validate_node(self) -> PayloadNode:
        if not self.name.isidentifier():
            raise ValueError("payload node names must be identifiers")
        if not any(
            not any(
                isinstance(element, PayloadReference) and element.node == self.name
                for element in alternative.elements
            )
            for alternative in self.alternatives
        ):
            raise ValueError(f"payload node {self.name} requires a non-recursive base")
        for alternative in self.alternatives:
            references_self = any(
                isinstance(element, PayloadReference) and element.node == self.name
                for element in alternative.elements
            )
            has_terminal = any(
                isinstance(element, PayloadTerminal) for element in alternative.elements
            )
            if references_self and not has_terminal:
                raise ValueError(
                    f"payload node {self.name} recursive alternatives need a terminal"
                )
        return self


class PayloadProduction(BaseModel):
    """A template or recursive production in the versioned corpus."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    production_id: str = Field(min_length=1, max_length=64)
    sink_types: tuple[str, ...] = Field(min_length=1, max_length=8)
    dialects: tuple[str, ...] = Field(min_length=1, max_length=8)
    template: str | None = Field(default=None, min_length=1, max_length=512)
    slots: tuple[PayloadSlot, ...] = Field(default=(), max_length=8)
    root: str | None = Field(default=None, min_length=1, max_length=64)
    nodes: tuple[PayloadNode, ...] = Field(default=(), max_length=MAX_PAYLOAD_NODES)
    default: bool = False

    @model_validator(mode="after")
    def validate_production(self) -> PayloadProduction:
        if not self.production_id:
            raise ValueError("payload productions require an id")
        if not self.sink_types or not self.dialects:
            raise ValueError("payload productions require sink types and dialects")
        if self.template is not None:
            return self._validate_template_production()
        if self.root is not None:
            return self._validate_grammar_production()
        raise ValueError("payload productions require a template or grammar")

    def _validate_template_production(self) -> PayloadProduction:
        if self.root is not None or self.nodes:
            raise ValueError(
                "payload template productions cannot contain grammar nodes"
            )
        if not self.slots:
            raise ValueError("payload productions require slots")
        slot_names = tuple(slot.name for slot in self.slots)
        if len(set(slot_names)) != len(slot_names):
            raise ValueError("payload production slots must be unique")
        template_names = _template_slot_names(self.template or "")
        if not template_names or set(template_names) != set(slot_names):
            raise ValueError("payload template must reference every slot")
        if not any(slot.marker_alternatives for slot in self.slots):
            raise ValueError("payload productions require a marker alternative")
        if any(not slot.payload_alternatives for slot in self.slots):
            raise ValueError("every payload slot requires a non-marker alternative")
        return self

    def _validate_grammar_production(self) -> PayloadProduction:
        if self.template is not None or self.slots:
            raise ValueError("payload grammar productions cannot contain templates")
        if not self.nodes:
            raise ValueError("payload grammar productions require nodes")
        node_names = tuple(node.name for node in self.nodes)
        if len(set(node_names)) != len(node_names):
            raise ValueError("payload grammar node names must be unique")
        nodes = {node.name: node for node in self.nodes}
        if self.root not in nodes:
            raise ValueError("payload grammar root must reference a declared node")
        terminal_values = tuple(
            alternative.value
            for node in self.nodes
            for production_alternative in node.alternatives
            for element in production_alternative.elements
            if isinstance(element, PayloadTerminal)
            for alternative in element.alternatives
        )
        if not any(PAYLOAD_MARKER_TOKEN in value for value in terminal_values):
            raise ValueError("payload grammar productions require a marker terminal")
        if all(PAYLOAD_MARKER_TOKEN in value for value in terminal_values):
            raise ValueError(
                "payload grammar productions require a non-marker terminal"
            )
        for node in self.nodes:
            for alternative in node.alternatives:
                for element in alternative.elements:
                    if (
                        isinstance(element, PayloadReference)
                        and element.node not in nodes
                    ):
                        raise ValueError(
                            f"payload reference is undeclared: {element.node}"
                        )
        return self

    def render(self, marker_placeholder: str = "") -> str:
        """Render the deterministic first production example."""

        if self.root is not None:
            nodes = {node.name: node for node in self.nodes}
            return _render_node(
                nodes[self.root],
                nodes,
                marker_placeholder=marker_placeholder,
                visiting=frozenset(),
            )

        values: dict[str, str] = {}
        for slot in self.slots:
            alternatives = (
                slot.marker_alternatives
                if marker_placeholder and slot.marker_alternatives
                else slot.payload_alternatives
            )
            value = alternatives[0] * slot.repeat_min
            if marker_placeholder:
                value = value.replace(PAYLOAD_MARKER_TOKEN, marker_placeholder)
            values[slot.name] = value
        return self.template.format(**values) if self.template is not None else ""


class PayloadCorpus(BaseModel):
    """A versioned collection of payload productions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1, 2]
    corpus_version: str
    productions: tuple[PayloadProduction, ...]

    @model_validator(mode="after")
    def validate_corpus(self) -> PayloadCorpus:
        if not self.corpus_version.strip():
            raise ValueError("payload corpus_version must not be empty")
        if not self.productions:
            raise ValueError("payload corpus must contain productions")
        production_ids = tuple(
            production.production_id for production in self.productions
        )
        if len(set(production_ids)) != len(production_ids):
            raise ValueError("payload production ids must be unique")
        if self.schema_version == 1 and any(
            production.root is not None for production in self.productions
        ):
            raise ValueError("schema v1 cannot contain grammar productions")
        return self

    def productions_for(
        self,
        sink_types: Iterable[str],
        dialects: Iterable[str],
    ) -> tuple[PayloadProduction, ...]:
        """Select deterministic productions for one field rule."""

        requested_sinks = set(sink_types)
        requested_dialects = set(dialects)
        matches = tuple(
            production
            for production in self.productions
            if requested_sinks.intersection(production.sink_types)
        )
        if requested_dialects:
            exact = tuple(
                production
                for production in matches
                if requested_dialects.intersection(production.dialects)
            )
            return tuple(sorted(exact, key=lambda item: item.production_id))
        return tuple(
            production
            for production in sorted(matches, key=lambda item: item.production_id)
            if production.default
        )

    def render_marker(
        self,
        sink_types: Iterable[str],
        dialects: Iterable[str],
        marker: str,
    ) -> str | None:
        """Render a deterministic runtime marker for a sink class."""

        if not marker:
            return None
        productions = self.productions_for(sink_types, dialects)
        if not productions:
            return None
        return productions[0].render(marker)


def _template_elements(
    template: str,
    slots: dict[str, PayloadSlot],
) -> tuple[PayloadElement, ...]:
    elements: list[PayloadElement] = []
    try:
        parsed = tuple(Formatter().parse(template))
    except ValueError as error:
        raise ValueError("invalid payload production template") from error
    for literal, name, format_spec, conversion in parsed:
        if format_spec or conversion:
            raise ValueError("payload template slots cannot use format specifications")
        if literal:
            elements.append(
                PayloadTerminal(
                    alternatives=(PayloadTerminalAlternative(value=literal),),
                ),
            )
        if name is not None:
            slot = slots[name]
            elements.append(
                PayloadReference(
                    node=slot.name,
                    repeat_min=slot.repeat_min,
                    repeat_max=slot.repeat_max,
                ),
            )
    return tuple(elements)


def _root_node_name(slots: dict[str, PayloadSlot]) -> str:
    candidate = "start"
    suffix = 0
    while candidate in slots:
        candidate = f"start{suffix}"
        suffix += 1
    return candidate


def _render_node(
    node: PayloadNode,
    nodes: dict[str, PayloadNode],
    *,
    marker_placeholder: str,
    visiting: frozenset[str],
) -> str:
    alternatives = _renderable_alternatives(
        node,
        nodes,
        marker_placeholder=marker_placeholder,
        visiting=visiting,
    )
    alternative = alternatives[0]
    chunks: list[str] = []
    for element in alternative.elements:
        if isinstance(element, PayloadTerminal):
            chunks.append(
                _render_terminal(element, marker_placeholder=marker_placeholder),
            )
        elif isinstance(element, PayloadReference):
            child = nodes[element.node]
            chunks.extend(
                _render_node(
                    child,
                    nodes,
                    marker_placeholder=marker_placeholder,
                    visiting=visiting | {node.name},
                )
                * element.repeat_min
            )
    return "".join(chunks)


def _renderable_alternatives(
    node: PayloadNode,
    nodes: dict[str, PayloadNode],
    *,
    marker_placeholder: str,
    visiting: frozenset[str],
) -> tuple[PayloadAlternative, ...]:
    candidates = (
        tuple(
            alternative
            for alternative in node.alternatives
            if not any(
                isinstance(element, PayloadReference) and element.node in visiting
                for element in alternative.elements
            )
        )
        or node.alternatives
    )
    if marker_placeholder:
        with_marker = tuple(
            alternative
            for alternative in candidates
            if _alternative_has_marker(alternative, nodes, frozenset({node.name}))
        )
        return with_marker or candidates
    without_marker = tuple(
        alternative
        for alternative in candidates
        if not _alternative_has_marker(alternative, nodes, frozenset({node.name}))
    )
    return without_marker or candidates


def _render_terminal(
    element: PayloadTerminal,
    *,
    marker_placeholder: str,
) -> str:
    marker_values = tuple(
        alternative
        for alternative in element.alternatives
        if PAYLOAD_MARKER_TOKEN in alternative.value
    )
    plain_values = tuple(
        alternative
        for alternative in element.alternatives
        if PAYLOAD_MARKER_TOKEN not in alternative.value
    )
    if marker_placeholder:
        selected = marker_values or plain_values
        value = selected[0].value if selected else ""
        return value.replace(PAYLOAD_MARKER_TOKEN, marker_placeholder)
    selected = plain_values or marker_values
    value = selected[0].value if selected else ""
    return value.replace(PAYLOAD_MARKER_TOKEN, "")


def _alternative_has_marker(
    alternative: PayloadAlternative,
    nodes: dict[str, PayloadNode],
    visited: frozenset[str],
) -> bool:
    for element in alternative.elements:
        if isinstance(element, PayloadTerminal):
            if any(PAYLOAD_MARKER_TOKEN in item.value for item in element.alternatives):
                return True
        elif isinstance(element, PayloadReference) and element.node not in visited:
            child = nodes[element.node]
            if any(
                _alternative_has_marker(item, nodes, visited | {element.node})
                for item in child.alternatives
            ):
                return True
    return False


def _template_slot_names(template: str) -> tuple[str, ...]:
    try:
        parsed = tuple(Formatter().parse(template))
    except ValueError as error:
        raise ValueError("invalid payload production template") from error
    if any(format_spec or conversion for _, _, format_spec, conversion in parsed):
        raise ValueError("payload template slots cannot use format specifications")
    return tuple(name for _, name, _, _ in parsed if name is not None)


__all__ = [
    "MAX_PAYLOAD_ELEMENTS",
    "MAX_PAYLOAD_NODES",
    "MAX_PAYLOAD_RECURSION_LEAVES",
    "MAX_PAYLOAD_REPEAT",
    "MAX_PAYLOAD_SLOT_ALTERNATIVES",
    "MAX_PAYLOAD_TERMINAL_LENGTH",
    "PAYLOAD_MARKER_TOKEN",
    "PayloadAlternative",
    "PayloadCondition",
    "PayloadCorpus",
    "PayloadElement",
    "PayloadNode",
    "PayloadProduction",
    "PayloadReference",
    "PayloadSlot",
    "PayloadTerminal",
    "PayloadTerminalAlternative",
]
