"""Bounded declarative payload-corpus proposal contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cloud_dast.contracts.payloads import (
    MAX_PAYLOAD_REPEAT,
    MAX_PAYLOAD_SLOT_ALTERNATIVES,
    MAX_PAYLOAD_TERMINAL_LENGTH,
    PayloadCorpus,
    PayloadProduction,
    PayloadReference,
    PayloadSlot,
    PayloadTerminal,
)

MAX_PAYLOAD_PRODUCTIONS_PER_DELTA = 4
MAX_PAYLOAD_SLOT_UPDATES_PER_DELTA = 8
MAX_PAYLOAD_TOTAL_ALTERNATIVES = 32
MAX_PAYLOAD_CORPUS_DELTA_ITEMS = 32

_PRODUCTION_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_Terminal = Annotated[
    str,
    StringConstraints(max_length=MAX_PAYLOAD_TERMINAL_LENGTH),
]


class PayloadSlotAlternative(BaseModel):
    """New alternatives and optional repetition bounds for one corpus slot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    production_id: str = Field(min_length=1, max_length=64)
    slot_name: str = Field(min_length=1, max_length=64)
    alternatives: tuple[_Terminal, ...] = Field(
        min_length=1,
        max_length=MAX_PAYLOAD_SLOT_ALTERNATIVES,
    )
    repeat_min: int | None = Field(default=None, ge=1, le=MAX_PAYLOAD_REPEAT)
    repeat_max: int | None = Field(default=None, ge=1, le=MAX_PAYLOAD_REPEAT)

    @model_validator(mode="after")
    def validate_update(self) -> PayloadSlotAlternative:
        if len(set(self.alternatives)) != len(self.alternatives):
            raise ValueError("payload slot alternatives must be unique")
        if (
            self.repeat_min is not None
            and self.repeat_max is not None
            and self.repeat_min > self.repeat_max
        ):
            raise ValueError("payload slot repetition bounds are invalid")
        return self


class PayloadCorpusDelta(BaseModel):
    """A bounded, declarative delta to the versioned payload corpus."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    productions: tuple[PayloadProduction, ...] = Field(
        default_factory=tuple,
        max_length=MAX_PAYLOAD_PRODUCTIONS_PER_DELTA,
    )
    slot_alternatives: tuple[PayloadSlotAlternative, ...] = Field(
        default_factory=tuple,
        max_length=MAX_PAYLOAD_SLOT_UPDATES_PER_DELTA,
    )

    @model_validator(mode="after")
    def validate_delta(self) -> PayloadCorpusDelta:
        if not self.productions and not self.slot_alternatives:
            raise ValueError("payload corpus delta is empty")
        production_ids = tuple(item.production_id for item in self.productions)
        if len(set(production_ids)) != len(production_ids):
            raise ValueError("payload corpus delta production ids must be unique")
        targets = tuple(
            (item.production_id, item.slot_name) for item in self.slot_alternatives
        )
        if len(set(targets)) != len(targets):
            raise ValueError("payload corpus delta slot targets must be unique")
        return self

    @property
    def item_count(self) -> int:
        return len(self.productions) + len(self.slot_alternatives)

    @property
    def alternative_count(self) -> int:
        return sum(
            _production_alternative_count(production) for production in self.productions
        ) + sum(len(item.alternatives) for item in self.slot_alternatives)


class SeedEnrichmentUncertainty(BaseModel):
    """A self-reported gap in one seed-enrichment response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Field(default="", max_length=256)
    question: str = Field(max_length=4096)


class SeedEnrichmentModelWireOutput(BaseModel):
    """Closed model schema for payload-corpus data, never strategy code."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    context: Literal["proposal"] = "proposal"
    productions: tuple[PayloadProduction, ...] = Field(
        default_factory=tuple,
        max_length=MAX_PAYLOAD_PRODUCTIONS_PER_DELTA,
    )
    slot_alternatives: tuple[PayloadSlotAlternative, ...] = Field(
        default_factory=tuple,
        max_length=MAX_PAYLOAD_SLOT_UPDATES_PER_DELTA,
    )
    uncertainties: tuple[SeedEnrichmentUncertainty, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @model_validator(mode="after")
    def validate_output(self) -> SeedEnrichmentModelWireOutput:
        if not self.productions and not self.slot_alternatives:
            raise ValueError("seed enrichment output is empty")
        return self

    def to_delta(self) -> PayloadCorpusDelta:
        return PayloadCorpusDelta(
            productions=self.productions,
            slot_alternatives=self.slot_alternatives,
        )


@dataclass(frozen=True, slots=True)
class PayloadCorpusGuardrail:
    """Hard campaign-wide bounds for every model-proposed corpus delta."""

    max_productions: int = MAX_PAYLOAD_PRODUCTIONS_PER_DELTA
    max_slot_updates: int = MAX_PAYLOAD_SLOT_UPDATES_PER_DELTA
    max_alternatives_per_slot: int = MAX_PAYLOAD_SLOT_ALTERNATIVES
    max_total_alternatives: int = MAX_PAYLOAD_TOTAL_ALTERNATIVES
    max_repeat: int = MAX_PAYLOAD_REPEAT
    max_items: int = MAX_PAYLOAD_CORPUS_DELTA_ITEMS

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.max_productions,
                self.max_slot_updates,
                self.max_alternatives_per_slot,
                self.max_total_alternatives,
                self.max_repeat,
                self.max_items,
            )
        ):
            raise ValueError("payload corpus guardrail bounds must be positive")

    def rejection_reasons(self, delta: PayloadCorpusDelta) -> tuple[str, ...]:
        reasons: list[str] = []
        if len(delta.productions) > self.max_productions:
            reasons.append("too many productions")
        if len(delta.slot_alternatives) > self.max_slot_updates:
            reasons.append("too many slot updates")
        if delta.item_count > self.max_items:
            reasons.append("delta item cap exceeded")
        if delta.alternative_count > self.max_total_alternatives:
            reasons.append("delta alternative cap exceeded")
        for production in delta.productions:
            if production.default:
                reasons.append(
                    f"production {production.production_id} cannot be default"
                )
            if production.root is None:
                for slot in production.slots:
                    if len(slot.alternatives) > self.max_alternatives_per_slot:
                        reasons.append(
                            f"production {production.production_id} slot {slot.name} "
                            "has too many alternatives"
                        )
                    if slot.repeat_max > self.max_repeat:
                        reasons.append(
                            f"production {production.production_id} slot {slot.name} "
                            "repeat bound exceeded"
                        )
            else:
                for node in production.nodes:
                    for alternative in node.alternatives:
                        for element in alternative.elements:
                            if (
                                isinstance(element, PayloadTerminal)
                                and len(element.alternatives)
                                > self.max_alternatives_per_slot
                            ):
                                reasons.append(
                                    f"production {production.production_id} node "
                                    f"{node.name} has too many alternatives"
                                )
                            if (
                                isinstance(element, PayloadReference)
                                and element.repeat_max > self.max_repeat
                            ):
                                reasons.append(
                                    f"production {production.production_id} node "
                                    f"{node.name} repeat bound exceeded"
                                )
        for update in delta.slot_alternatives:
            if len(update.alternatives) > self.max_alternatives_per_slot:
                reasons.append(
                    f"slot update {update.production_id}.{update.slot_name} "
                    "has too many alternatives"
                )
            if update.repeat_max is not None and update.repeat_max > self.max_repeat:
                reasons.append(
                    f"slot update {update.production_id}.{update.slot_name} "
                    "repeat bound exceeded"
                )
        return tuple(dict.fromkeys(reasons))


def merge_payload_corpus_delta(
    corpus: PayloadCorpus,
    delta: PayloadCorpusDelta,
    guardrail: PayloadCorpusGuardrail | None = None,
) -> PayloadCorpus:
    """Merge one validated delta while preserving corpus invariants.

    The merge is deliberately mechanical: it never interprets terminal text,
    never compiles model prose, and rejects duplicate or empty deltas.
    """

    bounds = guardrail or PayloadCorpusGuardrail()
    reasons = bounds.rejection_reasons(delta)
    if reasons:
        raise ValueError("; ".join(reasons))

    existing = {item.production_id: item for item in corpus.productions}
    new_productions: list[PayloadProduction] = []
    for production in delta.productions:
        if production.production_id in existing:
            raise ValueError(
                f"payload production already exists: {production.production_id}"
            )
        if not _PRODUCTION_ID.fullmatch(production.production_id):
            raise ValueError("new payload production id must be a lowercase slug")
        new_productions.append(production)

    updated_productions: dict[str, PayloadProduction] = {}
    for update in delta.slot_alternatives:
        production = existing.get(update.production_id)
        if production is None:
            raise ValueError(f"unknown payload production: {update.production_id}")
        slots = {slot.name: slot for slot in production.slots}
        slot = slots.get(update.slot_name)
        if slot is None:
            raise ValueError(
                f"unknown payload slot: {update.production_id}.{update.slot_name}"
            )
        alternatives = tuple(dict.fromkeys((*slot.alternatives, *update.alternatives)))
        repeat_min = (
            update.repeat_min if update.repeat_min is not None else slot.repeat_min
        )
        repeat_max = (
            update.repeat_max if update.repeat_max is not None else slot.repeat_max
        )
        bounds_changed = repeat_min != slot.repeat_min or repeat_max != slot.repeat_max
        if alternatives == slot.alternatives and not bounds_changed:
            raise ValueError(
                f"payload slot has no new alternatives: "
                f"{update.production_id}.{update.slot_name}"
            )
        slots[update.slot_name] = PayloadSlot(
            name=slot.name,
            alternatives=alternatives,
            repeat_min=repeat_min,
            repeat_max=repeat_max,
        )
        updated_productions[production.production_id] = production.model_copy(
            update={"slots": tuple(slots.values())}
        )

    productions = tuple(
        updated_productions.get(item.production_id, item)
        if item.production_id in existing
        else item
        for item in (*corpus.productions, *new_productions)
    )
    return PayloadCorpus(
        schema_version=corpus.schema_version,
        corpus_version=_next_corpus_version(corpus.corpus_version),
        productions=productions,
    )


def _next_corpus_version(version: str) -> str:
    match = re.fullmatch(r"(.*?)(\d+)", version)
    if match is None:
        return f"{version}.1"
    prefix, number = match.groups()
    return f"{prefix}{int(number) + 1}"


def _production_alternative_count(production: PayloadProduction) -> int:
    if production.root is None:
        return sum(len(slot.alternatives) for slot in production.slots)
    return sum(
        len(element.alternatives)
        for node in production.nodes
        for alternative in node.alternatives
        for element in alternative.elements
        if isinstance(element, PayloadTerminal)
    )


__all__ = [
    "MAX_PAYLOAD_CORPUS_DELTA_ITEMS",
    "MAX_PAYLOAD_PRODUCTIONS_PER_DELTA",
    "MAX_PAYLOAD_REPEAT",
    "MAX_PAYLOAD_SLOT_ALTERNATIVES",
    "MAX_PAYLOAD_SLOT_UPDATES_PER_DELTA",
    "MAX_PAYLOAD_TERMINAL_LENGTH",
    "MAX_PAYLOAD_TOTAL_ALTERNATIVES",
    "PayloadCorpusDelta",
    "PayloadCorpusGuardrail",
    "PayloadSlotAlternative",
    "SeedEnrichmentModelWireOutput",
    "SeedEnrichmentUncertainty",
    "merge_payload_corpus_delta",
]
