"""Partial-request algebra used by runtime candidate generation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Generic, TypeVar

from cloud_dast.model import FieldSpec, JsonValue

ValueT = TypeVar("ValueT")
FieldValue = tuple[tuple[str, JsonValue], ...]


@dataclass(frozen=True, slots=True)
class Absent:
    """The ``1`` summand of an optional-field domain."""


@dataclass(frozen=True, slots=True)
class Present(Generic[ValueT]):
    """The ``Value`` summand of an optional-field domain."""

    value: ValueT


OptionalFieldValue = Absent | Present[FieldValue]


def field_value(
    request: Mapping[str, JsonValue] | tuple[tuple[str, JsonValue], ...],
    field: FieldSpec,
) -> OptionalFieldValue:
    """Return the explicit presence assignment for one contract field."""

    values = dict(request)
    entries = tuple(
        (name, value)
        for name, value in values.items()
        if _belongs_to_field(name, field)
    )
    return Present(entries) if entries else Absent()


def with_field_value(
    request: tuple[tuple[str, JsonValue], ...],
    field: FieldSpec,
    value: OptionalFieldValue,
) -> tuple[tuple[str, JsonValue], ...]:
    """Apply one presence assignment to a partial request map.

    A present field replaces its whole flattened subtree. An absent field
    removes the field and all of its dotted children.
    """

    if isinstance(value, Absent):
        return tuple(
            (name, item) for name, item in request if not _belongs_to_field(name, field)
        )

    if not value.value:
        raise ValueError("a present field value requires at least one entry")
    for name, _ in value.value:
        if not _belongs_to_field(name, field):
            raise ValueError(
                f"request entry {name!r} does not belong to {field.name!r}"
            )

    return (
        *(item for item in request if not _belongs_to_field(item[0], field)),
        *value.value,
    )


def omit_optional_field(
    request: tuple[tuple[str, JsonValue], ...],
    field: FieldSpec,
) -> tuple[tuple[str, JsonValue], ...]:
    """Map one optional field to the absent summand of its domain."""

    if field.required:
        raise ValueError(f"required field {field.name!r} cannot be omitted")
    return with_field_value(request, field, Absent())


def _belongs_to_field(name: str, field: FieldSpec) -> bool:
    return name == field.name or name.startswith(f"{field.name}.")


__all__ = [
    "Absent",
    "OptionalFieldValue",
    "Present",
    "field_value",
    "omit_optional_field",
    "with_field_value",
]
