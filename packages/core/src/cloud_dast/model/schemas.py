"""Canonical transport-neutral request and response message schemas."""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

_INTEGER_RANGES: dict[str, tuple[int, int]] = {
    "int32": (-(2**31), 2**31 - 1),
    "sint32": (-(2**31), 2**31 - 1),
    "sfixed32": (-(2**31), 2**31 - 1),
    "uint32": (0, 2**32 - 1),
    "fixed32": (0, 2**32 - 1),
    "int64": (-(2**63), 2**63 - 1),
    "sint64": (-(2**63), 2**63 - 1),
    "sfixed64": (-(2**63), 2**63 - 1),
    "uint64": (0, 2**64 - 1),
    "fixed64": (0, 2**64 - 1),
}
_FLOAT_RANGES: dict[str, tuple[float, float]] = {
    "float": (-3.4028234663852886e38, 3.4028234663852886e38),
    "double": (-1.7976931348623157e308, 1.7976931348623157e308),
}


def is_integer_type(field_type: str) -> bool:
    return field_type.lower() in _INTEGER_RANGES


def is_float_type(field_type: str) -> bool:
    return field_type.lower() in _FLOAT_RANGES


def integer_range(field_type: str) -> tuple[int, int] | None:
    return _INTEGER_RANGES.get(field_type.lower())


def float_range(field_type: str) -> tuple[float, float] | None:
    return _FLOAT_RANGES.get(field_type.lower())


class FieldSpec(BaseModel):
    """One field in a transport message schema."""

    model_config = ConfigDict(frozen=True)

    name: str
    type: str
    required: bool = False
    repeated: bool = False
    oneof: str | None = None
    enum_values: tuple[str, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None

    @field_validator("minimum", "maximum", mode="before")
    @classmethod
    def reject_bool_bounds(cls, value: object) -> object:
        if type(value) is bool:
            raise ValueError("numeric bound must be a number, not bool")
        return value

    @model_validator(mode="after")
    def validate_bounds(self) -> FieldSpec:
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("minimum must not be greater than maximum")
        for name, bound in (("minimum", self.minimum), ("maximum", self.maximum)):
            if bound is not None:
                self._validate_bound(name, bound)
        return self

    def _validate_bound(self, name: str, bound: float) -> None:
        if isinstance(bound, float) and math.isnan(bound):
            raise ValueError(f"{name} must not be NaN")
        if is_integer_type(self.type):
            if not isinstance(bound, int):
                raise ValueError(f"{name} for integer field must be int")
            bounds = integer_range(self.type)
            if bounds is not None and not bounds[0] <= bound <= bounds[1]:
                raise ValueError(f"{name} is outside the {self.type} range")
        if is_float_type(self.type):
            bounds = float_range(self.type)
            if bounds is not None and not bounds[0] <= bound <= bounds[1]:
                raise ValueError(f"{name} is outside the {self.type} range")


class MessageSchema(BaseModel):
    """Transport-neutral immutable schema for one message shape."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type_name: str | None = None
    fields: tuple[FieldSpec, ...] = ()

    @model_validator(mode="after")
    def validate_field_names(self) -> MessageSchema:
        names = tuple(field.name for field in self.fields)
        if len(names) != len(set(names)):
            raise ValueError("schema field names must be unique")
        return self


class RequestSchema(MessageSchema):
    """Complete request shape shared by all candidate generators."""


class ResponseSchema(MessageSchema):
    """Declared response shape shared by evidence and response consumers."""


__all__ = [
    "FieldSpec",
    "MessageSchema",
    "RequestSchema",
    "ResponseSchema",
    "float_range",
    "integer_range",
    "is_float_type",
    "is_integer_type",
]
