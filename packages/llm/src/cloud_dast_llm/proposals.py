"""Bounded schemas for model-proposed request candidates."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cloud_dast.model import JsonValue
from cloud_dast.ports import (
    MAX_MODEL_CHECKS,
    MAX_MODEL_STRING_LENGTH,
)


class LlmGeneratedCheck(BaseModel):
    """One model-proposed request mapping."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: dict[str, JsonValue]
    rationale: str = Field(default="", max_length=512)

    @field_validator("request")
    @classmethod
    def bound_request_strings(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if not _json_strings_are_bounded(value):
            raise ValueError("request string exceeds the model output cap")
        return value


class LlmGeneratedChecks(BaseModel):
    """Structured model output for the request-generator extension."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    checks: tuple[LlmGeneratedCheck, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MODEL_CHECKS,
    )


def _json_strings_are_bounded(value: JsonValue) -> bool:
    if isinstance(value, str):
        return len(value) <= MAX_MODEL_STRING_LENGTH
    if isinstance(value, dict):
        return all(_json_strings_are_bounded(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return all(_json_strings_are_bounded(item) for item in value)
    return True


__all__ = ["LlmGeneratedCheck", "LlmGeneratedChecks"]
