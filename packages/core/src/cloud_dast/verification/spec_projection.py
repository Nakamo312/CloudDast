"""Project external input specifications into the canonical QDL substrate."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    RequestSchema,
)
from cloud_dast.verification.contract_projection import (
    ClassificationProfile,
    ContractProjection,
    ContractProjector,
)


class SpecField(BaseModel):
    """One potentially nested field in a binary or protocol input spec."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    type: str = Field(min_length=1)
    required: bool = False
    repeated: bool = False
    oneof: str | None = None
    enum_values: tuple[str, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    fields: tuple["SpecField", ...] = ()


class SpecAction(BaseModel):
    """One executable action described by a binary or protocol spec."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=1)
    layer: EndpointLayer = EndpointLayer.PRIVATE
    fields: tuple[SpecField, ...] = ()


class InputSpecification(BaseModel):
    """A declarative input specification for a local or protocol target."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str = Field(min_length=1)
    actions: tuple[SpecAction, ...] = ()

    @model_validator(mode="after")
    def validate_actions(self) -> Self:
        if not self.actions:
            raise ValueError("input specification requires at least one action")
        action_ids = [action.action_id for action in self.actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("input specification action IDs must be unique")
        return self


class SpecProjector:
    """Project binary and protocol input specs through the contract projector."""

    def __init__(
        self,
        classification_profile: ClassificationProfile | None = None,
    ) -> None:
        self._projector = ContractProjector(classification_profile)

    def project(self, specification: InputSpecification) -> ContractProjection:
        """Compile one input specification into extension-safe QDL facts."""

        methods = tuple(
            MethodSpec(
                method_id=action.action_id,
                service=specification.service,
                name=action.action_id.rsplit(".", 1)[-1],
                layer=action.layer,
                request_schema=RequestSchema(
                    fields=tuple(_flatten_fields(action.fields))
                ),
            )
            for action in specification.actions
        )
        return self._projector.project_methods(
            specification.service,
            methods,
        )


def _flatten_fields(
    fields: tuple[SpecField, ...],
    prefix: str = "",
) -> Iterator[FieldSpec]:
    for field in fields:
        path = f"{prefix}{field.name}"
        yield FieldSpec(
            name=path,
            type=field.type,
            required=field.required,
            repeated=field.repeated,
            oneof=field.oneof,
            enum_values=field.enum_values,
            minimum=field.minimum,
            maximum=field.maximum,
        )
        yield from _flatten_fields(field.fields, f"{path}.")


__all__ = [
    "InputSpecification",
    "SpecAction",
    "SpecField",
    "SpecProjector",
]
