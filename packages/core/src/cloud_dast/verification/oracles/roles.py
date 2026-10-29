"""Witness channel roles configured for deterministic primitive oracles."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

type WitnessRoleName = Literal["witness", "candidate", "unclassified"]


class WitnessRolePolicy(BaseModel):
    """Declarative role policy joining QDL sink kinds to witness channels.

    The policy never invents a sink: QDL ``is(term, kind)`` facts decide which
    probe field reaches which kind.  This object only declares the deterministic
    role of that kind for the marker oracle.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    sink_roles: dict[str, WitnessRoleName]
    error_witness_sink_types: frozenset[str] = Field(default=frozenset())
    resource_not_found_witness_sink_types: frozenset[str] = Field(default=frozenset())

    @classmethod
    def load_default(cls) -> WitnessRolePolicy:
        path = Path(__file__).with_name("witness_roles.yaml")
        with path.open(encoding="utf-8") as stream:
            raw = yaml.safe_load(stream)
        return cls.model_validate(raw)

    def role_for(self, sink_type: str | None) -> WitnessRoleName:
        if sink_type is None:
            return "unclassified"
        return self.sink_roles.get(sink_type.casefold(), "unclassified")

    def accepts_error_witness(self, sink_type: str | None) -> bool:
        return sink_type is not None and (
            sink_type.casefold() in self.error_witness_sink_types
        )

    def accepts_resource_not_found_witness(self, sink_type: str | None) -> bool:
        return sink_type is not None and (
            sink_type.casefold() in self.resource_not_found_witness_sink_types
        )

    @model_validator(mode="after")
    def validate_error_witness_roles(self) -> WitnessRolePolicy:
        invalid_error_types = {
            sink_type
            for sink_type in self.error_witness_sink_types
            if self.role_for(sink_type) != "witness"
        }
        invalid_not_found_types = {
            sink_type
            for sink_type in self.resource_not_found_witness_sink_types
            if self.role_for(sink_type) != "witness"
        }
        if invalid_error_types or invalid_not_found_types:
            raise ValueError("error witness sink types must have the witness role")
        return self
