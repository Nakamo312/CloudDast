"""Typed verdict contract shared by deterministic primitive oracles."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model import VerdictStatus

type WitnessRoleName = Literal["witness", "candidate", "unclassified"]
type OracleDeficitKind = Literal[
    "candidate_witness",
    "echo_witness",
    "incomplete_negative_scope",
    "partial_sequence",
    "principal_scope",
    "ungrounded_expectation",
]


class OracleDeficit(BaseModel):
    """A typed reason why an oracle could not establish a witness scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: OracleDeficitKind
    action_id: str | None = None
    context: tuple[tuple[str, str], ...] = ()
    rationale: str


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


class PolicyVerdict(BaseModel):
    """A deterministic or grounded verdict produced by an oracle.

    A ``PASS`` is a universal negative witness.  It must name the complete
    observation channels that made the negative scope local-closed-world; an
    absent marker or another unknown value must remain ``UNSCOREABLE``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: VerdictStatus
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    model_id: str
    negative_scope: tuple[str, ...] = Field(
        default=(),
        description="complete channels proving the universal negative witness",
    )
    deficits: tuple[OracleDeficit, ...] = ()
    sink_ids: tuple[str, ...] = Field(
        default=(),
        description="formal sink identifiers named by the violated norm",
    )
    probe_fields: tuple[str, ...] = Field(
        default=(),
        description="grounded input fields carried by the finding witness",
    )
    deterministic: bool = False
    grounded: bool = False
    oracle_called: bool = True

    @model_validator(mode="after")
    def enforce_pass_semantics(self) -> PolicyVerdict:
        if self.status is VerdictStatus.PASS:
            if not self.negative_scope:
                raise ValueError("PASS requires a complete negative witness scope")
            if not self.grounded:
                raise ValueError("PASS requires grounded negative witness evidence")
            if self.deficits:
                raise ValueError("PASS must not carry oracle deficits")
        return self
