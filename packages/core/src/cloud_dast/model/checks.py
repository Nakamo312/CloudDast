from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from enum import StrEnum
from hashlib import sha256
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model.evidence import JsonValue
from cloud_dast.model.schemas import (
    FieldSpec,
    MessageSchema,  # noqa: F401 - compatibility re-export from the schema owner
    RequestSchema,
    ResponseSchema,
)


class EndpointLayer(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    GATEWAY = "gateway"


class ScopeRelation(StrEnum):
    SAME_FOLDER = "same_folder"
    CROSS_FOLDER = "cross_folder"
    CROSS_CLOUD = "cross_cloud"
    CROSS_ORG = "cross_org"
    CROSS_TENANT = "cross_tenant"


type BindingLevel = Literal["resource", "folder", "cloud", "organization"]
type ResourceState = Literal["existing", "created", "updated", "deleted"]
type IdentityClass = Literal["owner", "attacker", "administrator", "service"]
type AddressingMode = Literal["direct", "inherited", "federated"]
type GeneratorName = Literal[
    "template", "symbolic", "fuzzing", "adaptive", "llm", "grammar", "textual"
]
ANONYMOUS_PRINCIPAL_ID = "anonymous"
_replay_logger = logging.getLogger("cloud_dast.model.checks")
"""Principal id of the unauthenticated principal term.

The id is ordinary data: a stand or QDL graph declares
``principal:anonymous`` exactly like any other subject, and generators may
use it only when the identity algebra derives it.  It is never injected as
an untyped string by generator code.
"""


class PrincipalRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    principal_id: str
    principal_type: Literal["user", "service_account", "group", "anonymous"]


class ResourceRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    resource_type: str
    resource_id: str


class BindingRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    principal_id: str
    role: str
    resource_id: str | None = None
    folder_id: str | None = None
    cloud_id: str | None = None
    organization_id: str | None = None


class MethodSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    method_id: str
    service: str
    name: str
    layer: EndpointLayer
    permissions: frozenset[str] = Field(default_factory=frozenset)
    resource_types: frozenset[str] = Field(default_factory=frozenset)
    request_schema: RequestSchema = Field(default_factory=RequestSchema)
    response_schema: ResponseSchema | None = None

    @model_validator(mode="before")
    @classmethod
    def migrate_flat_request_fields(cls, value: Any) -> Any:
        """Accept the legacy manifest shape only at the model boundary.

        The stored model has one owner (`request_schema.fields`).  This input
        normalization keeps existing contract fixtures readable while callers
        migrate to the explicit schema field.
        """

        if not isinstance(value, Mapping) or "fields" not in value:
            return value
        if "request_schema" in value:
            return value
        normalized = dict(value)
        normalized["request_schema"] = {"fields": normalized.pop("fields")}
        return normalized

    @property
    def fields(self) -> tuple[FieldSpec, ...]:
        """Return request fields during the staged consumer migration."""

        return self.request_schema.fields

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> MethodSpec:
        """Keep staged updates on the canonical request-schema owner."""

        if update is None or "fields" not in update or "request_schema" in update:
            return super().model_copy(update=update, deep=deep)
        normalized = dict(update)
        normalized["request_schema"] = self.request_schema.model_copy(
            update={"fields": normalized.pop("fields")},
            deep=deep,
        )
        return super().model_copy(update=normalized, deep=deep)


class ScenarioProfile(BaseModel):
    """Immutable semantic dimensions that classify one security scenario."""

    model_config = ConfigDict(frozen=True)

    scope_relation: ScopeRelation
    binding_level: BindingLevel
    endpoint_layer: EndpointLayer
    resource_state: ResourceState
    identity_class: IdentityClass
    addressing_mode: AddressingMode


class StandState(BaseModel):
    """Immutable stand snapshot bound to a scenario for one run."""

    model_config = ConfigDict(frozen=True)

    resources: tuple[ResourceRef, ...] = ()
    principals: tuple[PrincipalRef, ...] = ()
    bindings: tuple[BindingRef, ...] = ()
    effective_permissions: frozenset[str] = Field(default_factory=frozenset)
    permissions_known: bool = False


class ScenarioPosition(BaseModel):
    """Canonical bound-scenario value: identity, profile, and stand snapshot."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str
    profile: ScenarioProfile
    stand: StandState


def scenario_id_for(
    *,
    principal_id: str,
    resource_id: str,
    method_id: str | None,
    profile: ScenarioProfile,
) -> str:
    """Return the stable identity of one concrete bound scenario.

    This is an identity function, not a grouping or deduplication key. Two
    scenarios with the same profile may still have different stands.
    """

    identity = "\x1f".join(
        (
            principal_id,
            resource_id,
            method_id or "",
            str(profile.scope_relation),
            str(profile.binding_level),
            str(profile.endpoint_layer),
            str(profile.resource_state),
            str(profile.identity_class),
            str(profile.addressing_mode),
        )
    )
    return sha256(identity.encode()).hexdigest()


class Check(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str = Field(default_factory=lambda: uuid4().hex)
    invariant_id: str
    method_id: str
    scenario_id: str
    request: tuple[tuple[str, JsonValue], ...]
    identities: tuple[str, ...]
    generator: GeneratorName = "template"
    seed_id: str | None = None
    probe_marker: str | None = Field(
        default=None,
        description="unique runtime canary injected for this candidate",
    )

    @model_validator(mode="after")
    def validate_request_names(self) -> Check:
        names = tuple(name for name, _ in self.request)
        if len(names) != len(set(names)):
            raise ValueError("request field names must be unique")
        return self


def replay_gaps(
    check: Check,
    *,
    replayable_fields: Iterable[str] = (),
) -> tuple[str, ...]:
    """Return request fields without an accepted replay-safe field role."""

    replayable = frozenset(replayable_fields)
    return tuple(
        name
        for name, value in check.request
        if name not in replayable or not (value is None or isinstance(value, str))
    )


def is_replayable_check(
    check: Check,
    *,
    replayable_fields: Iterable[str] = (),
) -> bool:
    """Retain a check for replay only when every field has an accepted role."""

    gaps = replay_gaps(check, replayable_fields=replayable_fields)
    if gaps:
        _replay_logger.warning(
            "check request redacted for replay: fields without accepted "
            "replay-safe roles: method=%s fields=%s",
            check.method_id,
            ",".join(gaps),
        )
        return False
    return True
