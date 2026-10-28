"""TOML launch profiles for live campaigns.

Profiles hold campaign defaults, not secrets.  Secret-bearing values are
referenced through environment variable names and resolved by the existing
secret adapters at runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import tomllib
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.verification.contract_projection import (
    ClassificationProfile,
)
from cloud_dast.verification.differential.modes import DiffMode


class ModelProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    api: Literal["chat", "responses"] | None = None
    reasoning_effort: Literal["low", "high", "max"] | None = None
    timeout: float | None = Field(default=None, gt=0)
    retries: int | None = Field(default=None, ge=0)
    url: str | None = None


_TRUE_FLAGS = frozenset({"1", "true", "yes", "on"})
_FALSE_FLAGS = frozenset({"0", "false", "no", "off", ""})


def parse_environment_flag(
    name: str,
    *,
    default: bool = False,
    environ: MutableMapping[str, str] | None = None,
) -> bool:
    """Parse one boolean environment flag at a configuration boundary."""

    environment = os.environ if environ is None else environ
    raw = environment.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_FLAGS:
        return True
    if value in _FALSE_FLAGS:
        return False
    raise RuntimeError(
        f"{name} must be one of: 1, true, yes, on, 0, false, no, off, or empty"
    )


class GroundingProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skip_llm: bool = False
    cache: bool = True
    cache_dir: str | None = None
    workers: int = Field(default=4, ge=1)
    reactive_workers: int = Field(default=4, ge=1)
    batch_size: int = Field(default=8, ge=1)
    promote_proposals: bool = False
    reactive_budget: int | Literal["all"] | None = None


class DifferentialProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: bool = False
    modes: tuple[DiffMode, ...] = ()


class Neo4jProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uri: str | None = None
    user: str | None = None
    password_file_env: str | None = None
    method_prefix_aliases: dict[str, str] = Field(default_factory=dict)


class StandProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["file", "neo4j"] | None = None
    file: str | None = None


class RuntimeProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: tuple[str, ...] = ()
    setup_identity: str | None = None
    iam_token_prefer_command: bool = False
    descriptor_set_env: str | None = None


class ClassificationLaunchProfile(BaseModel):
    """Launch-facing selector for the curated classification profile."""

    model_config = ConfigDict(extra="forbid")

    path: str | None = None


class LiveProfile(BaseModel):
    """Defaults for one service campaign."""

    model_config = ConfigDict(extra="forbid")

    service: str | None = None
    method_id: str | None = None
    identity: str | None = None
    identity_env: str | None = None
    principal_id: str | None = None
    principal_id_env: str | None = None
    resource_id: str | None = None
    resource_id_env: str | None = None
    environment: str | None = None
    environment_env: str | None = None
    event_log: str | None = None
    event_log_dir: str | None = None
    progress: Literal["auto", "live", "plain", "off"] | None = None
    progress_color: Literal["auto", "always", "never"] | None = None
    timeout: float | None = Field(default=None, gt=0)
    max_checks: int | None = Field(default=None, ge=1)
    safe_fields: tuple[str, ...] = ()

    model: ModelProfile = Field(default_factory=ModelProfile)
    grounding: GroundingProfile = Field(default_factory=GroundingProfile)
    differential: DifferentialProfile = Field(default_factory=DifferentialProfile)
    neo4j: Neo4jProfile = Field(default_factory=Neo4jProfile)
    stand: StandProfile = Field(default_factory=StandProfile)
    runtime: RuntimeProfile = Field(default_factory=RuntimeProfile)
    classification: ClassificationLaunchProfile = Field(
        default_factory=ClassificationLaunchProfile
    )


@dataclass(frozen=True, slots=True)
class LiveSettings:
    """Resolved CLI values after explicit arguments and profile settings."""

    service: str
    identity: str
    principal_id: str
    resource_id: str
    method_id: str | None
    max_checks: int | None
    event_log: str | None
    event_log_dir: str
    environment: str | None
    timeout: float
    safe_fields: tuple[str, ...]
    progress: str
    progress_color: str
    method_prefix_aliases: Mapping[str, str] = field(default_factory=dict)


def load_profile(path: str | Path) -> LiveProfile:
    profile_path = Path(path).expanduser()
    try:
        with profile_path.open("rb") as stream:
            payload = tomllib.load(stream)
    except OSError as error:
        raise RuntimeError(f"cannot read launch profile {profile_path}") from error
    except tomllib.TOMLDecodeError as error:
        raise RuntimeError(f"invalid launch profile {profile_path}: {error}") from error
    try:
        profile = LiveProfile.model_validate(payload)
    except ValueError as error:
        raise RuntimeError(f"invalid launch profile {profile_path}: {error}") from error
    if profile.classification.path:
        classification_path = Path(profile.classification.path).expanduser()
        if not classification_path.is_absolute():
            classification_path = profile_path.parent / classification_path
        classification_path = classification_path.resolve()
        profile = profile.model_copy(
            update={
                "classification": ClassificationLaunchProfile(
                    path=str(classification_path)
                )
            }
        )
    return profile


def load_classification_profile(path: str | Path) -> ClassificationProfile:
    """Load and validate one curated classification profile."""

    profile_path = Path(path).expanduser()
    try:
        with profile_path.open("rb") as stream:
            payload = tomllib.load(stream)
    except OSError as error:
        raise RuntimeError(
            f"cannot read classification profile {profile_path}"
        ) from error
    except tomllib.TOMLDecodeError as error:
        raise RuntimeError(
            f"invalid classification profile {profile_path}: {error}"
        ) from error
    try:
        return ClassificationProfile.model_validate(payload)
    except ValueError as error:
        raise RuntimeError(
            f"invalid classification profile {profile_path}: {error}"
        ) from error


def classification_profile_from_environment(
    environ: MutableMapping[str, str] | None = None,
) -> ClassificationProfile:
    """Resolve the profile-selected classification mapping."""

    environment = os.environ if environ is None else environ
    raw = environment.get("CLOUD_DAST_CLASSIFICATION_PROFILE", "").strip()
    if not raw:
        return ClassificationProfile()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "CLOUD_DAST_CLASSIFICATION_PROFILE must be a JSON classification profile"
        ) from error
    try:
        return ClassificationProfile.model_validate(payload)
    except ValueError as error:
        raise RuntimeError(
            "CLOUD_DAST_CLASSIFICATION_PROFILE is not a valid classification profile"
        ) from error


def apply_profile_environment(
    profile: LiveProfile,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Apply explicit profile values to the campaign environment.

    A selected profile is authoritative for non-secret campaign settings.
    This prevents stale values in a shared ``.env`` (for example, an old
    allowed service or model id) from silently changing the target campaign.
    Secrets themselves never live in the profile; the profile only points at
    their environment-backed sources.

    Only fields explicitly present in the TOML profile override the process
    environment.  An explicit empty string or empty list clears the derived
    environment value; omitted fields keep their environment-backed default.
    """

    environment = os.environ if environ is None else environ

    for model, fields in (
        (profile, (("event_log", "CLOUD_DAST_EVENT_LOG"),)),
        (
            profile.model,
            (
                ("id", "CLOUD_DAST_MODEL_ID"),
                ("api", "CLOUD_DAST_MODEL_API"),
                ("reasoning_effort", "CLOUD_DAST_MODEL_REASONING_EFFORT"),
                ("timeout", "CLOUD_DAST_MODEL_TIMEOUT"),
                ("retries", "CLOUD_DAST_MODEL_RETRIES"),
                ("url", "CLOUD_DAST_MODEL_URL"),
            ),
        ),
        (
            profile.grounding,
            (
                ("skip_llm", "CLOUD_DAST_SKIP_LLM_GROUNDING"),
                ("cache", "CLOUD_DAST_GROUNDING_CACHE"),
                ("cache_dir", "CLOUD_DAST_GROUNDING_CACHE_DIR"),
                ("workers", "CLOUD_DAST_GROUNDING_WORKERS"),
                ("reactive_workers", "CLOUD_DAST_REACTIVE_WORKERS"),
                ("batch_size", "CLOUD_DAST_GROUNDING_BATCH_SIZE"),
                ("promote_proposals", "CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS"),
                ("reactive_budget", "CLOUD_DAST_REACTIVE_BUDGET"),
            ),
        ),
        (
            profile.differential,
            (
                ("mode", "CLOUD_DAST_DIFF_MODE"),
                ("modes", "CLOUD_DAST_DIFF_MODES"),
            ),
        ),
        (
            profile.neo4j,
            (("uri", "CPA_NEO4J_URI"), ("user", "CPA_NEO4J_USER")),
        ),
        (
            profile.stand,
            (("source", "CLOUD_DAST_STAND_SOURCE"), ("file", "CLOUD_DAST_STAND_FILE")),
        ),
        (
            profile.runtime,
            (
                ("allowed", "CLOUD_DAST_ALLOWED_SERVICES"),
                ("setup_identity", "CLOUD_DAST_SETUP_IDENTITY"),
                ("iam_token_prefer_command", "CLOUD_DAST_IAM_TOKEN_PREFER_COMMAND"),
            ),
        ),
    ):
        for field_name, name in fields:
            _apply_value(environment, model, field_name, name)

    for model, field_name, name in (
        (profile.neo4j, "password_file_env", "CPA_NEO4J_PASSWORD_FILE"),
        (profile.runtime, "descriptor_set_env", "CLOUD_DAST_DESCRIPTOR_SET"),
    ):
        _apply_reference(environment, model, field_name, name)

    if "classification" in profile.model_fields_set:
        path = profile.classification.path
        if not path:
            environment.pop("CLOUD_DAST_CLASSIFICATION_PROFILE", None)
        else:
            classification = load_classification_profile(path)
            environment["CLOUD_DAST_CLASSIFICATION_PROFILE"] = (
                classification.model_dump_json()
            )


def resolve_live_settings(
    args: argparse.Namespace,
    profile: LiveProfile | None = None,
) -> LiveSettings:
    profile = profile or LiveProfile()
    service = _first(args.service, profile.service)
    identity = _first(
        args.identity,
        profile.identity,
        _environment(profile.identity_env),
    )
    principal_id = _first(
        args.principal_id,
        profile.principal_id,
        _environment(profile.principal_id_env),
        identity,
    )
    resource_id = _first(
        args.resource_id,
        profile.resource_id,
        _environment(profile.resource_id_env),
    )
    environment = _first(
        args.environment,
        profile.environment,
        _environment(profile.environment_env),
    )
    method_id = _first(args.method_id, profile.method_id)
    max_checks = _first(args.max_checks, profile.max_checks)
    event_log = _first(args.event_log, profile.event_log)
    event_log_dir = str(
        _first(profile.event_log_dir, "/tmp"),
    )
    timeout = float(_first(args.timeout, profile.timeout, 30.0))
    safe_fields = tuple(args.safe_field or ()) or profile.safe_fields
    progress = str(_first(args.progress, profile.progress, "auto"))
    progress_color = str(_first(args.progress_color, profile.progress_color, "auto"))

    missing = [
        name
        for name, value in (
            ("service", service),
            ("identity", identity),
            ("resource_id", resource_id),
        )
        if not value
    ]
    if missing:
        raise RuntimeError("live profile is missing: " + ", ".join(missing))

    return LiveSettings(
        service=service,
        identity=identity,
        principal_id=principal_id,
        resource_id=resource_id,
        method_id=method_id,
        max_checks=max_checks,
        event_log=event_log,
        event_log_dir=event_log_dir,
        environment=environment,
        timeout=timeout,
        safe_fields=safe_fields,
        progress=progress,
        progress_color=progress_color,
        method_prefix_aliases=dict(profile.neo4j.method_prefix_aliases),
    )


def _set(
    environment: MutableMapping[str, str],
    name: str,
    value: Any,
) -> None:
    if value is None or value == "" or (isinstance(value, tuple) and not value):
        environment.pop(name, None)
        return
    if isinstance(value, bool):
        serialized = "1" if value else "0"
    elif isinstance(value, tuple):
        serialized = ",".join(str(item) for item in value)
    else:
        serialized = str(value)
    environment[name] = serialized


def _apply_value(
    environment: MutableMapping[str, str],
    model: BaseModel,
    field: str,
    name: str,
) -> None:
    if field not in model.model_fields_set:
        return
    _set(environment, name, getattr(model, field))


def _apply_reference(
    environment: MutableMapping[str, str],
    model: BaseModel,
    field: str,
    name: str,
) -> None:
    if field not in model.model_fields_set:
        return
    reference = getattr(model, field)
    if not reference:
        value = None
    elif reference in environment:
        value = environment[reference]
    else:
        value = os.environ.get(reference)
    _set(environment, name, value)


def _environment(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name, "").strip()
    return value or None


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None
