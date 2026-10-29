"""Normalized advisory data and the ``affects`` QDL predicate."""

from __future__ import annotations

import re
from typing import Literal, Self
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Predicate,
    PredicateSchema,
    TermKind,
)

type AdvisorySourceKind = Literal["osv", "ghsa", "nvd"]

ALLOWED_ADVISORY_HOSTS: dict[AdvisorySourceKind, frozenset[str]] = {
    "osv": frozenset({"api.osv.dev", "osv.dev"}),
    "ghsa": frozenset({"api.github.com", "github.com"}),
    "nvd": frozenset({"services.nvd.nist.gov", "nvd.nist.gov"}),
}

AFFECTS = Predicate.from_schema(
    PredicateSchema(
        name="affects",
        arguments=(
            ArgumentSchema(
                name="package",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
            ),
            ArgumentSchema(
                name="version",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
            ),
        ),
    )
)

_EPOCH_PATTERN = re.compile(r"^(\d+)!")
_VERSION_TOKEN_PATTERN = re.compile(r"\d+|[a-z]+")


class AdvisorySource(BaseModel):
    """One allowlisted HTTPS source of advisory records."""

    model_config = ConfigDict(frozen=True)

    kind: AdvisorySourceKind
    url: str

    @model_validator(mode="after")
    def validate_url(self) -> Self:
        parsed = urlparse(self.url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or not host:
            raise ValueError("advisory source URL must use HTTPS")
        if host not in ALLOWED_ADVISORY_HOSTS[self.kind]:
            raise ValueError(f"{host} is not allowed for {self.kind} advisories")
        return self


class VersionRange(BaseModel):
    """A closed or half-open range of package versions."""

    model_config = ConfigDict(frozen=True)

    introduced: str | None = None
    introduced_exclusive: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None
    exact: str | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        bounds = (
            self.introduced,
            self.introduced_exclusive,
            self.fixed,
            self.last_affected,
            self.limit,
            self.exact,
        )
        if all(value is None for value in bounds):
            raise ValueError("version range requires at least one bound")
        return self

    def matches(self, version: str) -> bool:
        if self.exact is not None and compare_versions(version, self.exact) != 0:
            return False
        if (
            self.introduced is not None
            and compare_versions(version, self.introduced) < 0
        ):
            return False
        if (
            self.introduced_exclusive is not None
            and compare_versions(version, self.introduced_exclusive) <= 0
        ):
            return False
        if self.fixed is not None and compare_versions(version, self.fixed) >= 0:
            return False
        if (
            self.last_affected is not None
            and compare_versions(version, self.last_affected) > 0
        ):
            return False
        if self.limit is not None and compare_versions(version, self.limit) >= 0:
            return False
        return True


class AdvisoryPackage(BaseModel):
    """One package affected by an advisory."""

    model_config = ConfigDict(frozen=True)

    ecosystem: str = Field(min_length=1)
    name: str = Field(min_length=1)
    ranges: tuple[VersionRange, ...]

    @field_validator("ecosystem", "name")
    @classmethod
    def strip_identifier(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("advisory package identifier must not be empty")
        return normalized

    @field_validator("ecosystem")
    @classmethod
    def normalize_ecosystem(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_ranges(self) -> Self:
        if not self.ranges:
            raise ValueError("advisory package requires at least one version range")
        return self

    @property
    def canonical_name(self) -> str:
        return f"{self.ecosystem}:{self.name}"


class AdvisoryRecord(BaseModel):
    """A normalized advisory with its affected packages."""

    model_config = ConfigDict(frozen=True)

    source_kind: AdvisorySourceKind
    advisory_id: str = Field(min_length=1)
    packages: tuple[AdvisoryPackage, ...]

    @field_validator("advisory_id")
    @classmethod
    def strip_advisory_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("advisory_id must not be empty")
        return normalized

    @model_validator(mode="after")
    def validate_packages(self) -> Self:
        if not self.packages:
            raise ValueError("advisory record requires at least one package")
        return self


class PackageVersion(BaseModel):
    """One concrete package version in the pre-scan inventory."""

    model_config = ConfigDict(frozen=True)

    ecosystem: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)

    @field_validator("ecosystem", "name", "version")
    @classmethod
    def strip_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("package inventory values must not be empty")
        return normalized

    @field_validator("ecosystem")
    @classmethod
    def normalize_ecosystem(cls, value: str) -> str:
        return value.strip().lower()

    @property
    def canonical_package(self) -> str:
        return f"{self.ecosystem}:{self.name}"


def compare_versions(left: str, right: str) -> int:
    """Compare two package versions without a package-manager-specific parser.

    The ordering is intentionally generic: epochs, numeric release components,
    and pre-release components are ordered deterministically. Exact corpus
    semantics remain in the source-specific parser; this comparator only makes
    range bounds executable.
    """

    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _version_key(
    value: str,
) -> tuple[
    int,
    tuple[tuple[int, int, str], ...],
    tuple[int, tuple[tuple[int, int, str], ...]],
]:
    normalized = value.strip().lower()
    epoch = 0
    if match := _EPOCH_PATTERN.match(normalized):
        epoch = int(match.group(1))
        normalized = normalized[match.end() :]
    if normalized.startswith("v"):
        normalized = normalized[1:]
    normalized = normalized.split("+", 1)[0]
    release, separator, prerelease = normalized.partition("-")
    release_key = _token_key(release)
    if not separator or not prerelease:
        return epoch, release_key, (1, ())
    return epoch, release_key, (0, _token_key(prerelease))


def _token_key(value: str) -> tuple[tuple[int, int, str], ...]:
    tokens: list[tuple[int, int, str]] = []
    for token in _VERSION_TOKEN_PATTERN.findall(value):
        if token.isdigit():
            tokens.append((1, int(token), ""))
        else:
            tokens.append((0, 0, token))
    return tuple(tokens)
