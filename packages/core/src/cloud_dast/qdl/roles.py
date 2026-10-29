"""Canonical semantic-role alphabet owned by QDL and used by verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cloud_dast.qdl.graph import Atom

type SemanticRoleReason = Literal["unknown", "engine"]


@dataclass(frozen=True, slots=True)
class SemanticRole:
    name: str
    description: str
    stride: tuple[str, ...]
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    sensitive: bool = False
    privileged: bool = False


@dataclass(frozen=True, slots=True)
class SemanticRoleViolation:
    role: str
    reason: SemanticRoleReason


SEMANTIC_ROLES: tuple[SemanticRole, ...] = (
    SemanticRole(
        "attacker_controlled",
        "requester-influenced free text or value",
        ("T",),
        ("CWE-74",),
        ("A03",),
    ),
    SemanticRole(
        "component", "component or dependency boundary", ("T",), ("CWE-1104",), ("A06",)
    ),
    SemanticRole(
        "credential",
        "authentication or authorization secret",
        ("S",),
        ("CWE-287",),
        ("A07",),
        sensitive=True,
    ),
    SemanticRole(
        "deprecated",
        "deprecated or legacy contract element",
        ("E",),
        ("CWE-1104",),
        ("API9",),
    ),
    SemanticRole(
        "downstream_trust",
        "trusted downstream consumer or dependency",
        ("T",),
        ("CWE-829",),
        ("A10",),
    ),
    SemanticRole(
        "mutable_input",
        "request field the contract declares mutable",
        ("T",),
        ("CWE-20",),
        ("A03",),
    ),
    SemanticRole(
        "object_ref", "addresses another resource", ("E",), ("CWE-639",), ("A01",)
    ),
    SemanticRole(
        "payload",
        "attacker-mutable request value carried into processing",
        ("T",),
        ("CWE-74",),
        ("A03",),
    ),
    SemanticRole(
        "privileged",
        "admin-only or permission-bearing attribute",
        ("T",),
        ("CWE-915",),
        ("API3",),
        sensitive=True,
        privileged=True,
    ),
    SemanticRole(
        "sensitive",
        "secret or confidential data",
        ("I",),
        ("CWE-200",),
        ("A02",),
        sensitive=True,
    ),
    SemanticRole("type", "type discriminator", ("T",), ("CWE-843",), ("A03",)),
    SemanticRole(
        "type_confusion",
        "attacker-controlled type discriminator",
        ("T",),
        ("CWE-843",),
        ("A03",),
    ),
    SemanticRole(
        "unbounded",
        "no explicit size, cardinality, or duration bound",
        ("D",),
        ("CWE-400",),
        ("API4",),
    ),
    SemanticRole(
        "unverified_source",
        "data from an unverified source",
        ("T",),
        ("CWE-345",),
        ("A08",),
    ),
    SemanticRole("verbose", "diagnostic exposure", ("I",), ("CWE-209",), ("API8",)),
    SemanticRole(
        "weak_binding", "witness weakly binds a subject", ("S",), ("CWE-346",), ("A02",)
    ),
)

SEMANTIC_ROLE_NAMES = frozenset(role.name for role in SEMANTIC_ROLES)
SEMANTIC_ROLES_BY_NAME = {role.name: role for role in SEMANTIC_ROLES}
ENGINE_ROLES = frozenset({"probe_target", "oob_target", "setup_value", "setup_skip"})


def format_semantic_roles() -> str:
    return "; ".join(f"{role.name} ({role.description})" for role in SEMANTIC_ROLES)


def semantic_role_violation(
    predicate: str,
    args: tuple[object, ...] | list[object],
) -> SemanticRoleViolation | None:
    if predicate != "has" or len(args) != 2:
        return None
    role = args[1]
    if not isinstance(role, Atom):
        return None
    value = role.value
    if not isinstance(value, str):
        return SemanticRoleViolation(role="<non-string>", reason="unknown")
    if value in ENGINE_ROLES:
        return SemanticRoleViolation(role=value, reason="engine")
    if value not in SEMANTIC_ROLE_NAMES:
        return SemanticRoleViolation(role=value, reason="unknown")
    return None


def semantic_role_stride(role_name: str) -> tuple[str, ...]:
    role = SEMANTIC_ROLES_BY_NAME.get(role_name)
    return role.stride if role is not None else ()


def semantic_role_taxonomy(
    role_name: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    role = SEMANTIC_ROLES_BY_NAME.get(role_name)
    if role is None:
        return (), (), ()
    return role.cwe, role.owasp, role.stride


__all__ = [
    "ENGINE_ROLES",
    "SEMANTIC_ROLE_NAMES",
    "SEMANTIC_ROLES",
    "SemanticRole",
    "SemanticRoleViolation",
    "format_semantic_roles",
    "semantic_role_stride",
    "semantic_role_taxonomy",
    "semantic_role_violation",
]
