from __future__ import annotations

from cloud_dast.model import MethodSpec


def capability_closure(
    method: MethodSpec,
    effective_permissions: frozenset[str],
) -> frozenset[str]:
    """Return the permissions the principal has among method requirements."""

    return method.permissions & effective_permissions


def missing_capabilities(
    method: MethodSpec,
    effective_permissions: frozenset[str],
) -> frozenset[str]:
    """Return the method permissions that the principal does not have."""

    return method.permissions - effective_permissions


def has_capabilities(
    method: MethodSpec,
    effective_permissions: frozenset[str],
) -> bool:
    """Return whether the principal has every permission required by the method."""

    return not missing_capabilities(method, effective_permissions)
