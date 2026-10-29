from __future__ import annotations

import pytest

from cloud_dast.model import (
    EndpointLayer,
    MethodSpec,
)
from cloud_dast.verification.scenarios import (
    capability_closure,
    has_capabilities,
    missing_capabilities,
)


@pytest.fixture
def method() -> MethodSpec:
    return MethodSpec(
        method_id="grpc-priv:lockbox.PayloadService.Get",
        service="lockbox",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"lockbox.secrets.get", "lockbox.secrets.getPayload"}),
    )


def test_capability_closure_returns_fullly_covered_permissions(method) -> None:
    effective = frozenset(
        {"lockbox.secrets.get", "lockbox.secrets.getPayload", "lockbox.extra"}
    )

    assert capability_closure(method, effective) == method.permissions
    assert missing_capabilities(method, effective) == frozenset()
    assert has_capabilities(method, effective) is True


def test_capability_closure_returns_partially_covered_permissions(method) -> None:
    effective = frozenset({"lockbox.secrets.get"})

    assert capability_closure(method, effective) == frozenset({"lockbox.secrets.get"})
    assert missing_capabilities(method, effective) == frozenset(
        {"lockbox.secrets.getPayload"}
    )
    assert has_capabilities(method, effective) is False


def test_capability_closure_returns_no_permissions(method) -> None:
    effective = frozenset({"lockbox.other"})

    assert capability_closure(method, effective) == frozenset()
    assert missing_capabilities(method, effective) == method.permissions
    assert has_capabilities(method, effective) is False


def test_method_without_required_permissions_needs_no_capabilities(method) -> None:
    method_without_permissions = method.model_copy(update={"permissions": frozenset()})
    effective = frozenset()

    assert capability_closure(method_without_permissions, effective) == frozenset()
    assert missing_capabilities(method_without_permissions, effective) == frozenset()
    assert has_capabilities(method_without_permissions, effective) is True
