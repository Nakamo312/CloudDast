from __future__ import annotations

import pytest
from pydantic import ValidationError

from cloud_dast.model import (
    Check,
    FieldSpec,
)
from cloud_dast.model.events import InvestigationIntent
from cloud_dast.model.schemas import float_range


def test_float_range_uses_exact_binary32_limit() -> None:
    assert float_range("float") == (
        -3.4028234663852886e38,
        3.4028234663852886e38,
    )


def test_field_spec_rejects_reversed_bounds() -> None:
    with pytest.raises(ValidationError, match="minimum must not be greater"):
        FieldSpec(name="offset", type="int32", minimum=10, maximum=5)


def test_field_spec_rejects_float_bounds_for_integer_type() -> None:
    with pytest.raises(ValidationError, match="integer field must be int"):
        FieldSpec(name="offset", type="int32", minimum=1.5)


def test_field_spec_rejects_bool_bounds() -> None:
    with pytest.raises(ValidationError, match="must be a number, not bool"):
        FieldSpec(name="offset", type="int32", minimum=True)


@pytest.mark.parametrize(
    ("field_type", "minimum", "maximum"),
    [
        ("uint32", -1, None),
        ("fixed32", None, 2**32),
        ("int32", None, 2**31),
        ("sfixed64", -(2**63) - 1, None),
        ("fixed64", None, 2**64),
        ("float", None, 4.0e38),
        ("double", -2.0e308, None),
    ],
)
def test_field_spec_rejects_bounds_outside_primitive_range(
    field_type: str,
    minimum: float | None,
    maximum: float | None,
) -> None:
    with pytest.raises(ValidationError, match="outside the .* range"):
        FieldSpec(name="value", type=field_type, minimum=minimum, maximum=maximum)


def test_field_spec_rejects_nan_bounds() -> None:
    with pytest.raises(ValidationError, match="must not be NaN"):
        FieldSpec(name="ratio", type="double", minimum=float("nan"))


def test_check_rejects_duplicate_request_names(check: Check) -> None:
    with pytest.raises(ValidationError, match="request field names must be unique"):
        Check(
            invariant_id=check.invariant_id,
            method_id=check.method_id,
            scenario_id=check.scenario_id,
            request=(("secret_id", "secret-victim"), ("secret_id", "secret-attacker")),
            identities=check.identities,
        )


def test_investigation_intent_rejects_duplicate_payload_names() -> None:
    with pytest.raises(ValidationError, match="payload field names must be unique"):
        InvestigationIntent(
            method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            payload=(("secret_id", "secret-victim"), ("secret_id", "secret-attacker")),
            identity="attacker",
            reason="Investigate duplicate fields",
        )
