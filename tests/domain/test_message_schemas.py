from __future__ import annotations

import pytest

from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    RequestSchema,
    ResponseSchema,
)


def test_method_owns_request_and_response_schemas() -> None:
    method = MethodSpec(
        method_id="grpc:svc.Get",
        service="svc",
        name="Get",
        layer=EndpointLayer.PUBLIC,
        request_schema=RequestSchema(
            type_name="svc.GetRequest",
            fields=(FieldSpec(name="id", type="string", required=True),),
        ),
        response_schema=ResponseSchema(type_name="svc.GetResponse"),
    )

    assert method.request_schema.type_name == "svc.GetRequest"
    assert method.response_schema is not None
    assert method.fields == method.request_schema.fields
    assert "fields" not in method.model_dump()


def test_legacy_flat_fields_are_normalized_at_the_boundary() -> None:
    method = MethodSpec(
        method_id="grpc:svc.Get",
        service="svc",
        name="Get",
        layer=EndpointLayer.PUBLIC,
        fields=(FieldSpec(name="id", type="string"),),
    )

    assert method.request_schema.fields[0].name == "id"


def test_schema_rejects_duplicate_field_names() -> None:
    with pytest.raises(ValueError, match="schema field names must be unique"):
        RequestSchema(
            fields=(
                FieldSpec(name="id", type="string"),
                FieldSpec(name="id", type="string"),
            )
        )
