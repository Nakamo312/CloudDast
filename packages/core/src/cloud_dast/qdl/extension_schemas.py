"""QDL predicate schemas used by contract projections and proposal validation."""

from __future__ import annotations

from cloud_dast.qdl.graph import ArgumentSchema, PredicateSchema, TermKind


def _reference(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
        reference=True,
    )


def _string(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
    )


def _boolean(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("boolean",),
    )


def _number(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("integer", "string"),
    )


def _field_term(name: str = "field") -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.STRUCT,),
        struct_names=("input_field",),
        reference=True,
    )


def _object_reference_term(name: str = "field") -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.STRUCT,),
        struct_names=("input_field", "output_field", "output_header"),
        reference=True,
    )


def _relation_schema(name: str, left: str, right: str) -> PredicateSchema:
    return PredicateSchema(
        name=name,
        arguments=(_reference(left), _reference(right)),
    )


EXTENSION_PREDICATE_SCHEMAS: tuple[PredicateSchema, ...] = (
    PredicateSchema(
        name="refers_to", arguments=(_object_reference_term(), _reference("resource"))
    ),
    _relation_schema("serves", "endpoint", "api_surface"),
    _relation_schema("known_as", "service", "alias"),
    _relation_schema("describes", "doc_page", "service"),
    PredicateSchema(name="field_type", arguments=(_field_term(), _string("type"))),
    PredicateSchema(
        name="field_required",
        arguments=(_field_term(), _boolean("required")),
    ),
    PredicateSchema(
        name="field_repeated",
        arguments=(_field_term(), _boolean("repeated")),
    ),
    PredicateSchema(name="field_oneof", arguments=(_field_term(), _string("oneof"))),
    PredicateSchema(
        name="field_enum_value",
        arguments=(_field_term(), _string("value")),
    ),
    PredicateSchema(
        name="field_minimum",
        arguments=(_field_term(), _number("minimum")),
    ),
    PredicateSchema(
        name="field_maximum",
        arguments=(_field_term(), _number("maximum")),
    ),
)


__all__ = ["EXTENSION_PREDICATE_SCHEMAS"]
