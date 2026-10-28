"""Core literals preserve data; schema reference/declaration slots reject blank IDs."""

from pathlib import Path

import clingo
import pytest
from pydantic import ValidationError

import cloud_dast
from cloud_dast.model import ResourceRef
from cloud_dast.qdl.asp import decode_term, encode_atom
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    create,
    input_field,
)
from tests.test_review_I1 import _manifest, _project


@pytest.mark.parametrize("literal", ["", "   ", " admin ", "admin"])
def test_literal_survives_json_clingo_and_projection_hash(tmp_path, literal):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    atom = Atom(value=literal)
    assert Atom.model_validate_json(atom.model_dump_json()) == atom
    assert decode_term(clingo.parse_term(encode_atom(atom))) == atom
    graph = _project(_manifest(tmp_path, ["grpc:svc.Update"], (literal,))).graph
    assert QdlGraph.model_validate_json(graph.model_dump_json()) == graph
    facts = ClingoEngine().solve(graph)[0].atoms
    values = {
        decode_term(clingo.parse_term(fact).arguments[-1])
        for fact in facts
        if fact.startswith("field_enum_value(")
    }
    assert values == {atom}
    other = "other" if literal == "admin" else "admin"
    other_graph = _project(_manifest(tmp_path, ["grpc:svc.Update"], (other,))).graph
    assert graph.content_hash != other_graph.content_hash


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
@pytest.mark.parametrize(
    "position", ["declaration", "reference", "constructor", "resource_ref"]
)
def test_blank_ids_fail_at_schema_positions(blank, position):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    # Constructing literal data is legal; only the graph-ID position rejects it.
    value = Atom(value=blank)
    with pytest.raises(ValidationError, match="must not be blank"):
        if position == "declaration":
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(value, Atom(value="Resource")),
            )
        elif position == "reference":
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("targets"),
                args=(Atom(value="action:update"), value),
            )
        elif position == "constructor":
            input_field(value, Atom(value="status"))
        else:
            ref = ResourceRef(service="svc", resource_type=blank, resource_id="fixture")
            create(Atom(value=ref.resource_type))


def test_empty_padded_and_plain_literals_have_distinct_schema_identity(tmp_path):
    literals = ("", "   ", " admin ", "admin")
    hashes = {
        _project(_manifest(tmp_path, ["grpc:svc.Update"], (literal,))).canonical_hash
        for literal in literals
    }
    assert len(hashes) == len(literals)
    graph = _project(_manifest(tmp_path, ["grpc:svc.Update"], literals)).graph
    assert {fact.args[1].value for fact in graph.facts_for("field_enum_value")} == set(
        literals
    )
