from __future__ import annotations

import clingo
import pytest

from cloud_dast.qdl.asp import (
    asp_string,
    decode_term,
    encode_atom,
)
from cloud_dast.qdl.graph import Atom


def test_asp_string_escapes_supported_control_characters() -> None:
    assert asp_string("a\nb") == '"a\\nb"'
    assert asp_string('a"b\\c') == '"a\\"b\\\\c"'


def test_asp_string_rejects_nul() -> None:
    with pytest.raises(ValueError, match="NUL"):
        asp_string("a\0b")


def test_encode_atom_preserves_literal_types() -> None:
    assert encode_atom(Atom(value=1, literal_type="integer")) == 'qdl_int("1")'
    assert encode_atom(Atom(value=1.5, literal_type="float")) == 'qdl_float("1.5")'
    assert encode_atom(Atom(value=True, literal_type="boolean")) == 'qdl_bool("true")'
    assert encode_atom(Atom(value="1.5", literal_type="string")) == '"1.5"'


def test_decode_term_round_trips_typed_atoms() -> None:
    for atom in (
        Atom(value=1, literal_type="integer"),
        Atom(value=1.5, literal_type="float"),
        Atom(value=False, literal_type="boolean"),
        Atom(value="1.5", literal_type="string"),
        Atom(value="a\nb", literal_type="string"),
    ):
        encoded = encode_atom(atom)
        symbol = clingo.parse_term(encoded)
        assert decode_term(symbol) == atom
