from __future__ import annotations

from cloud_dast.qdl.parser import parse_fact, parse_term


def test_parse_fact_preserves_namespaced_atoms_and_nested_terms() -> None:
    fact = parse_fact(
        "prevents(norm:quota, duration(action:nsfy.List, 100))",
        max_length=8192,
    )

    assert fact is not None
    assert fact["predicate"] == "prevents"
    assert fact["args"][0]["value"] == "norm:quota"
    assert fact["args"][1]["name"] == "duration"
    assert fact["args"][1]["args"][0]["value"] == "action:nsfy.List"
    assert fact["args"][1]["args"][1]["value"] == 100


def test_parse_term_decodes_scalar_literals() -> None:
    assert parse_term("true")["value"] is True
    assert parse_term("-12")["value"] == -12
    assert parse_term("'quoted\\'atom'")["value"] == "quoted'atom"


def test_parse_term_rejects_overlong_input_before_grammar() -> None:
    assert parse_term("x", max_length=0) is None
    assert parse_fact("is(x, Action)", max_length=4) is None
