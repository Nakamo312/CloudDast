from __future__ import annotations

import pytest
from pydantic import ValidationError

from cloud_dast.contracts.proposals import (
    FormalModelOutputValidator,
    FormalModelWireOutput,
)
from cloud_dast.ports import (
    MAX_MODEL_CHECKS,
    MAX_MODEL_FACTS,
    MAX_MODEL_RULES,
    MAX_MODEL_STRING_LENGTH,
    MAX_MODEL_UNCERTAINTIES,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
)
from cloud_dast_llm.proposals import LlmGeneratedChecks


def fact(predicate: str, args: tuple[object, ...], context: Context) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def test_formal_model_output_rejects_fact_overflow() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {"kind": "atom", "value": f"a:{index}", "literal_type": "string"},
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            }
            for index in range(MAX_MODEL_FACTS + 1)
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code == "schema" for issue in result.issues)


def test_salvage_rejects_fact_overflow_without_keeping_a_subset() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:get, Action)",
            *(["not a fact"] * MAX_MODEL_FACTS),
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is None
    assert any(
        issue.code == "limit" and issue.path == "facts" for issue in result.issues
    )


def test_salvage_rejects_string_overflow_without_keeping_a_subset() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:get, Action)",
            "x" * (MAX_MODEL_STRING_LENGTH + 1),
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is None
    assert any(issue.code == "limit" for issue in result.issues)


def test_wire_output_rejects_oversized_strings() -> None:
    with pytest.raises(ValidationError, match="too_long"):
        FormalModelWireOutput.model_validate(
            {"facts": ["x" * (MAX_MODEL_STRING_LENGTH + 1)]}
        )


def test_wire_output_rejects_rule_and_uncertainty_overflow() -> None:
    rules = ["is(action:get, Action)"] * (MAX_MODEL_RULES + 1)
    uncertainties = [{"field": "response", "question": "what shape?"}] * (
        MAX_MODEL_UNCERTAINTIES + 1
    )

    with pytest.raises(ValidationError, match="too_long"):
        FormalModelWireOutput.model_validate(
            {"rules": rules, "uncertainties": uncertainties}
        )


def test_llm_checks_reject_check_overflow() -> None:
    checks = [
        {"request": {"value": str(index)}, "rationale": ""}
        for index in range(MAX_MODEL_CHECKS + 1)
    ]

    with pytest.raises(ValidationError, match="too_long"):
        LlmGeneratedChecks.model_validate({"checks": checks})


def test_llm_checks_reject_string_overflow() -> None:
    with pytest.raises(ValidationError, match="request string exceeds"):
        LlmGeneratedChecks.model_validate(
            {
                "checks": [
                    {
                        "request": {"value": "x" * (MAX_MODEL_STRING_LENGTH + 1)},
                        "rationale": "",
                    }
                ]
            }
        )


def test_structured_fact_rejects_atom_string_overflow() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "atom",
                        "value": "x" * (MAX_MODEL_STRING_LENGTH + 1),
                        "literal_type": "string",
                    },
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            }
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code == "schema" for issue in result.issues)


def test_salvage_rejects_structured_string_overflow_without_keeping_a_subset() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "atom",
                        "value": "x" * (MAX_MODEL_STRING_LENGTH + 1),
                        "literal_type": "string",
                    },
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            },
            "is(action:get, Action)",
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is None
    assert any(issue.code == "limit" for issue in result.issues)


def test_validator_accepts_proposal_graph() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {"kind": "atom", "value": "action:get", "literal_type": "string"},
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            }
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert result.valid
    assert isinstance(result.graph, QdlGraph)


def test_validator_rejects_non_proposal_context() -> None:
    payload = {
        "context": "accepted",
        "facts": [],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code == "context" for issue in result.issues)


def test_validator_rejects_an_empty_model_response() -> None:
    result = FormalModelOutputValidator().validate(
        {"context": "proposal", "facts": [], "rules": []}
    )

    assert result.graph is None
    assert not result.valid
    assert any(issue.code == "empty" for issue in result.issues)


def test_salvage_does_not_cache_background_as_an_empty_response() -> None:
    action = Atom(value="action:get")
    background = QdlGraph(
        facts=(
            fact(
                "is",
                (action, Atom(value="Action")),
                Context.CONTRACT,
            ),
        )
    )

    result = FormalModelOutputValidator().salvage(
        {"context": "proposal", "facts": [], "rules": []},
        background=background,
    )

    assert result.graph is None
    assert not result.valid
    assert any(issue.code == "empty" for issue in result.issues)


def test_validator_rejects_unknown_predicate() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "unknown",
                "args": [{"kind": "atom", "value": "a", "literal_type": "string"}],
            }
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code in {"schema", "graph"} for issue in result.issues)


def test_validator_rejects_wrong_arity() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "requires",
                "args": [
                    {"kind": "atom", "value": "action:get", "literal_type": "string"}
                ],
            }
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code in {"schema", "graph"} for issue in result.issues)


def test_validator_rejects_free_text_effect() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "prevents",
                "args": [
                    {"kind": "atom", "value": "norm:x", "literal_type": "string"},
                    {
                        "kind": "atom",
                        "value": "mass assignment",
                        "literal_type": "string",
                    },
                ],
            }
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code in {"schema", "graph"} for issue in result.issues)


def test_validator_rejects_cross_context_rule() -> None:
    payload = {
        "context": "proposal",
        "facts": [],
        "rules": [
            {
                "body": [
                    {
                        "context": "proposal",
                        "predicate": "is",
                        "args": [
                            {"kind": "variable", "name": "Action"},
                            {"kind": "variable", "name": "Type"},
                        ],
                    }
                ],
                "head": [
                    {
                        "context": "accepted",
                        "predicate": "requires",
                        "args": [
                            {"kind": "variable", "name": "Action"},
                            {"kind": "variable", "name": "Requirement"},
                        ],
                    }
                ],
            }
        ],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert not result.valid
    assert any(issue.code in {"context", "graph"} for issue in result.issues)


def test_validator_accepts_contract_extension_predicate() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "targets",
                "args": [
                    {"kind": "atom", "value": "action:get", "literal_type": "string"},
                    {
                        "kind": "atom",
                        "value": "resource:secret",
                        "literal_type": "string",
                    },
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {"kind": "atom", "value": "action:get", "literal_type": "string"},
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "atom",
                        "value": "resource:secret",
                        "literal_type": "string",
                    },
                    {"kind": "atom", "value": "ResourceType", "literal_type": "string"},
                ],
            },
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().validate(payload)

    assert result.valid
    assert any(fact.predicate.name == "targets" for fact in result.graph.facts)


def test_salvage_keeps_valid_facts_and_drops_bad_rules() -> None:
    validator = FormalModelOutputValidator()
    action = {"kind": "atom", "value": "action:get", "literal_type": "string"}
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    action,
                    {"kind": "atom", "value": "Action", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "is",
                "args": [
                    {
                        "kind": "struct",
                        "name": "input_field",
                        "args": [
                            action,
                            {"kind": "atom", "value": "id", "literal_type": "string"},
                        ],
                    },
                    {"kind": "atom", "value": "Field", "literal_type": "string"},
                ],
            },
            {
                "context": "proposal",
                "predicate": "has",
                "args": [
                    {
                        "kind": "struct",
                        "name": "input_field",
                        "args": [
                            action,
                            {"kind": "atom", "value": "id", "literal_type": "string"},
                        ],
                    },
                    {"kind": "atom", "value": "object_ref", "literal_type": "string"},
                ],
            },
        ],
        # This rule constructs a new structural term in the head — the exact
        # failure that used to discard the whole 45-fact proposal.
        "rules": [
            {
                "body": [
                    {
                        "context": "proposal",
                        "predicate": "is",
                        "args": [
                            {"kind": "variable", "name": "A"},
                            {"kind": "variable", "name": "T"},
                        ],
                    }
                ],
                "head": [
                    {
                        "context": "proposal",
                        "predicate": "causes",
                        "args": [
                            {"kind": "variable", "name": "A"},
                            {
                                "kind": "struct",
                                "name": "reached",
                                "args": [
                                    {"kind": "variable", "name": "A"},
                                    {
                                        "kind": "atom",
                                        "value": "sink:x",
                                        "literal_type": "string",
                                    },
                                ],
                            },
                        ],
                    }
                ],
            }
        ],
    }

    full = validator.validate(payload)
    assert not full.valid

    salvaged = validator.salvage(payload)

    assert salvaged.graph is not None
    assert len(salvaged.graph.facts) == 3
    assert salvaged.graph.rules == ()
    assert any(issue.path.startswith("rules[0]") for issue in salvaged.issues)


def test_salvage_returns_none_without_valid_facts() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            {
                "context": "accepted",
                "predicate": "is",
                "args": [
                    {"kind": "atom", "value": "x", "literal_type": "string"},
                    {"kind": "atom", "value": "X", "literal_type": "string"},
                ],
            }
        ],
        "rules": [],
    }

    salvaged = FormalModelOutputValidator().salvage(payload)

    assert salvaged.graph is None
    assert salvaged.issues[0].code == "salvage"
