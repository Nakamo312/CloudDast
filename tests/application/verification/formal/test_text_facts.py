"""Tests for salvaging textual QDL facts emitted by models."""

from __future__ import annotations

from cloud_dast.contracts.proposals import (
    FormalModelOutputValidator,
)
from cloud_dast.infrastructure.runtime.model import _parse_json


def test_parse_content_strips_markdown_fence() -> None:
    payload = _parse_json('```json\n{"facts": [], "rules": []}\n```')

    assert payload == {"facts": [], "rules": []}


def test_parse_content_returns_empty_payload_for_prose() -> None:
    payload = _parse_json("the model refused to answer")

    assert payload is None


def test_salvage_accepts_textual_facts() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:nsfy.GetDocument, Action)",
            "is(input_field(action:nsfy.GetDocument, name), InputField)",
            "has(input_field(action:nsfy.GetDocument, name), object_ref)",
            "not a fact",
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    assert len(result.graph.facts) == 3
    predicates = {fact.predicate.name for fact in result.graph.facts}
    assert predicates == {"is", "has"}


def test_salvage_unquotes_textual_atoms() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            'is("action:nsfy.List", "Action")',
            'has("action:nsfy.List", "unbounded")',
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    is_fact = next(fact for fact in result.graph.facts if fact.predicate.name == "is")
    has_fact = next(fact for fact in result.graph.facts if fact.predicate.name == "has")
    assert has_fact.args[0] == is_fact.args[0]
    assert has_fact.args[1].value == "unbounded"


def test_salvage_parses_structured_arguments() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:nsfy.List, Action)",
            "is(norm:quota, Norm)",
            "prevents(norm:quota, duration(action:nsfy.List, 100))",
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    prevents = next(
        fact for fact in result.graph.facts if fact.predicate.name == "prevents"
    )
    effect = prevents.args[1]
    assert effect.name == "duration"
    assert effect.args[1].value == 100


def test_salvage_accepts_schema_shaped_predicate() -> None:
    """Models copy the JSON Schema of ``predicate`` into the value."""

    payload = {
        "facts": [
            {
                "predicate": {
                    "name": "is",
                    "arguments": [{"name": "entity"}, {"name": "type"}],
                },
                "args": [
                    {
                        "kind": "atom",
                        "value": "action:nsfy.List",
                        "literal_type": "string",
                    },
                    {
                        "kind": "atom",
                        "value": "Action",
                        "literal_type": "string",
                    },
                ],
            },
            {
                "predicate": "has",
                "args": [
                    {
                        "kind": "atom",
                        "value": "action:nsfy.List",
                        "literal_type": "string",
                    },
                    {
                        "kind": "atom",
                        "value": "unbounded",
                        "literal_type": "string",
                    },
                ],
            },
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    assert len(result.graph.facts) == 2
    assert all(fact.context.value == "proposal" for fact in result.graph.facts)
    assert {fact.predicate.name for fact in result.graph.facts} == {"is", "has"}


def test_salvage_recovers_args_embedded_in_predicate() -> None:
    """Providers can put ``args`` inside the predicate string by mistake."""

    action = "action:nsfy.Search"
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:nsfy.Search, Action)",
            {
                "context": "proposal",
                "predicate": (
                    "is,'args':[{'kind':'struct','name':'input_field',"
                    f"'args':[{{'kind':'atom','value':'{action}',"
                    "'literal_type':'string'},{'kind':'atom','value':'query',"
                    "'literal_type':'string'}]},{'kind':'atom','value':'Field',"
                    "'literal_type':'string'}]"
                ),
                "args": [],
            },
            {
                "context": "proposal",
                "predicate": (
                    "has,'args':[{'kind':'struct','name':'input_field',"
                    f"'args':[{{'kind':'atom','value':'{action}',"
                    "'literal_type':'string'},{'kind':'atom','value':'query',"
                    "'literal_type':'string'}]},{'kind':'atom',"
                    "'value':'attacker_controlled','literal_type':'string'}]"
                ),
                "args": [],
            },
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    facts = result.graph.facts
    assert {fact.predicate.name for fact in facts} == {"is", "has"}
    role = next(fact for fact in facts if fact.predicate.name == "has")
    assert role.args[1].value == "attacker_controlled"


def test_salvage_recovers_textual_predicate_with_empty_args() -> None:
    payload = {
        "context": "proposal",
        "facts": [
            "is(action:nsfy.List, Action)",
            "is(input_field(action:nsfy.List, query), Field)",
            {
                "context": "proposal",
                "predicate": "has(input_field(action:nsfy.List, query), "
                "attacker_controlled)",
                "args": [],
            },
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    assert any(
        fact.predicate.name == "has" and fact.args[1].value == "attacker_controlled"
        for fact in result.graph.facts
    )


def test_salvage_accepts_norms_array_with_flat_args() -> None:
    """The norms axis emits its own array and flat string arguments."""

    payload = {
        "norms": [
            {
                "id": "norm_deny_get_invoice",
                "prevents": "denied(action:nsfy.GetInvoice)",
            },
            {
                "id": "norm_quota",
                "prevents": "duration(action:nsfy.List, 100)",
            },
        ],
        "facts": [
            {"predicate": "is", "args": ["action:nsfy.GetInvoice", "Action"]},
            {"predicate": "is", "args": ["action:nsfy.List", "Action"]},
            {"predicate": "has", "args": ["action:nsfy.List", "unbounded"]},
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload)

    assert result.graph is not None
    predicates = {fact.predicate.name for fact in result.graph.facts}
    assert predicates == {"is", "has", "prevents"}
    quota = next(
        fact
        for fact in result.graph.facts
        if fact.predicate.name == "prevents" and fact.args[0].value == "norm_quota"
    )
    assert quota.args[1].name == "duration"
    assert quota.args[1].args[1].value == 100


def test_salvage_resolves_references_against_background() -> None:
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph

    background = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:nsfy.List"), Atom(value="Action")),
            ),
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            {"predicate": "has", "args": ["action:nsfy.List", "unbounded"]},
        ],
        "rules": [],
    }

    isolated = FormalModelOutputValidator().salvage(payload)
    resolved = FormalModelOutputValidator().salvage(payload, background=background)

    assert isolated.graph is None
    assert resolved.graph is not None
    assert any(fact.predicate.name == "has" for fact in resolved.graph.facts)


def test_salvage_deduplicates_background_declarations_across_contexts() -> None:
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph

    action = Atom(value="action:nsfy.List")

    def declaration(context: Context) -> Fact:
        return Fact(
            context=context,
            predicate=Predicate.from_name("is"),
            args=(action, Atom(value="Action")),
        )

    background = QdlGraph(
        facts=(
            declaration(Context.CONTRACT),
            declaration(Context.RUNTIME),
        )
    )
    payload = {
        "context": "proposal",
        "facts": [
            {"predicate": "has", "args": ["action:nsfy.List", "unbounded"]},
        ],
        "rules": [],
    }

    result = FormalModelOutputValidator().salvage(payload, background=background)

    assert result.graph is not None
    assert (
        sum(
            1
            for fact in result.graph.facts
            if fact.predicate.name == "is" and fact.args[0] == action
        )
        == 1
    )
