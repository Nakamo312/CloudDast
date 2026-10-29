from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Variable,
    input_field,
    output_field,
)
from cloud_dast.qdl.reasoning import compile_probe_fields


def _fact(name, *args, context=Context.ACCEPTED):
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


def _build_graph(*facts):
    return QdlGraph(
        facts=(
            _fact(
                "is",
                Atom(value="action:send"),
                Atom(value="Action"),
                context=Context.CONTRACT,
            ),
            *facts,
        )
    )


@pytest.mark.parametrize("role", ["probe_target", "oob_target", "privileged"])
def test_declared_input_roles_are_carriers(role):
    field = input_field(Atom(value="action:send"), Atom(value="opaque"))
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField"), context=Context.CONTRACT),
        _fact("has", field, Atom(value=role)),
    )
    assert compile_probe_fields(graph) == {"action:send": ("opaque",)}


@pytest.mark.parametrize(
    "sink_type",
    [
        "interpreter",
        "external_net",
        "filesystem",
        "sql",
        "command",
        "command_shell",
    ],
)
def test_supported_transitive_reach_is_a_carrier(sink_type):
    field = input_field(Atom(value="action:send"), Atom(value="opaque"))
    middle, sink = Atom(value="middle"), Atom(value="sink")
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField"), context=Context.CONTRACT),
        _fact("is", middle, Atom(value="Resource")),
        _fact("is", sink, Atom(value=sink_type)),
        _fact("reaches", field, middle),
        _fact("reaches", middle, sink),
    )
    assert compile_probe_fields(graph) == {"action:send": ("opaque",)}


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME])
def test_non_executable_roles_and_reach_cannot_prove_a_carrier(context):
    field = input_field(Atom(value="action:send"), Atom(value="opaque"))
    sink = Atom(value="sink")
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField"), context=Context.CONTRACT),
        _fact("is", sink, Atom(value="sql"), context=Context.CONTRACT),
        _fact("has", field, Atom(value="probe_target"), context=context),
        _fact("reaches", field, sink, context=context),
    )
    assert compile_probe_fields(graph) == {}


def test_nonexistent_and_non_input_fields_are_excluded():
    action = Atom(value="action:send")
    missing = input_field(action, Atom(value="missing"))
    wrong_type = input_field(action, Atom(value="wrong"))
    output = output_field(action, Atom(value="result"))
    with pytest.raises(ValueError, match="unknown reference"):
        _build_graph(_fact("has", missing, Atom(value="probe_target")))
    graph = _build_graph(
        _fact("is", wrong_type, Atom(value="Resource")),
        _fact("is", output, Atom(value="OutputField")),
        _fact("has", wrong_type, Atom(value="probe_target")),
        _fact("has", output, Atom(value="probe_target")),
    )
    assert compile_probe_fields(graph) == {}


def test_aliases_merge_to_declared_action_and_fields_are_sorted():
    raw, action = Atom(value="send"), Atom(value="action:send")
    raw_field = input_field(raw, Atom(value="opaque"))
    field = input_field(action, Atom(value="opaque"))
    graph = _build_graph(
        _fact("is", raw, Atom(value="Action"), context=Context.CONTRACT),
        _fact("is", raw_field, Atom(value="InputField"), context=Context.CONTRACT),
        _fact("is", field, Atom(value="InputField"), context=Context.CONTRACT),
        _fact("has", raw_field, Atom(value="probe_target")),
        _fact("has", field, Atom(value="oob_target")),
    )
    assert compile_probe_fields(graph) == {"action:send": ("opaque",)}


def test_superseded_role_is_not_a_current_carrier():
    field = input_field(Atom(value="action:send"), Atom(value="opaque"))
    old, new = Atom(value="probe_target"), Atom(value="object_ref")
    old_replacement = Struct(name="replacement", args=(field, old))
    new_replacement = Struct(name="replacement", args=(field, new))
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField")),
        _fact("is", old, Atom(value="Role")),
        _fact("is", new, Atom(value="Role")),
        _fact("is", old_replacement, Atom(value="Replacement")),
        _fact("is", new_replacement, Atom(value="Replacement")),
        _fact("has", field, old),
        _fact("has", field, new),
        _fact("supersedes", new_replacement, old_replacement),
    )
    assert compile_probe_fields(graph) == {}


def test_field_names_and_unsupported_sinks_are_not_evidence():
    field = input_field(Atom(value="action:send"), Atom(value="url"))
    sink = Atom(value="sink")
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField")),
        _fact("is", sink, Atom(value="Database")),
        _fact("reaches", field, sink),
    )
    assert compile_probe_fields(graph) == {}


def test_executable_rules_can_derive_carrier_semantics():
    action = Atom(value="action:send")
    field = input_field(action, Atom(value="opaque"))
    sink = Atom(value="sink")
    graph = _build_graph(
        _fact("is", field, Atom(value="InputField")),
        _fact("is", sink, Atom(value="sql")),
    )
    source = Variable(name="Source")
    graph = QdlGraph(
        facts=graph.facts,
        rules=(
            Rule(
                body=(_fact("is", source, Atom(value="InputField")),),
                head=(_fact("reaches", source, sink),),
            ),
        ),
    )
    assert compile_probe_fields(graph) == {"action:send": ("opaque",)}


def test_carrier_requires_an_action_declaration():
    action = Atom(value="send")
    field = input_field(action, Atom(value="opaque"))
    graph = QdlGraph(
        facts=(
            _fact("is", action, Atom(value="Resource")),
            _fact("is", field, Atom(value="InputField")),
            _fact("has", field, Atom(value="probe_target")),
        )
    )
    assert compile_probe_fields(graph) == {}
