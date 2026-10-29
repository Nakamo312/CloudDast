"""Payload-hint compilation from grounded semantics."""

from __future__ import annotations

import pytest

from cloud_dast.qdl.field_roles import OBJECT_REF_ROLE, resolve_field_roles
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    external_call,
    input_field,
)
from cloud_dast.qdl.reasoning import compile_probe_fields, read_input_field
from cloud_dast.runtime.payload_hints import compile_payload_hints, sink_types_by_action
from cloud_dast.runtime.reference_projection import fields_with_role_by_action


def _fact(predicate: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _declared_field(field) -> Fact:
    return _fact("is", (field, Atom(value="Field")))


def _build_graph(*facts: Fact) -> QdlGraph:
    return QdlGraph(facts=facts)


def test_reaches_interpreter_sink_compiles_probe_hint() -> None:
    action = Atom(value="action:search")
    field = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql_engine")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(field),
        _fact("is", (sink, Atom(value="interpreter"))),
        _fact("reaches", (field, sink)),
    )

    hints = compile_payload_hints(graph)

    assert hints == {"action:search": ("query",)}


@pytest.mark.parametrize("context", tuple(Context))
def test_sink_types_require_executable_facts_and_selected_fields(
    context: Context,
) -> None:
    action = Atom(value="action:search")
    field = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql_engine")
    facts = (
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(field),
        _fact("is", (sink, Atom(value="interpreter"))),
        _fact("reaches", (field, sink)),
    )
    graph = QdlGraph(
        facts=tuple(
            Fact(context=context, predicate=fact.predicate, args=fact.args)
            for fact in facts
        )
    )
    expected = (
        {"action:search": (("query", "interpreter"),)}
        if context in {Context.CONTRACT, Context.ACCEPTED}
        else {}
    )

    assert sink_types_by_action(graph, {"action:search": ("query",)}) == expected
    assert sink_types_by_action(graph, {"action:search": ("other",)}) == {}


def test_reaches_external_net_sink_compiles_probe_hint() -> None:
    action = Atom(value="action:webhook")
    field = input_field(action, Atom(value="url"))
    net = Atom(value="collaborator:oob")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(field),
        _fact("is", (net, Atom(value="external_net"))),
        _fact("reaches", (field, net)),
    )

    hints = compile_payload_hints(graph)

    assert hints == {"action:webhook": ("url",)}


def test_direct_external_call_cause_does_not_compile_probe_hint() -> None:
    action = Atom(value="action:webhook")
    marker = Atom(value="collaborator:oob")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (marker, Atom(value="external_net"))),
        _fact("causes", (action, external_call(action, marker))),
    )

    assert compile_payload_hints(graph) == {}


def test_privileged_role_compiles_probe_hint() -> None:
    action = Atom(value="action:update")
    field = input_field(action, Atom(value="total"))
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(field),
        _fact("has", (field, Atom(value="privileged"))),
    )

    hints = compile_payload_hints(graph)

    assert hints == {"action:update": ("total",)}


def test_untyped_sink_and_other_roles_do_not_compile() -> None:
    action = Atom(value="action:get")
    field = input_field(action, Atom(value="order_id"))
    sink = Atom(value="sink:unknown")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(field),
        _fact("is", (sink, Atom(value="Database"))),
        _fact("reaches", (field, sink)),
        _fact("has", (field, Atom(value="object_ref"))),
    )

    assert compile_payload_hints(graph) == {}


def test_probe_compiler_merges_semantic_hints_with_explicit_roles() -> None:

    action = Atom(value="action:svc.search")
    query = input_field(action, Atom(value="query"))
    callback = input_field(action, Atom(value="callback"))
    sink = Atom(value="sink:sql")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(query),
        _declared_field(callback),
        _fact("has", (callback, Atom(value="oob_target"))),
        _fact("is", (sink, Atom(value="interpreter"))),
        _fact("reaches", (query, sink)),
    )

    probe_fields = compile_probe_fields(graph)

    assert probe_fields == {"action:svc.search": ("callback", "query")}
    assert compile_payload_hints(graph) == {"action:svc.search": ("query",)}


def test_binder_collects_executable_object_refs() -> None:
    action = Atom(value="action:svc.get")
    target = input_field(action, Atom(value="opaque_target"))
    proposal = input_field(action, Atom(value="proposal_only"))
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _declared_field(target),
        _declared_field(proposal),
        _fact("has", (target, Atom(value="object_ref"))),
        Fact(
            context=Context.PROPOSAL,
            predicate=Predicate.from_name("has"),
            args=(proposal, Atom(value="object_ref")),
        ),
    )

    # The field-role policy normalizes both action spellings, so every lookup
    # site can resolve the action with or without the ``action:`` namespace.
    assert fields_with_role_by_action(resolve_field_roles(graph), OBJECT_REF_ROLE) == {
        "action:svc.get": ("opaque_target",),
        "svc.get": ("opaque_target",),
    }


@pytest.mark.parametrize(
    "args",
    [
        (Atom(value=42), Atom(value="field")),
        (Atom(value="action:read"), Atom(value=42)),
    ],
)
def test_non_text_input_references_have_no_partial_binding(args) -> None:
    term = Struct.model_construct(name="input_field", args=args)
    assert read_input_field(term) == (None, None)
