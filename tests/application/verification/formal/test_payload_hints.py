from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Variable,
    input_field,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    FormalCompilationError,
)
from cloud_dast.runtime.payload_hints import (
    compile_payload_hints,
)


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def test_payload_hints_keep_executable_rules() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (query, Atom(value="Field")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT),
        ),
        rules=(
            Rule(
                body=(
                    _fact(
                        "is",
                        (Variable(name="Source"), Atom(value="Field")),
                        Context.CONTRACT,
                    ),
                    _fact(
                        "is",
                        (Variable(name="Sink"), Atom(value="interpreter")),
                        Context.CONTRACT,
                    ),
                ),
                head=(
                    _fact(
                        "reaches",
                        (Variable(name="Source"), Variable(name="Sink")),
                        Context.CONTRACT,
                    ),
                ),
            ),
        ),
    )

    hints = compile_payload_hints(graph)

    assert hints == {"action:search": ("query",)}


def test_invalid_filtered_graph_is_not_an_empty_payload_result() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (sink, Atom(value="interpreter")), Context.CONTRACT),
            _fact("is", (query, Atom(value="Field")), Context.PROPOSAL),
        ),
        rules=(
            Rule(
                body=(_fact("is", (query, Atom(value="Field")), Context.CONTRACT),),
                head=(_fact("reaches", (query, sink), Context.CONTRACT),),
            ),
        ),
    )

    with pytest.raises(FormalCompilationError, match="invalid QDL graph"):
        compile_payload_hints(graph)


def test_payload_hints_ignore_proposal_and_runtime_semantics() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (query, Atom(value="Field"))),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("reaches", (query, sink), Context.PROPOSAL),
            _fact("has", (query, Atom(value="privileged")), Context.RUNTIME),
        )
    )

    hints = compile_payload_hints(graph)

    assert hints == {}


def test_payload_hints_use_transitive_reachability() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    middle = Atom(value="sink:join")
    sink = Atom(value="sink:sql")
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            _fact("is", (query, Atom(value="Field"))),
            _fact("is", (middle, Atom(value="Resource"))),
            _fact("is", (sink, Atom(value="interpreter"))),
            _fact("reaches", (query, middle)),
            _fact("reaches", (middle, sink)),
        )
    )

    hints = compile_payload_hints(graph)

    assert hints == {"action:search": ("query",)}
