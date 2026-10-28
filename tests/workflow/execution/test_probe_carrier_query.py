from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
    input_field,
)
from cloud_dast.runtime.planning import QdlSubgoal, derivable


def _build_graph(context):
    action = Atom(value="action:send")
    field = input_field(action, Atom(value="opaque"))
    return QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(field, Atom(value="InputField")),
            ),
            Fact(
                context=context,
                predicate=Predicate.from_name("has"),
                args=(field, Atom(value="probe_target")),
            ),
        )
    )


@pytest.mark.parametrize("action", ["send", "action:send"])
@pytest.mark.parametrize("field", [Atom(value="opaque"), Variable(name="Field")])
def test_exact_and_existential_carrier_queries(action, field):
    assert derivable(
        QdlSubgoal("probe_carrier", (Atom(value=action), field)),
        _build_graph(Context.ACCEPTED),
    )


def test_existential_action_and_exact_misses():
    graph = _build_graph(Context.ACCEPTED)
    assert derivable(
        QdlSubgoal("probe_carrier", (Variable(name="Action"), Variable(name="Field"))),
        graph,
    )
    for action, field in [("send", "missing"), ("other", "opaque")]:
        assert not derivable(
            QdlSubgoal("probe_carrier", (Atom(value=action), Atom(value=field))), graph
        )
    assert not derivable(QdlSubgoal("probe_carrier", ()), graph)


@pytest.mark.parametrize("context", [Context.PROPOSAL, Context.RUNTIME])
def test_non_executable_provenance_never_proves_carriers(context):
    graph = _build_graph(context)
    query = QdlSubgoal("probe_carrier", (Atom(value="send"), Variable(name="Field")))
    assert not derivable(query, graph)
    assert not derivable(query, graph, contexts=(Context.CONTRACT, context))


def test_selected_contexts_restrict_carrier_projection():
    graph = _build_graph(Context.ACCEPTED)
    query = QdlSubgoal("probe_carrier", (Atom(value="send"), Variable(name="Field")))
    assert not derivable(query, graph, contexts=(Context.CONTRACT,))
    assert derivable(query, graph, contexts=(Context.CONTRACT, Context.ACCEPTED))


def test_probe_carrier_is_not_a_model_writable_predicate():
    with pytest.raises(ValueError):
        Predicate.from_name("probe_carrier")
