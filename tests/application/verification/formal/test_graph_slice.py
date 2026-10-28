from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.graph_slice import slice_graph_by_actions


def _fact(predicate: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _build_graph() -> QdlGraph:
    facts = []
    for index in range(3):
        action = Atom(value=f"action:get-{index}")
        permission = Atom(value=f"permission:get-{index}")
        facts.extend(
            (
                _fact("is", (action, Atom(value="Action"))),
                _fact("is", (permission, Atom(value="Permission"))),
                _fact("requires", (action, permission)),
            )
        )
    return QdlGraph(facts=tuple(facts))


def test_slice_graph_by_actions_limits_and_keeps_declarations() -> None:
    graph = _build_graph()

    result = slice_graph_by_actions(graph, max_actions=2)

    actions = {
        atom_value(fact.args[0])
        for fact in result.facts
        if fact.predicate.name == "is" and atom_value(fact.args[1]) == "Action"
    }
    permissions = {
        atom_value(fact.args[0])
        for fact in result.facts
        if fact.predicate.name == "is" and atom_value(fact.args[1]) == "Permission"
    }
    assert actions == {"action:get-0", "action:get-1"}
    assert permissions == {"permission:get-0", "permission:get-1"}
    assert (
        len([fact for fact in result.facts if fact.predicate.name == "requires"]) == 2
    )


def test_slice_graph_rejects_invalid_limit() -> None:
    with pytest.raises(ValueError, match="max_actions"):
        slice_graph_by_actions(_build_graph(), max_actions=0)
