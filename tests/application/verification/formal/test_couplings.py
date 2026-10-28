from __future__ import annotations

import pytest

from cloud_dast.couplings import (
    COUPLED_OPERATORS,
    FieldCoupling,
    all_couplings,
    couplings_by_action,
    couplings_from_graph,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
    output_field,
)


def _build_graph(*facts: Fact) -> QdlGraph:
    return QdlGraph(facts=facts)


def _declaration(term, type_name: str = "Field") -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("is"),
        args=(term, Atom(value=type_name)),
    )


ADD = Atom(value="action:add")
REMOVE = Atom(value="action:remove")
ADD_NAME = input_field(ADD, Atom(value="cName"))
REMOVE_NAME = input_field(REMOVE, Atom(value="cName"))


def _coupled(left, right, operator: str) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("coupled"),
        args=(left, right, Atom(value=operator)),
    )


def test_operators_form_a_closed_alphabet() -> None:
    assert COUPLED_OPERATORS == {"eq", "ne", "lt", "le", "gt", "ge"}


def _declared_graph(*facts: Fact) -> QdlGraph:
    """Declare every action atom and field term referenced by the facts."""

    declarations = [
        _declaration(ADD, "Action"),
        _declaration(REMOVE, "Action"),
        _declaration(ADD_NAME),
        _declaration(REMOVE_NAME),
    ]
    return QdlGraph(facts=tuple(declarations) + facts)


def test_extracts_cross_action_couplings() -> None:
    graph = _declared_graph(_coupled(ADD_NAME, REMOVE_NAME, "eq"))

    assert couplings_from_graph(graph) == (
        FieldCoupling(
            left=ADD_NAME,
            right=REMOVE_NAME,
            operator="eq",
        ),
    )


def test_groups_same_action_couplings_for_plans() -> None:
    left = input_field(ADD, Atom(value="from"))
    right = input_field(ADD, Atom(value="to"))
    graph = _declared_graph(
        _declaration(left),
        _declaration(right),
        _coupled(left, right, "lt"),
    )

    by_action = couplings_by_action(graph)

    assert by_action == {"action:add": ((left, right, "lt"),)}


def test_all_couplings_keeps_cross_action_identity() -> None:
    graph = _declared_graph(_coupled(ADD_NAME, REMOVE_NAME, "eq"))

    grouped = all_couplings(graph)

    coupling = (
        ADD_NAME,
        REMOVE_NAME,
        "eq",
    )
    assert grouped == {
        "action:add": (coupling,),
        "action:remove": (coupling,),
    }


def test_skips_bare_atom_sides() -> None:
    graph = _declared_graph(
        _declaration(Atom(value="cName")),
        _coupled(ADD_NAME, Atom(value="cName"), "eq"),
    )

    assert couplings_from_graph(graph) == ()


def test_unknown_operator_is_rejected() -> None:
    graph = _declared_graph(_coupled(ADD_NAME, REMOVE_NAME, "equals"))

    with pytest.raises(ValueError, match="unknown coupled operator"):
        couplings_from_graph(graph)


def test_output_direction_survives_graph_plan_roundtrip():
    from cloud_dast.qdl.couplings import couplings_for_method, couplings_from_plan

    output = output_field(ADD, Atom(value="id"))
    target = input_field(REMOVE, Atom(value="widget_id"))
    graph = _declared_graph(
        _declaration(output), _declaration(target), _coupled(output, target, "eq")
    )
    grouped = all_couplings(graph)
    coupling = couplings_from_plan(grouped["action:remove"])[0]
    assert coupling.left == output and coupling.right == target
    assert couplings_for_method(grouped["action:remove"], "remove") == ()


def test_proposal_coupling_is_not_executable():
    proposal = _coupled(ADD_NAME, REMOVE_NAME, "eq").model_copy(
        update={"context": Context.PROPOSAL}
    )
    assert couplings_from_graph(_declared_graph(proposal)) == ()


@pytest.mark.parametrize("operator", sorted(COUPLED_OPERATORS))
@pytest.mark.parametrize("reverse", [False, True])
def test_reuse_selects_only_equal_downstream_outputs(operator, reverse):
    from cloud_dast.couplings import select_outputs

    witness = output_field(ADD, Atom(value="id"))
    left, right = (REMOVE_NAME, witness) if reverse else (witness, REMOVE_NAME)
    constraints = ((left, right, operator),)
    selected = select_outputs(constraints, "add", {"remove"})
    assert selected == ({witness} if operator == "eq" else None)
    assert select_outputs(constraints, "add", {"other"}) == set()
    assert select_outputs(constraints, "other", {"remove"}) == set()


def test_reuse_rejects_current_input_as_an_output_witness():
    from cloud_dast.couplings import select_outputs

    assert select_outputs(((ADD_NAME, REMOVE_NAME, "eq"),), "add", {"remove"}) is None
