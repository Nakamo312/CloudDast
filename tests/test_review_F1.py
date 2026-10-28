"""Review F3/F4: context isolation and the limits of letter classification."""

from pathlib import Path

import clingo
import pytest

import cloud_dast
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Term,
    Variable,
    create,
    input_field,
    trace,
)


def fact(name: str, *args: Term, context: Context = Context.CONTRACT) -> Fact:
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


def test_import_is_from_worker_copy() -> None:
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )


@pytest.mark.parametrize("rule_context", list(Context))
@pytest.mark.parametrize("fact_context", list(Context))
@pytest.mark.parametrize("algebra", [False, True])
def test_rule_context_is_concrete(rule_context, fact_context, algebra) -> None:
    action, resource, seed = (
        Atom(value="action:a"),
        Atom(value="resource:r"),
        Atom(value="seed"),
    )
    variable = Variable(name="Action")
    rule = Rule(
        body=(fact("has", variable, seed, context=rule_context),),
        head=(fact("targets", variable, resource, context=rule_context),),
    )
    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", resource, Atom(value="Resource")),
            fact("has", action, seed, context=fact_context),
        ),
        rules=(rule,),
    )
    engine = ClingoEngine()
    if algebra:
        solution = engine.solve(graph, algebra=True)[0]
    else:
        # The same compiler is used by incremental planner grounding.
        program = engine.compile_statements(graph.facts, graph.rules)
        control = clingo.Control(["--warn=none"])
        control.add("base", [], program)
        control.ground([("base", [])])
        atoms = []
        control.solve(on_model=lambda m: atoms.extend(map(str, m.symbols(atoms=True))))
        solution = engine.solve(graph)[0]
        assert set(solution.atoms) == set(atoms)
    expected = rule_context == fact_context and (
        not algebra or rule_context in {Context.CONTRACT, Context.ACCEPTED}
    )
    targets = [a for a in solution.atoms if a.startswith("targets(")]
    assert targets == (
        [f'targets("{rule_context.value}","action:a","resource:r")'] if expected else []
    )


@pytest.mark.parametrize("query_context", list(Context))
@pytest.mark.parametrize("edge_context", list(Context))
@pytest.mark.parametrize(
    "relation",
    [
        "part",
        "part_plus",
        "requires",
        "requires_plus",
        "reaches",
        "chain",
        "chain_plus",
        "reachable",
    ],
)
def test_path_edges_join_requested_context(
    query_context, edge_context, relation
) -> None:
    first, middle, last = (Atom(value=name) for name in ("a", "b", "c"))
    effect = create(middle)
    declarations = tuple(
        fact("is", term, Atom(value="Node"), context=query_context)
        for term in (first, middle, last, effect)
    )
    if relation.startswith("chain"):
        edges = (
            fact("causes", first, effect, context=edge_context),
            fact("requires", last, effect, context=edge_context),
        )
        path = ("a", "c")
    else:
        base = (
            "part"
            if relation in {"part", "part_plus", "reachable"}
            else ("requires" if relation.startswith("requires") else "reaches")
        )
        edges = (
            fact(base, first, middle, context=edge_context),
            fact(base, middle, last, context=edge_context),
        )
        path = ("a", "b", "c")
    graph = QdlGraph(facts=(*declarations, *edges))
    assert ClingoEngine().find_path(
        graph, relation, "a", "c", context=query_context
    ) == (path if query_context == edge_context else None)


@pytest.mark.parametrize("permitted", [True, False])
@pytest.mark.parametrize("privileged", [True, False])
def test_norm_violation_need_not_have_a_letter(permitted, privileged) -> None:
    subject, action, resource, auditor, norm = (
        Atom(value=name) for name in ("s", "a", "r", "audit", "n")
    )
    effect = create(resource)
    field = input_field(action, Atom(value="role"))
    facts = [
        fact("is", subject, Atom(value="Subject")),
        fact("is", action, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", auditor, Atom(value="auditor")),
        fact("is", norm, Atom(value="Norm")),
        fact("is", field, Atom(value="Field")),
        fact("is", trace(action), Atom(value="Witness")),
        fact("executes", subject, action),
        fact("targets", action, resource),
        fact("causes", action, effect),
        fact("observes", auditor, trace(action)),
        fact("prevents", norm, effect),
    ]
    if permitted:
        facts.append(fact("may", subject, action, resource))
    if privileged:
        facts.append(fact("has", field, Atom(value="privileged")))
    solution = ClingoEngine().solve(QdlGraph(facts=tuple(facts)), algebra=True)[0]
    symbols = {clingo.parse_term(a) for a in solution.atoms}
    assert clingo.parse_term('causes("contract","a",create("r"))') in symbols
    assert clingo.parse_term('prevents("contract","n",create("r"))') in symbols
    letters = {s.name for s in symbols} & {
        "spoofing",
        "tampering",
        "repudiation",
        "disclosure",
        "denial",
        "elevation",
    }
    assert letters == (set() if permitted else {"tampering", "elevation"})
    assert any(s.name == "owasp_api3_mass_assignment" for s in symbols) == (
        not permitted and privileged
    )


def test_declaration_is_not_a_semantic_sort_proof() -> None:
    resource, permission = Atom(value="r"), Atom(value="p")
    graph = QdlGraph(
        facts=(
            fact("is", resource, Atom(value="Resource")),
            fact("is", permission, Atom(value="Permission")),
            fact("executes", resource, permission),
        )
    )
    assert ClingoEngine().solve(graph)[0].contains('executes("contract","r","p")')


@pytest.mark.parametrize("query_context", list(Context))
@pytest.mark.parametrize("other_context", list(Context))
@pytest.mark.parametrize("relation", ["part", "chain", "reachable"])
def test_path_does_not_splice_contexts(query_context, other_context, relation) -> None:
    first, middle, last = (Atom(value=name) for name in ("a", "b", "c"))
    effect = create(middle)
    declarations = tuple(
        fact("is", term, Atom(value="Node"), context=query_context)
        for term in (first, middle, last, effect)
    )
    if relation == "chain":
        edges = (
            fact("causes", first, effect, context=query_context),
            fact("requires", last, effect, context=other_context),
        )
        path = ("a", "c")
    else:
        edges = (
            fact("part", first, middle, context=query_context),
            fact("part", middle, last, context=other_context),
        )
        path = ("a", "b", "c")
    graph = QdlGraph(facts=(*declarations, *edges))
    assert ClingoEngine().find_path(
        graph, relation, "a", "c", context=query_context
    ) == (path if query_context == other_context else None)
