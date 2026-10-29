from __future__ import annotations

from types import SimpleNamespace

import pytest

import cloud_dast.qdl.engine as clingo_engine_module
from cloud_dast.qdl.engine import (
    DEFAULT_POLICY_RULE_PACK,
    DEFAULT_THREAT_RULE_PACK,
    ClingoEngine,
    ClingoLimits,
    PolicyRulePack,
    ThreatRulePack,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Variable,
    changed,
    input_field,
    reached,
)


def fact(predicate: str, args: tuple[object, ...], context: Context) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def entity(identifier: str, type_name: str) -> Fact:
    return fact("is", (Atom(value=identifier), Atom(value=type_name)), Context.CONTRACT)


def make_graph() -> QdlGraph:
    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    principal = Atom(value="principal:attacker")

    return QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            fact("is", (permission, Atom(value="Permission")), Context.CONTRACT),
            fact("is", (principal, Atom(value="Principal")), Context.CONTRACT),
            fact("requires", (action, permission), Context.CONTRACT),
        ),
        rules=(
            Rule(
                body=(
                    fact(
                        "is",
                        (Variable(name="Action"), Variable(name="ActionType")),
                        Context.CONTRACT,
                    ),
                    fact(
                        "is",
                        (
                            Variable(name="Permission"),
                            Variable(name="PermissionType"),
                        ),
                        Context.CONTRACT,
                    ),
                    fact(
                        "is",
                        (
                            Variable(name="Principal"),
                            Variable(name="PrincipalType"),
                        ),
                        Context.CONTRACT,
                    ),
                    fact(
                        "requires",
                        (Variable(name="Action"), Variable(name="Permission")),
                        Context.CONTRACT,
                    ),
                ),
                head=(
                    fact(
                        "may",
                        (
                            Variable(name="Principal"),
                            Variable(name="Action"),
                            Variable(name="Permission"),
                        ),
                        Context.CONTRACT,
                    ),
                ),
            ),
        ),
    )


def make_closure_graph() -> QdlGraph:
    grandchild = Atom(value="resource:grandchild")
    child = Atom(value="resource:child")
    parent = Atom(value="resource:parent")
    create = Atom(value="action:create")
    use = Atom(value="action:use")
    escalate = Atom(value="action:escalate")
    read = Atom(value="permission:read")
    admin = Atom(value="permission:admin")
    attacker = Atom(value="principal:attacker")
    role_change = changed(child, Atom(value="role"))
    owner_change = changed(parent, Atom(value="owner"))
    state_change = changed(grandchild, Atom(value="state"))

    return QdlGraph(
        facts=(
            entity("resource:grandchild", "Resource"),
            entity("resource:child", "Resource"),
            entity("resource:parent", "Resource"),
            fact("part", (grandchild, child), Context.CONTRACT),
            fact("part", (child, parent), Context.CONTRACT),
            entity("action:create", "Action"),
            entity("action:use", "Action"),
            entity("action:escalate", "Action"),
            entity("permission:read", "Permission"),
            entity("permission:admin", "Permission"),
            entity("principal:attacker", "Principal"),
            fact("is", (role_change, Atom(value="Effect")), Context.CONTRACT),
            fact("is", (owner_change, Atom(value="Effect")), Context.CONTRACT),
            fact("requires", (create, read), Context.CONTRACT),
            fact("requires", (read, admin), Context.CONTRACT),
            fact("causes", (create, role_change), Context.CONTRACT),
            fact("requires", (use, role_change), Context.CONTRACT),
            fact("causes", (use, owner_change), Context.CONTRACT),
            fact("requires", (escalate, owner_change), Context.CONTRACT),
            fact("may", (attacker, create, parent), Context.CONTRACT),
            fact("causes", (escalate, state_change), Context.CONTRACT),
        )
    )


def make_cycle_graph() -> QdlGraph:
    first = Atom(value="resource:first")
    second = Atom(value="resource:second")

    return QdlGraph(
        facts=(
            entity("resource:first", "Resource"),
            entity("resource:second", "Resource"),
            fact("part", (first, second), Context.CONTRACT),
            fact("part", (second, first), Context.CONTRACT),
        )
    )


def test_compile_preserves_context_and_facts() -> None:
    program = ClingoEngine().compile(make_graph())

    assert 'is("contract","action:get","Action").' in program
    assert 'requires("contract","action:get","permission:read").' in program
    assert 'may("contract",Principal,Action,Permission) :-' in program


def test_solve_derives_rule_head() -> None:
    solution = ClingoEngine().solve(make_graph())[0]

    assert solution.contains(
        'may("contract","principal:attacker","action:get","permission:read")'
    )


def test_solve_program_is_the_query_boundary() -> None:
    solution = ClingoEngine().solve_program('answer("ok").')[0]

    assert solution.contains('answer("ok")')


def test_incremental_program_session_stays_inside_engine_boundary() -> None:
    session = ClingoEngine().program_session()
    session.add("base", 'answer("ok").')
    session.ground([("base", [])])

    assert session.solve()[0].contains('answer("ok")')


def test_solve_rejects_invalid_model_limit() -> None:
    with pytest.raises(ValueError, match="max_models must not be negative"):
        ClingoEngine().solve(make_graph(), max_models=-1)


def test_clingo_limits_reject_non_positive_values() -> None:
    with pytest.raises(ValueError, match="max_conflicts must be positive"):
        ClingoLimits(max_conflicts=0)
    with pytest.raises(ValueError, match="max_restarts must be positive"):
        ClingoLimits(max_restarts=0)


def test_solve_applies_clingo_search_limits(monkeypatch) -> None:
    controls = []
    original_control = clingo_engine_module.clingo.Control

    def control():
        instance = original_control()
        controls.append(instance)
        return instance

    monkeypatch.setattr(clingo_engine_module.clingo, "Control", control)
    solution = ClingoEngine(
        limits=ClingoLimits(max_conflicts=12, max_restarts=34)
    ).solve(make_graph())[0]

    assert solution.contains(
        'may("contract","principal:attacker","action:get","permission:read")'
    )
    assert controls[0].configuration.solve.solve_limit == "12,34"
    assert controls[0].configuration.solve.models == "1"


def test_solve_limit_is_not_reported_as_an_empty_model(monkeypatch) -> None:
    class UnknownResult:
        unknown = True

    class UnknownHandle:
        def __iter__(self):
            return iter(())

        def get(self):
            return UnknownResult()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            del exc_type, exc_value, traceback

    class UnknownControl:
        def __init__(self):
            self.configuration = SimpleNamespace(solve=SimpleNamespace())

        def add(self, name, arguments, program):
            del name, arguments, program

        def ground(self, parts):
            del parts

        def solve(self, *, yield_=False):
            assert yield_ is True
            return UnknownHandle()

    monkeypatch.setattr(clingo_engine_module.clingo, "Control", UnknownControl)

    with pytest.raises(RuntimeError, match="Clingo solve limit reached"):
        ClingoEngine(limits=ClingoLimits(max_conflicts=12, max_restarts=34)).solve(
            make_graph()
        )


def test_compile_adds_recursive_closure_rules() -> None:
    program = ClingoEngine().compile(make_closure_graph(), closures="part_plus")

    assert "part_plus(C,Child,Parent) :- part(C,Child,Parent)." in program
    assert (
        "part_plus(C,Child,Grandparent) :- "
        "part(C,Child,Parent), part_plus(C,Parent,Grandparent)."
    ) in program


def test_compile_resolves_closure_dependencies() -> None:
    program = ClingoEngine().compile(make_closure_graph(), closures="may_plus")

    assert "may_plus(C,Principal,Action) :-" in program
    assert "chain_plus(C,Action,Next) :-" in program

    program = ClingoEngine().compile(make_closure_graph(), closures="affected_plus")

    assert "affected_plus(C,Action,Resource) :-" in program
    assert "part_plus(C,Child,Parent) :-" in program


def test_compile_rejects_unknown_closure() -> None:
    with pytest.raises(ValueError, match="unknown closure predicate"):
        ClingoEngine().compile(make_closure_graph(), closures="path_plus")


def test_solve_materializes_all_closure_predicates() -> None:
    solution = ClingoEngine().solve(
        make_closure_graph(),
        closures={
            "part_plus",
            "requires_plus",
            "chain_plus",
            "may_plus",
            "affected_plus",
            "reachable",
        },
    )[0]

    assert solution.contains(
        'part_plus("contract","resource:grandchild","resource:parent")'
    )
    assert solution.contains(
        'part_plus("contract","resource:grandchild","resource:child")'
    )
    assert solution.contains(
        'requires_plus("contract","action:create","permission:admin")'
    )
    assert solution.contains(
        'requires_plus("contract","action:create","permission:read")'
    )
    assert solution.contains('chain_plus("contract","action:create","action:escalate")')
    assert solution.contains('chain_plus("contract","action:create","action:use")')
    assert solution.contains('may_plus("contract","principal:attacker","action:use")')
    assert solution.contains(
        'may_plus("contract","principal:attacker","action:escalate")'
    )
    assert solution.contains(
        'affected_plus("contract","action:escalate","resource:grandchild")'
    )
    assert solution.contains(
        'affected_plus("contract","action:escalate","resource:parent")'
    )
    assert solution.contains(
        'reachable("contract","resource:grandchild","resource:parent")'
    )
    assert solution.contains('reachable("contract","action:create","permission:admin")')


def test_closure_solve_is_deterministic_and_terminates_on_cycle() -> None:
    first = ClingoEngine().solve(make_cycle_graph(), closures="part_plus")[0]
    second = ClingoEngine().solve(make_cycle_graph(), closures="part_plus")[0]

    assert first == second
    assert first.contains('part_plus("contract","resource:first","resource:second")')
    assert first.contains('part_plus("contract","resource:second","resource:first")')


def test_find_path_returns_intermediate_nodes() -> None:
    engine = ClingoEngine()
    graph = make_closure_graph()

    assert engine.find_path(
        graph,
        "part",
        "resource:grandchild",
        "resource:parent",
    ) == ("resource:grandchild", "resource:child", "resource:parent")
    assert engine.find_path(
        graph,
        "part_plus",
        "resource:grandchild",
        "resource:parent",
    ) == ("resource:grandchild", "resource:child", "resource:parent")
    assert engine.find_path(
        graph,
        "chain",
        "action:create",
        "action:escalate",
    ) == ("action:create", "action:use", "action:escalate")
    assert engine.find_path(
        graph,
        "reachable",
        "action:create",
        "permission:admin",
    ) == ("action:create", "permission:read", "permission:admin")


def test_find_path_respects_depth_and_missing_target() -> None:
    engine = ClingoEngine()
    graph = make_closure_graph()

    assert (
        engine.find_path(
            graph,
            "part",
            "resource:grandchild",
            "resource:parent",
            max_depth=1,
        )
        is None
    )
    assert (
        engine.find_path(
            graph,
            "part",
            "resource:grandchild",
            "resource:missing",
        )
        is None
    )


def test_find_path_rejects_invalid_relation_and_depth() -> None:
    engine = ClingoEngine()

    with pytest.raises(ValueError, match="unsupported path relation"):
        engine.find_path(make_closure_graph(), "unknown", "a", "b")
    with pytest.raises(ValueError, match="max_depth must be positive"):
        engine.find_path(
            make_closure_graph(),
            "part",
            "resource:grandchild",
            "resource:parent",
            max_depth=0,
        )


def test_clingo_preserves_float_and_string_literal_types() -> None:
    float_value = Atom(value=1.5, literal_type="float")
    string_value = Atom(value="1.5", literal_type="string")
    graph = QdlGraph(
        facts=(
            fact("is", (float_value, Atom(value="Value")), Context.CONTRACT),
            fact("is", (string_value, Atom(value="Value")), Context.CONTRACT),
            fact("has", (float_value, Atom(value="kind")), Context.CONTRACT),
            fact("has", (string_value, Atom(value="kind")), Context.CONTRACT),
        )
    )

    program = ClingoEngine().compile(graph)
    solution = ClingoEngine().solve(graph)[0]

    assert 'qdl_float("1.5")' in program
    assert '"1.5"' in program
    assert any(
        atom.startswith('has("contract",qdl_float("1.5")') for atom in solution.atoms
    )
    assert any(atom.startswith('has("contract","1.5"') for atom in solution.atoms)


def test_clingo_rejects_nul_in_string_atom() -> None:
    value = Atom(value="a\0b", literal_type="string")
    graph = QdlGraph(
        facts=(fact("is", (value, Atom(value="Value")), Context.CONTRACT),)
    )

    with pytest.raises(ValueError, match="NUL"):
        ClingoEngine().compile(graph)


def test_clingo_max_models_zero_returns_available_models() -> None:
    solutions = ClingoEngine().solve(make_graph(), max_models=0)

    assert len(solutions) == 1


def test_algebra_filters_runtime_and_proposal_contexts() -> None:
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            fact(
                "is",
                (Atom(value="action:runtime"), Atom(value="Action")),
                Context.RUNTIME,
            ),
            fact(
                "is",
                (Atom(value="action:proposal"), Atom(value="Action")),
                Context.PROPOSAL,
            ),
        )
    )

    program = ClingoEngine().compile(graph, algebra=True)

    assert "context" not in program
    assert "runtime" not in program
    assert "proposal" not in program
    assert '"contract"' in program


def test_algebra_policy_rule_pack_is_replaceable() -> None:
    graph = QdlGraph(
        facts=(
            fact(
                "is",
                (Atom(value="action:approve"), Atom(value="Action")),
                Context.ACCEPTED,
            ),
            fact(
                "is",
                (Atom(value="resource:invoice-1"), Atom(value="Resource")),
                Context.ACCEPTED,
            ),
            fact(
                "is",
                (Atom(value="principal:alice"), Atom(value="Subject")),
                Context.ACCEPTED,
            ),
            fact("attacker", (Atom(value="principal:alice"),), Context.ACCEPTED),
        )
    )
    custom_rule = (
        "may(C,Subject,Action,Resource) :- attacker(C,Subject), "
        'is(_,Action,"Action"), is(_,Resource,"Resource").'
    )
    engine = ClingoEngine(
        policy_rule_pack=PolicyRulePack(name="test", rules=(custom_rule,))
    )

    program = engine.compile(graph, algebra=True)
    solution = engine.solve(graph, algebra=True)[0]

    assert custom_rule in program
    assert DEFAULT_POLICY_RULE_PACK.rules[0] not in program
    assert solution.contains(
        'may("accepted","principal:alice","action:approve","resource:invoice-1")'
    )


def test_reaches_plus_pairs_include_transitive_dataflow() -> None:
    action = Atom(value="action:get")
    field = input_field(action, Atom(value="name"))
    middle = Atom(value="resource:middle")
    sink = Atom(value="resource:sink")
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            fact("is", (field, Atom(value="Field")), Context.CONTRACT),
            entity("resource:middle", "Resource"),
            entity("resource:sink", "Resource"),
            fact("reaches", (field, middle), Context.CONTRACT),
            fact("reaches", (middle, sink), Context.CONTRACT),
        )
    )

    pairs = ClingoEngine().reaches_plus_pairs(graph)

    assert (field, sink) in pairs


def test_superseded_reached_is_excluded_from_current_reached() -> None:
    action = Atom(value="action:get")
    old_sink = Atom(value="sink:sql")
    new_sink = Atom(value="sink:template")
    old_effect = reached(action, old_sink)
    new_effect = reached(action, new_sink)
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            entity("sink:sql", "Sink"),
            entity("sink:template", "Sink"),
            fact("is", (old_effect, Atom(value="Effect")), Context.RUNTIME),
            fact("is", (new_effect, Atom(value="Effect")), Context.RUNTIME),
            fact("causes", (action, new_effect), Context.RUNTIME),
            fact("supersedes", (new_effect, old_effect), Context.RUNTIME),
        )
    )

    solution = ClingoEngine().solve(graph, closures={"current_reached"})[0]

    assert solution.contains('reached("runtime","action:get","sink:sql")')
    assert solution.contains('current_reached("runtime","action:get","sink:template")')
    assert not solution.contains('current_reached("runtime","action:get","sink:sql")')


def test_superseded_has_is_excluded_from_current_has() -> None:
    action = Atom(value="action:get")
    holder = input_field(action, Atom(value="token"))
    old_value = Atom(value="sensitive")
    new_value = Atom(value="credential")
    old_node = Struct(name="replacement", args=(holder, old_value))
    new_node = Struct(name="replacement", args=(holder, new_value))
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            fact("is", (holder, Atom(value="Field")), Context.ACCEPTED),
            fact("is", (old_value, Atom(value="Role")), Context.ACCEPTED),
            fact("is", (new_value, Atom(value="Role")), Context.ACCEPTED),
            fact("is", (old_node, Atom(value="Node")), Context.ACCEPTED),
            fact("is", (new_node, Atom(value="Node")), Context.ACCEPTED),
            fact("has", (holder, old_value), Context.ACCEPTED),
            fact("has", (holder, new_value), Context.ACCEPTED),
            fact("supersedes", (new_node, old_node), Context.ACCEPTED),
        )
    )

    solution = ClingoEngine().solve(
        graph,
        closures={"current_has", "superseded_has"},
    )[0]

    assert solution.contains(
        'superseded_has("accepted",input_field("action:get","token"),"sensitive")'
    )
    assert solution.contains(
        'current_has("accepted",input_field("action:get","token"),"credential")'
    )
    assert not solution.contains(
        'current_has("accepted",input_field("action:get","token"),"sensitive")'
    )
    algebra_program = ClingoEngine().compile(graph, algebra=True)
    assert "superseded_has(C,Holder,Value) :-" in algebra_program
    assert "current_has(C,Holder,Value) :-" in algebra_program


def make_signal_graph(*, with_sink_interpretation: bool = True) -> QdlGraph:
    action = Atom(value="action:get")
    sink = Atom(value="sink:interpreter")
    query = input_field(action, Atom(value="query"))
    effect = reached(action, sink)
    facts = [
        entity("action:get", "Action"),
        fact(
            "is",
            (Atom(value="norm:marker"), Atom(value="Norm")),
            Context.ACCEPTED,
        ),
        fact("is", (sink, Atom(value="Sink")), Context.CONTRACT),
        fact("is", (query, Atom(value="Field")), Context.CONTRACT),
        fact("reaches", (query, sink), Context.CONTRACT),
        fact("signal", (action, Atom(value="marker_echo")), Context.RUNTIME),
        fact(
            "signal_grounds",
            (Atom(value="marker_echo"), effect),
            Context.CONTRACT,
        ),
        fact(
            "prevents",
            (Atom(value="norm:marker"), effect),
            Context.ACCEPTED,
        ),
        fact("causes", (action, effect), Context.ACCEPTED),
    ]
    if with_sink_interpretation:
        facts.append(
            fact(
                "sink_interprets",
                (Atom(value="marker_echo"), sink),
                Context.CONTRACT,
            )
        )
    return QdlGraph(facts=tuple(facts))


def test_threat_rules_join_signal_sink_and_norm() -> None:
    solution = ClingoEngine().solve(make_signal_graph(), threat_rules=True)[0]

    assert solution.contains(
        'signal_finding("action:get","marker_echo","norm:marker","sink:interpreter")'
    )
    assert not solution.contains('uninterpreted_signal("action:get","marker_echo")')


def test_signal_without_interpretation_is_reactive_not_a_finding() -> None:
    solution = ClingoEngine().solve(
        make_signal_graph(with_sink_interpretation=False),
        threat_rules=True,
    )[0]

    assert not solution.contains("signal_finding(")
    assert solution.contains('uninterpreted_signal("action:get","marker_echo")')


def test_threat_rule_pack_is_replaceable() -> None:
    custom_rule = "custom_threat(Action,Signal) :- signal(_,Action,Signal)."
    engine = ClingoEngine(
        threat_rule_pack=ThreatRulePack(name="test", rules=(custom_rule,))
    )
    graph = make_signal_graph()

    program = engine.compile(graph, threat_rules=True)
    solution = engine.solve(graph, threat_rules=True)[0]

    assert custom_rule in program
    assert DEFAULT_THREAT_RULE_PACK.rules[0] not in program
    assert solution.contains('custom_threat("action:get","marker_echo")')


@pytest.mark.parametrize("context", list(Context))
@pytest.mark.parametrize("derived", [False, True])
@pytest.mark.parametrize("predicate", ["causes", "has"])
def test_current_facts_preserves_canonical_context_and_history(
    context, derived, predicate
):
    from clingo import parse_term

    from cloud_dast.qdl.asp import encode_term
    from cloud_dast.qdl.graph_ops import current_facts

    action = Atom(value="action:get")
    holder = input_field(action, Atom(value="token"))
    other_holder = Struct(name="field", args=holder.args)
    subject = action if predicate == "causes" else holder
    old = (
        reached(action, Atom(value="sink:old"))
        if predicate == "causes"
        else Atom(value="setup_value")
    )
    new = (
        reached(action, Atom(value="sink:new"))
        if predicate == "causes"
        else Atom(value="setup_skip")
    )
    old_node = (
        old if predicate == "causes" else Struct(name="replacement", args=(holder, old))
    )
    new_node = (
        new if predicate == "causes" else Struct(name="replacement", args=(holder, new))
    )
    other_context = (
        Context.CONTRACT if context != Context.CONTRACT else Context.ACCEPTED
    )
    old_row = fact(predicate, (subject, old), context)
    new_row = fact(predicate, (subject, new), context)
    historical = fact(predicate, (subject, old), other_context)
    other_role = fact("has", (other_holder, Atom(value="setup_value")), context)
    tombstone = fact("supersedes", (new_node, old_node), context)
    raw = fact("requires", (action, old_node), context)
    trigger = fact("is", (action, Atom(value="Action")), context)
    graph = QdlGraph(
        facts=(
            trigger,
            entity("sink:old", "Sink"),
            entity("sink:new", "Sink"),
            entity("setup_value", "Role"),
            entity("setup_skip", "Role"),
            fact("is", (holder, Atom(value="InputField")), context),
            fact("is", (other_holder, Atom(value="Field")), context),
            fact("is", (old_node, Atom(value="Node")), context),
            fact("is", (new_node, Atom(value="Node")), context),
            old_row,
            historical,
            other_role,
            raw,
            *((new_row, tombstone) if not derived else ()),
        ),
        rules=tuple(
            Rule(
                body=(
                    trigger,
                    fact("is", (holder, Atom(value="InputField")), context),
                    fact("is", (old_node, Atom(value="Node")), context),
                    fact("is", (new_node, Atom(value="Node")), context),
                ),
                head=(row,),
            )
            for row in (new_row, tombstone)
        )
        if derived
        else (),
    )
    before = graph.model_dump_json()

    rows = current_facts(graph)

    assert new_row in rows
    assert old_row not in rows
    assert historical in rows
    assert (
        other_role in rows
    )  # Exact holder identity survives, even with the same field name.
    assert raw in rows  # A tombstone is not a blanket last-argument deletion policy.
    assert all(
        f in rows for f in graph.facts if f.predicate.name not in {"causes", "has"}
    )
    assert len(rows) == len({f.model_dump_json() for f in rows})
    assert graph.model_dump_json() == before
    solution = ClingoEngine().solve(graph, closures={"current_has", "current_reached"})[
        0
    ]
    assert solution.contains(
        str(
            parse_term(
                f'{predicate}("{context.value}",{encode_term(subject)},{encode_term(old)})'
            )
        )
    )


@pytest.mark.parametrize(
    "graph", [QdlGraph(), make_signal_graph()], ids=["empty", "facts"]
)
@pytest.mark.parametrize("projection", ["current_facts", "superseded_effects"])
def test_current_projection_fastpath_matches_real_engine(
    graph, projection, monkeypatch
):
    from cloud_dast.qdl import graph_ops
    from cloud_dast.qdl.graph import canonical_json

    solve = ClingoEngine.solve
    calls = []

    def record_solve(self, source, **kwargs):
        calls.append(source)
        return solve(self, source, **kwargs)

    monkeypatch.setattr(ClingoEngine, "solve", record_solve)
    project = getattr(graph_ops, projection)
    before = graph.model_dump_json()
    fast = project(graph)
    assert calls == []
    solved = project(graph, engine=ClingoEngine())
    assert len(calls) == 1 and calls[0] is graph
    if projection == "current_facts":
        assert (
            {canonical_json(row) for row in fast}
            == {canonical_json(row) for row in solved}
            == {canonical_json(row) for row in graph.facts}
        )
    else:
        assert fast == solved == frozenset()
    assert graph.model_dump_json() == before


@pytest.mark.parametrize("context", [Context.ACCEPTED, Context.RUNTIME])
@pytest.mark.parametrize("derived", [False, True])
@pytest.mark.parametrize("provider", ["retired", "other_context", "norm_only"])
def test_superseded_effects_requires_a_context_local_provider(
    context, derived, provider
):
    from cloud_dast.qdl.graph import canonical_json
    from cloud_dast.qdl.graph_ops import superseded_effects

    action = Atom(value="action:get")
    old = reached(action, Atom(value="sink:old"))
    new = reached(action, Atom(value="sink:new"))
    old_declaration = fact("is", (old, Atom(value="Effect")), context)
    new_declaration = fact("is", (new, Atom(value="Effect")), context)
    tombstone = fact("supersedes", (new, old), context)
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            entity("sink:old", "Sink"),
            entity("sink:new", "Sink"),
            entity("norm:old", "Norm"),
            old_declaration,
            new_declaration,
            fact("prevents", (Atom(value="norm:old"), old), context),
            *((tombstone,) if not derived else ()),
            *(
                (
                    fact(
                        "causes",
                        (action, old),
                        context if provider == "retired" else Context.CONTRACT,
                    ),
                )
                if provider != "norm_only"
                else ()
            ),
        ),
        rules=(Rule(body=(old_declaration, new_declaration), head=(tombstone,)),)
        if derived
        else (),
    )
    before = graph.model_dump_json()
    expected = (
        frozenset({(context, canonical_json(old))})
        if provider == "retired"
        else frozenset()
    )

    assert superseded_effects(graph) == expected
    assert superseded_effects(graph, engine=ClingoEngine()) == expected
    assert graph.model_dump_json() == before


@pytest.mark.parametrize(
    "name",
    [
        "current_has",
        "current_effect",
        "superseded_has",
        "superseded_effect",
    ],
)
def test_typed_current_collision_matches_real_engine(name):
    from cloud_dast.qdl.graph import ArgumentSchema, PredicateSchema, canonical_json
    from cloud_dast.qdl.graph_ops import current_facts, superseded_effects

    action = Atom(value="action:get")
    holder = input_field(action, Atom(value="token"))
    sensitive, credential = Atom(value="sensitive"), Atom(value="credential")
    old, new = (
        reached(action, Atom(value="sink:old")),
        reached(action, Atom(value="sink:new")),
    )
    args = {
        "current_has": (holder, credential),
        "current_effect": (action, new),
        "superseded_has": (holder, sensitive),
        "superseded_effect": (action, old),
    }[name]
    extension = Fact(
        context=Context.ACCEPTED,
        args=args,
        predicate=Predicate.from_schema(
            PredicateSchema(
                name=name,
                arguments=(
                    ArgumentSchema(name="subject"),
                    ArgumentSchema(name="value"),
                ),
            )
        ),
    )
    role = fact("has", (holder, sensitive), Context.ACCEPTED)
    cause = fact("causes", (action, old), Context.ACCEPTED)
    graph = QdlGraph(
        facts=(
            entity("action:get", "Action"),
            entity("sink:old", "Sink"),
            entity("sink:new", "Sink"),
            fact("is", (holder, Atom(value="InputField")), Context.ACCEPTED),
            fact("is", (old, Atom(value="Effect")), Context.ACCEPTED),
            fact("is", (new, Atom(value="Effect")), Context.ACCEPTED),
            role,
            cause,
            extension,
        )
    )
    before = graph.model_dump_json()
    rows = current_facts(graph)
    solved = current_facts(graph, engine=ClingoEngine())
    assert {canonical_json(row) for row in rows} == {
        canonical_json(row) for row in solved
    }
    assert extension in rows
    assert (role in rows) == (name != "superseded_has")
    assert (cause in rows) == (name != "superseded_effect")
    if name == "current_has":
        assert fact("has", (holder, credential), Context.ACCEPTED) in rows
    if name == "current_effect":
        assert fact("causes", (action, new), Context.ACCEPTED) in rows
    retired = (
        frozenset({(Context.ACCEPTED, canonical_json(old))})
        if name == "superseded_effect"
        else frozenset()
    )
    assert (
        superseded_effects(graph)
        == superseded_effects(graph, engine=ClingoEngine())
        == retired
    )
    assert graph.model_dump_json() == before


@pytest.mark.parametrize("name", ["current_has", "current_effect", "superseded_effect"])
@pytest.mark.parametrize("arity", [1, 3])
def test_current_overload_does_not_create_canonical_rows(name, arity):
    from cloud_dast.qdl.graph import ArgumentSchema, PredicateSchema
    from cloud_dast.qdl.graph_ops import current_facts, superseded_effects

    extension = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_schema(
            PredicateSchema(
                name=name,
                arguments=tuple(ArgumentSchema(name=f"arg_{i}") for i in range(arity)),
            )
        ),
        args=tuple(Atom(value=f"literal:{i}") for i in range(arity)),
    )
    graph = QdlGraph(facts=(extension,))
    before = graph.model_dump_json()
    assert (
        current_facts(graph)
        == current_facts(graph, engine=ClingoEngine())
        == (extension,)
    )
    assert (
        superseded_effects(graph)
        == superseded_effects(graph, engine=ClingoEngine())
        == frozenset()
    )
    assert graph.model_dump_json() == before
