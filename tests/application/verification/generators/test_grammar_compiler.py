from __future__ import annotations

from unittest.mock import patch

import pytest

from cloud_dast.contracts.grammar import (
    GrammarConstraint,
    GrammarFacts,
    GrammarFieldRule,
    GrammarSolution,
)
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.couplings import FieldCoupling
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
)
from cloud_dast.runtime import grammar_facts
from cloud_dast.runtime.grammar_facts import compile
from cloud_dast_fuzzing.corpus import (
    PayloadAlternative,
    PayloadCorpus,
    PayloadCorpusCompiler,
    PayloadNode,
    PayloadProduction,
    PayloadReference,
    PayloadSlot,
    PayloadTerminal,
    PayloadTerminalAlternative,
)
from cloud_dast_fuzzing.strategies.grammar import GrammarCompiler, GrammarGenerator
from cloud_dast_symbolic import FieldValueConstraint, solve_request


def _request_solver(request, method, couplings, constraints):
    solution = solve_request(
        request,
        method,
        couplings,
        tuple(
            FieldValueConstraint(
                field=constraint.field,
                operator=constraint.operator,
                value=constraint.value,
            )
            for constraint in constraints
        ),
    )
    return GrammarSolution(
        request=solution.request,
        status=solution.status,
        dropped_couplings=solution.dropped_couplings,
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


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(name="path", type="string", required=True),
            FieldSpec(name="from", type="int32", required=True, minimum=0, maximum=10),
            FieldSpec(name="to", type="int32", required=True, minimum=0, maximum=10),
        ),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="norm",
        severity=Severity.HIGH,
    )


def _plan(**updates: object) -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id="get",
        scenario_id="scenario",
        **updates,  # type: ignore[arg-type]
    )


def _build_graph(*facts: Fact) -> QdlGraph:
    return QdlGraph(facts=facts)


def _filesystem_graph() -> QdlGraph:
    action = Atom(value="action:get")
    path = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:file")
    return _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (path, Atom(value="Field"))),
        _fact("is", (sink, Atom(value="filesystem"))),
        _fact("reaches", (path, sink)),
        _fact("format", (path, Atom(value="path"))),
        _fact("constraint", (path, Atom(value="ne"), Atom(value="seed"))),
        _fact("dialect", (sink, Atom(value="posix"))),
    )


def test_graph_facts_compile_into_deterministic_strategies() -> None:
    facts = compile(_filesystem_graph(), ("get",))["get"]
    compiled = GrammarCompiler(
        PayloadCorpusCompiler(),
        _request_solver,
    ).compile(
        _method(),
        facts,
        couplings=(
            FieldCoupling(
                input_field(Atom(value="get"), Atom(value="from")),
                input_field(Atom(value="get"), Atom(value="to")),
                "eq",
            ),
        ),
    )

    first = compiled.examples(3)
    second = compiled.examples(3)

    assert first == second
    assert first
    for request in first:
        assert request["path"] != "seed"
        assert "/" in request["path"] or "\\" in request["path"]
        assert request["from"] == request["to"]
        assert 0 <= request["from"] <= 10
        assert set(request) == {"path", "from", "to"}


def test_proposal_facts_do_not_become_executable_grammar() -> None:
    action = Atom(value="action:get")
    path = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:file")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (path, Atom(value="Field"))),
        _fact(
            "is",
            (sink, Atom(value="filesystem")),
            context=Context.PROPOSAL,
        ),
        _fact("reaches", (path, sink), context=Context.PROPOSAL),
        _fact("format", (path, Atom(value="path")), context=Context.PROPOSAL),
    )

    assert compile(graph, ("get",))["get"].fields == ()


def test_plan_carries_all_grammar_fact_layers() -> None:
    plan = _plan(
        sink_types=(("path", "filesystem"),),
        grammar_formats=(("path", "path"),),
        grammar_constraints=(("path", "ne", "seed"),),
        grammar_dialects=(("path", "posix"),),
    )

    facts = GrammarFacts.from_plan(plan)

    assert facts.fields == (
        GrammarFieldRule(
            field="path",
            formats=("path",),
            constraints=(GrammarConstraint("path", "ne", "seed"),),
            sink_types=("filesystem",),
            dialects=("posix",),
        ),
    )


def test_unknown_constraint_operator_is_rejected() -> None:
    action = Atom(value="action:get")
    path = input_field(action, Atom(value="path"))
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (path, Atom(value="Field"))),
        _fact("constraint", (path, Atom(value="matches"), Atom(value="seed"))),
    )

    with pytest.raises(ValueError, match="unknown constraint operator"):
        compile(graph, ("get",))["get"]


def test_carrier_placeholder_survives_payload_composition() -> None:
    action = Atom(value="action:get")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:interpreter")
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (query, Atom(value="Field"))),
        _fact("is", (sink, Atom(value="interpreter"))),
        _fact("reaches", (query, sink)),
    )
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="query", type="string", required=True),),
    )
    compiled = GrammarCompiler(PayloadCorpusCompiler()).compile(
        method,
        compile(graph, ("get",))["get"],
        carrier_fields=("query",),
        placeholder="{probe_marker}",
    )

    for request in compiled.examples(3):
        assert request["query"].count("{probe_marker}") == 1


def test_carrier_without_sink_grammar_keeps_bare_placeholder() -> None:
    """An unknown carrier grammar must not be wrapped in quote canaries.

    Without a corpus production for the declared format the runtime token is
    positioned bare; decorating it with quotes would guess a quoted-literal
    carrier the QDL facts never declared.
    """

    action = Atom(value="action:get")
    query = input_field(action, Atom(value="query"))
    graph = _build_graph(
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (query, Atom(value="Field"))),
        _fact("format", (query, Atom(value="identifier"))),
    )
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="query", type="string", required=True),),
    )
    compiled = GrammarCompiler(PayloadCorpusCompiler()).compile(
        method,
        compile(graph, ("get",))["get"],
        carrier_fields=("query",),
        placeholder="{probe_marker}",
    )

    examples = compiled.examples(3)
    assert examples
    for request in examples:
        assert request["query"] == "{probe_marker}"


@pytest.mark.parametrize(
    ("dialect", "quote", "terminators"),
    [
        ("ansi", "'", {"--", ";", ""}),
        ("mysql", "`", {"--", "#", ";", ""}),
        ("double", '"', {"--", ";", ""}),
    ],
)
def test_sql_dialect_composes_quote_marker_and_terminator(
    dialect: str,
    quote: str,
    terminators: set[str],
) -> None:
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="query", type="string", required=True),),
    )
    plan = _plan(
        sink_types=(("query", "interpreter"),),
        grammar_dialects=(("query", dialect),),
        probe_fields=("query",),
    )

    compiled = GrammarCompiler(PayloadCorpusCompiler()).compile(
        method,
        GrammarFacts.from_plan(plan),
        carrier_fields=("query",),
        placeholder="{probe_marker}",
    )

    assert compiled.payload is not None
    for request in compiled.examples(4):
        value = request["query"]
        prefix = f"{quote}{{probe_marker}}{quote}"
        assert value.startswith(prefix)
        assert value.removeprefix(prefix) in terminators


@pytest.mark.parametrize(
    ("dialect", "metachars"),
    [
        ("posix", {"; printf ", "&& printf ", "|| printf ", "| printf ", "`", "$("}),
        ("windows", {"& echo ", "&& echo ", "|| echo ", "| echo "}),
    ],
)
def test_command_grammar_composes_metachar_and_witness(
    dialect: str,
    metachars: set[str],
) -> None:
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="command", type="string", required=True),),
    )
    plan = _plan(
        sink_types=(("command", "command"),),
        grammar_dialects=(("command", dialect),),
        probe_fields=("command",),
    )

    compiled = GrammarCompiler(PayloadCorpusCompiler()).compile(
        method,
        GrammarFacts.from_plan(plan),
        carrier_fields=("command",),
        placeholder="{probe_marker}",
    )

    assert compiled.payload is not None
    for request in compiled.examples(4):
        value = request["command"]
        assert value.count("{probe_marker}") == 1
        assert value.split("{probe_marker}", 1)[0] in metachars


def test_grammar_compiler_uses_injected_payload_corpus() -> None:
    corpus = PayloadCorpus(
        schema_version=1,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="custom",
                sink_types=("custom",),
                dialects=("custom",),
                template="{prefix}{witness}",
                slots=(
                    PayloadSlot(name="prefix", alternatives=("engine-",)),
                    PayloadSlot(name="witness", alternatives=("{marker}", "payload")),
                ),
            ),
        ),
    )
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="value", type="string", required=True),),
    )
    facts = GrammarFacts(
        fields=(
            GrammarFieldRule(
                field="value",
                sink_types=("custom",),
                dialects=("custom",),
            ),
        )
    )

    compiled = GrammarCompiler(PayloadCorpusCompiler(corpus)).compile(method, facts)

    assert compiled.payload is not None
    assert all(request["value"] == "engine-payload" for request in compiled.examples(2))


def test_grammar_compiler_composes_recursive_payload_grammar() -> None:
    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="recursive",
                sink_types=("custom",),
                dialects=("custom",),
                root="expression",
                nodes=(
                    PayloadNode(
                        name="expression",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    PayloadTerminal(
                                        alternatives=(
                                            PayloadTerminalAlternative(
                                                value="{marker}",
                                            ),
                                            PayloadTerminalAlternative(
                                                value="value",
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                            PayloadAlternative(
                                elements=(
                                    PayloadTerminal(
                                        alternatives=(
                                            PayloadTerminalAlternative(value="("),
                                        ),
                                    ),
                                    PayloadReference(node="expression"),
                                    PayloadTerminal(
                                        alternatives=(
                                            PayloadTerminalAlternative(value=")"),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="value", type="string", required=True),),
    )
    facts = GrammarFacts(
        fields=(
            GrammarFieldRule(
                field="value",
                sink_types=("custom",),
                dialects=("custom",),
            ),
        )
    )

    compiled = GrammarCompiler(PayloadCorpusCompiler(corpus)).compile(method, facts)

    assert compiled.payload is not None
    values = compiled.examples(4)
    assert any("(" in value["value"] and ")" in value["value"] for value in values)
    assert all(
        value["value"].count("(") == value["value"].count(")") for value in values
    )


class _StaticSeed:
    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del plan, invariant, feedback
        return (
            Check(
                invariant_id="inv",
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=(("path", "seed"),),
                identities=("attacker",),
            ),
        )


def test_grammar_generator_compiles_plan_sink_facts_without_model() -> None:
    plan = _plan(sink_types=(("path", "filesystem"),))

    checks = GrammarGenerator(
        _StaticSeed(), payload_compiler=PayloadCorpusCompiler()
    ).generate(
        plan,
        _method(),
        _invariant(),
        _scenario(),
    )
    repeated = GrammarGenerator(
        _StaticSeed(), payload_compiler=PayloadCorpusCompiler()
    ).generate(
        plan,
        _method(),
        _invariant(),
        _scenario(),
    )

    assert checks
    assert checks == repeated
    assert all(check.generator == "grammar" for check in checks)
    assert all(
        "/" in dict(check.request)["path"] or "\\" in dict(check.request)["path"]
        for check in checks
    )


def test_grammar_generator_compiles_command_sink_facts_without_model() -> None:
    method = MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="command", type="string", required=True),),
    )
    plan = _plan(sink_types=(("command", "command"),))

    checks = GrammarGenerator(
        _StaticSeed(), payload_compiler=PayloadCorpusCompiler()
    ).generate(
        plan,
        method,
        _invariant(),
        _scenario(),
    )

    assert checks
    assert all(check.generator == "grammar" for check in checks)
    assert all(
        dict(check.request)["command"].startswith(("; ", "&& ", "|| ", "| ", "`", "$("))
        for check in checks
    )


@pytest.mark.parametrize(
    "requested", ["get", "action:get", "action:action:get", "missing"]
)
def test_batch_preserves_asymmetric_aliases_and_fact_order(requested: str) -> None:
    plain = Atom(value="get")
    facts = [
        _fact("is", (plain, Atom(value="Action"))),
        _fact("is", (input_field(plain, Atom(value="path")), Atom(value="Field"))),
    ]
    for action, operator, value in (
        ("action:get", "ne", 1),
        ("get", "gt", 2),
        ("action:get", "lt", 3),
    ):
        field = input_field(Atom(value=action), Atom(value="path"))
        facts.append(
            _fact("constraint", (field, Atom(value=operator), Atom(value=value)))
        )
    graph = _build_graph(*_filesystem_graph().facts, *facts)
    result = compile(
        graph, iter(("missing", "get", "action:get", "action:action:get", "get"))
    )[requested]
    if requested in {"get", "action:get"}:
        constraints = [
            GrammarConstraint("path", "lt", 3),
            GrammarConstraint("path", "ne", 1),
            GrammarConstraint("path", "ne", "seed"),
        ]
        if requested == "get":
            constraints.append(GrammarConstraint("path", "gt", 2))
        assert result.fields == (
            GrammarFieldRule(
                "path",
                ("path",),
                tuple(constraints),
                ("filesystem",),
                ("posix",),
            ),
        )
    else:
        assert result == GrammarFacts()


@pytest.mark.parametrize(
    ("requests", "expected"),
    [
        (["z", "a"], "a_first"),
        (["z"], "z_first"),
        (["action:a"], "a_qualified"),
        (["a", "action:a"], "a_first"),
        (["missing"], None),
        (["action:z"], None),
        ([], None),
    ],
)
def test_batch_rejects_in_requested_action_then_fact_order(requests, expected) -> None:
    declarations = []
    for action in ("z", "a", "action:a"):
        term = Atom(value=action)
        declarations.extend(
            (
                _fact("is", (term, Atom(value="Action"))),
                _fact(
                    "is", (input_field(term, Atom(value="field")), Atom(value="Field"))
                ),
            )
        )
    graph = _build_graph(
        *declarations,
        *(
            _fact(
                "constraint",
                (
                    input_field(Atom(value=action), Atom(value="field")),
                    Atom(value=operator),
                    Atom(value=1),
                ),
            )
            for action, operator in (
                ("z", "z_first"),
                ("a", "a_first"),
                ("action:a", "a_qualified"),
                ("a", "a_last"),
            )
        ),
    )
    if expected is None:
        assert compile(graph, iter(requests)) == dict.fromkeys(requests, GrammarFacts())
    else:
        with pytest.raises(ValueError, match=repr(expected)):
            compile(graph, iter(requests))


@pytest.mark.parametrize("actions", [(), ("get", "action:get", "missing", "get")])
def test_batch_queries_solver_once_unless_empty(actions) -> None:
    with patch.object(
        ClingoEngine,
        "reaches_plus_pairs",
        autospec=True,
        side_effect=ClingoEngine.reaches_plus_pairs,
    ) as reaches:
        result = compile(_filesystem_graph(), iter(actions))
    assert reaches.call_count == bool(actions)
    assert list(result) == sorted(set(actions))
    if actions:
        assert result["get"] == result["action:get"]
        assert result["get"].fields[0].sink_types == ("filesystem",)
        assert result["missing"] == GrammarFacts()


def test_batch_preserves_interleaved_alias_fact_order() -> None:
    graph = _filesystem_graph()
    constraints = tuple(
        _fact(
            "constraint",
            (
                input_field(Atom(value=action), Atom(value="path")),
                Atom(value="ne"),
                Atom(value=value),
            ),
        )
        for action, value in (("get", 1), ("action:get", 2), ("get", 3))
    )
    source = graph.model_copy(update={"facts": (*graph.facts, *constraints)})
    with patch.object(grammar_facts, "filter_executable_graph", return_value=source):
        result = compile(graph, ("get", "action:get"))
    assert [c.value for c in result["get"].fields[0].constraints] == ["seed", 1, 2, 3]
    assert [c.value for c in result["action:get"].fields[0].constraints] == ["seed", 2]
