from __future__ import annotations

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
    reached,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticNormCompiler,
)
from cloud_dast.runtime.payload_hints import (
    compile_payload_hints,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
    TemplateGenerator,
)
from cloud_dast_fuzzing.corpus import PayloadCorpusCompiler
from cloud_dast_fuzzing.strategies.grammar import GrammarGenerator


def _fact(predicate: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _build_graph(*, with_filesystem_sink: bool) -> QdlGraph:
    action = Atom(value="action:alien.Service.Zorp")
    field = input_field(action, Atom(value="zork"))
    sink = Atom(value="sink:storage")
    facts = [
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (field, Atom(value="Field"))),
        _fact("reaches", (field, sink)),
    ]
    if with_filesystem_sink:
        facts.append(_fact("is", (sink, Atom(value="filesystem"))))
    else:
        facts.append(_fact("is", (sink, Atom(value="Sink"))))
    return QdlGraph(facts=tuple(facts))


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="alien.Service.Zorp",
        service="alien",
        name="Zorp",
        layer=EndpointLayer.PUBLIC,
        fields=(FieldSpec(name="zork", type="string"),),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _invariant(norm_fact: Fact) -> InvariantProjection:
    norm_id = norm_fact.args[0]
    return InvariantProjection(
        invariant_id="invariant:alien:filesystem",
        norm_id=str(norm_id.value) if isinstance(norm_id, Atom) else "norm:alien",
        statement="QDL filesystem reachability norm",
        severity=Severity.HIGH,
        norm_fact=norm_fact,
    )


def _prevents_facts(graph: QdlGraph) -> tuple[Fact, ...]:
    return tuple(
        fact
        for fact in SemanticNormCompiler().compile(graph)
        if fact.predicate.name == "prevents"
    )


def test_filesystem_reach_compiles_generic_grammar_carrier() -> None:
    graph = _build_graph(with_filesystem_sink=True)
    hints = compile_payload_hints(graph)
    norm_facts = _prevents_facts(graph)

    assert hints == {"action:alien.Service.Zorp": ("zork",)}
    assert len(norm_facts) == 1
    assert norm_facts[0].args[1] == reached(
        Atom(value="action:alien.Service.Zorp"),
        Atom(value="sink:storage"),
    )

    method = _method()
    scenario = _scenario()
    invariant = _invariant(norm_facts[0])
    plan = VerificationPlan(
        plan_id="plan:alien:filesystem",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        probe_fields=hints["action:alien.Service.Zorp"],
        sink_types=(("zork", "filesystem"),),
    )

    checks = GoalPayloadGenerator(
        GrammarGenerator(
            TemplateGenerator(),
            payload_compiler=PayloadCorpusCompiler(),
        )
    ).generate(
        plan,
        method,
        invariant,
        scenario,
    )

    assert checks
    assert all(check.generator == "grammar" for check in checks)
    assert all(check.probe_marker is not None for check in checks)
    values = [dict(check.request)["zork"] for check in checks]
    assert all(
        value.count(check.probe_marker) == 1
        for value, check in zip(values, checks, strict=True)
    )
    assert all("/" in value or "\\" in value for value in values)
    assert any("../" in value or "..\\" in value for value in values)


def test_filesystem_sink_fact_is_required_for_payload_hint() -> None:
    graph = _build_graph(with_filesystem_sink=False)

    assert compile_payload_hints(graph) == {}
    assert _prevents_facts(graph) == ()
