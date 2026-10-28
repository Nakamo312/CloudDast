from __future__ import annotations

from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    reached,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionView
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import (
    QdlAttackPath,
    QdlInvariant,
    QdlPlan,
)


def _method(method_id: str) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service="files",
        name=method_id.replace("_", " ").title(),
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="payload", type="string", required=True),),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _invariant(norm: str, effect) -> QdlInvariant:
    norm_id = f"norm:{norm}"
    return QdlInvariant(
        norm=norm_id,
        effect=effect,
        primitive="outcome" if effect.name == "allowed" else "marker",
        required_evidence=(
            ("observed_outcome", "expected_outcome")
            if effect.name == "allowed"
            else ("trace", "sink_evidence")
        ),
        verdict_policy="deterministic",
        fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=norm_id), effect),
        ),
    )


def _view(invariants) -> QdlExecutionView:
    first = Atom(value="action:first")
    edge_effect = allowed(first)
    graph = QdlGraph(facts=())
    attack = QdlAttackPath(
        path_id="qdl-attack-test",
        context=Context.CONTRACT,
        actions=("action:first", "action:second"),
        edge_effects=((edge_effect,),),
    )
    plan = QdlPlan(
        graph_hash=graph.content_hash,
        attack_paths=(attack,),
        invariants=invariants,
    )
    methods = (_method("first"), _method("second"))
    return build(
        plan,
        graph,
        methods=methods,
        scenarios_by_method={method.method_id: _scenario() for method in methods},
        exposes_by_witness={},
    )


def test_attack_edge_selects_its_effect_invariant_not_first_action_norm() -> None:
    first = Atom(value="action:first")
    second = Atom(value="action:second")
    edge_effect = allowed(first)
    foreign_effect = reached(first, Atom(value="sink:unrelated"))
    final_effect = allowed(second)

    view = _view(
        (
            _invariant("a-foreign", foreign_effect),
            _invariant("z-edge", edge_effect),
            _invariant("z-final", final_effect),
        )
    )
    attack = next(path for path in view.paths if path.kind == "attack")

    assert attack.steps[0].invariant.norm_fact is not None
    assert attack.steps[0].invariant.norm_fact.args[1] == edge_effect
    assert attack.steps[0].invariant.norm_fact.args[1] != foreign_effect
    assert attack.steps[1].invariant.norm_fact is not None
    assert attack.steps[1].invariant.norm_fact.args[1] == final_effect


def test_foreign_norm_is_not_used_as_the_causal_edge_witness() -> None:
    first = Atom(value="action:first")
    second = Atom(value="action:second")
    edge_effect = allowed(first)
    foreign_effect = reached(first, Atom(value="sink:unrelated"))
    final_effect = allowed(second)

    view = _view(
        (
            _invariant("a-foreign", foreign_effect),
            _invariant("z-final", final_effect),
        )
    )

    assert edge_effect != foreign_effect
    attack = next(path for path in view.paths if path.kind == "attack")
    assert attack.steps[0].invariant.norm_fact is None
    assert attack.steps[0].required_effects == (edge_effect,)
    assert attack.steps[1].invariant.norm_fact is not None
    assert attack.steps[1].invariant.norm_fact.args[1] == final_effect
