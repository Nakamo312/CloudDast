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
    field,
    has,
    reached,
    transition,
)
from cloud_dast.runtime.execution.view import build
from cloud_dast.runtime.planning import QdlInvariant, QdlPlan


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


def _invariant(norm: str, effect, *, primitive: str = "marker") -> QdlInvariant:
    norm_id = f"norm:{norm}"
    return QdlInvariant(
        norm=norm_id,
        effect=effect,
        primitive=primitive,
        required_evidence=(
            ("trace", "state_before", "state_after")
            if primitive == "sequence"
            else ("trace", "sink_evidence")
        ),
        verdict_policy="deterministic",
        fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=norm_id), effect),
        ),
    )


def _view(invariants, *, methods, exposes_by_witness=None):
    graph = QdlGraph(facts=())
    plan = QdlPlan(graph_hash=graph.content_hash, invariants=invariants)
    return build(
        plan,
        graph,
        methods=tuple(methods),
        scenarios_by_method={method.method_id: _scenario() for method in methods},
        exposes_by_witness=exposes_by_witness or {},
    )


def test_duplicate_action_norms_collapse_before_scheduling() -> None:
    effect = reached(Atom(value="action:import_pickle"), Atom(value="sink:pickle"))
    view = _view(
        (_invariant("manual", effect), _invariant("synthetic", effect)),
        methods=(_method("import_pickle"),),
    )

    assert len(view.invariants) == 1
    assert len(view.paths) == 1
    assert len(view.paths[0].steps) == 1


def test_qdl_norm_identifier_is_not_prefixed_twice() -> None:
    effect = reached(Atom(value="action:search"), Atom(value="sink:sql"))
    view = _view(
        (_invariant("search-injection", effect),),
        methods=(_method("search"),),
    )

    projection = next(iter(view.invariants.values()))

    assert projection.norm_id == "norm:search-injection"


def test_distinct_actions_keep_separate_paths_for_one_witness() -> None:
    witness = field(Atom(value="resource:secret"), Atom(value="private_key"))
    effect = has(Atom(value="principal:attacker"), witness)
    view = _view(
        (_invariant("manual", effect), _invariant("synthetic", effect)),
        methods=(_method("import_pickle"), _method("parse_config")),
        exposes_by_witness={
            ("resource:secret", "private_key"): [
                "action:import_pickle",
                "action:parse_config",
            ]
        },
    )

    assert len(view.invariants) == 1
    assert len(view.paths) == 2
    assert len({path.path_id for path in view.paths}) == 2
    assert {path.steps[0].method.method_id for path in view.paths} == {
        "import_pickle",
        "parse_config",
    }


def test_transition_norm_binds_to_graph_transition_actions() -> None:
    action = Atom(value="action:approve")
    from_state = Atom(value="state:created")
    to_state = Atom(value="state:approved")
    effect = transition(from_state, to_state)
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(from_state, Atom(value="State")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(to_state, Atom(value="State")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("transition"),
                args=(action, from_state, to_state),
            ),
        )
    )
    plan = QdlPlan(
        graph_hash=graph.content_hash,
        invariants=(_invariant("transition", effect, primitive="sequence"),),
    )

    view = build(
        plan,
        graph,
        methods=(_method("approve"),),
        scenarios_by_method={"approve": _scenario()},
        exposes_by_witness={},
    )

    assert len(view.paths) == 1
    path = view.paths[0]
    assert path.kind == "invariant"
    assert path.steps[0].method.method_id == "approve"
    assert path.steps[0].invariant.norm_fact is not None
    assert path.steps[0].invariant.norm_fact.args[1] == effect


def test_transition_norm_ignores_proposal_transition_actions() -> None:
    action = Atom(value="action:approve")
    from_state = Atom(value="state:created")
    to_state = Atom(value="state:approved")
    effect = transition(from_state, to_state)
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(from_state, Atom(value="State")),
            ),
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(to_state, Atom(value="State")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("transition"),
                args=(action, from_state, to_state),
            ),
        )
    )
    plan = QdlPlan(
        graph_hash=graph.content_hash,
        invariants=(_invariant("transition", effect, primitive="sequence"),),
    )

    view = build(
        plan,
        graph,
        methods=(_method("approve"),),
        scenarios_by_method={"approve": _scenario()},
        exposes_by_witness={},
    )

    assert all(path.kind == "smoke" for path in view.paths)
    assert not any(
        path.kind in {"invariant", "forbidden", "attack"} for path in view.paths
    )
