from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    canonical_json,
    duration,
    input_field,
    source,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.projection import planner_view
from cloud_dast.qdl.threat_compiler import (
    ThreatIntentCompiler,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.campaign.graph import (
    Assembler,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.planning import IncrementalQdlPlanner


class FormalRepository:
    def __init__(self) -> None:
        self.saved: list[dict[str, object]] = []

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: dict[str, object],
        adapter_version: str,
        mapping_report: dict[str, object],
    ) -> None:
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id: str) -> QdlGraph:
        return next(
            (
                item["graph"]
                for item in reversed(self.saved)
                if item["source_id"] == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix: str) -> QdlGraph:
        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


class MethodRepo:
    def __init__(self, methods: tuple[MethodSpec, ...]) -> None:
        self.methods = methods

    def list_methods(self, service: str) -> tuple[MethodSpec, ...]:
        return self.methods


class ScenarioRepo:
    def __init__(self, scenario: ScenarioPosition) -> None:
        self.scenario = scenario

    def get_scenario(
        self,
        principal_id: str,
        resource_id: str,
        method: MethodSpec | None = None,
        **kwargs: object,
    ) -> ScenarioPosition:
        return self.scenario


class CountingThreatCompiler(ThreatIntentCompiler):
    def __init__(self) -> None:
        super().__init__()
        self.compile_calls = 0

    def compile(self, graph: QdlGraph) -> tuple[Fact, ...]:
        self.compile_calls += 1
        return super().compile(graph)


def _fact(
    name: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


def _save(
    repository: FormalRepository,
    source_id: str,
    graph: QdlGraph,
) -> None:
    repository.save(
        source_id,
        graph,
        provenance={"source_kind": "test"},
        adapter_version="test-v1",
        mapping_report={"mapped": len(graph.facts), "unmapped": 0},
    )


def _contract_graph(method: MethodSpec) -> tuple[QdlGraph, Atom, Atom]:
    action = Atom(value=f"action:{method.method_id}")
    resource = Atom(value="resource:secret-victim")
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("targets", (action, resource)),
            _fact("causes", (action, allowed(action))),
        )
    )
    return graph, action, resource


def _request(method: MethodSpec) -> LiveRequest:
    return LiveRequest(
        service=method.service,
        principal_id="attacker",
        resource_id="secret-victim",
    )


def test_planner_view_drops_runtime_evidence_and_contract_redeclarations(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    repository = FormalRepository()
    contract, action, _resource = _contract_graph(method_spec)
    _save(repository, f"contract:{method_spec.service}", contract)
    _save(
        repository,
        f"accepted-batch:{method_spec.service}:declarations",
        QdlGraph(
            facts=(
                _fact(
                    "is",
                    (action, Atom(value="Action")),
                    Context.ACCEPTED,
                ),
            )
        ),
    )

    observation = Atom(value="observation:1")
    evidence = tuple(
        _fact(
            "evidence",
            (
                observation,
                source(Atom(value="response_field"), Atom(value=f"f{index}")),
            ),
            Context.RUNTIME,
        )
        for index in range(10)
    )
    _save(
        repository,
        f"diff:{method_spec.service}:observed",
        QdlGraph(
            facts=(
                _fact(
                    "is",
                    (observation, Atom(value="Observation")),
                    Context.RUNTIME,
                ),
                *evidence,
            )
        ),
    )

    full = merge_graphs(
        contract,
        repository.load_merged(f"accepted-batch:{method_spec.service}:"),
        repository.load_merged(f"diff:{method_spec.service}:"),
    )
    assembler = Assembler(
        repository,
        None,
        PromotionPolicy(enabled=False),
    )
    planner = assembler.load(method_spec.service, formal_proposal=False)

    assert not any(
        fact.context is Context.RUNTIME and fact.predicate.name == "evidence"
        for fact in planner.facts
    )
    action_declarations = [
        fact
        for fact in planner.facts
        if fact.predicate.name == "is" and fact.args == (action, Atom(value="Action"))
    ]
    assert len(action_declarations) == 1
    assert action_declarations[0].context is Context.CONTRACT
    assert len(planner.facts) == len(full.facts) - 11


def test_planner_view_collapses_proposal_redeclaration_to_contract(
    method_spec: MethodSpec,
) -> None:
    contract, action, _resource = _contract_graph(method_spec)
    proposal = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                Context.PROPOSAL,
            ),
        )
    )

    planner = planner_view(merge_graphs(contract, proposal))

    action_declarations = [
        fact
        for fact in planner.facts
        if fact.predicate.name == "is" and fact.args == (action, Atom(value="Action"))
    ]
    assert len(action_declarations) == 1
    assert action_declarations[0].context is Context.CONTRACT


def test_binder_reuses_threat_compilation_for_the_same_slice(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    repository = FormalRepository()
    contract, _action, _resource = _contract_graph(method_spec)
    _save(repository, f"contract:{method_spec.service}", contract)
    compiler = CountingThreatCompiler()
    binder = ScenarioBinder(
        MethodRepo((method_spec,)),
        ScenarioRepo(scenario_position),
        repository,
        threat_compiler=compiler,
        qdl_planner=IncrementalQdlPlanner(),
    )

    first = binder.bind(_request(method_spec), formal_proposal=False)
    action = Atom(value=f"action:{method_spec.method_id}")
    field_term = input_field(action, Atom(value="query"))
    witness = Atom(value="witness:status")
    _save(
        repository,
        f"accepted-batch:{method_spec.service}:semantics",
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
                _fact("is", (field_term, Atom(value="InputField")), Context.ACCEPTED),
                _fact("is", (witness, Atom(value="Witness")), Context.ACCEPTED),
                _fact("has", (field_term, Atom(value="sensitive")), Context.ACCEPTED),
                _fact("exposes", (action, witness), Context.ACCEPTED),
            )
        ),
    )
    second = binder.bind(_request(method_spec), formal_proposal=False)

    assert compiler.compile_calls == 1
    assert first.graph.content_hash != second.graph.content_hash
    action_declarations = [
        fact
        for fact in first.graph.facts
        if fact.predicate.name == "is"
        and fact.args
        and canonical_json(fact.args[0])
        == canonical_json(Atom(value=f"action:{method_spec.method_id}"))
        and fact.args[1] == Atom(value="Action")
    ]
    assert len(action_declarations) == 1
    assert action_declarations[0].context is Context.CONTRACT


def test_new_permission_invalidates_threat_compilation_cache(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    repository = FormalRepository()
    contract, action, resource = _contract_graph(method_spec)
    _save(repository, f"contract:{method_spec.service}", contract)
    compiler = CountingThreatCompiler()
    binder = ScenarioBinder(
        MethodRepo((method_spec,)),
        ScenarioRepo(scenario_position),
        repository,
        threat_compiler=compiler,
        qdl_planner=IncrementalQdlPlanner(),
    )

    binder.bind(_request(method_spec), formal_proposal=False)
    assert compiler.compile_calls == 1

    principal = Atom(value="principal:attacker")
    _save(
        repository,
        f"accepted-batch:{method_spec.service}:permission",
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
                _fact("is", (principal, Atom(value="Subject")), Context.ACCEPTED),
                _fact("is", (resource, Atom(value="Resource")), Context.ACCEPTED),
                _fact(
                    "may",
                    (principal, action, resource),
                    Context.ACCEPTED,
                ),
            )
        ),
    )
    binder.bind(_request(method_spec), formal_proposal=False)

    assert compiler.compile_calls == 2


def test_unrelated_layers_do_not_invalidate_threat_cache() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:secret")
    principal = Atom(value="principal:attacker")
    base = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (principal, Atom(value="Subject"))),
            _fact("attacker", (principal,)),
            _fact("targets", (action, resource)),
            _fact("causes", (action, allowed(action))),
            _fact("may", (principal, action, resource)),
        )
    )
    field_term = input_field(action, Atom(value="query"))
    witness = Atom(value="witness:status")
    observation = Atom(value="observation:1")
    unrelated = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field_term, Atom(value="InputField"))),
            _fact("is", (witness, Atom(value="Witness"))),
            _fact("has", (field_term, Atom(value="sensitive"))),
            _fact("exposes", (action, witness)),
            _fact(
                "is",
                (observation, Atom(value="Observation")),
                Context.RUNTIME,
            ),
            _fact(
                "evidence",
                (observation, duration(action, Atom(value=150))),
                Context.RUNTIME,
            ),
        )
    )
    compiler = CountingThreatCompiler()

    compiler.compile_cached(base)
    compiler.compile_cached(merge_graphs(base, unrelated))

    assert compiler.compile_calls == 1


def test_promotion_persistence_is_append_only(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    repository = FormalRepository()
    assembler = Assembler(
        repository,
        None,
        PromotionPolicy(enabled=False),
    )
    promoted = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="action:promoted"), Atom(value="Action")),
                Context.ACCEPTED,
            ),
        )
    )

    assembler.persist_promotion(method_spec.service, promoted)

    source_ids = [item["source_id"] for item in repository.saved]
    assert source_ids == [
        f"accepted-batch:{method_spec.service}:proposal:{promoted.content_hash}"
    ]
    assert repository.load(f"accepted:{method_spec.service}").facts == ()
    assert repository.load_merged(f"accepted-batch:{method_spec.service}:") == promoted


@pytest.mark.parametrize("entry", ["load", "ground"])
@pytest.mark.parametrize("rejected", [False, True])
def test_formal_proposals_are_cached_per_service(entry, rejected) -> None:
    repository = FormalRepository()
    sources = {}
    proposals = {}
    for service in ("alpha", "beta"):
        sources[service] = QdlGraph(
            facts=(
                _fact("is", (Atom(value=f"action:{service}"), Atom(value="Action"))),
            )
        )
        proposals[service] = (
            None
            if rejected
            else QdlGraph(
                facts=(
                    _fact(
                        "is",
                        (
                            Atom(value=f"action:{service}:proposal"),
                            Atom(value="Action"),
                        ),
                        Context.PROPOSAL,
                    ),
                )
            )
        )
        _save(repository, f"contract:{service}", sources[service])
    calls = []

    def propose(source):
        service = next(name for name, graph in sources.items() if graph == source)
        calls.append(service)
        return SimpleNamespace(proposal=proposals[service], attempts=1, issues=())

    assembler = Assembler(
        repository, SimpleNamespace(propose=propose), PromotionPolicy(enabled=False)
    )
    for service in sources:
        if entry == "load":
            assembler.load(service)
        else:
            prepared = assembler.prepare(service)
            if prepared is not None:
                assembler.commit(service, prepared)
    for service, contract in sources.items():
        expected = contract if rejected else merge_graphs(contract, proposals[service])
        assert assembler.load(service) == planner_view(expected)
        assert assembler.prepare(service) is None
    assert calls == ["alpha", "beta"]


def test_formal_model_failure_remains_retryable() -> None:
    repository = FormalRepository()
    source = QdlGraph(
        facts=(_fact("is", (Atom(value="action:read"), Atom(value="Action"))),)
    )
    _save(repository, "contract:svc", source)
    model = Mock()
    error = RuntimeError("model failed")
    model.propose.side_effect = [
        error,
        SimpleNamespace(proposal=None, attempts=1, issues=()),
    ]
    assembler = Assembler(repository, model, PromotionPolicy(enabled=False))
    with pytest.raises(RuntimeError) as caught:
        assembler.load("svc")
    assert caught.value is error
    assert assembler.load("svc") == source
    assert assembler.load("svc") == source
    assert model.propose.call_count == 2


@pytest.mark.parametrize("second", ["load", "ground"])
def test_simultaneous_formal_calls_share_one_proposal(second) -> None:
    repository = FormalRepository()
    source = QdlGraph(
        facts=(_fact("is", (Atom(value="action:read"), Atom(value="Action"))),)
    )
    _save(repository, "contract:svc", source)
    entered = threading.Event()
    release = threading.Event()
    started = threading.Event()
    duplicate = threading.Event()
    calls = []

    def propose(graph):
        calls.append(graph)
        if len(calls) > 1:
            duplicate.set()
        entered.set()
        assert release.wait(3)
        return SimpleNamespace(proposal=None, attempts=1, issues=())

    assembler = Assembler(
        repository, SimpleNamespace(propose=propose), PromotionPolicy(enabled=False)
    )

    def invoke_second():
        started.set()
        return assembler.load("svc") if second == "load" else assembler.prepare("svc")

    with ThreadPoolExecutor(max_workers=3) as workers:
        first = workers.submit(assembler.prepare, "svc")
        try:
            assert entered.wait(1)
            contract = workers.submit(assembler.load, "svc", formal_proposal=False)
            assert contract.result(timeout=1) == source
            other = workers.submit(invoke_second)
            assert started.wait(1)
            assert not duplicate.wait(0.2)
        finally:
            release.set()
        assert first.result(timeout=1) is None
        assert other.result(timeout=1) == (source if second == "load" else None)
    assert calls == [source]


@pytest.mark.parametrize("entry", ["load", "ground"])
def test_cached_proposal_uses_fresh_promotion_source(method_spec, entry) -> None:
    repository = FormalRepository()
    contract, _, _ = _contract_graph(method_spec)
    _save(repository, f"contract:{method_spec.service}", contract)
    proposal = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="action:proposal"), Atom(value="Action")),
                Context.PROPOSAL,
            ),
        )
    )
    model = Mock()
    model.propose.return_value = SimpleNamespace(
        proposal=proposal, attempts=1, issues=()
    )
    policy = Mock(wraps=PromotionPolicy(enabled=False))
    assembler = Assembler(repository, model, policy)
    if entry == "load":
        assembler.load(method_spec.service)
    else:
        prepared = assembler.prepare(method_spec.service)
        assert prepared is not None
        assembler.commit(method_spec.service, prepared)
    addition = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="observation:new"), Atom(value="Observation")),
                Context.RUNTIME,
            ),
        )
    )
    _save(repository, f"diff:{method_spec.service}:new", addition)
    assembler.load(method_spec.service)
    assert model.propose.call_count == 1
    assert policy.promote.call_count == 2
    assert policy.promote.call_args_list[0].args[0].source == contract
    assert policy.promote.call_args_list[1].args[0].source == merge_graphs(
        contract, addition
    )
