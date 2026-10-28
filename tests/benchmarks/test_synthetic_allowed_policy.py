"""B27 policy validation for synthetic ``allowed`` findings."""

from __future__ import annotations

from benchmarks.nsfy_bench.app import BenchService, BenchState
from benchmarks.nsfy_bench.contract import (
    CHECK_USERNAME,
    CREATE_API_KEY,
    CREATE_ORDER,
    CREATE_REFUND,
    DELETE_ORDER,
    DOWNLOAD_ORDER,
    GET_BUNDLE_VERSION,
    GET_INVOICE,
    GET_ORDER,
    IMPORT_PICKLE,
    LIST_ORDERS,
    PAY_ORDER,
    REQUEST_PAYOUT,
    SEARCH_ORDERS,
    SET_WEBHOOK,
    SHIP_ORDER,
)
from benchmarks.nsfy_bench.graph import build_graph
from benchmarks.nsfy_bench.norms import (
    ATTACKER,
    AUTHORIZED_ATTACKER_METHODS,
    policy_facts,
)
from benchmarks.nsfy_bench.stand import SERVICE, _save_policy_source

from cloud_dast.model import AccessOutcome
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import (
    SemanticNormCompiler,
)
from cloud_dast.qdl.threat_compiler import (
    ThreatIntentCompiler,
)

_AUTHORIZED_REQUESTS: tuple[tuple[str, dict[str, object]], ...] = (
    (CREATE_ORDER, {"note": "authorized setup"}),
    (PAY_ORDER, {"order_id": "order-1001"}),
    (SHIP_ORDER, {"order_id": "order-1001", "note": "authorized setup"}),
    (LIST_ORDERS, {"limit": 1}),
    (SEARCH_ORDERS, {"query": "authorized"}),
    (SET_WEBHOOK, {"url": "http://127.0.0.1:9/authorized"}),
    (CREATE_REFUND, {"order_id": "order-1001"}),
    (DOWNLOAD_ORDER, {"order_id": "order-1001"}),
    (REQUEST_PAYOUT, {"amount": 1.0}),
    (CHECK_USERNAME, {"username": "victim"}),
    (GET_BUNDLE_VERSION, {}),
    (IMPORT_PICKLE, {"data": "authorized"}),
    (CREATE_API_KEY, {"scope": "read"}),
)


def _granted_methods() -> set[str]:
    return {
        atom_value(fact.args[1]).removeprefix("action:")
        for fact in policy_facts()
        if fact.predicate.name == "may"
    }


def _attacker_graph() -> QdlGraph:
    attacker = Atom(value=ATTACKER)
    return QdlGraph(
        facts=(
            *build_graph().facts,
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(attacker, Atom(value="Subject")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("attacker"),
                args=(attacker,),
            ),
        )
    )


def test_policy_grants_only_the_authorized_attacker_methods() -> None:
    facts = policy_facts()

    assert len(facts) == len(AUTHORIZED_ATTACKER_METHODS)
    assert _granted_methods() == set(AUTHORIZED_ATTACKER_METHODS)
    assert {GET_ORDER, DELETE_ORDER, GET_INVOICE}.isdisjoint(_granted_methods())
    for fact in facts:
        assert fact.context is Context.ACCEPTED
        assert fact.predicate.name == "may"


def test_authorized_methods_actually_succeed_for_the_attacker() -> None:
    for method_id, request in _AUTHORIZED_REQUESTS:
        service = BenchService(BenchState.seed(), fetch=lambda _url: None)

        response = service.dispatch(method_id, "attacker", request)

        assert response.outcome is AccessOutcome.ALLOWED, method_id
        assert response.status_code == 200, method_id


def test_planted_authz_defects_and_control_stay_policy_grounded() -> None:
    service = BenchService(BenchState.seed())

    order = service.dispatch(GET_ORDER, "attacker", {"order_id": "order-1001"})
    deleted = service.dispatch(DELETE_ORDER, "attacker", {"order_id": "order-1002"})
    invoice = service.dispatch(GET_INVOICE, "attacker", {"invoice_id": "inv-2001"})

    assert order.outcome is AccessOutcome.ALLOWED
    assert deleted.outcome is AccessOutcome.ALLOWED
    assert invoice.outcome is AccessOutcome.DENIED


def test_compilers_do_not_emit_synthetic_allowed_for_authorized_methods() -> None:
    graph = _attacker_graph()
    facts = (
        *ThreatIntentCompiler().compile(graph),
        *SemanticNormCompiler().compile(graph),
    )
    allowed_actions = {
        atom_value(fact.args[1].args[0])
        for fact in facts
        if fact.predicate.name == "prevents"
        and len(fact.args) == 2
        and fact.args[1].name == "allowed"
    }
    authorized_actions = {
        f"action:{method_id}" for method_id in AUTHORIZED_ATTACKER_METHODS
    }

    assert allowed_actions.isdisjoint(authorized_actions)
    assert f"action:{GET_ORDER}" in allowed_actions
    assert f"action:{DELETE_ORDER}" in allowed_actions


def test_fresh_stand_policy_source_is_self_contained(monkeypatch) -> None:
    saved: dict[str, QdlGraph] = {}

    class FakeRepository:
        def __init__(self, _session_factory) -> None:
            pass

        def save(self, source_id: str, graph: QdlGraph, **_kwargs) -> None:
            saved[source_id] = graph

    monkeypatch.setattr(
        "cloud_dast.infrastructure.neo4j.formal_repository.Neo4jFormalRepository",
        FakeRepository,
    )

    _save_policy_source(session_factory=lambda: None)

    graph = saved[f"accepted-batch:{SERVICE}:policy"]
    assert sum(fact.predicate.name == "may" for fact in graph.facts) == len(
        AUTHORIZED_ATTACKER_METHODS
    )
