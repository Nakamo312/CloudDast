from __future__ import annotations

from benchmarks.nsfy_bench import build_graph
from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import (
    _CREATE_ACTIONS,
    _CREATE_OUTPUT_FIELDS,
    _FIELD_RESOURCES,
    _FIELD_ROLES,
    _METHOD_RESOURCES,
    _MUTABLE_ROLES,
    _MUTATING_EFFECTS,
    ACCEPT_TRANSFER,
    ACTIVATE_USER,
    BUY_GIFT_CARD,
    CREATE_API_KEY,
    CREATE_ORDER,
    CREATE_REFUND,
    CREATE_TRANSFER,
    ESCALATE_API_KEY,
    EXECUTE_PAYOUT,
    EXECUTE_REFUND,
    FS_ESCAPE_SINK,
    GET_DOCUMENT,
    GET_INVOICE,
    GET_ORDER,
    GET_USER,
    PAY_ORDER,
    REQUEST_PAYOUT,
    SEARCH_ORDERS,
    SHIP_ORDER,
    SPEND_GIFT_CARD,
    SQL_ENGINE_SINK,
    UPDATE_ORDER,
    action_id,
    grounding_facts,
    methods,
)

from cloud_dast.api import (
    LiveRequest,
)
from cloud_dast.model import (
    EndpointLayer,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.qdl.graph import Atom, QdlGraph, input_field, output_field
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.payload_hints import (
    compile_payload_hints,
)
from cloud_dast.runtime.planning import IncrementalQdlPlanner, QdlPlanner
from cloud_dast.verification.differential.contracts import (
    read_resource_reference,
)
from cloud_dast_fuzzing import TemplateGenerator
from cloud_dast_fuzzing.corpus import (
    load_payload_corpus,
)


class _FormalRepository:
    def __init__(self, graph: QdlGraph) -> None:
        self._build_graph = graph

    def load(self, source_id: str) -> QdlGraph:
        return self._build_graph

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return QdlGraph()


class _MethodRepo:
    def list_methods(self, service: str):
        return methods()


class _ScenarioRepo:
    def get_scenario(self, principal_id: str, resource_id: str, method=None, **kwargs):
        return ScenarioPosition(
            scenario_id="contract-facts",
            profile=ScenarioProfile(
                scope_relation=ScopeRelation.SAME_FOLDER,
                binding_level="resource",
                endpoint_layer=EndpointLayer.PUBLIC,
                resource_state="existing",
                identity_class="attacker",
                addressing_mode="direct",
            ),
            stand=StandState(
                resources=(
                    ResourceRef(
                        service="nsfy.shop.v1",
                        resource_type="order",
                        resource_id="order-1001",
                    ),
                ),
                principals=(
                    PrincipalRef(principal_id="attacker", principal_type="user"),
                    PrincipalRef(principal_id="victim", principal_type="user"),
                ),
                permissions_known=True,
            ),
        )


def test_create_actions_declare_output_resource_fields() -> None:
    facts = grounding_facts()
    expected_fields = {
        CREATE_ORDER: "order_id",
        PAY_ORDER: "order_id",
        CREATE_TRANSFER: "transfer_id",
        BUY_GIFT_CARD: "card_id",
        CREATE_API_KEY: "key_id",
        REQUEST_PAYOUT: "payout_id",
        CREATE_REFUND: "refund_id",
    }

    for method_id, field_name in expected_fields.items():
        field = output_field(action_id(method_id), Atom(value=field_name))

        assert any(
            fact.predicate.name == "is"
            and fact.args == (field, Atom(value="OutputField"))
            for fact in facts
        )
        assert any(
            fact.predicate.name == "has"
            and fact.args == (field, Atom(value="object_ref"))
            for fact in facts
        )
        assert any(
            f.predicate.name == "refers_to" and f.args[0] == field for f in facts
        )


def test_buy_gift_card_payment_transfer_refers_to_transfer() -> None:
    facts = grounding_facts()
    field = input_field(
        action_id(BUY_GIFT_CARD),
        Atom(value="payment_transfer_id"),
    )
    references = {
        str(fact.args[1].value)
        for fact in facts
        if fact.predicate.name == "refers_to" and fact.args[0] == field
    }

    # Resource references share the structural target/policy namespace.
    assert references == {"resource:transfer"}


def test_mutating_actions_declare_changed_effects() -> None:
    facts = grounding_facts()
    causes = {
        (fact.args[0].value, fact.args[1].name)
        for fact in facts
        if fact.predicate.name == "causes"
    }

    for method_id in _MUTATING_EFFECTS:
        assert (action_id(method_id).value, "changed") in causes


def test_read_actions_expose_object_references() -> None:
    facts = grounding_facts()
    expected = {
        GET_ORDER: ("order", "order_id"),
        GET_USER: ("user", "user_id"),
        GET_INVOICE: ("invoice", "invoice_id"),
    }

    for method_id, (resource_name, field_name) in expected.items():
        action = action_id(method_id)
        witness = output_field(action, Atom(value=field_name))

        assert any(
            fact.predicate.name == "exposes" and fact.args == (action, witness)
            for fact in facts
        )
        assert any(
            fact.predicate.name == "has"
            and fact.args == (witness, Atom(value="object_ref"))
            for fact in facts
        )
        assert any(
            fact.predicate.name == "refers_to"
            and fact.args == (witness, Atom(value=f"resource:{resource_name}"))
            for fact in facts
        )


def test_chain_facts_create_attack_paths() -> None:
    plan = QdlPlanner().plan(build_graph())
    paths = {path.actions for path in plan.attack_paths}

    expected_paths = {
        (
            action_id("grpc:nsfy.shop.v1.OrderService.PayOrder").value,
            action_id("grpc:nsfy.shop.v1.DocumentService.GetDocument").value,
        ),
        (
            action_id("grpc:nsfy.shop.v1.TransferService.CreateTransfer").value,
            action_id("grpc:nsfy.shop.v1.TransferService.AcceptTransfer").value,
        ),
        (
            action_id("grpc:nsfy.shop.v1.KeyService.CreateApiKey").value,
            action_id("grpc:nsfy.shop.v1.KeyService.EscalateApiKey").value,
        ),
        (
            action_id("grpc:nsfy.shop.v1.PayoutService.RequestPayout").value,
            action_id("grpc:nsfy.shop.v1.PayoutService.ExecutePayout").value,
        ),
        (
            action_id("grpc:nsfy.shop.v1.OrderService.CreateRefund").value,
            action_id("grpc:nsfy.shop.v1.OrderService.ExecuteRefund").value,
        ),
        (
            action_id("grpc:nsfy.shop.v1.GiftService.BuyGiftCard").value,
            action_id("grpc:nsfy.shop.v1.GiftService.SpendGiftCard").value,
        ),
    }

    assert expected_paths <= paths


def test_get_document_transition_prerequisite_is_an_ordinary_qdl_step():
    binding = ScenarioBinder(
        _MethodRepo(),
        _ScenarioRepo(),
        _FormalRepository(build_graph()),
        qdl_planner=IncrementalQdlPlanner(),
    ).bind(
        LiveRequest(
            service="nsfy.shop.v1",
            principal_id="attacker",
            resource_id="order-1001",
            method_id=GET_DOCUMENT,
        )
    )
    paths = [
        path
        for path in binding.execution.paths
        if path.steps[-1].method.method_id == GET_DOCUMENT
    ]
    path = next(
        path
        for path in paths
        if any(step.method.method_id == PAY_ORDER for step in path.steps[:-1])
    )
    pay = next(step for step in path.steps if step.method.method_id == PAY_ORDER)
    document = path.steps[-1]
    assert pay.required_effects
    assert ("order_id", "order") in pay.plan.resource_types
    assert "name" in document.plan.probe_fields
    assert "name" not in document.plan.resource_params
    seed = TemplateGenerator().generate(
        pay.plan, pay.method, pay.invariant, pay.scenario
    )[0]
    observation = BenchTarget(BenchService(BenchState.seed()))(seed)
    assert dict(seed.request)["order_id"] == "order-1001"
    assert seed.identities == ("attacker",)
    assert observation.transport_status.code == 200
    assert dict(observation.output.fields) == {
        "order_id": "order-1001",
        "state": "paid",
    }


def test_object_reference_fields_declare_refers_to_targets() -> None:
    facts = grounding_facts()

    for method in methods():
        for spec in method.fields:
            if _FIELD_ROLES[(method.method_id, spec.name)] != "object_ref":
                continue
            field = input_field(action_id(method.method_id), Atom(value=spec.name))
            resource_name = _FIELD_RESOURCES.get(
                (method.method_id, spec.name),
                _METHOD_RESOURCES[method.method_id],
            )
            target = Atom(value=f"resource:{resource_name}")

            assert any(
                fact.predicate.name == "refers_to" and fact.args == (field, target)
                for fact in facts
            ), (method.method_id, spec.name)


def test_mutable_fields_declare_payload_roles() -> None:
    facts = grounding_facts()

    for (method_id, field_name), role in _MUTABLE_ROLES.items():
        field = input_field(action_id(method_id), Atom(value=field_name))

        assert role in {"payload", "mutable_input"}
        assert any(
            fact.predicate.name == "has" and fact.args == (field, Atom(value=role))
            for fact in facts
        )


def test_carrier_facts_ground_sql_and_filesystem_markers() -> None:
    facts = grounding_facts()
    search_query = input_field(action_id(SEARCH_ORDERS), Atom(value="query"))
    document_name = input_field(action_id(GET_DOCUMENT), Atom(value="name"))
    sql_sink = Atom(value=SQL_ENGINE_SINK)
    fs_sink = Atom(value=FS_ESCAPE_SINK)
    expected = {
        ("is", (sql_sink, Atom(value="interpreter"))),
        ("reaches", (search_query, sql_sink)),
        ("dialect", (sql_sink, Atom(value="ansi"))),
        ("is", (fs_sink, Atom(value="filesystem"))),
        ("reaches", (document_name, fs_sink)),
        ("format", (document_name, Atom(value="path"))),
    }

    for predicate, args in expected:
        assert any(
            fact.predicate.name == predicate and fact.args == args for fact in facts
        ), (predicate, args)

    hints = compile_payload_hints(build_graph())
    assert hints[action_id(SEARCH_ORDERS).value] == ("query",)
    assert hints[action_id(GET_DOCUMENT).value] == ("name",)
    assert (
        load_payload_corpus().render_marker(("interpreter",), ("ansi",), "marker")
        == "'marker'--"
    )


def test_shared_type_namespace_enables_readback_and_user_reveal() -> None:
    graph = build_graph()
    methods_by_id = {method.method_id: method for method in methods()}

    assert read_resource_reference(
        methods_by_id[UPDATE_ORDER],
        methods_by_id[GET_ORDER],
        graph=graph,
    ) == ("order_id", "order")

    paths = {path.actions for path in QdlPlanner().plan(graph).attack_paths}
    assert (
        action_id(ACTIVATE_USER).value,
        action_id(GET_USER).value,
    ) in paths


def test_created_resource_outputs_declare_refers_to_targets() -> None:
    facts = grounding_facts()
    resources_by_method = {
        method_id: resource_name for resource_name, method_id in _CREATE_ACTIONS.items()
    }

    for method_id, field_name in _CREATE_OUTPUT_FIELDS.items():
        field = output_field(action_id(method_id), Atom(value=field_name))
        target = Atom(value=f"resource:{resources_by_method[method_id]}")

        assert any(
            fact.predicate.name == "refers_to" and fact.args == (field, target)
            for fact in facts
        )


def test_binder_builds_ordinary_paths_for_key_creates():
    binding = ScenarioBinder(
        _MethodRepo(),
        _ScenarioRepo(),
        _FormalRepository(build_graph()),
        qdl_planner=IncrementalQdlPlanner(),
    ).bind(
        LiveRequest(
            service="nsfy.shop.v1", principal_id="attacker", resource_id="order-1001"
        )
    )
    consumers = {
        CREATE_ORDER: SHIP_ORDER,
        CREATE_TRANSFER: ACCEPT_TRANSFER,
        BUY_GIFT_CARD: SPEND_GIFT_CARD,
        CREATE_API_KEY: ESCALATE_API_KEY,
        REQUEST_PAYOUT: EXECUTE_PAYOUT,
        CREATE_REFUND: EXECUTE_REFUND,
    }
    for producer, consumer in consumers.items():
        path = next(
            path
            for path in binding.execution.paths
            if path.steps[-1].method.method_id == consumer
            and any(step.method.method_id == producer for step in path.steps[:-1])
        )
        source = next(step for step in path.steps if step.method.method_id == producer)
        assert source.required_effects
        assert any(effect.name == "create" for effect in source.required_effects)
        assert source.evidence_graph is not None
