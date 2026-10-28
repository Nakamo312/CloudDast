"""File-stand scenario resources preserve snapshot resource identity."""

from __future__ import annotations

import json
from pathlib import Path

from cloud_dast.api import LiveRequest
from cloud_dast.composition.run_provider import FileScenarioRepository
from cloud_dast.model import (
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ResourceRef,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    input_field,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)

SERVICE = "shop.v1"
STAND_SERVICE = "shop-stand"
GET_ORDER = f"grpc:{SERVICE}.OrderService.GetOrder"
GET_USER = f"grpc:{SERVICE}.UserService.GetUser"
ACTIVATE_USER = f"grpc:{SERVICE}.UserService.ActivateUser"


def write_stand(path: Path, *, with_user: bool = True) -> None:
    """Write one explicit file stand; ``with_user`` toggles the user fixture."""

    resources = [
        {
            "resource": "order-1001",
            "resource_type": "order",
            "service": STAND_SERVICE,
        }
    ]
    if with_user:
        resources.append(
            {"resource": "victim", "resource_type": "user", "service": STAND_SERVICE}
        )
    path.write_text(
        json.dumps(
            {
                "resources": resources,
                "permissions": (
                    {"subject": "attacker", "action": GET_ORDER, "resource": "order"},
                    {"subject": "attacker", "action": GET_USER, "resource": "user"},
                    {
                        "subject": "attacker",
                        "action": ACTIVATE_USER,
                        "resource": "user",
                    },
                ),
            }
        ),
        encoding="utf-8",
    )


def method(method_id: str, *resource_types: str) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service=SERVICE,
        name=method_id.rsplit(".", 1)[-1],
        layer=EndpointLayer.PUBLIC,
        permissions=frozenset({"shop.test"}),
        resource_types=frozenset(resource_types),
        fields=(FieldSpec(name="resource_id", type="string", required=True),),
    )


def test_scenario_resources_come_from_the_policy_snapshot(tmp_path) -> None:
    stand = tmp_path / "stand.json"
    write_stand(stand)
    repository = FileScenarioRepository(stand)

    order = repository.get_scenario(
        "attacker", "order-1001", method(GET_ORDER, "order")
    )
    user = repository.get_scenario("attacker", "order-1001", method(GET_USER, "user"))

    assert order is not None and user is not None
    assert order.stand.resources == (
        ResourceRef(
            service=STAND_SERVICE, resource_type="order", resource_id="order-1001"
        ),
    )
    assert user.stand.resources == ()
    assert not user.stand.permissions_known
    selected_user = repository.get_scenario(
        "attacker", "victim", method(GET_USER, "user")
    )
    assert selected_user.stand.resources == (
        ResourceRef(service=STAND_SERVICE, resource_type="user", resource_id="victim"),
    )


def test_method_resource_types_do_not_invent_resource_ids(tmp_path) -> None:
    stand = tmp_path / "stand.json"
    write_stand(stand, with_user=False)

    scenario = FileScenarioRepository(stand).get_scenario(
        "attacker",
        "resource-under-test",
        method(ACTIVATE_USER, "user", "order"),
    )

    assert scenario is not None
    assert scenario.stand.resources == ()
    assert not scenario.stand.permissions_known
    selected = FileScenarioRepository(stand).get_scenario(
        "attacker", "order-1001", method(ACTIVATE_USER, "user", "order")
    )
    assert selected.stand.resources == (
        ResourceRef(
            service=STAND_SERVICE, resource_type="order", resource_id="order-1001"
        ),
    )
    assert all(
        resource.resource_type != "user" for resource in scenario.stand.resources
    )
    assert all(
        resource.resource_id != "resource-under-test"
        for resource in scenario.stand.resources
    )


def test_missing_live_resource_retains_qdl_type_without_inventing_resource_or_policy(
    tmp_path,
) -> None:
    stand = tmp_path / "stand.json"
    write_stand(stand, with_user=False)

    binder = ScenarioBinder(
        _MethodRepository(method(GET_USER, "user")),
        FileScenarioRepository(stand),
        _FormalRepository(_user_norm_graph()),
        qdl_planner=IncrementalQdlPlanner(),
    )
    binding = binder.bind(
        LiveRequest(
            service=SERVICE,
            principal_id="attacker",
            resource_id="order-1001",
            method_id=GET_USER,
        )
    )

    assert binding.scenario.stand.resources == ()
    assert not binding.scenario.stand.permissions_known
    assert not binding.scenario.stand.effective_permissions
    steps = [step for path in binding.execution.paths for step in path.steps]
    assert steps
    assert all(step.plan.resource_params == ("resource_id",) for step in steps)
    assert all(step.plan.resource_types == (("resource_id", "user"),) for step in steps)
    assert all(step.scenario == binding.scenario for step in steps)
    assert all(not step.scenario.stand.resources for step in steps)
    assert not any(d.reason == "missing_service_part_fact" for d in binding.deficits)


class _MethodRepository:
    def __init__(self, method: MethodSpec) -> None:
        self._method = method

    def get_method(self, method_id: str):
        return self._method if method_id == self._method.method_id else None

    def list_methods(self, service: str):
        return (self._method,) if service == SERVICE else ()


class _FormalRepository:
    def __init__(self, graph: QdlGraph) -> None:
        self._build_graph = graph

    def save(self, source_id, graph, *, provenance, adapter_version, mapping_report):
        return None

    def load(self, source_id: str) -> QdlGraph:
        return (
            self._build_graph
            if source_id.startswith((f"contract:{SERVICE}", f"accepted:{SERVICE}"))
            else QdlGraph()
        )

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return QdlGraph()


def _user_norm_graph() -> QdlGraph:
    action = Atom(value=f"action:{GET_USER}")
    norm = Atom(value="norm:user-read")
    user_type = Atom(value="resource:user")
    reference = input_field(action, Atom(value="resource_id"))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (norm, Atom(value="Norm"))),
            _fact("is", (user_type, Atom(value="Resource"))),
            _fact("prevents", (norm, allowed(action))),
            _fact("targets", (action, user_type), Context.CONTRACT),
            _fact("is", (reference, Atom(value="InputField")), Context.CONTRACT),
            _fact("has", (reference, Atom(value="object_ref")), Context.CONTRACT),
            _fact("refers_to", (reference, user_type), Context.CONTRACT),
        )
    )


def _fact(name: str, args, context: Context = Context.ACCEPTED) -> Fact:
    schema = next((s for s in EXTENSION_PREDICATE_SCHEMAS if s.name == name), None)
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)
