from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from cloud_dast.infrastructure.neo4j.live.scenario_repository import (
    Neo4jScenarioRepository,
)
from cloud_dast.model import (
    BindingRef,
    EndpointLayer,
    MethodSpec,
    PrincipalRef,
    ResourceRef,
    ScopeRelation,
)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class FakeSession:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.params: list[dict[str, Any]] = []

    def run(self, query: str, **params: Any) -> FakeResult:
        self.params.append(params)
        return FakeResult(self.rows)


def make_factory(rows: list[dict[str, Any]]):
    session = FakeSession(rows)

    @contextmanager
    def factory():
        yield session

    return factory, session


def make_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "principal": {"principal_id": "attacker", "principal_type": "user"},
        "resource": {
            "resource_id": "secret-victim",
            "folder_id": "folder-victim",
            "cloud_id": "cloud-shared",
            "organization_id": "org-shared",
        },
        "canonical_resource_type": "lockbox.secret",
        "binding": None,
        "binding_relation": None,
        "target": None,
        "target_ancestors": [],
        "in_scope": False,
        "permission_id": None,
        "graph_method_id": None,
        "endpoint_layer": None,
    }
    row.update(overrides)
    return row


def test_get_scenario_builds_position_from_layer_two_graph(
    method_spec: MethodSpec,
) -> None:
    rows = [
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.payloadViewer",
                "target_type": "folder",
                "target_id": "folder-attacker",
            },
            binding_relation="ON_FOLDER",
            permission_id="lockbox.payload.get",
            target={"resource_id": "folder-attacker"},
            target_ancestors=[
                {"resource_id": "folder-attacker"},
                {"resource_id": "cloud-shared"},
                {"resource_id": "org-shared"},
            ],
        )
    ]
    factory, session = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim", method_spec)

    assert scenario is not None
    assert scenario.profile.scope_relation is ScopeRelation.CROSS_FOLDER
    assert scenario.profile.binding_level == "folder"
    assert scenario.profile.endpoint_layer is EndpointLayer.PRIVATE
    assert scenario.stand.resources == (
        ResourceRef(
            service="lockbox",
            resource_type="lockbox.secret",
            resource_id="secret-victim",
        ),
        ResourceRef(
            service="resources",
            resource_type="folder",
            resource_id="folder-victim",
        ),
        ResourceRef(
            service="resources",
            resource_type="cloud",
            resource_id="cloud-shared",
        ),
        ResourceRef(
            service="resources",
            resource_type="organization",
            resource_id="org-shared",
        ),
    )
    assert scenario.stand.principals == (
        PrincipalRef(principal_id="attacker", principal_type="user"),
    )
    assert scenario.stand.bindings == (
        BindingRef(
            principal_id="attacker",
            role="lockbox.payloadViewer",
            folder_id="folder-attacker",
        ),
    )
    assert scenario.stand.permissions_known
    assert scenario.stand.effective_permissions == frozenset()
    assert session.params == [
        {
            "principal_id": "attacker",
            "resource_id": "secret-victim",
            "method_id": method_spec.method_id,
        }
    ]


def test_scenario_id_separates_profile_and_method(
    method_spec: MethodSpec,
) -> None:
    rows = [make_row()]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    base = repository.get_scenario("attacker", "secret-victim", method_spec)
    changed_profile = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_spec,
        resource_state="created",
    )
    changed_method = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_spec.model_copy(
            update={"method_id": "grpc:yandex.cloud.lockbox.v1.PayloadService.GetEx"}
        ),
    )

    assert base is not None
    assert changed_profile is not None
    assert changed_method is not None
    assert (
        len(
            {
                base.scenario_id,
                changed_profile.scenario_id,
                changed_method.scenario_id,
            }
        )
        == 3
    )


def test_scenario_id_uses_normalized_method_id() -> None:
    rows = [make_row()]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    canonical = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
    )
    slashed = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_id="yandex.cloud.lockbox.v1.PayloadService/Get",
    )

    assert canonical is not None
    assert slashed is not None
    assert canonical.scenario_id == slashed.scenario_id


def test_graph_relationships_win_over_explicit_position_parameters() -> None:
    rows = [
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.viewer",
                "target_type": "organization",
                "target_id": "org-attacker",
            },
            binding_relation="ON_ORGANIZATION",
            target={"resource_id": "org-attacker"},
            target_ancestors=[{"resource_id": "org-attacker"}],
        )
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario(
        "attacker",
        "secret-victim",
        scope_relation=ScopeRelation.CROSS_FOLDER,
        binding_level="folder",
    )

    assert scenario is not None
    assert scenario.profile.scope_relation is ScopeRelation.CROSS_ORG
    assert scenario.profile.binding_level == "organization"
    assert scenario.stand.bindings[0].organization_id == "org-attacker"


def test_method_layer_wins_over_conflicting_graph_layer(
    method_spec: MethodSpec,
) -> None:
    rows = [
        make_row(
            graph_method_id="grpc:yandex.cloud.lockbox.v1.PayloadService.Get",
            endpoint_layer="public",
        )
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim", method_spec)

    assert scenario is not None
    assert scenario.profile.endpoint_layer is EndpointLayer.PRIVATE


def test_explicit_parameters_are_used_without_graph_relationships() -> None:
    rows = [
        make_row(principal={"principal_id": "svc", "principal_type": "service-account"})
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario(
        "svc",
        "secret-victim",
        scope_relation=ScopeRelation.CROSS_CLOUD,
        binding_level="cloud",
    )

    assert scenario is not None
    assert scenario.profile.scope_relation is ScopeRelation.CROSS_CLOUD
    assert scenario.profile.binding_level == "cloud"
    assert scenario.stand.bindings == ()
    assert scenario.stand.principals == (
        PrincipalRef(principal_id="svc", principal_type="service_account"),
    )


def test_unknown_principal_type_falls_back_to_user() -> None:
    rows = [make_row(principal={"principal_id": "robot", "principal_type": "robot"})]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("robot", "secret-victim")

    assert scenario is not None
    assert scenario.stand.principals == (
        PrincipalRef(principal_id="robot", principal_type="user"),
    )


def test_in_scope_binding_classifies_same_folder_position() -> None:
    rows = [
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.payloadViewer",
                "target_type": "folder",
                "target_id": "folder-attacker",
            },
            binding_relation="ON_FOLDER",
            target={"resource_id": "folder-attacker"},
            target_ancestors=[
                {"resource_id": "folder-attacker"},
                {"resource_id": "cloud-shared"},
            ],
        ),
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.admin",
                "target_type": "resource",
                "target_id": "secret-victim",
            },
            binding_relation="ON_RESOURCE",
            permission_id="lockbox.admin.get",
            target={"resource_id": "secret-victim"},
            target_ancestors=[
                {"resource_id": "secret-victim"},
                {"resource_id": "folder-victim"},
            ],
            in_scope=True,
        ),
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim")

    assert scenario is not None
    assert scenario.profile.scope_relation is ScopeRelation.SAME_FOLDER
    assert scenario.profile.binding_level == "resource"
    assert scenario.stand.permissions_known
    assert scenario.stand.effective_permissions == frozenset({"lockbox.admin.get"})
    assert scenario.stand.bindings == (
        BindingRef(
            principal_id="attacker",
            role="lockbox.payloadViewer",
            folder_id="folder-attacker",
        ),
        BindingRef(
            principal_id="attacker",
            role="lockbox.admin",
            resource_id="secret-victim",
        ),
    )


def test_endpoint_layer_is_read_from_graph_without_method_spec() -> None:
    rows = [
        make_row(
            graph_method_id=(
                "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
            )
        )
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_id="grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get",
    )

    assert scenario is not None
    assert scenario.profile.endpoint_layer is EndpointLayer.PRIVATE


def test_method_id_is_normalized_before_query() -> None:
    rows = [
        make_row(
            graph_method_id=(
                "grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"
            )
        )
    ]
    factory, session = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario(
        "attacker",
        "secret-victim",
        method_id=("yandex.cloud.priv.lockbox.v1.PayloadService/Get"),
    )

    assert scenario is not None
    assert scenario.profile.endpoint_layer is EndpointLayer.PRIVATE
    assert session.params == [
        {
            "principal_id": "attacker",
            "resource_id": "secret-victim",
            "method_id": ("grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get"),
        }
    ]


def test_duplicate_binding_rows_are_deduplicated() -> None:
    binding = {
        "principal_id": "attacker",
        "role_id": "lockbox.payloadViewer",
        "target_type": "folder",
        "target_id": "folder-attacker",
    }
    row = make_row(
        binding=binding,
        binding_relation="ON_FOLDER",
        target={"resource_id": "folder-attacker"},
        target_ancestors=[{"resource_id": "folder-attacker"}],
    )
    factory, _ = make_factory([row, dict(row)])
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim")

    assert scenario is not None
    assert scenario.stand.bindings == (
        BindingRef(
            principal_id="attacker",
            role="lockbox.payloadViewer",
            folder_id="folder-attacker",
        ),
    )


def test_binding_target_id_uses_target_and_binding_fallbacks() -> None:
    rows = [
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.viewer",
                "target_type": "folder",
                "target_id": "binding-folder",
            },
            binding_relation="ON_FOLDER",
            target={"id": "target-folder"},
            target_ancestors=[{"resource_id": "target-folder"}],
        ),
        make_row(
            binding={
                "principal_id": "attacker",
                "role_id": "lockbox.admin",
                "target_type": "folder",
                "target_id": "binding-folder",
            },
            binding_relation="ON_FOLDER",
            target={},
            target_ancestors=[],
        ),
    ]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim")

    assert scenario is not None
    assert [binding.folder_id for binding in scenario.stand.bindings] == [
        "target-folder",
        "binding-folder",
    ]


def test_api_surface_layer_is_used_from_graph() -> None:
    rows = [make_row(endpoint_layer="gateway")]
    factory, _ = make_factory(rows)
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "secret-victim")

    assert scenario is not None
    assert scenario.profile.endpoint_layer is EndpointLayer.GATEWAY


def test_get_scenario_returns_none_without_graph_data() -> None:
    factory, session = make_factory([])
    repository = Neo4jScenarioRepository(factory)

    scenario = repository.get_scenario("attacker", "missing")

    assert scenario is None
    assert session.params == [
        {
            "principal_id": "attacker",
            "resource_id": "missing",
            "method_id": None,
        }
    ]
