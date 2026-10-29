from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from cloud_dast.infrastructure.neo4j.common.repository import (
    Neo4jRepository,
    normalize_method_id,
)
from cloud_dast.model import (
    BindingRef,
    EndpointLayer,
    MethodSpec,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.model.checks import scenario_id_for

_RELATION_LEVELS = {
    "ON_RESOURCE": "resource",
    "ON_FOLDER": "folder",
    "ON_CLOUD": "cloud",
    "ON_ORGANIZATION": "organization",
}
_BINDING_LEVELS = frozenset({"resource", "folder", "cloud", "organization"})
_PRINCIPAL_TYPES = frozenset({"user", "service_account", "group", "anonymous"})

type BindingLevel = Literal["resource", "folder", "cloud", "organization"]
type ResourceState = Literal["existing", "created", "updated", "deleted"]
type IdentityClass = Literal["owner", "attacker", "administrator", "service"]
type AddressingMode = Literal["direct", "inherited", "federated"]


@dataclass(frozen=True)
class ScenarioRowReducer:
    """Reduce Neo4j result rows to a scenario position."""

    rows: tuple[dict[str, Any], ...]
    method: MethodSpec | None
    method_id: str | None
    principal_id: str
    resource_id: str
    scope_relation: ScopeRelation | None
    binding_level: BindingLevel | None
    resource_state: ResourceState
    identity_class: IdentityClass
    addressing_mode: AddressingMode

    def reduce(self) -> ScenarioPosition:
        first = self.rows[0]
        principal = dict(first.get("principal") or {})
        resource = dict(first.get("resource") or {})
        binding_rows = tuple(row for row in self.rows if row.get("binding"))
        scope_row = self._scope_row(binding_rows)
        graph_scope, graph_binding = self._graph_position(resource, scope_row)
        profile = ScenarioProfile(
            scope_relation=(
                graph_scope or self.scope_relation or ScopeRelation.SAME_FOLDER
            ),
            binding_level=graph_binding or self.binding_level or "folder",
            endpoint_layer=self._endpoint_layer(first),
            resource_state=self.resource_state,
            identity_class=self.identity_class,
            addressing_mode=self.addressing_mode,
        )

        return ScenarioPosition(
            scenario_id=scenario_id_for(
                principal_id=self.principal_id,
                resource_id=self.resource_id,
                method_id=self.method_id,
                profile=profile,
            ),
            profile=profile,
            stand=StandState(
                resources=self._resource_refs(
                    resource,
                    first.get("canonical_resource_type"),
                ),
                principals=(self._principal_ref(principal),),
                bindings=self._bindings(binding_rows, principal),
                effective_permissions=self._effective_permissions(self.rows),
                permissions_known=True,
            ),
        )

    def _scope_row(
        self,
        rows: tuple[dict[str, Any], ...],
    ) -> dict[str, Any] | None:
        if not rows:
            return None
        return next((row for row in rows if row.get("in_scope")), rows[0])

    def _graph_position(
        self,
        resource: dict[str, Any],
        scope_row: dict[str, Any] | None,
    ) -> tuple[ScopeRelation | None, str | None]:
        if scope_row is None:
            return None, None
        return (
            self._scope_relation(
                resource,
                self._target_ids(scope_row),
                bool(scope_row.get("in_scope")),
            ),
            self._binding_level(
                scope_row.get("binding_relation"),
                dict(scope_row.get("binding") or {}),
            ),
        )

    def _binding_level(self, relation: Any, binding: dict[str, Any]) -> str:
        level = _RELATION_LEVELS.get(str(relation or ""))
        if level is None:
            level = str(binding.get("target_type") or "")
        if level in _BINDING_LEVELS:
            return level
        return "resource"

    def _principal_ref(self, principal: dict[str, Any]) -> PrincipalRef:
        principal_type = (
            str(principal.get("principal_type") or "user").replace("-", "_").lower()
        )
        if principal_type not in _PRINCIPAL_TYPES:
            principal_type = "user"

        return PrincipalRef(
            principal_id=str(principal.get("principal_id", "")),
            principal_type=principal_type,  # type: ignore[arg-type]
        )

    def _resource_refs(
        self,
        resource: dict[str, Any],
        canonical_resource_type: Any,
    ) -> tuple[ResourceRef, ...]:
        resource_type = str(
            canonical_resource_type or resource.get("resource_type") or ""
        )
        service = str(resource.get("service") or resource_type.split(".", 1)[0])
        refs = [
            ResourceRef(
                service=service,
                resource_type=resource_type,
                resource_id=str(resource.get("resource_id", "")),
            )
        ]
        for key, container_type in (
            ("folder_id", "folder"),
            ("cloud_id", "cloud"),
            ("organization_id", "organization"),
        ):
            container_id = resource.get(key)
            if container_id:
                refs.append(
                    ResourceRef(
                        service="resources",
                        resource_type=container_type,
                        resource_id=str(container_id),
                    )
                )

        return tuple(refs)

    def _bindings(
        self,
        rows: tuple[dict[str, Any], ...],
        principal: dict[str, Any],
    ) -> tuple[BindingRef, ...]:
        principal_id = str(principal.get("principal_id", ""))
        return tuple(
            dict.fromkeys(self._binding_ref(row, principal_id) for row in rows)
        )

    def _effective_permissions(
        self, rows: tuple[dict[str, Any], ...]
    ) -> frozenset[str]:
        return frozenset(
            str(row["permission_id"])
            for row in rows
            if row.get("in_scope") and row.get("permission_id")
        )

    def _binding_ref(self, row: dict[str, Any], principal_id: str) -> BindingRef:
        binding = dict(row.get("binding") or {})
        target = dict(row.get("target") or {})
        level = self._binding_level(row.get("binding_relation"), binding)
        target_id = (
            target.get("resource_id")
            or target.get("folder_id")
            or target.get("cloud_id")
            or target.get("organization_id")
            or target.get("id")
            or binding.get("target_id")
        )

        return BindingRef(
            principal_id=str(binding.get("principal_id") or principal_id),
            role=str(binding.get("role_id") or ""),
            resource_id=target_id if level == "resource" else None,
            folder_id=target_id if level == "folder" else None,
            cloud_id=target_id if level == "cloud" else None,
            organization_id=target_id if level == "organization" else None,
        )

    def _target_ids(self, row: dict[str, Any]) -> frozenset[str]:
        target = dict(row.get("target") or {})
        binding = dict(row.get("binding") or {})
        ids = {
            str(value)
            for value in (
                target.get("resource_id"),
                target.get("folder_id"),
                target.get("cloud_id"),
                target.get("organization_id"),
                target.get("id"),
                binding.get("target_id"),
            )
            if value
        }
        ids.update(
            str(ancestor["resource_id"])
            for ancestor in row.get("target_ancestors", ())
            if isinstance(ancestor, dict) and ancestor.get("resource_id")
        )

        return frozenset(ids)

    def _scope_relation(
        self,
        resource: dict[str, Any],
        target_ids: frozenset[str],
        in_scope: bool,
    ) -> ScopeRelation:
        if in_scope:
            return ScopeRelation.SAME_FOLDER
        for key, relation in (
            ("organization_id", ScopeRelation.CROSS_ORG),
            ("cloud_id", ScopeRelation.CROSS_CLOUD),
            ("folder_id", ScopeRelation.CROSS_FOLDER),
        ):
            value = resource.get(key)
            if value and str(value) not in target_ids:
                return relation

        return ScopeRelation.SAME_FOLDER

    def _endpoint_layer(self, row: dict[str, Any]) -> EndpointLayer:
        if self.method is not None:
            return self.method.layer
        layer = str(row.get("endpoint_layer") or "")
        if layer in EndpointLayer._value2member_map_:
            return EndpointLayer(layer)
        if str(row.get("graph_method_id") or "").startswith("grpc-priv:"):
            return EndpointLayer.PRIVATE
        return EndpointLayer.PUBLIC


class Neo4jScenarioRepository(Neo4jRepository):
    """Build scenario positions from the existing Layer 2 graph."""

    _SCENARIO_QUERY = """
        MATCH (principal:LivePrincipal)
        WHERE principal.principal_id = $principal_id
           OR principal.profile = $principal_id
        MATCH (resource:LiveResource {resource_id: $resource_id})
        OPTIONAL MATCH (resource)-[:INSTANCE_OF]->(rt:ResourceType)
        OPTIONAL MATCH (principal)-[:HAS_BINDING]->(binding:LiveBinding)
              -[grants:ON_ORGANIZATION|ON_CLOUD|ON_FOLDER|ON_RESOURCE]->(target)
        OPTIONAL MATCH (binding)-[:GRANTS_ROLE]->(:Role)-[:GRANTS]->(permission:Permission)
        OPTIONAL MATCH (target)-[:CONTAINS*0..32]->(scope:LiveResource
              {resource_id: $resource_id})
        OPTIONAL MATCH (ancestor)-[:CONTAINS*0..32]->(target)
        OPTIONAL MATCH (m:Method {method_id: $method_id})
        OPTIONAL MATCH (api:ApiSurface)-[:HAS_METHOD]->(m)
        RETURN properties(principal) AS principal,
               properties(resource) AS resource,
               rt.resource_type AS canonical_resource_type,
               properties(binding) AS binding,
               type(grants) AS binding_relation,
               properties(target) AS target,
               collect(DISTINCT properties(ancestor)) AS target_ancestors,
               scope IS NOT NULL AS in_scope,
               permission.permission_id AS permission_id,
               m.method_id AS graph_method_id,
               api.layer AS endpoint_layer
        ORDER BY binding.target_type, binding.target_id, binding.role_id
    """

    def get_scenario(
        self,
        principal_id: str,
        resource_id: str,
        method: MethodSpec | None = None,
        *,
        method_id: str | None = None,
        scope_relation: ScopeRelation | None = None,
        binding_level: BindingLevel | None = None,
        resource_state: ResourceState = "existing",
        identity_class: IdentityClass = "attacker",
        addressing_mode: AddressingMode = "direct",
    ) -> ScenarioPosition | None:
        raw_method_id = method.method_id if method is not None else method_id
        normalized_method_id = (
            normalize_method_id(raw_method_id) if raw_method_id else None
        )
        rows = self._run(
            self._SCENARIO_QUERY,
            principal_id=principal_id,
            resource_id=resource_id,
            method_id=normalized_method_id,
        )
        if not rows:
            return None

        return ScenarioRowReducer(
            rows=tuple(rows),
            method=method,
            method_id=normalized_method_id,
            principal_id=principal_id,
            resource_id=resource_id,
            scope_relation=scope_relation,
            binding_level=binding_level,
            resource_state=resource_state,
            identity_class=identity_class,
            addressing_mode=addressing_mode,
        ).reduce()
