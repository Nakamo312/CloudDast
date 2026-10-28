"""Read the live stand into a generic policy snapshot.

Neo4j remains the source adapter for live principals, role bindings, and the
resource hierarchy.  QDL emission is delegated to the production
``GenericPolicyProjector``, so this module no longer owns Yandex-IAM-specific
predicate construction.
"""

from __future__ import annotations

from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.policy_projection import (
    GenericPolicyProjector,
    PolicyBinding,
    PolicyContainment,
    PolicyResource,
    PolicySnapshot,
)

_BINDINGS_QUERY = """
    MATCH (p:LivePrincipal)-[:HAS_BINDING]->(b:LiveBinding)
          -[g:ON_ORGANIZATION|ON_CLOUD|ON_FOLDER|ON_RESOURCE]->(t)
    RETURN p.principal_id AS principal_id,
           b.role_id AS role_id,
           coalesce(
               t.resource_id, t.folder_id, t.cloud_id, t.organization_id
           ) AS scope_id
"""

_RESOURCES_QUERY = """
    MATCH (r:LiveResource)
    OPTIONAL MATCH (r)-[:INSTANCE_OF]->(rt:ResourceType)
    RETURN r.resource_id AS resource_id,
           rt.resource_type AS resource_type,
           r.folder_id AS folder_id
"""

_FOLDERS_QUERY = """
    MATCH (f:LiveFolder)
    RETURN f.folder_id AS folder_id, f.cloud_id AS cloud_id
"""

_CLOUDS_QUERY = """
    MATCH (c:LiveCloud)
    RETURN c.cloud_id AS cloud_id, c.organization_id AS organization_id
"""


class Neo4jStandProjector:
    """Emit the live stand through the generic policy projector."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def snapshot(self, service: str) -> PolicySnapshot:
        del service  # the stand is shared; the source id carries the service
        bindings: list[PolicyBinding] = []
        resources: list[PolicyResource] = []
        containments: list[PolicyContainment] = []
        with self._session_factory() as session:
            for row in session.run(_BINDINGS_QUERY).data():
                principal = row.get("principal_id")
                role = row.get("role_id")
                scope = row.get("scope_id")
                if not principal or not role or not scope:
                    continue
                bindings.append(
                    PolicyBinding(subject=principal, role=role, scope=scope)
                )
            for row in session.run(_RESOURCES_QUERY).data():
                resource_id = row.get("resource_id")
                if not resource_id:
                    continue
                resource_type = row.get("resource_type")
                resources.append(
                    PolicyResource(
                        resource=resource_id,
                        resource_type=resource_type if resource_type else None,
                    )
                )
                folder_id = row.get("folder_id")
                if folder_id:
                    containments.append(
                        PolicyContainment(child=resource_id, parent=folder_id)
                    )
            for row in session.run(_FOLDERS_QUERY).data():
                folder_id = row.get("folder_id")
                cloud_id = row.get("cloud_id")
                if not folder_id or not cloud_id:
                    continue
                containments.append(PolicyContainment(child=folder_id, parent=cloud_id))
            for row in session.run(_CLOUDS_QUERY).data():
                cloud_id = row.get("cloud_id")
                organization_id = row.get("organization_id")
                if not cloud_id or not organization_id:
                    continue
                containments.append(
                    PolicyContainment(child=cloud_id, parent=organization_id)
                )
        return PolicySnapshot(
            bindings=tuple(bindings),
            resources=tuple(resources),
            containments=tuple(containments),
        )

    def project(self, service: str) -> QdlGraph:
        return GenericPolicyProjector(self.snapshot(service)).project(service)
