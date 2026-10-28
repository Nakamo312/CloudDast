"""Project transport-independent policy facts into the QDL ``may`` interface."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
)


@dataclass(frozen=True)
class PolicyPermission:
    """One effective ``may(subject, action, resource)`` decision."""

    subject: str
    action: str
    resource: str


@dataclass(frozen=True)
class PolicyBinding:
    subject: str
    role: str
    scope: str


@dataclass(frozen=True)
class PolicyGrant:
    role: str
    permission: str


@dataclass(frozen=True)
class PolicyRequirement:
    action: str
    permission: str


@dataclass(frozen=True)
class PolicyApplication:
    permission: str
    resource_type: str


@dataclass(frozen=True)
class PolicyTarget:
    action: str
    resource_type: str


@dataclass(frozen=True)
class PolicyOwnership:
    resource: str
    subject: str


@dataclass(frozen=True)
class PolicyResource:
    resource: str
    resource_type: str | None = None
    service: str | None = None


@dataclass(frozen=True)
class PolicyContainment:
    child: str
    parent: str


@dataclass(frozen=True)
class PolicyCompleteness:
    """Complete policy inventory for one service/subject/action and instances.

    Presence closes only these exact resource identities for this action.
    It neither grants access nor expands a resource type into its instances.
    Subject, action and resources use the same source identifiers as the
    snapshot's permission records, before the projector adds QDL namespaces.
    """

    service: str
    subject: str
    action: str
    resources: tuple[str, ...]


@dataclass(frozen=True)
class PolicySnapshot:
    """Transport-independent policy facts.

    ``permissions`` are already effective decisions and are the common
    ``may`` interface for policy families whose adapter normalizes decisions
    (including MAC).  The supporting relations are optional and use generic
    policy vocabulary, not a cloud-IAM hierarchy.
    """

    permissions: tuple[PolicyPermission, ...] = ()
    bindings: tuple[PolicyBinding, ...] = ()
    grants: tuple[PolicyGrant, ...] = ()
    requirements: tuple[PolicyRequirement, ...] = ()
    applications: tuple[PolicyApplication, ...] = ()
    targets: tuple[PolicyTarget, ...] = ()
    ownerships: tuple[PolicyOwnership, ...] = ()
    resources: tuple[PolicyResource, ...] = ()
    containments: tuple[PolicyContainment, ...] = ()
    completeness: tuple[PolicyCompleteness, ...] = ()


class GenericPolicyProjector:
    """Emit a generic policy snapshot as grounded QDL facts."""

    def __init__(self, snapshot: PolicySnapshot) -> None:
        self._snapshot = snapshot

    def project(self, service: str) -> QdlGraph:
        del service  # the snapshot is already service-scoped by its source
        facts: list[Fact] = []
        resource_ids = {resource.resource for resource in self._snapshot.resources}

        for permission in self._snapshot.permissions:
            facts.append(
                _fact(
                    "may",
                    (
                        _atom("principal", permission.subject),
                        _atom("action", permission.action),
                        _atom("resource", permission.resource),
                    ),
                )
            )
        for binding in self._snapshot.bindings:
            facts.append(
                _fact(
                    "binding",
                    (
                        _atom("principal", binding.subject),
                        _atom("role", binding.role),
                        _scope_atom(binding.scope, resource_ids),
                    ),
                )
            )
        for grant in self._snapshot.grants:
            facts.append(
                _fact(
                    "grants",
                    (
                        _atom("role", grant.role),
                        _atom("permission", grant.permission),
                    ),
                )
            )
        for requirement in self._snapshot.requirements:
            facts.append(
                _fact(
                    "requires",
                    (
                        _atom("action", requirement.action),
                        _atom("permission", requirement.permission),
                    ),
                )
            )
        for application in self._snapshot.applications:
            facts.append(
                _fact(
                    "applies_to",
                    (
                        _atom("permission", application.permission),
                        _atom("resource", application.resource_type),
                    ),
                )
            )
        for target in self._snapshot.targets:
            facts.append(
                _fact(
                    "targets",
                    (
                        _atom("action", target.action),
                        _atom("resource", target.resource_type),
                    ),
                )
            )
        for ownership in self._snapshot.ownerships:
            facts.append(
                _fact(
                    "owner",
                    (
                        _atom("resource", ownership.resource),
                        _atom("principal", ownership.subject),
                    ),
                )
            )
        for resource in self._snapshot.resources:
            resource_atom = _atom("resource", resource.resource)
            facts.append(_fact("is", (resource_atom, Atom(value="Resource"))))
            if resource.resource_type:
                facts.append(
                    _fact(
                        "is",
                        (resource_atom, _atom("resource", resource.resource_type)),
                    )
                )
        for containment in self._snapshot.containments:
            facts.append(
                _fact(
                    "part",
                    (
                        _scope_atom(containment.child, resource_ids),
                        _scope_atom(containment.parent, resource_ids),
                    ),
                )
            )

        facts.extend(_declarations(self._snapshot))
        unique: dict[str, Fact] = {}
        for fact in facts:
            unique.setdefault(canonical_json(fact), fact)
        return QdlGraph(facts=tuple(unique.values()))


def _declarations(snapshot: PolicySnapshot) -> list[Fact]:
    resource_ids = {resource.resource for resource in snapshot.resources}
    subjects = {
        *(permission.subject for permission in snapshot.permissions),
        *(binding.subject for binding in snapshot.bindings),
        *(ownership.subject for ownership in snapshot.ownerships),
        *(scope.subject for scope in snapshot.completeness),
    }
    actions = {
        *(permission.action for permission in snapshot.permissions),
        *(requirement.action for requirement in snapshot.requirements),
        *(target.action for target in snapshot.targets),
        *(scope.action for scope in snapshot.completeness),
    }
    resources = {
        *(permission.resource for permission in snapshot.permissions),
        *(ownership.resource for ownership in snapshot.ownerships),
        *(resource.resource for resource in snapshot.resources),
    }
    roles = {grant.role for grant in snapshot.grants}
    roles.update(binding.role for binding in snapshot.bindings)
    permissions = {
        *(grant.permission for grant in snapshot.grants),
        *(requirement.permission for requirement in snapshot.requirements),
        *(application.permission for application in snapshot.applications),
    }
    resource_types = {
        *(application.resource_type for application in snapshot.applications),
        *(target.resource_type for target in snapshot.targets),
        *(
            resource.resource_type
            for resource in snapshot.resources
            if resource.resource_type
        ),
    }
    scopes = {binding.scope for binding in snapshot.bindings}
    scopes.update(
        endpoint
        for containment in snapshot.containments
        for endpoint in (containment.child, containment.parent)
    )

    declarations: list[Fact] = []
    declarations.extend(
        _declaration("principal", value, "Subject") for value in subjects
    )
    declarations.extend(_declaration("role", value, "Role") for value in roles)
    declarations.extend(
        _declaration("permission", value, "Permission") for value in permissions
    )
    declarations.extend(_declaration("action", value, "Action") for value in actions)
    declarations.extend(
        _declaration("resource", value, "Resource") for value in resources
    )
    declarations.extend(
        _declaration("resource", value, "ResourceType") for value in resource_types
    )
    declarations.extend(_scope_declaration(value, resource_ids) for value in scopes)
    return declarations


def _scope_atom(value: str, resource_ids: set[str]) -> Atom:
    return _atom("resource" if value in resource_ids else "scope", value)


def _scope_declaration(value: str, resource_ids: set[str]) -> Fact:
    kind = "resource" if value in resource_ids else "scope"
    return _declaration(kind, value, "Scope")


def _declaration(kind: str, value: str, type_name: str) -> Fact:
    return _fact(
        "is",
        (_atom(kind, value), Atom(value=type_name)),
    )


def _atom(kind: str, value: str) -> Atom:
    if not value:
        raise ValueError(f"policy {kind} must not be empty")
    return Atom(value=f"{kind}:{value}")


def _fact(name: str, args: tuple[Atom, ...]) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name(name),
        args=args,
    )
