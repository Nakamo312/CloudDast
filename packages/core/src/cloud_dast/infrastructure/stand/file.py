"""File-backed stand source."""

from __future__ import annotations

from pathlib import Path

from pydantic import TypeAdapter

from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.policy_projection import (
    GenericPolicyProjector,
    PolicySnapshot,
)

_SNAPSHOT_ADAPTER = TypeAdapter(PolicySnapshot)


class FileStandSource:
    """Read a versioned ``stand.json`` launch fixture."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()

    def snapshot(self, service: str) -> PolicySnapshot:
        del service  # the stand is shared; the source id carries the service
        snapshot = _SNAPSHOT_ADAPTER.validate_json(
            self._path.read_text(encoding="utf-8")
        )
        _validate_snapshot(snapshot)
        return snapshot

    def project(self, service: str) -> QdlGraph:
        return GenericPolicyProjector(self.snapshot(service)).project(service)


def _validate_snapshot(snapshot: PolicySnapshot) -> None:
    """Reject malformed launch fixtures before they reach QDL projection."""

    for scope in snapshot.completeness:
        _require(scope.service, "completeness service")
        _require(scope.subject, "completeness subject")
        _require(scope.action, "completeness action")
        if not scope.resources:
            raise ValueError("policy completeness resources must not be empty")
        for resource_id in scope.resources:
            _require(resource_id, "completeness resource")
            resources = tuple(
                resource
                for resource in snapshot.resources
                if resource.resource == resource_id
            )
            if not resources:
                raise ValueError(
                    "policy completeness requires declared resource instances"
                )
            if any(
                resource.service not in (None, scope.service) for resource in resources
            ):
                raise ValueError(
                    "policy completeness resource belongs to another service"
                )
    for binding in snapshot.bindings:
        _require(binding.subject, "binding subject")
        _require(binding.role, "binding role")
        _require(binding.scope, "binding scope")
    for resource in snapshot.resources:
        _require(resource.resource, "resource")
        if resource.resource_type is not None:
            _require(resource.resource_type, "resource type")
        if resource.service is not None:
            _require(resource.service, "resource service")
    for containment in snapshot.containments:
        _require(containment.child, "containment child")
        _require(containment.parent, "containment parent")


def _require(value: str, name: str) -> None:
    if not value.strip():
        raise ValueError(f"policy {name} must not be empty")
