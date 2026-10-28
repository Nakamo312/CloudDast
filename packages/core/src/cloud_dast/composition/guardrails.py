from __future__ import annotations

import logging
import os
import urllib.parse
from collections.abc import Mapping
from fnmatch import fnmatchcase

from cloud_dast.model import (
    Check,
    Observation,
)
from cloud_dast.ports import Guardrail, MethodRepository, Target

logger = logging.getLogger("cloud_dast.guardrails")


class AllowlistGuardrail:
    """Deny-by-default execution policy backed by an environment allowlist.

    A check is allowed only when all of the following hold:

    * its method belongs to an allowed service;
    * its method matches the method allowlist (``*`` permits every method of
      an already allowed service);
    * every identity used by the check matches the identity allowlist.

    Service membership is resolved through the method repository rather than
    guessed from a method name. An unknown method is therefore denied.
    """

    def __init__(
        self,
        *,
        allowed_services: frozenset[str],
        allowed_methods: frozenset[str],
        allowed_identities: frozenset[str],
        service_by_method: Mapping[str, str],
    ) -> None:
        self._allowed_services = allowed_services
        self._allowed_methods = allowed_methods
        self._allowed_identities = allowed_identities
        self._service_by_method = dict(service_by_method)

    @classmethod
    def from_environment(
        cls, method_repository: MethodRepository
    ) -> AllowlistGuardrail:
        services = _env_set("CLOUD_DAST_ALLOWED_SERVICES")
        if any("*" in service or "?" in service for service in services):
            raise ValueError(
                "CLOUD_DAST_ALLOWED_SERVICES must contain exact canonical service IDs"
            )
        methods = _env_set("CLOUD_DAST_ALLOWED_METHODS", default=("*",))
        identities = _env_set("CLOUD_DAST_ALLOWED_IDENTITIES")

        service_by_method: dict[str, str] = {}
        for service in services:
            for method in method_repository.list_methods(service):
                service_by_method[method.method_id] = service

        return cls(
            allowed_services=services,
            allowed_methods=methods,
            allowed_identities=identities,
            service_by_method=service_by_method,
        )

    def allows(self, check: Check) -> bool:
        service = self._service_by_method.get(check.method_id)
        if service is None or service not in self._allowed_services:
            return False
        if not self._method_allowed(check.method_id):
            return False
        return self._identities_allowed(check.identities)

    def _method_allowed(self, method_id: str) -> bool:
        if "*" in self._allowed_methods:
            return True
        return _matches_any(method_id, self._allowed_methods)

    def _identities_allowed(self, identities: tuple[str, ...]) -> bool:
        if not identities:
            return False
        return all(
            _matches_any(identity, self._allowed_identities) for identity in identities
        )


class AllowlistEndpointPolicy:
    """Deny-by-default destination policy backed by environment patterns.

    A destination is allowed only when its graph-provided value matches an
    operator-configured fnmatch pattern. gRPC destinations use ``host:port``;
    HTTP destinations use an explicit ``http://`` or ``https://`` origin or
    base URL. Host-only gRPC patterns also match that host with any explicit
    port.
    """

    def __init__(self, patterns: frozenset[str]) -> None:
        self._patterns = patterns

    @classmethod
    def from_environment(cls) -> AllowlistEndpointPolicy:
        patterns = _env_set("CLOUD_DAST_ALLOWED_ENDPOINTS")
        if not patterns:
            raise ValueError(
                "CLOUD_DAST_ALLOWED_ENDPOINTS is required; set comma-separated "
                "host or host:port patterns"
            )
        return cls(patterns)

    def allows(self, endpoint: str) -> bool:
        candidates = _endpoint_candidates(endpoint)
        allowed = any(
            fnmatchcase(candidate, pattern)
            for candidate in candidates
            for pattern in self._patterns
        )
        display = endpoint if candidates else "<invalid endpoint>"
        logger.info("endpoint_policy_decision endpoint=%s allowed=%s", display, allowed)
        return allowed


class GuardedTarget:
    """Enforce the campaign guardrail before any target execution."""

    def __init__(self, target: Target, guardrail: Guardrail) -> None:
        self._target = target
        self._guardrail = guardrail

    def __call__(self, check: Check) -> Observation:
        if not self._guardrail.allows(check):
            raise PermissionError(f"check denied by guardrail: {check.method_id}")
        return self._target(check)


def _env_set(name: str, *, default: tuple[str, ...] = ()) -> frozenset[str]:
    raw = os.environ.get(name)
    if raw is None:
        raw = ",".join(default)
    values = {item.strip() for item in raw.split(",")}
    return frozenset(value for value in values if value)


def _matches_any(value: str, patterns: frozenset[str]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _endpoint_candidates(endpoint: str) -> tuple[str, ...]:
    """Return safe destination forms for endpoint-policy matching."""

    if not endpoint or any(
        character.isspace() or not character.isprintable() for character in endpoint
    ):
        return ()
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme in {"http", "https"}:
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return ()
        if not parsed.hostname:
            return ()
        try:
            parsed.port
        except ValueError:
            return ()
        return (endpoint.rstrip("/"),)
    if any(character in endpoint for character in "/?#@"):
        return ()
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        if closing == -1:
            return ()
        host = endpoint[: closing + 1]
        remainder = endpoint[closing + 1 :]
        if remainder and not remainder.startswith(":"):
            return ()
        port = remainder[1:]
        if not port or not _is_port(port):
            return ()
        return endpoint, host
    host, separator, port = endpoint.rpartition(":")
    if not separator:
        return (endpoint,)
    if not host or ":" in host or not port or not _is_port(port):
        return ()
    return endpoint, host


def _is_port(value: str) -> bool:
    return value.isascii() and value.isdigit()


__all__ = [
    "AllowlistEndpointPolicy",
    "AllowlistGuardrail",
    "GuardedTarget",
    "Guardrail",
]
