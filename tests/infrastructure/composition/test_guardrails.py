from __future__ import annotations

import logging

import pytest

from cloud_dast.composition.container import GuardrailProvider
from cloud_dast.composition.guardrails import (
    AllowlistEndpointPolicy,
    AllowlistGuardrail,
    GuardedTarget,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    MethodSpec,
    Observation,
)
from cloud_dast.ports import MethodRepository
from tests.support.guardrails import AllowAllGuardrail


class StaticMethodRepository:
    def list_methods(self, service: str) -> tuple[MethodSpec, ...]:
        if service != "certificate-manager":
            return ()
        return (
            MethodSpec(
                method_id="certificate-manager.v1.Get",
                service=service,
                name="Get",
                layer="private",
            ),
        )


def _check(
    method_id: str = "certificate-manager.v1.Get",
    identities: tuple[str, ...] = ("principal-1",),
) -> Check:
    return Check(
        invariant_id="invariant",
        method_id=method_id,
        scenario_id="scenario",
        request=(("certificate_id", "certificate"),),
        identities=identities,
    )


def _observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="executed",
    )


class _RecordingTarget:
    def __init__(self) -> None:
        self.checks: list[Check] = []

    def __call__(self, check: Check) -> Observation:
        self.checks.append(check)
        return _observation(check)


class _DenyGuardrail:
    def allows(self, check: Check) -> bool:
        return False


def test_guardrail_denies_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_SERVICES", raising=False)
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_METHODS", raising=False)
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_IDENTITIES", raising=False)

    guardrail = AllowlistGuardrail.from_environment(StaticMethodRepository())

    assert guardrail.allows(_check()) is False


def test_endpoint_policy_requires_environment_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_ENDPOINTS", raising=False)

    with pytest.raises(ValueError, match="CLOUD_DAST_ALLOWED_ENDPOINTS"):
        AllowlistEndpointPolicy.from_environment()


def test_endpoint_policy_matches_host_port_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "*.example.net:443")
    policy = AllowlistEndpointPolicy.from_environment()

    assert policy.allows("api.example.net:443") is True
    assert policy.allows("api.example.net:8443") is False
    assert policy.allows("evil.example.org:443") is False


def test_endpoint_policy_host_pattern_matches_any_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "*.example.net")
    policy = AllowlistEndpointPolicy.from_environment()

    assert policy.allows("api.example.net:443") is True


def test_endpoint_policy_matches_http_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "https://*.example.net")
    policy = AllowlistEndpointPolicy.from_environment()

    assert policy.allows("https://api.example.net") is True
    assert policy.allows("https://api.example.net/") is True
    assert policy.allows("http://api.example.net") is False


def test_endpoint_policy_logs_sanitized_endpoint(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_ENDPOINTS", "*.example.net:443")
    policy = AllowlistEndpointPolicy.from_environment()
    unsafe_endpoint = "https://token@example.net:443/path?token=secret"

    with caplog.at_level(logging.INFO, logger="cloud_dast.guardrails"):
        policy.allows("api.example.net:443")
        policy.allows(unsafe_endpoint)

    assert "endpoint=api.example.net:443" in caplog.text
    assert "endpoint=<invalid endpoint>" in caplog.text
    assert unsafe_endpoint not in caplog.text
    assert "secret" not in caplog.text


def test_guarded_target_blocks_check_before_target() -> None:
    target = _RecordingTarget()
    guarded_target = GuardedTarget(target, _DenyGuardrail())
    check = _check()

    with pytest.raises(PermissionError, match="denied by guardrail"):
        guarded_target(check)

    assert target.checks == []


def test_guarded_target_executes_allowed_check() -> None:
    target = _RecordingTarget()
    guarded_target = GuardedTarget(target, AllowAllGuardrail())
    check = _check()

    observation = guarded_target(check)

    assert target.checks == [check]
    assert observation.observed_outcome is AccessOutcome.ALLOWED


def test_guardrail_rejects_wildcard_service_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "*")

    with pytest.raises(ValueError, match="exact canonical service IDs"):
        AllowlistGuardrail.from_environment(StaticMethodRepository())


def test_guardrail_allows_configured_service_method_and_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-manager")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "certificate-manager.v1.*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "principal-1")

    guardrail = AllowlistGuardrail.from_environment(StaticMethodRepository())

    assert guardrail.allows(_check()) is True


def test_guardrail_denies_method_outside_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-manager")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "certificate-manager.v1.List")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "principal-1")

    guardrail = AllowlistGuardrail.from_environment(StaticMethodRepository())

    assert guardrail.allows(_check()) is False


def test_guardrail_denies_unlisted_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-manager")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "principal-1")

    guardrail = AllowlistGuardrail.from_environment(StaticMethodRepository())

    assert guardrail.allows(_check(identities=("principal-2",))) is False
    assert guardrail.allows(_check(identities=("principal-1", "principal-2"))) is False


def test_guardrail_denies_method_from_unknown_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-manager")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "*")

    guardrail = AllowlistGuardrail.from_environment(StaticMethodRepository())

    assert guardrail.allows(_check(method_id="other-service.v1.Get")) is False


def test_guardrail_provider_builds_environment_guardrail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", "certificate-manager")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "principal-1")

    guardrail = GuardrailProvider().guardrail(StaticMethodRepository())

    assert isinstance(guardrail, AllowlistGuardrail)
    assert guardrail.allows(_check()) is True


def test_method_repository_contract_is_satisfied() -> None:
    repository: MethodRepository = StaticMethodRepository()

    assert repository.list_methods("certificate-manager")
