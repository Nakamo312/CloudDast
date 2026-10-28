from __future__ import annotations

import sys

import pytest

from cloud_dast.composition import check_live_prerequisites
from cloud_dast.infrastructure.runtime import EnvironmentTokenProvider
from cloud_dast.infrastructure.runtime import tokens as tokens_module
from cloud_dast.infrastructure.runtime.tokens import FILE_TOKEN_CACHE_TTL_SECONDS


def test_token_provider_can_fetch_token_with_command(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER", raising=False)
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER_FILE", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_FILE", raising=False)
    command = f"{sys.executable} -c \"print('t1.command-token')\""
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_COMMAND", command)

    metadata = EnvironmentTokenProvider().metadata("attacker")

    assert metadata == (("authorization", "Bearer t1.command-token"),)


def test_token_command_can_take_precedence_over_static_secret(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER", "t1.static")
    monkeypatch.setenv("CLOUD_DAST_IAM_TOKEN_PREFER_COMMAND", "1")
    command = f"{sys.executable} -c \"print('t1.fresh')\""
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_COMMAND", command)

    metadata = EnvironmentTokenProvider().metadata("attacker")

    assert metadata == (("authorization", "Bearer t1.fresh"),)


def test_token_command_failure_does_not_leak_output(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER", raising=False)
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER_FILE", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_FILE", raising=False)
    command = f'{sys.executable} -c "raise SystemExit(7)"'
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_COMMAND", command)

    try:
        EnvironmentTokenProvider().metadata("attacker")
    except RuntimeError as error:
        message = str(error)
        assert "exit code 7" in message
        assert "SystemExit" not in message
        assert "t1." not in message
    else:  # pragma: no cover - assertion guard
        raise AssertionError("token command failure must raise RuntimeError")


def test_live_preflight_accepts_token_command(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_COMMAND", "true")

    result = check_live_prerequisites("attacker")

    assert not any("IAM token" in item for item in result.missing)


def test_explicit_identity_does_not_use_global_token(monkeypatch) -> None:
    for name in (
        "CLOUD_DAST_TOKEN_ATTACKER",
        "CLOUD_DAST_TOKEN_ATTACKER_FILE",
        "CLOUD_DAST_TOKEN_ATTACKER_COMMAND",
        "CLOUD_DAST_IAM_TOKEN",
        "CLOUD_DAST_IAM_TOKEN_FILE",
        "CLOUD_DAST_IAM_TOKEN_COMMAND",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUD_DAST_IAM_TOKEN", "t1.global")
    monkeypatch.setenv(
        "CLOUD_DAST_IAM_TOKEN_COMMAND",
        f"{sys.executable} -c \"print('t1.global-command')\"",
    )

    with pytest.raises(RuntimeError) as error:
        EnvironmentTokenProvider().metadata("attacker")

    message = str(error.value)
    assert "CLOUD_DAST_TOKEN_ATTACKER" in message
    assert "CLOUD_DAST_IAM_TOKEN" not in message


def test_explicit_identity_uses_identity_specific_token(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER", "t1.identity")
    monkeypatch.setenv("CLOUD_DAST_IAM_TOKEN", "t1.global")

    metadata = EnvironmentTokenProvider().metadata("attacker")

    assert metadata == (("authorization", "Bearer t1.identity"),)


def test_identity_key_collision_is_rejected(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_FILE", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_COMMAND", raising=False)
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_1", "t1.identity")
    provider = EnvironmentTokenProvider()

    assert provider.metadata("attacker-1")

    with pytest.raises(RuntimeError) as error:
        provider.metadata("attacker_1")

    message = str(error.value)
    assert "ATTACKER_1" in message
    assert "attacker-1" in message
    assert "attacker_1" in message


def test_file_token_cache_expires_after_short_ttl(monkeypatch, tmp_path) -> None:
    token_file = tmp_path / "iam-token"
    token_file.write_text("t1.file", encoding="utf-8")
    monkeypatch.setenv("CLOUD_DAST_TOKEN_ATTACKER_FILE", str(token_file))
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER", raising=False)
    monkeypatch.delenv("CLOUD_DAST_TOKEN_ATTACKER_COMMAND", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_FILE", raising=False)
    monkeypatch.delenv("CLOUD_DAST_IAM_TOKEN_COMMAND", raising=False)

    class Clock:
        def __init__(self) -> None:
            self.now = 0.0

        def monotonic(self) -> float:
            return self.now

    clock = Clock()
    monkeypatch.setattr(tokens_module, "time", clock)
    provider = EnvironmentTokenProvider()

    assert provider.metadata("attacker") == (("authorization", "Bearer t1.file"),)
    clock.now = FILE_TOKEN_CACHE_TTL_SECONDS - 0.1
    assert provider.metadata("attacker") == (("authorization", "Bearer t1.file"),)
    token_file.write_text("t2.file", encoding="utf-8")
    clock.now = FILE_TOKEN_CACHE_TTL_SECONDS
    assert provider.metadata("attacker") == (("authorization", "Bearer t2.file"),)
