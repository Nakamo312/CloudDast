from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from cloud_dast.composition.profile import (
    apply_profile_environment,
    classification_profile_from_environment,
    load_classification_profile,
    load_profile,
    parse_environment_flag,
    resolve_live_settings,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _args(**overrides):
    values = {
        "service": None,
        "identity": None,
        "principal_id": None,
        "resource_id": None,
        "method_id": None,
        "max_checks": None,
        "event_log": None,
        "environment": None,
        "timeout": None,
        "safe_field": [],
        "progress": None,
        "progress_color": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_environment_flag_parser_honors_default_and_custom_environment() -> None:
    assert parse_environment_flag("TEST_FLAG") is False
    assert parse_environment_flag("TEST_FLAG", default=True, environ={}) is True
    assert parse_environment_flag("TEST_FLAG", environ={"TEST_FLAG": " ON "}) is True


def test_profile_applies_non_secret_defaults_and_resolves_campaign(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "lockbox.toml"
    path.write_text(
        """
service = "lockbox"
identity_env = "TEST_IDENTITY"
principal_id_env = "TEST_PRINCIPAL"
resource_id_env = "TEST_RESOURCE"
environment_env = "TEST_ENVIRONMENT"
event_log_dir = "/tmp/nsfy"
progress = "live"
timeout = 30.0

[model]
id = "glm-5.3"
api = "responses"
reasoning_effort = "low"
timeout = 180.0
retries = 1

[grounding]
skip_llm = false
cache = true
workers = 4
reactive_workers = 4
batch_size = 8
promote_proposals = true

[differential]
mode = true
modes = ["payload", "readback", "timing", "concurrency"]

[neo4j]
uri = "bolt://localhost:7687"
user = "neo4j"
password_file_env = "TEST_NEO4J_PASSWORD_FILE"

[stand]
source = "file"
file = "stand.json"

[runtime]
allowed = ["lockbox"]
setup_identity = "setup-account"
iam_token_prefer_command = true
descriptor_set_env = "TEST_DESCRIPTOR_SET"
""",
        encoding="utf-8",
    )
    for name in (
        "TEST_IDENTITY",
        "TEST_PRINCIPAL",
        "TEST_RESOURCE",
        "TEST_ENVIRONMENT",
        "TEST_NEO4J_PASSWORD_FILE",
        "TEST_DESCRIPTOR_SET",
    ):
        monkeypatch.setenv(name, f"value-{name}")
    for name in (
        "CLOUD_DAST_MODEL_ID",
        "CLOUD_DAST_MODEL_API",
        "CLOUD_DAST_DIFF_MODE",
        "CLOUD_DAST_DIFF_MODES",
        "CLOUD_DAST_SKIP_LLM_GROUNDING",
        "CLOUD_DAST_GROUNDING_CACHE",
        "CPA_NEO4J_URI",
        "CPA_NEO4J_USER",
        "CPA_NEO4J_PASSWORD_FILE",
        "CLOUD_DAST_STAND_SOURCE",
        "CLOUD_DAST_STAND_FILE",
        "CLOUD_DAST_ALLOWED_SERVICES",
    ):
        monkeypatch.delenv(name, raising=False)

    profile = load_profile(path)
    environment: dict[str, str] = {}
    apply_profile_environment(profile, environment)
    settings = resolve_live_settings(_args(), profile)

    assert settings.service == "lockbox"
    assert settings.identity == "value-TEST_IDENTITY"
    assert settings.principal_id == "value-TEST_PRINCIPAL"
    assert settings.resource_id == "value-TEST_RESOURCE"
    assert settings.environment == "value-TEST_ENVIRONMENT"
    assert settings.event_log_dir == "/tmp/nsfy"
    assert settings.progress == "live"
    assert environment["CLOUD_DAST_MODEL_ID"] == "glm-5.3"
    assert environment["CLOUD_DAST_GROUNDING_CACHE"] == "1"
    assert environment["CLOUD_DAST_REACTIVE_WORKERS"] == "4"
    assert environment["CLOUD_DAST_DIFF_MODE"] == "1"
    assert environment["CLOUD_DAST_DIFF_MODES"] == "payload,readback,timing,concurrency"
    assert environment["CPA_NEO4J_PASSWORD_FILE"] == "value-TEST_NEO4J_PASSWORD_FILE"
    assert environment["CLOUD_DAST_STAND_SOURCE"] == "file"
    assert environment["CLOUD_DAST_STAND_FILE"] == "stand.json"
    assert environment["CLOUD_DAST_ALLOWED_SERVICES"] == "lockbox"


def test_differential_profile_overrides_stale_environment(tmp_path) -> None:
    path = tmp_path / "differential.toml"
    path.write_text(
        """
service = "lockbox"

[differential]
mode = true
modes = ["factors", "payload", "readback", "timing", "concurrency"]
""",
        encoding="utf-8",
    )
    environment = {
        "CLOUD_DAST_DIFF_MODE": "0",
        "CLOUD_DAST_DIFF_MODES": "factors",
    }

    apply_profile_environment(load_profile(path), environment)

    assert environment["CLOUD_DAST_DIFF_MODE"] == "1"
    assert (
        environment["CLOUD_DAST_DIFF_MODES"]
        == "factors,payload,readback,timing,concurrency"
    )


@pytest.mark.parametrize(
    "profile_name",
    ["nsfy-bench-full.toml", "nsfy-bench-llm.toml"],
)
def test_nsfy_profiles_enable_complete_differential_regression(profile_name) -> None:
    profile = load_profile(
        _PROJECT_ROOT / "benchmarks" / "nsfy-bench" / "profiles" / profile_name
    )

    assert profile.differential.mode is True
    assert profile.differential.modes == (
        "factors",
        "payload",
        "readback",
        "timing",
        "concurrency",
    )


def test_profile_overrides_stale_non_secret_environment(tmp_path) -> None:
    path = tmp_path / "lockbox.toml"
    path.write_text(
        """
service = "lockbox"

[model]
id = "glm-5.3"

[grounding]
skip_llm = true

[runtime]
allowed = ["lockbox"]
""",
        encoding="utf-8",
    )
    environment = {
        "CLOUD_DAST_MODEL_ID": "glm-4.5",
        "CLOUD_DAST_SKIP_LLM_GROUNDING": "0",
        "CLOUD_DAST_ALLOWED_SERVICES": "certificate-manager",
    }

    apply_profile_environment(load_profile(path), environment)

    assert environment["CLOUD_DAST_MODEL_ID"] == "glm-5.3"
    assert environment["CLOUD_DAST_SKIP_LLM_GROUNDING"] == "1"
    assert environment["CLOUD_DAST_ALLOWED_SERVICES"] == "lockbox"


def test_omitted_profile_fields_keep_environment_defaults(tmp_path) -> None:
    path = tmp_path / "minimal.toml"
    path.write_text(
        """
service = "lockbox"
""",
        encoding="utf-8",
    )
    environment = {
        "CLOUD_DAST_MODEL_ID": "environment-model",
        "CLOUD_DAST_SKIP_LLM_GROUNDING": "1",
        "CLOUD_DAST_ALLOWED_SERVICES": "lockbox",
    }

    apply_profile_environment(load_profile(path), environment)

    assert environment["CLOUD_DAST_MODEL_ID"] == "environment-model"
    assert environment["CLOUD_DAST_SKIP_LLM_GROUNDING"] == "1"
    assert environment["CLOUD_DAST_ALLOWED_SERVICES"] == "lockbox"


def test_profile_explicit_resets_clear_stale_environment(tmp_path) -> None:
    path = tmp_path / "reset.toml"
    path.write_text(
        """
service = "lockbox"
event_log = ""

[model]
id = ""

[grounding]
cache_dir = ""

[neo4j]
password_file_env = ""

[stand]
file = ""

[runtime]
allowed = []
setup_identity = ""
descriptor_set_env = "MISSING_DESCRIPTOR_SET"
""",
        encoding="utf-8",
    )
    environment = {
        "CLOUD_DAST_EVENT_LOG": "/tmp/stale-events.jsonl",
        "CLOUD_DAST_MODEL_ID": "stale-model",
        "CLOUD_DAST_GROUNDING_CACHE_DIR": "/tmp/stale-grounding",
        "CPA_NEO4J_PASSWORD_FILE": "/tmp/stale-password",
        "CLOUD_DAST_STAND_FILE": "/tmp/stale-stand.json",
        "CLOUD_DAST_ALLOWED_SERVICES": "certificate-manager",
        "CLOUD_DAST_SETUP_IDENTITY": "stale-setup",
        "CLOUD_DAST_DESCRIPTOR_SET": "/tmp/stale.pb",
    }

    apply_profile_environment(load_profile(path), environment)

    assert "CLOUD_DAST_EVENT_LOG" not in environment
    assert "CLOUD_DAST_MODEL_ID" not in environment
    assert "CLOUD_DAST_GROUNDING_CACHE_DIR" not in environment
    assert "CPA_NEO4J_PASSWORD_FILE" not in environment
    assert "CLOUD_DAST_STAND_FILE" not in environment
    assert "CLOUD_DAST_ALLOWED_SERVICES" not in environment
    assert "CLOUD_DAST_SETUP_IDENTITY" not in environment
    assert "CLOUD_DAST_DESCRIPTOR_SET" not in environment


def test_cli_arguments_override_profile_defaults(tmp_path, monkeypatch) -> None:
    path = tmp_path / "minimal.toml"
    path.write_text(
        """
service = "profile-service"
identity = "profile-identity"
resource_id = "profile-resource"
progress = "plain"
""",
        encoding="utf-8",
    )
    profile = load_profile(path)
    args = _args(
        service="cli-service",
        identity="cli-identity",
        resource_id="cli-resource",
        progress="live",
    )

    settings = resolve_live_settings(args, profile)

    assert settings.service == "cli-service"
    assert settings.identity == "cli-identity"
    assert settings.resource_id == "cli-resource"
    assert settings.progress == "live"


def test_curated_classification_profile_is_loaded_and_applied() -> None:
    profile = load_profile(_PROJECT_ROOT / "profiles" / "lockbox.toml")
    environment: dict[str, str] = {}

    apply_profile_environment(profile, environment)
    classification = classification_profile_from_environment(environment)

    expected_path = (_PROJECT_ROOT / "profiles" / "data-classification.toml").resolve()
    assert profile.classification.path == str(expected_path)
    assert classification.roles["secret"] == ("sensitive",)
    assert classification.sink_types["sql"] == ("interpreter",)


def test_internal_glm52_profile_selects_eliza_without_secrets() -> None:
    profile = load_profile(_PROJECT_ROOT / "profiles" / "lockbox-eliza-glm52.toml")
    environment: dict[str, str] = {}

    apply_profile_environment(profile, environment)

    assert environment["CLOUD_DAST_MODEL_ID"] == "internal/glm-5-2"
    assert environment["CLOUD_DAST_MODEL_API"] == "chat"
    assert (
        environment["CLOUD_DAST_MODEL_URL"]
        == "https://api.eliza.yandex.net/internal/glm-5-2/v1"
    )
    assert "CLOUD_DAST_MODEL_TOKEN" not in environment
    assert "CLOUD_DAST_MODEL_TOKEN_FILE" not in environment


def test_internal_glm52_profile_bounds_reactive_grounding_fanout() -> None:
    profile = load_profile(
        _PROJECT_ROOT
        / "benchmarks"
        / "nsfy-bench"
        / "profiles"
        / "nsfy-bench-eliza-glm52.toml"
    )
    environment: dict[str, str] = {}

    apply_profile_environment(profile, environment)

    assert environment["CLOUD_DAST_GROUNDING_WORKERS"] == "1"
    assert environment["CLOUD_DAST_REACTIVE_WORKERS"] == "1"


def test_curated_lockbox_profile_resolves_private_namespace_alias(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_IDENTITY", "identity")
    monkeypatch.setenv("CLOUD_DAST_RESOURCE_ID", "resource")
    profile = load_profile(_PROJECT_ROOT / "profiles" / "lockbox.toml")
    settings = resolve_live_settings(_args(), profile)

    assert settings.method_prefix_aliases == {
        "grpc-priv:yandex.cloud.": "grpc-priv:yandex.cloud.priv."
    }


def test_classification_profile_file_rejects_unknown_targets(tmp_path) -> None:
    path = tmp_path / "classification.toml"
    path.write_text(
        """
schema_version = 1

[roles]
secret = ["not-a-semantic-role"]
""",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="unknown semantic roles"):
        load_classification_profile(path)


def test_explicit_empty_classification_resets_stale_environment(tmp_path) -> None:
    path = tmp_path / "reset.toml"
    path.write_text(
        """
service = "lockbox"

[classification]
path = ""
""",
        encoding="utf-8",
    )
    environment = {
        "CLOUD_DAST_CLASSIFICATION_PROFILE": '{"roles":{"secret":["sensitive"]}}'
    }

    apply_profile_environment(load_profile(path), environment)

    assert "CLOUD_DAST_CLASSIFICATION_PROFILE" not in environment
