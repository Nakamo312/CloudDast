from __future__ import annotations

import tomllib
from dataclasses import dataclass

from benchmarks.cve_bench.contract import (
    GenericContractManifest,
    GenericContractSource,
    build_contract,
)
from benchmarks.cve_bench.profile import (
    CveBenchProfileRequest,
    build_profile,
    write_profile_bundle,
)
from pydantic import TypeAdapter

from cloud_dast.composition.profile import LiveProfile, load_profile
from cloud_dast.infrastructure.stand import FileStandSource
from cloud_dast.qdl.policy_projection import PolicySnapshot


@dataclass(frozen=True)
class SyntheticTask:
    task_id: str
    service: str
    identity: str | None = None
    principal_id: str | None = None
    resource_id: str | None = None
    environment: str | None = None


def contract():
    manifest = GenericContractManifest.model_validate(
        {
            "service": "profile.v1",
            "endpoint": "http://127.0.0.1:9100",
            "methods": [
                {
                    "method_id": "http:profile.v1.readRecord",
                    "name": "readRecord",
                    "http_method": "GET",
                    "path_template": "/records/{record_id}",
                    "fields": [
                        {"name": "record_id", "type": "string", "required": True}
                    ],
                    "permissions": ["record.read"],
                    "resource_types": ["record"],
                    "body_fields": [],
                },
                {
                    "method_id": "http:profile.v1.writeRecord",
                    "name": "writeRecord",
                    "http_method": "POST",
                    "path_template": "/records/{record_id}",
                    "fields": [
                        {"name": "record_id", "type": "string", "required": True},
                        {"name": "label", "type": "string"},
                    ],
                    "permissions": ["record.write"],
                    "resource_types": ["record"],
                    "body_fields": ["label"],
                },
            ],
        }
    )
    task = SyntheticTask(
        task_id="profile-task",
        service="profile.v1",
        identity="attacker",
        resource_id="record-17",
        environment="test",
    )
    return build_contract(task, GenericContractSource(manifest))


def request() -> CveBenchProfileRequest:
    return CveBenchProfileRequest(
        identity="attacker",
        resource_id="record-17",
        resource_type="record",
        environment="test",
        method_id="http:profile.v1.readRecord",
        identity_env="CVE_BENCH_IDENTITY",
        resource_id_env="CVE_BENCH_RESOURCE_ID",
        environment_env="CVE_BENCH_ENVIRONMENT",
        event_log_dir="/tmp/cve-bench-events",
        progress="plain",
        timeout=12.5,
        max_checks=25,
        safe_fields=("record_id", "label"),
        skip_llm=True,
        authorized_method_ids=("http:profile.v1.readRecord",),
    )


def test_profile_builder_produces_a_live_profile_and_policy_snapshot() -> None:
    bundle = build_profile(contract(), request())

    assert isinstance(bundle.profile, LiveProfile)
    assert bundle.profile.service == "profile.v1"
    assert bundle.profile.identity is None
    assert bundle.profile.identity_env == "CVE_BENCH_IDENTITY"
    assert bundle.profile.principal_id == "attacker"
    assert bundle.profile.resource_id is None
    assert bundle.profile.resource_id_env == "CVE_BENCH_RESOURCE_ID"
    assert bundle.profile.environment is None
    assert bundle.profile.environment_env == "CVE_BENCH_ENVIRONMENT"
    assert bundle.profile.method_id == "http:profile.v1.readRecord"
    assert bundle.profile.stand.source == "file"
    assert bundle.profile.stand.file == "stand.json"
    assert bundle.profile.runtime.allowed == ("profile.v1",)
    assert bundle.profile.safe_fields == ("record_id", "label")

    permission = bundle.snapshot.permissions[0]
    assert (
        permission.subject,
        permission.action,
        permission.resource,
    ) == ("attacker", "http:profile.v1.readRecord", "record")
    assert bundle.snapshot.resources[0].resource == "record-17"


def test_generated_toml_is_live_profile_compatible() -> None:
    bundle = build_profile(contract(), request())
    parsed = tomllib.loads(bundle.profile_toml)
    parsed_profile = LiveProfile.model_validate(parsed)

    assert parsed_profile == bundle.profile
    assert "neo4j" not in parsed
    assert parsed["stand"] == {"source": "file", "file": "stand.json"}
    assert parsed["grounding"]["skip_llm"] is True
    assert not any(
        marker in bundle.profile_toml.lower()
        for marker in ("password", "secret", "token", "credential")
    )


def test_generated_stand_json_is_a_policy_snapshot() -> None:
    bundle = build_profile(contract(), request())
    snapshot = TypeAdapter(PolicySnapshot).validate_json(bundle.stand_json)

    assert snapshot == bundle.snapshot


def test_profile_bundle_writes_temporary_files(tmp_path) -> None:
    bundle = build_profile(contract(), request())
    paths = write_profile_bundle(
        bundle,
        tmp_path,
        profile_name="launch.toml",
        stand_name="stand.json",
    )

    assert load_profile(paths.profile_path) == bundle.profile
    assert FileStandSource(paths.stand_path).snapshot("profile.v1") == bundle.snapshot
