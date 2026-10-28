"""Tests for CVE-Bench metadata validation and loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from benchmarks.cve_bench import load_cve_bench_tasks


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "task_id": "synthetic-task",
        "variant": "zero_day",
        "additional_info": "Synthetic application instructions.",
        "admin_username": "synthetic-admin",
        "admin_password": "synthetic-admin-password",
        "application_url": "synthetic-app.internal:9090",
        "attacker_role": "user",
        "default_password": "synthetic-password",
        "default_username": "synthetic-user",
        "denial_of_service_duration": 15,
        "outbound_service_url": "synthetic-outbound.internal:8000",
        "proof_uploading_url": "synthetic-proof.internal/upload",
        "remote_code_executable_path": "/synthetic/pwn",
        "secret_file_path": "/synthetic/secret",
        "secret_table_name": "synthetic_secret",
        "success_criteria": (
            {
                "criterion_id": "proof-upload",
                "kind": "proof-uploaded",
                "target": "synthetic-proof.internal/upload",
            },
        ),
    }
    document.update(overrides)
    return document


def _write_task(root: Path, filename: str, document: dict[str, Any]) -> Path:
    path = root / filename
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_loads_public_schema_shape_and_resolves_contract_sidecar(
    tmp_path: Path,
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text("openapi: 3.1.0\n", encoding="utf-8")
    _write_task(
        tmp_path,
        "task-a.yml",
        _document(
            contract_source="openapi",
            contract_path="contract.yaml",
        ),
    )

    tasks = load_cve_bench_tasks(tmp_path)

    assert len(tasks) == 1
    task = tasks[0]
    assert task.task_id == "synthetic-task"
    assert task.variant == "zero_day"
    assert task.application_url == "synthetic-app.internal:9090"
    assert task.attacker_role == "user"
    assert task.admin_username == "synthetic-admin"
    assert task.default_username == "synthetic-user"
    assert task.outbound_service_url == "synthetic-outbound.internal:8000"
    assert task.proof_uploading_url == "synthetic-proof.internal/upload"
    assert task.secret_file_path == "/synthetic/secret"
    assert task.secret_table_name == "synthetic_secret"
    assert task.remote_code_executable_path == "/synthetic/pwn"
    assert task.contract_source == "openapi"
    assert task.contract_path == contract.resolve()
    assert task.success_criteria[0].criterion_id == "proof-upload"


def test_loads_multiple_yaml_suffixes_and_variants(tmp_path: Path) -> None:
    _write_task(tmp_path, "task-a.yml", _document(variant="zero_day"))
    _write_task(
        tmp_path,
        "task-b.yaml",
        _document(
            task_id="synthetic-task-b",
            variant="one_day",
            attacker_role="administrator",
        ),
    )

    tasks = load_cve_bench_tasks(tmp_path)

    assert [(task.task_id, task.variant) for task in tasks] == [
        ("synthetic-task", "zero_day"),
        ("synthetic-task-b", "one_day"),
    ]


def test_rejects_unknown_variant_and_missing_required_field(
    tmp_path: Path,
) -> None:
    _write_task(tmp_path, "unknown-variant.yml", _document(variant="two_day"))

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "two_day" in str(exc)
    else:
        raise AssertionError("unknown variant was accepted")

    (tmp_path / "unknown-variant.yml").unlink()
    _write_task(
        tmp_path,
        "missing-field.yaml",
        {key: value for key, value in _document().items() if key != "application_url"},
    )

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "application_url" in str(exc)
    else:
        raise AssertionError("missing required field was accepted")


def test_rejects_duplicate_task_identity(tmp_path: Path) -> None:
    first = _write_task(tmp_path, "first.yml", _document())
    second = _write_task(tmp_path, "second.yaml", _document())

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "duplicate CVE-Bench task identity" in str(exc)
        assert first.name in str(exc)
        assert second.name in str(exc)
    else:
        raise AssertionError("duplicate task identity was accepted")


def test_requires_complete_contract_reference(tmp_path: Path) -> None:
    _write_task(
        tmp_path,
        "incomplete-contract.yml",
        _document(contract_source="manifest"),
    )

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "requires contract_path" in str(exc)
    else:
        raise AssertionError("incomplete contract reference was accepted")

    (tmp_path / "incomplete-contract.yml").unlink()
    _write_task(
        tmp_path,
        "missing-contract.yml",
        _document(
            contract_source="openapi",
            contract_path="missing-openapi.yaml",
        ),
    )

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "contract file" in str(exc)
    else:
        raise AssertionError("missing contract file was accepted")


def test_probe_contract_source_does_not_require_a_file(tmp_path: Path) -> None:
    _write_task(
        tmp_path,
        "probe-task.yml",
        _document(contract_source="probe"),
    )

    tasks = load_cve_bench_tasks(tmp_path)

    assert tasks[0].contract_source == "probe"
    assert tasks[0].contract_path is None


def test_rejects_non_mapping_yaml_and_duplicate_criteria(
    tmp_path: Path,
) -> None:
    (tmp_path / "not-a-mapping.yml").write_text("- synthetic\n", encoding="utf-8")

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "must contain a YAML mapping" in str(exc)
    else:
        raise AssertionError("non-mapping YAML was accepted")

    (tmp_path / "not-a-mapping.yml").unlink()
    _write_task(
        tmp_path,
        "duplicate-criteria.yml",
        _document(
            success_criteria=(
                {"criterion_id": "same", "kind": "first"},
                {"criterion_id": "same", "kind": "second"},
            ),
        ),
    )

    try:
        load_cve_bench_tasks(tmp_path)
    except ValueError as exc:
        assert "success criterion identifiers must be unique" in str(exc)
    else:
        raise AssertionError("duplicate success criteria were accepted")
