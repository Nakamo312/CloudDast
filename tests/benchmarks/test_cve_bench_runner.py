"""Tests for CVE-Bench task selection and callback execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from benchmarks.cve_bench import CveBenchTask, CveBenchTaskRunner


def _task(
    task_id: str,
    variant: str,
    *,
    attacker_role: str = "user",
    contract_source: str | None = None,
) -> CveBenchTask:
    document: dict[str, Any] = {
        "task_id": task_id,
        "variant": variant,
        "admin_username": "synthetic-admin",
        "application_url": f"{task_id}.internal:9090",
        "attacker_role": attacker_role,
        "default_password": "synthetic-password",
        "default_username": "synthetic-user",
        "denial_of_service_duration": 15,
        "outbound_service_url": "synthetic-outbound.internal:8000",
        "proof_uploading_url": "synthetic-proof.internal/upload",
        "remote_code_executable_path": "/synthetic/pwn",
        "secret_file_path": "/synthetic/secret",
        "secret_table_name": "synthetic_secret",
        "success_criteria": (
            {"criterion_id": "proof-upload", "kind": "proof-uploaded"},
        ),
    }
    if contract_source is not None:
        document["contract_source"] = contract_source
        document["contract_path"] = "contract.yaml"
    return CveBenchTask.model_validate(document)


def test_runner_enumerates_and_selects_by_objective_criteria() -> None:
    zero_day = _task("synthetic-a", "zero_day")
    one_day = _task("synthetic-b", "one_day", attacker_role="administrator")
    contract_task = _task(
        "synthetic-c",
        "zero_day",
        contract_source="openapi",
    )
    runner = CveBenchTaskRunner((zero_day, one_day, contract_task))

    assert runner.tasks == (zero_day, one_day, contract_task)
    assert runner.select(variants="one_day") == (one_day,)
    assert runner.select(task_ids=("synthetic-a", "synthetic-c")) == (
        zero_day,
        contract_task,
    )
    assert runner.select(contract_sources="openapi") == (contract_task,)
    assert runner.select(variants=()) == ()
    assert runner.select(task_ids=()) == ()
    assert runner.select(contract_sources=()) == ()
    assert (
        runner.select(
            variants="zero_day",
            where=lambda task: task.attacker_role == "administrator",
        )
        == ()
    )


def test_selection_rejects_unknown_values() -> None:
    runner = CveBenchTaskRunner((_task("synthetic-a", "zero_day"),))

    with pytest.raises(ValueError, match="unknown CVE-Bench task id"):
        runner.select(task_ids="missing")
    with pytest.raises(ValueError, match="unknown CVE-Bench variant"):
        runner.select(variants="two_day")
    with pytest.raises(ValueError, match="unknown CVE-Bench contract source"):
        runner.select(contract_sources="documentation")


def test_runner_executes_callback_only_for_selected_tasks() -> None:
    zero_day = _task("synthetic-a", "zero_day")
    one_day = _task("synthetic-b", "one_day")
    runner = CveBenchTaskRunner((zero_day, one_day))
    calls: list[tuple[str, str]] = []

    def callback(task: CveBenchTask) -> str:
        calls.append(task.identity)
        return f"done:{task.task_id}"

    executions = runner.run(callback, variants="one_day")

    assert calls == [("synthetic-b", "one_day")]
    assert len(executions) == 1
    assert executions[0].task is one_day
    assert executions[0].task_id == "synthetic-b"
    assert executions[0].variant == "one_day"
    assert executions[0].result == "done:synthetic-b"


def test_runner_can_be_loaded_from_directory_without_docker(
    tmp_path: Path,
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text("openapi: 3.1.0\n", encoding="utf-8")
    document = _task(
        "synthetic-a",
        "zero_day",
        contract_source="openapi",
    ).model_dump(mode="json")
    (tmp_path / "task.yml").write_text(yaml.safe_dump(document), encoding="utf-8")

    runner = CveBenchTaskRunner.from_directory(tmp_path)

    assert runner.select(variants="zero_day") == runner.tasks
    assert runner.tasks[0].contract_path == contract.resolve()


def test_runner_rejects_duplicate_identities_and_propagates_callback_errors() -> None:
    task = _task("synthetic-a", "zero_day")

    with pytest.raises(ValueError, match="task identities must be unique"):
        CveBenchTaskRunner((task, task))

    runner = CveBenchTaskRunner((task,))

    def failing_callback(task: CveBenchTask) -> str:
        raise RuntimeError("synthetic callback failure")

    with pytest.raises(RuntimeError, match="synthetic callback failure"):
        runner.run(failing_callback)
