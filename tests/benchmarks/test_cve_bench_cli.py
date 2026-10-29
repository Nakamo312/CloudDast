from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from benchmarks.cve_bench.cli import main
from benchmarks.cve_bench.models import CveBenchTask
from benchmarks.cve_bench.runtime import (
    CveBenchRunResult,
    CveBenchTaskValidationError,
    MissingContractSourceError,
    prepare_task_run,
)


def _task(
    task_id: str = "task-a",
    *,
    variant: str = "zero_day",
    contract_kind: str | None = "openapi",
    contract_path: Path | None = Path("contract.json"),
) -> CveBenchTask:
    return CveBenchTask.model_validate(
        {
            "task_id": task_id,
            "variant": variant,
            "admin_username": "synthetic-admin",
            "application_url": "https://synthetic-target.invalid",
            "attacker_role": "user",
            "default_password": "synthetic-password",
            "default_username": "synthetic-user",
            "denial_of_service_duration": 15,
            "outbound_service_url": "https://synthetic-outbound.invalid",
            "proof_uploading_url": "https://synthetic-proof.invalid/upload",
            "remote_code_executable_path": "/synthetic/path",
            "secret_file_path": "/synthetic/file",
            "secret_table_name": "synthetic_table",
            "success_criteria": ({"criterion_id": "synthetic", "kind": "synthetic"},),
            "contract_source": contract_kind,
            "contract_path": contract_path,
        }
    )


def _engine_result(*, findings: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        observations=(SimpleNamespace(check_id="check-1"),),
        findings=(SimpleNamespace(finding_id="finding-1"),) if findings else (),
    )


def _fake_harness(*, findings: bool = False) -> tuple[SimpleNamespace, list[str]]:
    events: list[str] = []

    class Harness:
        def run_task(self, task_run, *, event_log: Path, report: Path):
            events.append(f"run:{task_run.task_id}")
            event_log.parent.mkdir(parents=True, exist_ok=True)
            event_log.write_text("", encoding="utf-8")
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("{}", encoding="utf-8")
            return CveBenchRunResult(
                task_run=task_run,
                engine_result=_engine_result(findings=findings),
                event_log=event_log,
                report=report,
            )

    return SimpleNamespace(run_task=Harness().run_task), events


def test_cli_runs_selected_tasks_and_scores_after_durable_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tasks = (_task("task-a"), _task("task-b"))
    harness, events = _fake_harness()
    score_calls: list[tuple[str, Path]] = []

    def load_manifest(path: Path):
        assert path == tmp_path / "tasks"
        return tasks

    def score_run(task, result):
        assert result.report.is_file()
        score_calls.append((task.task_id, result.report))
        events.append(f"score:{task.task_id}")
        return {"matched": 1}

    monkeypatch.setattr("benchmarks.cve_bench.cli._load_tasks", load_manifest)
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli.make_cve_bench_runtime",
        lambda contract_factory: harness,
    )
    monkeypatch.setattr("benchmarks.cve_bench.cli._score_run", score_run)

    exit_code = main(
        [
            "--task-dir",
            str(tmp_path / "tasks"),
            "--task",
            "task-a",
            "--task",
            "task-b",
            "--variant",
            "zero_day",
            "--output-dir",
            str(tmp_path / "artifacts"),
        ]
    )

    assert exit_code == 0
    assert events == [
        "run:task-a",
        "score:task-a",
        "run:task-b",
        "score:task-b",
    ]
    assert [task_id for task_id, _ in score_calls] == ["task-a", "task-b"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "cloud-dast.cve-bench.cli"
    assert [run["task_id"] for run in payload["runs"]] == ["task-a", "task-b"]
    assert all(run["observations"] == 1 for run in payload["runs"])
    assert all(run["findings"] == [] for run in payload["runs"])

    for task_id in ("task-a", "task-b"):
        assert (tmp_path / "artifacts" / f"{task_id}-zero_day.events.jsonl").is_file()
        assert (tmp_path / "artifacts" / f"{task_id}-zero_day.report.json").is_file()
        score_path = tmp_path / "artifacts" / f"{task_id}-zero_day.score.json"
        assert score_path.is_file()
        score = json.loads(score_path.read_text(encoding="utf-8"))
        assert score["score"] == {"matched": 1}


def test_cli_returns_one_when_a_task_has_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    harness, _ = _fake_harness(findings=True)
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._load_tasks",
        lambda path: (_task(variant="one_day"),),
    )
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli.make_cve_bench_runtime",
        lambda contract_factory: harness,
    )
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._score_run",
        lambda task, result: {},
    )

    exit_code = main(
        [
            "--task-dir",
            str(tmp_path / "tasks"),
            "--task",
            "task-a",
            "--variant",
            "one_day",
            "--output-dir",
            str(tmp_path / "artifacts"),
        ]
    )

    assert exit_code == 1


def test_cli_fails_fast_when_a_selected_task_has_no_contract_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "artifacts"
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._load_tasks",
        lambda path: (_task(contract_kind=None, contract_path=None),),
    )

    def fail_runtime(contract_factory):
        raise AssertionError("runtime must not be created without a contract source")

    monkeypatch.setattr(
        "benchmarks.cve_bench.cli.make_cve_bench_runtime",
        fail_runtime,
    )

    with pytest.raises(MissingContractSourceError, match="task-a"):
        main(
            [
                "--task-dir",
                str(tmp_path / "tasks"),
                "--task",
                "task-a",
                "--variant",
                "zero_day",
                "--output-dir",
                str(output_dir),
            ]
        )

    assert not output_dir.exists()


def test_cli_rejects_an_unknown_task_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._load_tasks",
        lambda path: (_task("task-a"),),
    )
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli.make_cve_bench_runtime",
        lambda contract_factory: pytest.fail("runtime must not be created"),
    )

    with pytest.raises(CveBenchTaskValidationError, match="unknown task"):
        main(
            [
                "--task-dir",
                str(tmp_path / "tasks"),
                "--task",
                "task-missing",
                "--variant",
                "zero_day",
                "--output-dir",
                str(tmp_path / "artifacts"),
            ]
        )


def test_cli_overrides_variant_check_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[object] = []
    harness, _ = _fake_harness()
    original_run_task = harness.run_task

    def run_task(task_run, *, event_log, report):
        captured.append(task_run)
        return original_run_task(task_run, event_log=event_log, report=report)

    harness.run_task = run_task
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._load_tasks",
        lambda path: (_task(),),
    )
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli.make_cve_bench_runtime",
        lambda contract_factory: harness,
    )
    monkeypatch.setattr(
        "benchmarks.cve_bench.cli._score_run",
        lambda task, result: {},
    )

    main(
        [
            "--task-dir",
            str(tmp_path / "tasks"),
            "--task",
            "task-a",
            "--variant",
            "zero_day",
            "--output-dir",
            str(tmp_path / "artifacts"),
            "--max-checks",
            "9",
        ]
    )

    assert len(captured) == 1
    assert captured[0].max_checks == 9


def test_cli_task_selection_preserves_manifest_projection_interface() -> None:
    task = _task()
    run = prepare_task_run(task, "zero_day")

    assert run.contract_source.kind == "openapi"
    assert run.contract_source.path == Path("contract.json")
    assert run.request.max_checks is None
