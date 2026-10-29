from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks.cve_bench.contract import build_contract_runtime
from benchmarks.cve_bench.models import CveBenchTask
from benchmarks.cve_bench.runtime import (
    CveBenchContractRuntime,
    CveBenchContractSource,
    CveBenchRuntimeHarness,
    CveBenchTaskValidationError,
    MissingContractSourceError,
    UnsupportedContractSourceError,
    make_cve_bench_container,
    prepare_task_run,
    prepare_task_runs,
)

from cloud_dast.composition.runtime import CloudDastRuntime
from cloud_dast.model import (
    Check,
    Observation,
)
from cloud_dast.ports import (
    ContractGraphRepository,
    FormalRepository,
    InvocationRepository,
    MethodRepository,
    ScenarioRepository,
    ServiceGraphSlice,
    StandSource,
    Target,
)
from cloud_dast.qdl.graph import QdlGraph


def _source(path: str = "contract.json") -> CveBenchContractSource:
    return CveBenchContractSource(kind="manifest", path=Path(path))


def _task(
    task_id: str = "task-a",
    variant: str = "zero_day",
    *,
    contract_kind: str | None = "manifest",
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


def test_prepare_task_run_selects_the_requested_variant() -> None:
    task = _task(variant="one_day")

    run = prepare_task_run(task, "one_day")

    assert run.task_id == "task-a"
    assert run.variant == "one_day"
    assert run.service == "task-a"
    assert run.principal_id == "synthetic-user"
    assert run.resource_id == "resource-under-test"
    assert run.method_id is None
    assert run.target_url == "https://synthetic-target.invalid"
    assert run.request.service == "task-a"
    assert run.request.principal_id == "synthetic-user"


def test_task_run_strips_credentials_and_benchmark_answer_keys() -> None:
    run = prepare_task_run(_task(), "zero_day")

    assert {field.name for field in fields(run)} == {
        "task_id",
        "variant",
        "service",
        "principal_id",
        "resource_id",
        "method_id",
        "max_checks",
        "contract_source",
        "target_url",
    }


def test_prepare_task_run_rejects_an_invalid_variant() -> None:
    with pytest.raises(CveBenchTaskValidationError, match="variant"):
        prepare_task_run(_task(), "post-hoc")  # type: ignore[arg-type]


def test_missing_contract_source_fails_before_contract_or_engine_creation(
    tmp_path: Path,
) -> None:
    contract_calls: list[object] = []
    engine_calls: list[object] = []

    class ContractFactory:
        def build_contract_runtime(self, task_run):
            contract_calls.append(task_run)
            raise AssertionError("contract source must be validated first")

    class EngineFactory:
        def __call__(self, task_run, contract, event_store):
            engine_calls.append((contract, event_store))
            raise AssertionError("engine must not be created without a contract")

    task_run = replace(
        prepare_task_run(_task(), "zero_day"),
        contract_source=None,
    )
    harness = CveBenchRuntimeHarness(ContractFactory(), EngineFactory())

    with pytest.raises(MissingContractSourceError) as error:
        harness.run_task(
            task_run,
            event_log=tmp_path / "events.jsonl",
            report=tmp_path / "report.json",
        )

    assert error.value.task_id == "task-a"
    assert contract_calls == []
    assert engine_calls == []
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "report.json").exists()


def test_prepare_task_runs_validates_every_selected_task_first() -> None:
    tasks = (
        _task("task-valid"),
        _task("task-missing-contract", contract_kind=None, contract_path=None),
    )

    with pytest.raises(MissingContractSourceError, match="task-missing-contract"):
        prepare_task_runs(tasks, ("task-valid", "task-missing-contract"), "zero_day")


def test_harness_runs_fake_components_and_writes_a_durable_report(
    tmp_path: Path,
) -> None:
    engine_requests: list[object] = []
    event_store_paths: list[Path] = []

    class ContractFactory:
        def build_contract_runtime(self, task_run):
            return SimpleNamespace(built_for=task_run.task_id)

    class Engine:
        def execute(self, request):
            engine_requests.append(request)
            return SimpleNamespace(
                observations=(SimpleNamespace(check_id="check-1"),),
                findings=(SimpleNamespace(finding_id="finding-1"),),
            )

    class EngineFactory:
        def __call__(self, task_run, contract, event_store):
            assert contract.built_for == "task-a"
            return Engine()

    class EventStoreFactory:
        def __call__(self, path):
            event_store_paths.append(path)
            return SimpleNamespace(path=path)

    task_run = prepare_task_run(_task(), "zero_day", max_checks=7)
    event_log = tmp_path / "task-a-zero_day.events.jsonl"
    report = tmp_path / "task-a-zero_day.report.json"
    result = CveBenchRuntimeHarness(
        ContractFactory(),
        EngineFactory(),
        EventStoreFactory(),
    ).run_task(task_run, event_log=event_log, report=report)

    assert engine_requests == [task_run.request]
    assert event_store_paths == [event_log]
    assert result.event_log == event_log
    assert result.report == report
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["schema"] == "cloud-dast.cve-bench.run"
    assert document["task_id"] == "task-a"
    assert document["variant"] == "zero_day"
    assert document["request"]["max_checks"] == 7
    assert document["observations"] == 1
    assert document["findings"] == ["finding-1"]
    report_text = report.read_text(encoding="utf-8")
    assert "synthetic-password" not in report_text
    assert "https://synthetic-target.invalid" not in report_text


def test_contract_source_requires_an_explicit_kind() -> None:
    with pytest.raises(CveBenchTaskValidationError, match="contract source kind"):
        CveBenchContractSource(kind="guessed", path=Path("contract.json"))  # type: ignore[arg-type]


def test_probe_only_metadata_is_not_a_complete_contract_source() -> None:
    task = _task(contract_kind="probe")

    with pytest.raises(UnsupportedContractSourceError, match="openapi or manifest"):
        prepare_task_run(task, "zero_day")


def test_generated_factory_builds_runtime_from_explicit_manifest(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "contract.json"
    manifest_path.write_text(
        json.dumps(
            {
                "service": "synthetic.v1",
                "endpoint": "https://synthetic-target.invalid",
                "methods": [
                    {
                        "method_id": "http:synthetic.v1.readRecord",
                        "name": "readRecord",
                        "http_method": "GET",
                        "path_template": "/records/{record_id}",
                        "fields": [
                            {
                                "name": "record_id",
                                "type": "string",
                                "required": True,
                            }
                        ],
                        "permissions": ["record.read"],
                        "resource_types": ["record"],
                        "query_fields": [],
                        "body_fields": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    task = _task(contract_kind="manifest", contract_path=manifest_path)
    task_run = prepare_task_run(task, "zero_day")

    runtime = build_contract_runtime(task_run)

    assert task_run.service == "task-a"
    method = runtime.methods.get_method("http:synthetic.v1.readRecord")
    assert method is not None
    assert method.service == "task-a"
    invocation = runtime.invocations.get_invocation("http:synthetic.v1.readRecord")
    assert invocation is not None
    assert invocation.endpoint == "https://synthetic-target.invalid"
    assert runtime.contract_graph.load_slice("task-a").nodes
    assert (
        runtime.scenarios.get_scenario(
            "synthetic-user",
            "resource-under-test",
            method,
        )
        is not None
    )
    assert runtime.formal.load("task-a:zero_day").facts


def test_cve_bench_container_wires_contract_ports_without_neo4j(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_repository_selection(*args: object, **kwargs: object) -> None:
        raise AssertionError("CVE-Bench must not select Neo4j repositories")

    import cloud_dast.composition.run_provider as run_provider

    monkeypatch.setattr(
        run_provider,
        "select_scenario_repository",
        fail_repository_selection,
    )
    monkeypatch.setattr(run_provider, "select_stand_source", fail_repository_selection)

    contract = _contract_runtime()
    event_store = _EmptyEventStore()
    container = make_cve_bench_container(
        contract,
        event_store,
        service="synthetic-service",
        principal_id="synthetic-user",
    )

    with container as app, app() as run:
        assert run.get(Target) is contract.target
        assert run.get(MethodRepository) is contract.methods
        assert run.get(InvocationRepository) is contract.invocations
        assert run.get(ContractGraphRepository) is contract.contract_graph
        assert run.get(FormalRepository) is contract.formal
        assert run.get(ScenarioRepository) is contract.scenarios
        assert run.get(StandSource) is contract.stand
        runtime = run.get(CloudDastRuntime)

    assert isinstance(runtime, CloudDastRuntime)


def _contract_runtime() -> CveBenchContractRuntime:
    return CveBenchContractRuntime(
        methods=_EmptyMethodRepository(),
        invocations=_EmptyInvocationRepository(),
        contract_graph=_EmptyContractGraphRepository(),
        scenarios=_EmptyScenarioRepository(),
        formal=_EmptyFormalRepository(),
        stand=_EmptyStandSource(),
        target=_NoNetworkTarget(),
    )


class _EmptyEventStore:
    def append(self, event: object) -> None:
        return None

    def read(self) -> Iterator[object]:
        return iter(())

    def read_new(self, consumer_id: str) -> tuple[object, ...]:
        return ()


class _EmptyMethodRepository:
    def get_method(self, method_id: str):
        return None

    def list_methods(self, service: str):
        return ()


class _EmptyInvocationRepository:
    def get_invocation(self, method_id: str):
        return None


class _EmptyContractGraphRepository:
    def load_slice(self, service: str) -> ServiceGraphSlice:
        return ServiceGraphSlice(service=service)


class _EmptyScenarioRepository:
    def get_scenario(self, *args: object, **kwargs: object):
        return None


class _EmptyFormalRepository:
    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: Any,
        adapter_version: str,
        mapping_report: Any,
    ) -> None:
        return None

    def load(self, source_id: str) -> QdlGraph:
        return QdlGraph()

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return QdlGraph()


class _EmptyStandSource:
    def project(self, service: str) -> QdlGraph:
        return QdlGraph()


class _NoNetworkTarget:
    def __call__(self, check: Check) -> Observation:
        raise AssertionError("this wiring test must not call the target")
