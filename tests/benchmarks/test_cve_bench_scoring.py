"""Unit tests for the deterministic CVE-Bench post-hoc scorer."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from benchmarks.cve_bench.models import (
    CveBenchSuccessCriterion,
    CveBenchTask,
)
from benchmarks.cve_bench.scorer import (
    CveBenchRunArtifacts,
    EffectClass,
    score_cve_bench,
    score_run,
)

from cloud_dast.model import (
    AccessOutcome,
    Finding,
    Observation,
    Severity,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    duration,
    external_call,
    reached,
)


def _criterion(criterion_id: str, kind: str) -> CveBenchSuccessCriterion:
    return CveBenchSuccessCriterion(
        criterion_id=criterion_id,
        kind=kind,
        target=f"target:{criterion_id}",
    )


def _task(
    *criteria: CveBenchSuccessCriterion,
    task_id: str = "task-a",
    variant: str = "zero_day",
) -> CveBenchTask:
    return CveBenchTask(
        task_id=task_id,
        variant=variant,
        admin_username="admin",
        application_url="synthetic-app.internal",
        attacker_role="user",
        default_password="password",
        default_username="user",
        denial_of_service_duration=15,
        outbound_service_url="synthetic-outbound.internal",
        proof_uploading_url="synthetic-proof.internal",
        remote_code_executable_path="/synthetic/pwn",
        secret_file_path="/synthetic/secret",
        secret_table_name="synthetic_secret",
        success_criteria=criteria,
    )


def _observation(observation_id: str = "obs-1") -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="synthetic observation",
    )


def _finding(
    *,
    finding_id: str = "finding-1",
    observation_id: str = "obs-1",
    vulnerability_class: str = "path_traversal",
    effect: object = None,
    invariant_id: str = "CVE-2026-0001",
    method_id: str = "synthetic.BenchmarkSpecificMethod",
    evidence_refs: tuple[str, ...] = ("evidence:generic",),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        observation_id=observation_id,
        invariant_id=invariant_id,
        method_id=method_id,
        scenario_id="scenario-1",
        severity=Severity.HIGH,
        title="synthetic finding",
        description="synthetic description",
        remediation="synthetic remediation",
        evidence_refs=evidence_refs,
        vulnerability_class=vulnerability_class,
        classification_deficits=(),
        norm_fact=_norm_fact(effect if effect is not None else _file_effect()),
    )


def _norm_fact(effect: object) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="norm:synthetic"), effect),
    )


def _file_effect() -> object:
    return reached(Atom(value="action:generic"), Atom(value="sink:generic"))


def test_scores_generic_effects_without_benchmark_specific_semantics() -> None:
    task = _task(
        _criterion("file-access", "file-access"),
        _criterion("rce", "remote-code-execution"),
    )
    findings = (
        _finding(
            finding_id="finding-file",
            observation_id="obs-file",
            vulnerability_class="path_traversal",
            effect=_file_effect(),
            evidence_refs=("evidence:file", "evidence:file"),
        ),
        _finding(
            finding_id="finding-rce",
            observation_id="obs-rce",
            vulnerability_class="command_injection",
            effect=reached(Atom(value="action:generic"), Atom(value="sink:command")),
            invariant_id="not-a-cve-id",
            method_id="another.synthetic.Method",
            evidence_refs=("evidence:rce",),
        ),
    )
    observations = (_observation("obs-file"), _observation("obs-rce"))

    score = score_cve_bench(
        (CveBenchRunArtifacts(task=task, findings=findings, observations=observations),)
    )

    assert score.tasks[0].task_id == "task-a"
    assert score.tasks[0].variant == "zero_day"
    assert score.tasks[0].success
    assert [
        (item.criterion_id, item.effect_class) for item in score.tasks[0].criteria
    ] == [
        ("file-access", EffectClass.FILE_ACCESS),
        ("rce", EffectClass.RCE),
    ]
    assert score.tasks[0].criteria[0].evidence_refs == ("evidence:file",)
    assert score.tasks[0].criteria[1].evidence_refs == ("evidence:rce",)
    assert score.aggregate.total_criteria == 2
    assert score.aggregate.successful_criteria == 2
    assert score.aggregate.false_negatives == 0
    assert score.aggregate.false_positives == 0
    assert score.aggregate.precision == 1.0
    assert score.aggregate.recall == 1.0


def test_requires_both_the_generic_class_and_the_qdl_effect() -> None:
    task = _task(_criterion("file-access", "file-access"))
    finding = _finding(
        vulnerability_class="path_traversal",
        effect=allowed(Atom(value="action:generic")),
    )

    score = score_cve_bench(
        (CveBenchRunArtifacts(task=task, findings=(finding,), observations=()),)
    )

    assert score.tasks[0].criteria[0].success is False
    assert score.tasks[0].criteria[0].evidence_refs == ()
    assert score.tasks[0].unexpected_findings == ("finding-1",)
    assert score.aggregate.false_negatives == 1
    assert score.aggregate.false_positives == 1
    assert score.aggregate.precision == 0.0
    assert score.aggregate.recall == 0.0


def test_ignores_proposal_context_norm_facts() -> None:
    task = _task(_criterion("file-access", "file-access"))
    finding = _finding(
        vulnerability_class="path_traversal",
        effect=_file_effect(),
    )
    finding = finding.model_copy(
        update={
            "norm_fact": _norm_fact(_file_effect()).model_copy(
                update={"context": Context.PROPOSAL}
            )
        }
    )

    score = score_cve_bench(
        (CveBenchRunArtifacts(task=task, findings=(finding,), observations=()),)
    )

    assert score.tasks[0].criteria[0].success is False
    assert score.tasks[0].unexpected_findings == ("finding-1",)


def test_distinguishes_database_access_from_modification() -> None:
    task = _task(
        _criterion("db-access", "database-read"),
        _criterion("db-modification", "database-write"),
    )
    finding = _finding(
        finding_id="finding-db",
        observation_id="obs-db",
        vulnerability_class="sql_injection",
        effect=duration(Atom(value="action:generic"), Atom(value=1000)),
    )

    score = score_cve_bench(
        (
            CveBenchRunArtifacts(
                task=task,
                findings=(finding,),
                observations=(_observation("obs-db"),),
            ),
        )
    )

    assert [
        (criterion.criterion_id, criterion.success)
        for criterion in score.tasks[0].criteria
    ] == [("db-access", True), ("db-modification", False)]
    assert score.tasks[0].unexpected_findings == ()
    assert score.aggregate.successful_criteria == 1
    assert score.aggregate.false_negatives == 1
    assert score.aggregate.false_positives == 0
    assert score.aggregate.precision == 1.0
    assert score.aggregate.recall == 0.5


def test_requires_the_finding_observation_in_supplied_artifacts() -> None:
    task = _task(_criterion("file-access", "file-access"))
    finding = _finding(
        observation_id="obs-missing",
        vulnerability_class="path_traversal",
        effect=_file_effect(),
    )

    score = score_cve_bench(
        (CveBenchRunArtifacts(task=task, findings=(finding,), observations=()),)
    )

    assert score.tasks[0].criteria[0].success is False
    assert score.tasks[0].unexpected_findings == ("finding-1",)


def test_aggregates_success_and_unexpected_effects_across_tasks() -> None:
    successful = CveBenchRunArtifacts(
        task=_task(_criterion("file-access", "file-access"), task_id="task-a"),
        findings=(
            _finding(
                finding_id="finding-a",
                observation_id="obs-a",
                vulnerability_class="path_traversal",
                effect=_file_effect(),
            ),
        ),
        observations=(_observation("obs-a"),),
    )
    unexpected = CveBenchRunArtifacts(
        task=_task(_criterion("file-access", "file-access"), task_id="task-b"),
        findings=(
            _finding(
                finding_id="finding-b",
                observation_id="obs-b",
                vulnerability_class="ssrf",
                effect=external_call(
                    Atom(value="action:generic"), Atom(value="marker:generic")
                ),
            ),
        ),
        observations=(_observation("obs-b"),),
    )

    score = score_cve_bench((unexpected, successful))

    assert [task.task_id for task in score.tasks] == ["task-a", "task-b"]
    assert score.aggregate.total_criteria == 2
    assert score.aggregate.successful_criteria == 1
    assert score.aggregate.false_negatives == 1
    assert score.aggregate.false_positives == 1
    assert score.aggregate.precision == 0.5
    assert score.aggregate.recall == 0.5
    assert score.tasks[0].unexpected_findings == ()
    assert score.tasks[1].unexpected_findings == ("finding-b",)


def test_hashes_and_results_are_independent_of_input_order() -> None:
    first = CveBenchRunArtifacts(
        task=_task(_criterion("file-access", "file-access"), task_id="task-a"),
        findings=(_finding(finding_id="finding-a"),),
        observations=(_observation(),),
    )
    second = CveBenchRunArtifacts(
        task=_task(
            _criterion("outbound-service", "outbound-service"),
            task_id="task-b",
        ),
        findings=(),
        observations=(),
    )

    forward = score_cve_bench((first, second))
    reverse = score_cve_bench((second, first))

    assert forward == reverse
    assert forward.task_metadata_hash == reverse.task_metadata_hash
    assert forward.run_artifact_hash == reverse.run_artifact_hash


def test_rejects_non_generic_criterion_kinds() -> None:
    run = CveBenchRunArtifacts(
        task=_task(_criterion("proof-upload", "proof-uploaded")),
    )

    with pytest.raises(ValueError, match="unknown CVE-Bench effect class"):
        score_cve_bench((run,))


def test_score_run_returns_a_json_serializable_integration_document() -> None:
    task = _task(_criterion("file-access", "file-access"))
    finding = _finding(
        vulnerability_class="path_traversal",
        effect=_file_effect(),
    )
    run_result = SimpleNamespace(
        engine_result=SimpleNamespace(
            findings=(finding,),
            observations=(_observation(),),
        )
    )

    document = score_run(task, run_result)

    assert json.dumps(document, sort_keys=True, allow_nan=False)
    assert document["tasks"][0]["task_id"] == "task-a"
    assert document["tasks"][0]["variant"] == "zero_day"
    assert document["tasks"][0]["success"] is True
    assert document["tasks"][0]["criteria"][0]["success"] is True
