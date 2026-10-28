"""Unit tests for CVE-Bench score report rendering."""

from __future__ import annotations

import json

from benchmarks.cve_bench.models import (
    CveBenchSuccessCriterion,
    CveBenchTask,
)
from benchmarks.cve_bench.report import (
    CVE_BENCH_REPORT_SCHEMA_NAME,
    CVE_BENCH_REPORT_SCHEMA_VERSION,
    JsonCveBenchReportRenderer,
    MarkdownCveBenchReportRenderer,
)
from benchmarks.cve_bench.scorer import (
    CveBenchRunArtifacts,
    CveBenchScore,
    EffectClass,
    score_cve_bench,
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
    external_call,
    reached,
)


def _criterion(
    criterion_id: str = "file-access",
    kind: str = "file-access",
) -> CveBenchSuccessCriterion:
    return CveBenchSuccessCriterion(
        criterion_id=criterion_id,
        kind=kind,
        target="target:generic",
    )


def _task(
    *criteria: CveBenchSuccessCriterion,
    task_id: str = "task-a",
) -> CveBenchTask:
    return CveBenchTask(
        task_id=task_id,
        variant="zero_day",
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
    finding_id: str,
    observation_id: str,
    *,
    vulnerability_class: str = "path_traversal",
    effect: object | None = None,
    evidence_refs: tuple[str, ...] = ("evidence:generic",),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        observation_id=observation_id,
        invariant_id="invariant:generic",
        method_id="synthetic.Method",
        scenario_id="scenario-1",
        severity=Severity.HIGH,
        title="synthetic finding",
        description="synthetic description",
        remediation="synthetic remediation",
        evidence_refs=evidence_refs,
        vulnerability_class=vulnerability_class,
        classification_deficits=(),
        norm_fact=_norm_fact(
            effect
            if effect is not None
            else reached(Atom(value="action:generic"), Atom(value="sink:generic"))
        ),
    )


def _norm_fact(effect: object) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="norm:synthetic"), effect),
    )


def _score() -> CveBenchScore:
    task = _task(_criterion())
    findings = (
        _finding("finding-file", "obs-file"),
        _finding(
            "finding-outbound",
            "obs-outbound",
            vulnerability_class="ssrf",
            effect=external_call(
                Atom(value="action:generic"), Atom(value="marker:generic")
            ),
        ),
    )
    observations = (_observation("obs-file"), _observation("obs-outbound"))
    return score_cve_bench(
        (CveBenchRunArtifacts(task=task, findings=findings, observations=observations),)
    )


def test_json_renderer_emits_the_versioned_score_document() -> None:
    score = _score()

    rendered = JsonCveBenchReportRenderer().render(score)
    document = json.loads(rendered)

    assert document["schema"] == CVE_BENCH_REPORT_SCHEMA_NAME
    assert document["schema_version"] == CVE_BENCH_REPORT_SCHEMA_VERSION
    assert document["reproducibility"] == {
        "task_metadata_hash": score.task_metadata_hash,
        "run_artifact_hash": score.run_artifact_hash,
    }
    assert document["aggregate"] == {
        "total_criteria": 1,
        "successful_criteria": 1,
        "false_negatives": 0,
        "false_positives": 1,
        "precision": 0.5,
        "recall": 1.0,
    }
    assert document["tasks"] == [
        {
            "task_id": "task-a",
            "variant": "zero_day",
            "success": True,
            "criteria": [
                {
                    "criterion_id": "file-access",
                    "effect_class": EffectClass.FILE_ACCESS.value,
                    "success": True,
                    "evidence_refs": ["evidence:generic"],
                }
            ],
            "unexpected_findings": ["finding-outbound"],
        }
    ]
    assert rendered == json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def test_markdown_renderer_emits_task_criteria_evidence_and_metadata() -> None:
    score = _score()

    markdown = MarkdownCveBenchReportRenderer().render(score)

    assert "# CVE-Bench report" in markdown
    assert "## Reproducibility" in markdown
    assert f"- Task metadata hash: `{score.task_metadata_hash}`" in markdown
    assert f"- Run artifact hash: `{score.run_artifact_hash}`" in markdown
    assert "### `task-a` / `zero_day`" in markdown
    assert "- Outcome: success" in markdown
    assert "| `file-access` | `file_access` | success | `evidence:generic` |" in (
        markdown
    )
    assert "- Unexpected findings: `finding-outbound`" in markdown
    assert "- Precision: 0.500" in markdown
    assert "- Recall: 1.000" in markdown


def test_renderers_handle_an_empty_campaign() -> None:
    score = score_cve_bench(())

    json_document = json.loads(JsonCveBenchReportRenderer().render(score))
    markdown = MarkdownCveBenchReportRenderer().render(score)

    assert json_document["tasks"] == []
    assert json_document["aggregate"]["precision"] is None
    assert json_document["aggregate"]["recall"] is None
    assert "## Tasks" in markdown
    assert "_No scored tasks._" in markdown
    assert "Precision: not applicable" in markdown
    assert "Recall: not applicable" in markdown


def test_rendering_is_independent_of_task_input_order() -> None:
    first = CveBenchRunArtifacts(
        task=_task(_criterion("file-access"), task_id="task-a"),
        findings=(_finding("finding-a", "obs-a"),),
        observations=(_observation("obs-a"),),
    )
    second = CveBenchRunArtifacts(
        task=_task(
            _criterion("outbound-service", "outbound-service"), task_id="task-b"
        ),
        findings=(),
        observations=(),
    )

    forward = score_cve_bench((first, second))
    reverse = score_cve_bench((second, first))

    assert JsonCveBenchReportRenderer().render(forward) == (
        JsonCveBenchReportRenderer().render(reverse)
    )
    assert MarkdownCveBenchReportRenderer().render(forward) == (
        MarkdownCveBenchReportRenderer().render(reverse)
    )
