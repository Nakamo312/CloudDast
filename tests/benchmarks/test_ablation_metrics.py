from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from benchmarks.nsfy_bench import M1_SCENARIOS, NsfyAblationRun
from benchmarks.nsfy_bench.ablation import score_ablation_run, score_ablation_runs
from benchmarks.nsfy_bench.norms import norm_facts

from cloud_dast.contracts.metrics import TokenUsageSnapshot
from cloud_dast.model import (
    Finding,
    Severity,
)
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentOutput,
    ComponentSkipped,
    DownstreamDecision,
    FindingRaised,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, Term
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast_reporting import (
    AblationCoverageCellArtifact,
    AblationDeficitArtifact,
    AblationPathArtifact,
)

START = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def _effects() -> dict[str, Term]:
    effects: dict[str, Term] = {}
    for fact in norm_facts():
        if fact.predicate.name != "prevents" or len(fact.args) != 2:
            continue
        norm_id = atom_value(fact.args[0])
        if norm_id is not None:
            effects.setdefault(norm_id, fact.args[1])
    return effects


def _scenario(scenario_id: str):
    return next(
        scenario for scenario in M1_SCENARIOS if scenario.scenario_id == scenario_id
    )


def _finding(scenario_id: str, finding_id: str) -> Finding:
    scenario = _scenario(scenario_id)
    return Finding(
        finding_id=finding_id,
        observation_id=f"observation-{finding_id}",
        invariant_id=f"invariant:{finding_id}",
        method_id=scenario.method_id,
        scenario_id=scenario.scenario_id,
        severity=Severity.HIGH,
        title="Engine finding",
        description="Synthetic finding for ablation metrics",
        remediation="Fix the defect",
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=f"norm:{finding_id}"), _effects()[scenario.norm_id]),
        ),
    )


def _run(
    scenario_ids: tuple[str, ...],
    *,
    control_fp: bool = False,
) -> NsfyAblationRun:
    findings: list[Finding] = []
    if control_fp:
        findings.append(_finding("control-invoice-read", "finding-control"))
    findings.extend(
        _finding(scenario_id, f"finding-{index}")
        for index, scenario_id in enumerate(scenario_ids, start=1)
    )

    finding_events = tuple(
        FindingRaised(
            finding=finding,
            occurred_at=START + timedelta(seconds=2 + 2 * index),
        )
        for index, finding in enumerate(findings)
    )
    return NsfyAblationRun(
        finding_events=finding_events,
        started_at=START,
        ended_at=START + timedelta(seconds=10),
        checks=20,
        tokens=TokenUsageSnapshot(input_tokens=600, output_tokens=400),
        coverage_before=(
            AblationCoverageCellArtifact("cell-a", False),
            AblationCoverageCellArtifact("cell-b", False),
        ),
        coverage_after=(
            AblationCoverageCellArtifact("cell-a", True),
            AblationCoverageCellArtifact("cell-b", False),
        ),
        paths=(
            AblationPathArtifact("path-recovered", True, True),
            AblationPathArtifact("path-blocked", True, False),
        ),
        deficits=(
            AblationDeficitArtifact("deficit-a", True),
            AblationDeficitArtifact("deficit-b", False),
        ),
    )


def test_scores_one_benchmark_run_from_durable_artifacts() -> None:
    score = score_ablation_run(_run(("sql-injection-search",), control_fp=True))
    metrics = score.metrics

    assert score.status == "VALID"
    assert score.useless is False
    assert metrics.tp_count == 1
    assert metrics.fp_count == 1
    assert metrics.fn_count == 8
    assert metrics.precision == pytest.approx(0.5)
    assert metrics.recall == pytest.approx(1 / 9)
    assert metrics.f1 == pytest.approx(2 / 11)
    assert metrics.time_to_first_finding_ms == pytest.approx(4000)
    assert metrics.first_finding_censored is False
    assert metrics.findings_per_check == pytest.approx(1 / 20)
    assert metrics.findings_per_token == pytest.approx(1 / 1000)
    assert metrics.findings_per_second == pytest.approx(0.1)
    assert metrics.coverage_cells_closed == 1
    assert metrics.blocked_paths_recovered == 1
    assert metrics.deficit_closure_rate == pytest.approx(0.5)


def test_run_without_true_positive_is_censored_at_wall_time_budget() -> None:
    score = score_ablation_run(_run((), control_fp=True))
    metrics = score.metrics

    assert score.status == "VALID"
    assert score.useless is True
    assert metrics.tp_count == 0
    assert metrics.fp_count == 1
    assert metrics.fn_count == 9
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.time_to_first_finding_ms == pytest.approx(10000)
    assert metrics.first_finding_censored is True


def test_repeat_runs_are_aggregated_with_mean_and_std() -> None:
    summary = score_ablation_runs(
        (
            _run(("sql-injection-search",), control_fp=True),
            _run(("sql-injection-search", "bola-order-read")),
        )
    )

    assert summary.run_count == 2
    assert summary.tp_count.mean == pytest.approx(1.5)
    assert summary.tp_count.std == pytest.approx(0.7071067811865476)
    assert summary.precision.mean == pytest.approx(0.75)
    assert summary.precision.std == pytest.approx(0.3535533905932738)
    assert summary.time_to_first_finding_ms.mean == pytest.approx(3000)
    assert summary.time_to_first_finding_ms.std == pytest.approx(1414.2135623730951)
    assert summary.first_finding_censored_count == 0


def test_activation_proof_validates_enabled_component() -> None:
    run = replace(
        _run(("sql-injection-search",), control_fp=True),
        component_events=(
            ComponentInvoked(
                component="generator:grammar",
                input_digest="digest",
                input_completeness={"sink_facts": 3, "probe_fields": 2},
                invocation_id="invocation",
                check_id="check",
                path_id="path",
            ),
            ComponentOutput(
                component="generator:grammar",
                summary={
                    "candidates_produced": 1,
                    "candidates_survived_prefilter": 1,
                    "candidates_survived_guardrail": 1,
                    "scored": 1,
                    "witnesses": 1,
                },
                invocation_id="invocation",
                check_id="check",
                observation_id="observation",
                path_id="path",
            ),
            DownstreamDecision(
                component="generator:grammar",
                consumed=True,
                by="oracle",
                outcome="fail",
                invocation_id="invocation",
                check_id="check",
                observation_id="observation",
                path_id="path",
            ),
        ),
        required_components=("generator:grammar",),
    )

    score = score_ablation_run(run)

    assert score.status == "VALID"
    assert score.component_activations[0].valid is True


def test_invalid_activation_is_not_interpreted_as_useless() -> None:
    invalid_run = replace(
        _run(()),
        component_events=(
            ComponentSkipped(
                component="generator:grammar",
                reason="disabled_by_flag",
            ),
        ),
        required_components=("generator:grammar",),
    )

    score = score_ablation_run(invalid_run)

    assert score.status == "INVALID"
    assert "invocations=0" in score.reason
    with pytest.raises(ValueError, match="useless interpretation is forbidden"):
        _ = score.useless
    with pytest.raises(ValueError, match="invalid ablation runs"):
        score_ablation_runs((invalid_run,))
