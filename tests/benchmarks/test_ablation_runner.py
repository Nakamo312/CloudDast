from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from benchmarks.nsfy_bench import (
    AblationArm,
    AblationExperiment,
    AblationRunBudget,
    AblationRunner,
    NsfyAblationRun,
    mann_whitney_u,
    render_ablation_comparison_json,
)

from cloud_dast.contracts.metrics import TokenUsageSnapshot
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentLifecycleEvent,
    ComponentOutput,
    DownstreamDecision,
)
from cloud_dast_reporting import AblationCoverageCellArtifact

START = datetime(2026, 10, 21, 13, 0, tzinfo=UTC)


@dataclass(slots=True)
class RecordingProbeExecutor:
    artifacts: dict[tuple[str, int], NsfyAblationRun]
    calls: list[tuple[AblationArm, int, AblationRunBudget]] = field(
        default_factory=list
    )

    def execute_run(
        self,
        arm: AblationArm,
        repeat_index: int,
        budget: AblationRunBudget,
    ) -> NsfyAblationRun:
        self.calls.append((arm, repeat_index, budget))
        return self.artifacts[(arm.arm_id, repeat_index)]


def _component_events(component: str) -> tuple[ComponentLifecycleEvent, ...]:
    invocation_id = f"invocation-{component}"
    return (
        ComponentInvoked(
            component=component,
            input_digest=f"digest-{component}",
            input_completeness={"inputs": 1},
            invocation_id=invocation_id,
            check_id="check",
            path_id="path",
        ),
        ComponentOutput(
            component=component,
            summary={
                "candidates_produced": 1,
                "candidates_survived_prefilter": 1,
                "candidates_survived_guardrail": 1,
                "scored": 1,
            },
            invocation_id=invocation_id,
            check_id="check",
            observation_id="observation",
            path_id="path",
        ),
        DownstreamDecision(
            component=component,
            consumed=True,
            by="ablation-test",
            outcome="consumed",
            invocation_id=invocation_id,
            check_id="check",
            observation_id="observation",
            path_id="path",
        ),
    )


def _run(
    *,
    coverage_closed: int = 1,
    wall_time_ms: float = 10_000,
    checks: int = 20,
    components: tuple[str, ...] = ("generator_selector:fix",),
) -> NsfyAblationRun:
    return NsfyAblationRun(
        finding_events=(),
        started_at=START,
        ended_at=START + timedelta(milliseconds=wall_time_ms),
        checks=checks,
        tokens=TokenUsageSnapshot(),
        coverage_before=(
            AblationCoverageCellArtifact("cell-a", False),
            AblationCoverageCellArtifact("cell-b", False),
        ),
        coverage_after=(
            AblationCoverageCellArtifact("cell-a", True),
            AblationCoverageCellArtifact("cell-b", coverage_closed == 2),
        ),
        component_events=tuple(
            event for component in components for event in _component_events(component)
        ),
    )


def test_arm_configuration_declares_every_required_component() -> None:
    arm = AblationArm(
        "all-components",
        generator="bandit",
        grammar_engine=True,
        llm_grounding=True,
        differential=True,
        z3_prefilter=True,
        interest_prioritizer=True,
    )

    assert arm.configuration == {
        "generator": "bandit",
        "grammar_engine": True,
        "llm_grounding": True,
        "differential": True,
        "z3_prefilter": True,
        "interest_prioritizer": True,
    }
    assert arm.required_components == (
        "generator_selector:bandit",
        "generator:grammar",
        "grounding:llm",
        "differential:comparator",
        "symbolic_prefilter",
        "interest_prioritizer",
    )


def test_experiment_requires_repeats_and_a_known_baseline() -> None:
    arm = AblationArm("baseline")
    budget = AblationRunBudget(20, 100, 10_000)

    with pytest.raises(ValueError, match="at least two repeats"):
        AblationExperiment((arm,), repeats=1, budget=budget)
    with pytest.raises(ValueError, match="arm identifiers must be unique"):
        AblationExperiment((arm, arm), repeats=2, budget=budget)
    with pytest.raises(ValueError, match="baseline ablation arm does not exist"):
        AblationExperiment(
            (arm,),
            repeats=2,
            budget=budget,
            baseline_arm_id="missing",
        )
    with pytest.raises(ValueError, match="significance level"):
        AblationExperiment((arm,), repeats=2, budget=budget, significance_level=1.0)


def test_runner_repeats_arms_and_collects_r8_artifacts() -> None:
    budget = AblationRunBudget(20, 100, 10_000)
    executor = RecordingProbeExecutor(
        {
            ("baseline", 0): _run(coverage_closed=1),
            ("baseline", 1): _run(coverage_closed=1, wall_time_ms=9_000),
            ("grammar", 0): _run(
                coverage_closed=2,
                components=("generator_selector:fix", "generator:grammar"),
            ),
            ("grammar", 1): _run(
                coverage_closed=2,
                wall_time_ms=8_000,
                components=("generator_selector:fix", "generator:grammar"),
            ),
        }
    )
    experiment = AblationExperiment(
        arms=(
            AblationArm("baseline"),
            AblationArm("grammar", grammar_engine=True),
        ),
        repeats=2,
        budget=budget,
    )

    result = AblationRunner(executor).run(experiment)

    assert [(arm.arm_id, repeat) for arm, repeat, _ in executor.calls] == [
        ("baseline", 0),
        ("baseline", 1),
        ("grammar", 0),
        ("grammar", 1),
    ]
    assert all(run_budget is budget for _, _, run_budget in executor.calls)
    assert result.status == "VALID"
    assert all(arm.summary is not None for arm in result.arms)
    assert all(arm.summary.run_count == 2 for arm in result.arms)
    assert all(
        isinstance(run.run, NsfyAblationRun) for arm in result.arms for run in arm.runs
    )
    assert all(
        run.run.required_components == arm.arm.required_components
        for arm in result.arms
        for run in arm.runs
    )


def test_runner_compares_valid_arms_with_mann_whitney_u() -> None:
    budget = AblationRunBudget(20, 100, 10_000)
    executor = RecordingProbeExecutor(
        {
            ("baseline", 0): _run(coverage_closed=1),
            ("baseline", 1): _run(coverage_closed=1),
            ("grammar", 0): _run(
                coverage_closed=2,
                components=("generator_selector:fix", "generator:grammar"),
            ),
            ("grammar", 1): _run(
                coverage_closed=2,
                components=("generator_selector:fix", "generator:grammar"),
            ),
        }
    )
    experiment = AblationExperiment(
        arms=(
            AblationArm("baseline"),
            AblationArm("grammar", grammar_engine=True),
        ),
        repeats=2,
        budget=budget,
    )

    result = AblationRunner(executor).run(experiment)
    comparison = next(
        item for item in result.comparisons if item.metric == "coverage_cells_closed"
    )

    assert comparison.baseline_arm_id == "baseline"
    assert comparison.treatment_arm_id == "grammar"
    assert comparison.baseline_sample_size == 2
    assert comparison.treatment_sample_size == 2
    assert comparison.u_baseline == 0.0
    assert comparison.u_treatment == 4.0
    assert comparison.p_value == pytest.approx(1 / 3)
    assert comparison.significant is False

    document = json.loads(render_ablation_comparison_json(result))
    assert document["schema"] == "cloud-dast.ablation-comparison"
    assert document["schema_version"] == 1
    assert document["status"] == "VALID"
    assert document["budget"] == {
        "max_checks": 20,
        "max_tokens": 100,
        "max_wall_time_ms": 10_000,
    }
    assert document["arms"][1]["summary"]["coverage_cells_closed"] == {
        "run_count": 2,
        "mean": 2.0,
        "std": 0.0,
    }
    assert {
        "metric": "coverage_cells_closed",
        "baseline_arm_id": "baseline",
        "treatment_arm_id": "grammar",
        "baseline_sample_size": 2,
        "treatment_sample_size": 2,
        "u_baseline": 0.0,
        "u_treatment": 4.0,
        "p_value": pytest.approx(1 / 3),
        "significant": False,
    } in document["comparisons"]


def test_runner_proves_activation_for_every_enabled_component() -> None:
    arm = AblationArm(
        "all-components",
        generator="bandit",
        grammar_engine=True,
        llm_grounding=True,
        differential=True,
        z3_prefilter=True,
        interest_prioritizer=True,
    )
    budget = AblationRunBudget(20, 100, 10_000)
    executor = RecordingProbeExecutor(
        {
            (arm.arm_id, repeat): _run(components=arm.required_components)
            for repeat in range(2)
        }
    )

    result = AblationRunner(executor).run(
        AblationExperiment((arm,), repeats=2, budget=budget)
    )

    assert result.status == "VALID"
    assert result.arms[0].useless is True
    assert (
        tuple(
            proof.component
            for proof in result.arms[0].runs[0].score.component_activations
        )
        == arm.required_components
    )
    assert all(
        proof.valid
        for run in result.arms[0].runs
        for proof in run.score.component_activations
    )


def test_invalid_activation_is_not_interpreted_as_useless() -> None:
    budget = AblationRunBudget(20, 100, 10_000)
    invalid_run = _run(components=())
    executor = RecordingProbeExecutor(
        {
            ("baseline", 0): invalid_run,
            ("baseline", 1): _run(),
            ("grammar", 0): _run(
                coverage_closed=2,
                components=("generator_selector:fix", "generator:grammar"),
            ),
            ("grammar", 1): _run(
                coverage_closed=2,
                components=("generator_selector:fix", "generator:grammar"),
            ),
        }
    )
    experiment = AblationExperiment(
        arms=(
            AblationArm("baseline"),
            AblationArm("grammar", grammar_engine=True),
        ),
        repeats=2,
        budget=budget,
    )

    result = AblationRunner(executor).run(experiment)
    baseline = result.arms[0]

    assert result.status == "INVALID"
    assert baseline.invalid is True
    assert baseline.summary is None
    assert result.comparisons == ()
    assert "invocations=0" in baseline.invalid_runs[0].score.reason
    with pytest.raises(ValueError, match="useless interpretation is forbidden"):
        _ = baseline.useless

    payload = render_ablation_comparison_json(result)
    assert "useless" not in payload
    document = json.loads(payload)
    assert document["status"] == "INVALID"
    assert document["arms"][0]["status"] == "INVALID"
    assert document["arms"][0]["invalid_runs"] == [
        {"repeat": 1, "reason": baseline.invalid_runs[0].score.reason}
    ]
    assert document["comparisons"] == []
    assert (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        == payload
    )


def test_budget_violation_marks_the_run_invalid() -> None:
    budget = AblationRunBudget(20, 100, 10_000)
    executor = RecordingProbeExecutor(
        {
            ("baseline", 0): _run(checks=20),
            ("baseline", 1): _run(checks=21),
        }
    )
    experiment = AblationExperiment(
        arms=(AblationArm("baseline"),),
        repeats=2,
        budget=budget,
    )

    result = AblationRunner(executor).run(experiment)

    assert result.status == "INVALID"
    assert (
        "checks=21 exceeds max_checks=20" in result.arms[0].invalid_runs[0].score.reason
    )


def test_mann_whitney_u_is_exact_and_tie_aware() -> None:
    separated = mann_whitney_u((1, 2, 3), (4, 5, 6))
    identical = mann_whitney_u((2, 2, 2), (2, 2, 2))

    assert separated == (0.0, 9.0, pytest.approx(0.1))
    assert identical[0] == 4.5
    assert identical[1] == 4.5
    assert identical[2] == 1.0
    tie_aware = mann_whitney_u((1, 2, 2), (2, 3, 3))
    assert tie_aware == (1.0, 8.0, pytest.approx(0.3))
    assert tie_aware == mann_whitney_u((1, 2, 2), (2, 3, 3))
    with pytest.raises(ValueError, match="non-empty samples"):
        mann_whitney_u((), (1, 2))
    with pytest.raises(ValueError, match="finite values"):
        mann_whitney_u((1, float("nan")), (2, 3))
