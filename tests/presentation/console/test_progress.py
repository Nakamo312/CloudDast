from __future__ import annotations

import io

import pytest

from cloud_dast.infrastructure.events import EventBus
from cloud_dast.model import (
    AccessOutcome,
    Finding,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    FactVerified,
    FindingRaised,
    PhaseChanged,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate
from cloud_dast_reporting import (
    CoverageSnapshot,
    PlanReady,
    QdlCoverageCounts,
    QdlCoverageModel,
)
from cloud_dast_reporting.formats.console.progress import (
    ConsoleProgressRenderer,
    make_progress_renderer,
)


def _plan_snapshot() -> PlanReady:
    return PlanReady(
        plan={
            "graph_hash": "graph",
            "paths": [{"path_id": "p1", "goal_id": "g1", "gate": "AND", "steps": []}],
        },
        max_checks=2,
    )


def _coverage_snapshot() -> CoverageSnapshot:
    return CoverageSnapshot(
        coverage=QdlCoverageModel(
            service="svc",
            fields=QdlCoverageCounts(1, 1, 0, 0, 0),
            effects=QdlCoverageCounts(0, 0, 0, 0, 0),
            by_field_kind={},
            deficit_counts={},
            field_cells=(),
            effect_cells=(),
            gaps=(),
            state_machine=None,
        )
    )


def _finding_event() -> FindingRaised:
    return FindingRaised(
        finding=Finding(
            observation_id="obs",
            invariant_id="inv",
            method_id="method",
            scenario_id="scenario",
            severity=Severity.HIGH,
            title="Finding",
            description="Description",
            remediation="Remediation",
        )
    )


def _fact_event() -> FactVerified:
    return FactVerified(
        fact=Fact(
            context=Context.RUNTIME,
            predicate=Predicate.from_name("is"),
            args=(Atom(value="fact:1"), Atom(value="VerifiedFact")),
        )
    )


def test_progress_logger_publishes_campaign_events() -> None:
    stream = io.StringIO()
    renderer = ConsoleProgressRenderer(
        service="svc",
        mode="plain",
        stream=stream,
        clock=lambda: 0.0,
    )
    bus = EventBus()
    renderer.attach(bus)

    bus.publish(PhaseChanged(phase="qdl_planning"))
    bus.publish(_plan_snapshot())
    bus.publish(_coverage_snapshot())
    bus.publish(
        QdlStepEvaluated(
            path_id="p1",
            step_id="s1",
            verdict=VerdictStatus.FAIL,
            phase="active",
            reason="confirmed",
            step_index=1,
        )
    )
    bus.publish(
        QdlPathEvaluated(
            path_id="p1",
            outcome="completed",
            attempted_steps=1,
            step_count=1,
            probe_count=1,
            reason="done",
        )
    )
    bus.publish(
        CheckCompleted(
            observation=Observation(
                check_id="c1",
                scenario_id="scenario",
                observed_outcome=AccessOutcome.ALLOWED,
                response_summary="allowed",
            )
        )
    )
    bus.publish(_finding_event())
    bus.publish(_fact_event())
    renderer.finished(1)

    output = stream.getvalue()
    assert "phase: qdl_planning" in output
    assert "campaign started: service=svc paths=1 steps=0 max_checks=2" in output
    assert "coverage updated" in output
    assert "step path=p1 step=s1 verdict=fail phase=active" in output
    assert "path p1 completed steps=1/1 probes=1" in output
    assert "FINDING" in output
    assert "campaign finished: checks=1 probes=1/0 paths=1 findings=1 facts=1" in output


def test_auto_and_live_modes_use_plain_logger() -> None:
    for mode in ("auto", "live", "plain"):
        renderer = ConsoleProgressRenderer(
            service="svc",
            mode=mode,
            stream=io.StringIO(),
        )
        assert renderer._mode == "plain"


@pytest.mark.parametrize(
    ("mode", "color", "message"),
    [
        ("unknown", "auto", "unknown progress mode: unknown"),
        ("plain", "unknown", "unknown progress color mode: unknown"),
    ],
)
def test_invalid_progress_options_are_rejected(
    mode: str, color: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        ConsoleProgressRenderer(service="svc", mode=mode, color=color)


def test_off_renderer_is_noop() -> None:
    class Bus:
        def subscribe(self, event_type, handler):
            raise AssertionError("off renderer must not subscribe")

    renderer = make_progress_renderer("off", service="svc")
    renderer.attach(Bus())
    renderer.set_metrics(None)


def test_write_failure_does_not_kill_campaign() -> None:
    class FailingStream:
        def write(self, text):
            raise OSError("stream closed")

    renderer = ConsoleProgressRenderer(
        service="svc",
        mode="plain",
        stream=FailingStream(),
    )
    renderer.phase("executing")
