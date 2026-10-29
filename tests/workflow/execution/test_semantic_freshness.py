"""Evidence-sensitive terminal lifecycle, independent of the projection implementation."""

from __future__ import annotations

from dataclasses import replace

import pytest

from cloud_dast.model.events import DownstreamDecision, QdlPathEvaluated
from cloud_dast.runtime.campaign.round import (
    Runner,
)
from cloud_dast.runtime.execution.terminal import (
    Callbacks,
    PathAttempt,
    PathTerminalizer,
)
from cloud_dast.runtime.metrics import CampaignMetrics, IntentState
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from tests.workflow.execution.test_scheduler import make_path


def replay(events, scheduler):
    return Runner.replay_state(
        tuple(events),
        scheduler=scheduler,
        scope=None,
        blocked_reasons=None,
        evidence_store=None,
    )


def terminalizer(events, signature, metrics=None):
    return PathTerminalizer(
        Callbacks(
            publish=lambda event, scope: events.append(event),
            refresh_events=lambda: tuple(events),
            path_definitions=lambda: {},
            metrics=metrics,
            evidence_signature=signature,
        )
    )


@pytest.mark.parametrize("completed", [False, True])
def test_changed_evidence_reopens_terminal_without_resetting_attempts(completed):
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    events = []
    current = ["typed:id=X;proof=PayX"]
    metrics = CampaignMetrics()
    metrics.set_intent_state(path.path_id, IntentState.PENDING)
    metrics.set_intent_state(path.path_id, IntentState.EXECUTING)
    terminal = terminalizer(events, lambda path: current[0], metrics)
    state = replay(events, scheduler)
    assert scheduler.next_path() == path
    terminal.finish(
        PathAttempt(path, effect_verified=completed), scheduler, state, scope=None
    )
    attempts = dict(scheduler.state.attempts)
    canonical = dict(scheduler.state.canonical_attempts)
    assert events[-1].evidence_signature == current[0]
    terminal.reconsider_paths(scheduler, state, scope=None)
    assert scheduler.next_path() is None
    # A changed target/proof (or a revocation) is new semantic information.
    current[0] = "typed:id=Y;proof=PayY"
    terminal.reconsider_paths(scheduler, state, scope=None)
    assert isinstance(events[-1], DownstreamDecision)
    assert metrics.intent_state(path.path_id) is IntentState.PENDING
    assert scheduler.state.attempts == attempts
    assert scheduler.state.canonical_attempts == canonical
    assert scheduler.next_path() == path
    metrics.set_intent_state(path.path_id, IntentState.EXECUTING)
    terminal.finish(PathAttempt(path), scheduler, state, scope=None)
    terminal.reconsider_paths(scheduler, state, scope=None)
    assert scheduler.next_path() is None


def test_post_attempt_evidence_does_not_reopen_itself_after_restart():
    path = make_path("main")
    events = []
    scheduler = CoverageDrivenScheduler((path,))
    current = ["empty"]
    terminal = terminalizer(events, lambda path: current[0])
    state = replay(events, scheduler)
    assert scheduler.next_path() == path
    # This attempt generated its own evidence before finishing.
    current[0] = "typed:id=X"
    terminal.finish(PathAttempt(path), scheduler, state, scope=None)
    restarted = CoverageDrivenScheduler((path,))
    state = replay(events, restarted)
    assert restarted.state.evidence_signatures == {path.path_id: "typed:id=X"}
    terminal.reconsider_paths(restarted, state, scope=None)
    assert path.path_id in state.replay.evaluated_outcomes
    assert restarted.next_path() == path
    terminal.skip_evaluated_path(path, restarted, state, scope=None)
    assert restarted.next_path() is None
    assert events[-1].evidence_signature == "typed:id=X"
    current[0] = "typed:id=Y"
    terminal.reconsider_paths(restarted, state, scope=None)
    assert path.path_id not in state.replay.evaluated_outcomes
    assert restarted.next_path() == path
    # Invalidation remains effective if a process stops before its next attempt.
    assert path.path_id not in replay(events, scheduler).replay.evaluated_outcomes


@pytest.mark.parametrize(
    "previous,current", [(None, "new"), ("old", None), ("same", "same")]
)
def test_missing_or_equivalent_evidence_keeps_replay_gate(previous, current):
    path = make_path("main")
    events = [
        QdlPathEvaluated(
            path_id=path.path_id,
            outcome="blocked",
            evidence_signature=previous,
            attempted_steps=0,
            step_count=1,
            probe_count=0,
            reason="blocked",
        )
    ]
    scheduler = CoverageDrivenScheduler((path,))
    terminal = terminalizer(events, lambda path: current)
    state = replay(events, scheduler)
    terminal.reconsider_paths(scheduler, state, scope=None)
    assert state.replay.evaluated_outcomes[path.path_id] == "blocked"
    assert len(events) == 1


def test_reconsideration_preserves_canonical_retry_cap_and_supersession():
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    for _ in range(3):
        assert scheduler.next_path() == path
        scheduler.record_outcome(
            path.path_id, "blocked", attempted_steps=[path.steps[0].step_id], reward=0.5
        )
    assert scheduler.next_path() is None
    attempts = dict(scheduler.state.canonical_attempts)
    assert not scheduler.reopen_path(path.path_id)
    assert scheduler.state.canonical_attempts == attempts
    other = CoverageDrivenScheduler((path,))
    other.supersede_paths({path.path_id: "replacement"})
    assert not other.reopen_path(path.path_id)


def test_same_id_refreshes_execution_path_without_renewing_attempts():
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() == path
    scheduler.record_outcome(path.path_id, "blocked", attempted_steps=())
    refreshed = replace(path, description="refreshed evidence snapshot")
    assert scheduler.add_paths((refreshed,)) == 0
    assert scheduler.paths[0] is refreshed
    assert scheduler.state.attempts == {path.path_id: 1}
    assert scheduler.next_path() is None


def test_metrics_requires_explicit_invalidation_for_terminal_regression():
    metrics = CampaignMetrics()
    metrics.set_intent_state("main", IntentState.PENDING)
    metrics.set_intent_state("main", IntentState.BLOCKED)
    with pytest.raises(ValueError, match="invalid intent transition"):
        metrics.set_intent_state("main", IntentState.PENDING)
    with pytest.raises(ValueError, match="requires changed path evidence"):
        metrics.invalidate_intent(
            DownstreamDecision(
                component="unrelated",
                by="scheduler",
                path_id="main",
                consumed=True,
                outcome="evidence_invalidated",
            )
        )
    assert metrics.intent_state("main") is IntentState.BLOCKED


def test_round_rechecks_before_selection_and_suppresses_equivalent_evidence():
    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.runtime.budget import CallLimits
    from cloud_dast.runtime.campaign.round import RunnerDeps

    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    events = []
    evidence = {"required_value": None, "irrelevant": None, "observation_id": "o1"}

    def signature(path):
        return repr(evidence["required_value"])

    metrics = CampaignMetrics()
    terminal = terminalizer(events, signature, metrics)
    calls = []

    def execute(request, path, scheduler, state, *, budget, scope):
        assert metrics.intent_state(path.path_id) is IntentState.EXECUTING
        calls.append(path.path_id)
        assert len(calls) <= 2, "unchanged post-attempt evidence caused a loop"
        # Evidence observed during an attempt must be consumed by that attempt.
        evidence["observation_id"] = f"self:{len(calls)}"
        terminal.finish(PathAttempt(path), scheduler, state, scope=scope)
        return True

    round_runner = Runner(
        RunnerDeps(
            reset_checks=lambda: None,
            refresh_events=lambda: tuple(events),
            register_paths=lambda paths: None,
            skip_evaluated_path=terminal.skip_evaluated_path,
            execute_path=execute,
            publish_scheduler_terminal_events=lambda scheduler, scope: None,
            publish_missing_terminal_path_events=lambda scope: None,
            service_checks=lambda: (),
            reconsider_paths=terminal.reconsider_paths,
        ),
        metrics=metrics,
    )
    request = LiveRequest(
        service="svc", principal_id="attacker", resource_id="resource"
    )
    budget = CallLimits(4)
    round_runner.run(request, scheduler, budget=budget)
    assert calls == ["main"]
    # Repeated observations and unrelated evidence cannot make a path eligible.
    evidence.update(irrelevant="new", observation_id="equivalent:o2")
    round_runner.run(request, scheduler, budget=budget)
    assert calls == ["main"]
    evidence["required_value"] = "X"
    round_runner.run(request, scheduler, budget=budget)
    assert calls == ["main", "main"]
    evidence["observation_id"] = "equivalent:o3"
    round_runner.run(request, scheduler, budget=budget)
    assert calls == ["main", "main"]


def test_replayed_terminal_can_initialize_fresh_metrics_on_invalidation():
    path = make_path("main")
    events = [
        QdlPathEvaluated(
            path_id=path.path_id,
            outcome="completed",
            evidence_signature="old",
            attempted_steps=1,
            step_count=1,
            probe_count=1,
            reason="verified earlier",
        )
    ]
    metrics = CampaignMetrics()
    terminal = terminalizer(events, lambda path: "revoked", metrics)
    scheduler = CoverageDrivenScheduler((path,))
    terminal.reconsider_paths(scheduler, replay(events, scheduler), scope=None)
    metrics.set_intent_state(path.path_id, IntentState.EXECUTING)
    assert metrics.intent_state(path.path_id) is IntentState.EXECUTING


def test_separate_scoped_reconsideration_survives_next_round_replay():
    from cloud_dast.model.events import EventScope

    path = make_path("main")
    scope = EventScope(campaign_id="campaign", run_id="restarted-run")
    previous_scope = EventScope(campaign_id="campaign", run_id="first-run")
    unrelated_scope = EventScope(campaign_id="other-campaign", run_id="other-run")
    old = QdlPathEvaluated(
        path_id=path.path_id,
        outcome="blocked",
        evidence_signature="old",
        attempted_steps=1,
        step_count=1,
        probe_count=1,
        reason="old premises",
    )
    events = [previous_scope.apply(old), unrelated_scope.apply(old)]
    scheduler = CoverageDrivenScheduler((path,))
    terminal = PathTerminalizer(
        Callbacks(
            publish=lambda event, scope: events.append(scope.apply(event)),
            refresh_events=lambda: tuple(events),
            path_definitions=lambda: {path.path_id: path},
            metrics=None,
            evidence_signature=lambda path: "new",
        )
    )

    def scoped_replay(selected_scope):
        return Runner.replay_state(
            tuple(events),
            scheduler=scheduler,
            scope=selected_scope,
            blocked_reasons=None,
            evidence_store=None,
        )

    terminal.reconsider_paths(scheduler, scoped_replay(scope), scope=scope)
    # The delegate's transient state is discarded. The next round must recover
    # the invalidation from the durable event stream, across run boundaries.
    new_round = scoped_replay(scope)
    assert path.path_id not in new_round.replay.evaluated_outcomes
    assert scoped_replay(unrelated_scope).replay.evaluated_outcomes == {
        path.path_id: "blocked"
    }
    assert scheduler.next_path() == path


@pytest.mark.parametrize("failure", ["publish", "metrics"])
def test_failed_invalidation_keeps_evidence_for_another_reconsideration(failure):
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    assert scheduler.next_path() == path
    scheduler.record_outcome(path.path_id, "completed", attempted_steps=())
    scheduler.state.remember_evidence(path.path_id, "old")
    events = []
    marker = RuntimeError(failure)

    class Metrics:
        def invalidate_intent(self, event):
            raise marker

    def publish(event, scope):
        if failure == "publish":
            raise marker
        events.append(event)

    terminal = PathTerminalizer(
        Callbacks(
            publish=publish,
            refresh_events=lambda: tuple(events),
            path_definitions=lambda: {},
            metrics=Metrics() if failure == "metrics" else None,
            evidence_signature=lambda path: "new",
        )
    )
    state = replay((), scheduler)
    with pytest.raises(RuntimeError) as caught:
        terminal.reconsider_paths(scheduler, state, scope=None)
    assert caught.value is marker
    assert scheduler.state.evidence_signatures[path.path_id] == "old"
    assert len(events) == (failure == "metrics")
    assert scheduler.next_path() == path


def test_historical_missing_signature_masks_retained_scheduler_evidence():
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    scheduler.state.remember_evidence(path.path_id, "retained")
    events = [
        QdlPathEvaluated(
            path_id=path.path_id,
            outcome="completed",
            evidence_signature=None,
            attempted_steps=1,
            step_count=1,
            probe_count=1,
            reason="legacy",
        )
    ]
    calls = []
    terminal = terminalizer(events, lambda path: calls.append(path.path_id) or "new")
    state = replay(events, scheduler)
    terminal.reconsider_paths(scheduler, state, scope=None)
    assert calls == []
    assert scheduler.next_path() == path
    terminal.skip_evaluated_path(path, scheduler, state, scope=None)
    assert events[-1].evidence_signature is None
    assert scheduler.next_path() is None


def test_invalidated_history_preserves_retained_unpublished_evidence():
    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    events = [
        DownstreamDecision(
            component="qdl_path",
            kind="gate",
            path_id=path.path_id,
            consumed=True,
            by="scheduler",
            outcome="evidence_invalidated",
        )
    ]
    terminal = terminalizer(events, lambda path: "retained")
    assert scheduler.next_path() == path
    terminal.finish(
        PathAttempt(path, effect_verified=True),
        scheduler,
        replay((), scheduler),
        scope=None,
    )
    # The successful local attempt's event is unavailable to this replay.
    events.pop()
    calls = []
    terminal = terminalizer(events, lambda path: calls.append(path.path_id) or "new")
    terminal.reconsider_paths(scheduler, replay(events, scheduler), scope=None)
    assert calls == [path.path_id]
    assert events[-1].outcome == "evidence_invalidated"
    assert scheduler.next_path() == path


def test_early_exit_recaptures_retained_evidence_in_each_round():
    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.runtime.campaign.round import RunnerDeps

    path = make_path("main")
    scheduler = CoverageDrivenScheduler((path,))
    captures = []

    terminal = terminalizer(
        [], lambda path: captures.append(path.path_id) or str(len(captures))
    )

    def execute(request, path, scheduler, state, *, budget, scope):
        terminal.block(
            path, scheduler, state, reason="symbolic", prerequisite=False, scope=scope
        )
        return True

    runner = Runner(
        RunnerDeps(
            reset_checks=lambda: None,
            refresh_events=lambda: (),
            register_paths=lambda paths: None,
            skip_evaluated_path=lambda *args, **kwargs: pytest.fail(
                "unexpected replay skip"
            ),
            execute_path=execute,
            publish_scheduler_terminal_events=lambda *args, **kwargs: None,
            publish_missing_terminal_path_events=lambda scope: None,
            service_checks=lambda: (),
        )
    )
    request = LiveRequest(service="svc", principal_id="actor", resource_id="resource")
    runner.run(request, scheduler)
    assert captures == [path.path_id]
    assert scheduler.reopen_path(path.path_id)
    runner.run(request, scheduler)
    assert captures == [path.path_id, path.path_id]
    assert scheduler.state.evidence_signatures[path.path_id] == "2"


@pytest.mark.parametrize("mode", ["witness", "symbolic"])
@pytest.mark.parametrize("fail_publish", [False, True])
def test_early_terminal_snapshot_exists_before_publication(
    monkeypatch, mode, fail_publish
):
    from types import SimpleNamespace

    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.model.events import EventScope
    from cloud_dast.qdl.graph import Atom, Variable
    from cloud_dast.qdl.reasoning import QdlSubgoal
    from cloud_dast.runtime.budget import CallLimits
    from cloud_dast.runtime.execution.evidence import PathSignature
    from tests.workflow.execution.test_path_runner_fuzzing import (
        EventLog,
        RecordingTarget,
        _runner,
    )

    path = make_path("early")
    if mode == "witness":
        step = replace(
            path.steps[0],
            witness_requirement=QdlSubgoal(
                "probe_carrier", (Atom(value="action:get"), Variable(name="Carrier"))
            ),
        )
        path = replace(path, steps=(step,))
    scheduler = CoverageDrivenScheduler((path,))
    scope = EventScope(campaign_id="campaign", run_id="run")
    metrics = CampaignMetrics()
    captures = []
    failure = RuntimeError("publication failed")

    class ObservedLog(EventLog):
        def publish(self, event):
            if isinstance(event, QdlPathEvaluated):
                assert (
                    scheduler.state.evidence_signatures[path.path_id]
                    == event.evidence_signature
                )
                assert captures == [path.path_id]
                assert metrics.intent_state(path.path_id) is IntentState.BLOCKED
                assert (event.campaign_id, event.run_id) == (
                    scope.campaign_id,
                    scope.run_id,
                )
                if fail_publish:
                    raise failure
            super().publish(event)

    monkeypatch.setattr(
        PathSignature,
        "build",
        lambda self, candidate: captures.append(candidate.path_id) or "proof",
    )
    target = RecordingTarget(())
    runner, events = _runner(target, metrics=metrics, events=ObservedLog())
    monkeypatch.setattr(
        runner._campaign_round._callbacks.execute_path.__self__.prefilter,
        "run",
        lambda *args, **kwargs: SimpleNamespace(status="unsat"),
    )
    request = LiveRequest(service="svc", principal_id="actor", resource_id="resource")
    budget = CallLimits(5)
    if fail_publish:
        with pytest.raises(RuntimeError) as caught:
            runner.execute_round(request, scheduler, budget=budget, scope=scope)
        assert caught.value is failure
    else:
        result = runner.execute_round(request, scheduler, budget=budget, scope=scope)
        assert result.observations == result.checks == ()
        assert len([e for e in events.events if isinstance(e, QdlPathEvaluated)]) == 1
    assert target.executed == []
    assert budget.live_calls == 0
    assert scheduler.state.evidence_signatures[path.path_id] == "proof"
    assert scheduler.state.attempts.get(path.path_id, 0) == (
        0 if mode == "witness" else 1
    )
