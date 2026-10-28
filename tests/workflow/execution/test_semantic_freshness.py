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


def replay(events):
    return Runner.replay_state(
        tuple(events), scope=None, blocked_reasons=None, evidence_store=None
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
    state = replay(events)
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
    state = replay(events)
    assert scheduler.next_path() == path
    # This attempt generated its own evidence before finishing.
    current[0] = "typed:id=X"
    terminal.finish(PathAttempt(path), scheduler, state, scope=None)
    restarted = CoverageDrivenScheduler((path,))
    state = replay(events)
    assert state.replay.evaluated_signatures == {path.path_id: "typed:id=X"}
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
    assert path.path_id not in replay(events).replay.evaluated_outcomes


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
    state = replay(events)
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
    from cloud_dast.api import LiveRequest
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

    def initialize(scheduler, state):
        for candidate in scheduler.paths:
            if metrics.intent_state(candidate.path_id) is None:
                metrics.set_intent_state(candidate.path_id, IntentState.PENDING)

    def execute(request, path, scheduler, state, *, budget, scope):
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
            initialize_intents=initialize,
            mark_executing=lambda path: metrics.set_intent_state(
                path.path_id, IntentState.EXECUTING
            ),
            has_finding_examples=lambda path: False,
            skip_evaluated_path=terminal.skip_evaluated_path,
            execute_path=execute,
            publish_scheduler_terminal_events=lambda scheduler, scope: None,
            publish_missing_terminal_path_events=lambda scope: None,
            service_checks=lambda: (),
            evidence_signature=signature,
            reconsider_paths=terminal.reconsider_paths,
        )
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
    terminal.reconsider_paths(scheduler, replay(events), scope=None)
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
            scope=selected_scope,
            blocked_reasons=None,
            evidence_store=None,
        )

    terminal.reconsider_paths(scheduler, scoped_replay(scope), scope=scope)
    # The delegate's transient state is discarded. The next round must recover
    # the invalidation from the durable event stream, across run boundaries.
    new_round = scoped_replay(scope)
    assert path.path_id not in new_round.replay.evaluated_outcomes
    assert path.path_id not in new_round.replay.evaluated_signatures
    assert scoped_replay(unrelated_scope).replay.evaluated_outcomes == {
        path.path_id: "blocked"
    }
    assert scheduler.next_path() == path
