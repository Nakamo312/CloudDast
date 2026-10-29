"""Reactive proposals have no durable authority before campaign handoff."""

import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

import cloud_dast
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
    denied,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.deficits import (
    Deficit,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    single_deficit_work_item,
)
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.inputs import PairInput
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence import (
    build_paired_evidence_view,
)
from cloud_dast.verification.slices import build_sibling_action_slice
from tests.grounding_owner import make_grounding


def fact(name, *args, context=Context.CONTRACT):
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


class Store:
    def __init__(self):
        action = Atom(value="action:get")
        self.graphs = {
            "contract:svc": QdlGraph(facts=(fact("is", action, Atom(value="Action")),))
        }
        self.writes = []

    def load(self, key):
        return self.graphs.get(key, QdlGraph())

    def load_merged(self, prefix):
        return merge_graphs(
            *(v for k, v in self.graphs.items() if k.startswith(prefix))
        )

    def save(self, key, graph, **kwargs):
        self.graphs[key] = graph
        self.writes.append((key, threading.get_ident()))


class Axis:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def ground_reactive(self, axis, actions, source, **kwargs):
        self.entered.set()
        assert self.release.wait(3)
        action = Atom(value=actions[0])
        norm = Atom(value="norm:forbidden:" + actions[0])
        graph = QdlGraph(
            facts=(
                fact("is", action, Atom(value="Action"), context=Context.PROPOSAL),
                fact("is", norm, Atom(value="Norm"), context=Context.PROPOSAL),
                fact("prevents", norm, denied(action), context=Context.PROPOSAL),
            )
        )
        self.finished.set()
        return AxisResult(axis, graph, 0, 1)

    def ground_alternatives(self, source, action, **kwargs):
        return self.ground_reactive("alternatives", (action,), source, **kwargs)

    def ground_variance(self, source, action, **kwargs):
        return self.ground_reactive("variance", (action,), source, **kwargs)


@pytest.mark.parametrize("axis_name", ["roles", "alternatives", "variance"])
def test_timed_out_closed_worker_cannot_write_accepted_or_spend_quota(axis_name):
    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    store, axis = Store(), Axis()
    policy = PromotionPolicy(enabled=True, max_norms=1)
    grounding = make_grounding(
        store, startup=axis, reactive=axis, promotion_policy=policy
    )
    runner = ThreadedGroundingRunner()

    source = store.load("contract:svc")
    siblings = build_sibling_action_slice(source, action="action:get")
    control, treatment, report = pair()
    evidence = build_paired_evidence_view(
        control=control, treatment=treatment, report=report
    )

    def task():
        try:
            if axis_name == "alternatives":
                return grounding.batches.prepare_branch(
                    source, "action:get", sibling_slice=siblings
                )
            if axis_name == "variance":
                return grounding.variance.prepare_batch(
                    PairInput(
                        source=source,
                        action_id="action:get",
                        control=control,
                        treatment=treatment,
                        report=report,
                        evidence=evidence,
                    )
                )
            return grounding.batches.prepare_reactive(source, "roles", ("action:get",))
        finally:
            axis.finished.set()

    handle = runner.start_task(task)
    assert axis.entered.wait(1)
    with pytest.raises(TimeoutError):
        handle.result(timeout=0.01)
    runner.close()
    axis.release.set()
    assert axis.finished.wait(1)
    assert not [key for key, _ in store.writes if key.startswith(("accepted", "diff:"))]
    assert policy.promoted_norms == 0


def campaign(store, axis, runner=None, policy=None):
    policy = policy or PromotionPolicy(enabled=True, max_norms=1)
    grounding = make_grounding(
        store, startup=axis, reactive=axis, promotion_policy=policy
    )
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding.batches,
        lifecycle=grounding.lifecycle,
        source=grounding.source,
        variance=grounding.variance,
        options=LiveWorkflowOptions(
            formal_repository=store,
            grounding_runner=runner or ThreadedGroundingRunner(),
            batch_timeout=0.02,
        ),
    )
    return workflow, policy


def item(action="action:get", axis="roles"):
    return single_deficit_work_item(
        Deficit(
            subgoal=QdlSubgoal(
                "prevents", (Variable(name="Norm"), denied(Atom(value=action)))
            ),
            predicate_class="prevents",
            axis=axis,
            context=(("control", "control"), ("treatment", "treatment"))
            if axis == "variance"
            else (),
            action=action,
        )
    )


def run_wave(workflow, store, items=None):
    items = items or (item(),)
    deficits = DeficitQueue()
    deficits.add(tuple(d for i in items for d in i.deficits))
    accumulator = CampaignAccumulator.empty()
    records = {}
    for i in items:
        if i.axis == "variance":
            control, treatment, report = pair()
            accumulator.observations.extend((control, treatment))
            for deficit in i.deficits:
                records[deficit.work_item_key] = VarianceRecord(
                    control, treatment, report
                )
    return workflow._replanning._consultation.run_wave(
        LiveRequest(service="svc", principal_id="attacker", resource_id="resource"),
        items,
        deficits,
        accumulator,
        variance_records=records,
        base_graph=store.load("contract:svc"),
    )


@pytest.mark.parametrize("axis_name", ["roles", "alternatives", "variance"])
def test_campaign_timeout_then_close_then_release_has_no_durable_effect(axis_name):
    store, axis = Store(), Axis()
    workflow, policy = campaign(store, axis)
    assert run_wave(workflow, store, (item(axis=axis_name),)).promoted == 0
    workflow._finalizer.close_grounding_lifecycle()
    axis.release.set()
    assert axis.finished.wait(1)
    assert store.writes == []
    assert policy.promoted_norms == 0


@pytest.mark.parametrize("axis_name", ["roles", "alternatives", "variance"])
def test_successful_campaign_commits_once_on_owner(axis_name):
    store, axis = Store(), Axis()
    axis.release.set()
    workflow, policy = campaign(store, axis)
    outcome = run_wave(workflow, store, (item(axis=axis_name),))
    accepted = [
        (key, thread)
        for key, thread in store.writes
        if key.startswith(("accepted", "diff:"))
    ]
    assert outcome.promoted == 1
    assert len(accepted) == 1
    assert accepted[0][1] == threading.get_ident()
    assert policy.promoted_norms == 1
    assert any(f.predicate.name == "prevents" for f in outcome.graph.facts)
    assert run_wave(workflow, store, (item(axis=axis_name),)).promoted == 0
    assert (
        len([key for key, _ in store.writes if key.startswith(("accepted", "diff:"))])
        == 1
    )
    assert policy.promoted_norms == 1


def test_close_after_result_before_owner_merge_discards_without_quota():
    class CloseAfterHandoff(ThreadedGroundingRunner):
        def run_tasks(self, *args, **kwargs):
            results = list(super().run_tasks(*args, **kwargs))
            self.close()
            yield from results

    store, axis = Store(), Axis()
    axis.release.set()
    workflow, policy = campaign(store, axis, CloseAfterHandoff())
    assert run_wave(workflow, store).promoted == 0
    assert store.writes == []
    assert policy.promoted_norms == 0


def test_source_revision_change_before_merge_discards_without_quota():
    class ReviseAfterHandoff(ThreadedGroundingRunner):
        def run_tasks(self, *args, **kwargs):
            results = list(super().run_tasks(*args, **kwargs))
            store.graphs["stand:svc"] = QdlGraph(
                facts=(fact("is", Atom(value="other"), Atom(value="Action")),)
            )
            yield from results

    store, axis = Store(), Axis()
    axis.release.set()
    workflow, policy = campaign(store, axis, ReviseAfterHandoff())
    assert run_wave(workflow, store).promoted == 0
    assert store.writes == []
    assert policy.promoted_norms == 0


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("priorities", [(1, 0, 1, 0), (1, 3, 2, 0), (4, 7, 1, 0)])
def test_shared_cap_is_applied_in_existing_structural_merge_order(reverse, priorities):
    class OrderedHandoff(ThreadedGroundingRunner):
        def run_tasks(self, *args, **kwargs):
            results = list(super().run_tasks(*args, **kwargs))
            yield from sorted(results, reverse=reverse, key=lambda pair: pair[0])

    store, axis = Store(), Axis()
    other = Atom(value="action:other")
    store.graphs["contract:svc"] = merge_graphs(
        store.load("contract:svc"),
        QdlGraph(facts=(fact("is", other, Atom(value="Action")),)),
    )
    axis.release.set()
    workflow, policy = campaign(store, axis, OrderedHandoff())
    fan_out, order, other_fan_out, other_order = priorities
    items = (
        replace(item(), fan_out=fan_out, order=order),
        replace(item("action:other"), fan_out=other_fan_out, order=other_order),
    )
    outcome = run_wave(workflow, store, items)
    winner = min(items, key=lambda i: i.structural_priority)
    norms = [f for f in outcome.graph.facts if f.predicate.name == "prevents"]
    assert len(norms) == 1
    assert norms[0].args[1] == denied(Atom(value=winner.action))
    assert policy.promoted_norms == 1
    assert len([k for k, _ in store.writes if k.startswith("accepted")]) == 1


def pair():
    control = Observation(
        observation_id="control",
        check_id="c",
        scenario_id="scenario",
        response_summary="denied",
        observed_outcome=AccessOutcome.DENIED,
    )
    treatment = Observation(
        observation_id="treatment",
        check_id="t",
        scenario_id="scenario",
        response_summary="allowed",
        observed_outcome=AccessOutcome.ALLOWED,
    )
    return (
        control,
        treatment,
        DiffReport(
            action_id="action:get",
            control_observation_id="control",
            treatment_observation_id="treatment",
            outcome_differs=True,
        ),
    )


def test_close_while_worker_is_held_discards_wave_without_promotion():
    store, axis = Store(), Axis()
    runner = ThreadedGroundingRunner()
    workflow, policy = campaign(store, axis, runner)

    def close_pending():
        assert axis.entered.wait(1)
        runner.close()
        axis.release.set()

    closer = threading.Thread(target=close_pending)
    closer.start()
    assert run_wave(workflow, store).promoted == 0
    closer.join(timeout=1)
    assert not closer.is_alive()
    assert axis.finished.wait(1)
    assert store.writes == []
    assert policy.promoted_norms == 0


def test_discarded_member_cannot_spend_successful_members_shared_cap():
    held, release, finished = threading.Event(), threading.Event(), threading.Event()

    class PartialAxis(Axis):
        def ground_reactive(self, axis, actions, source, **kwargs):
            if actions == ("action:get",):
                held.set()
                assert release.wait(1)
                try:
                    return super().ground_reactive(axis, actions, source, **kwargs)
                finally:
                    finished.set()
            return super().ground_reactive(axis, actions, source, **kwargs)

    store, axis = Store(), PartialAxis()
    axis.release.set()
    store.graphs["contract:svc"] = merge_graphs(
        store.load("contract:svc"),
        QdlGraph(facts=(fact("is", Atom(value="action:other"), Atom(value="Action")),)),
    )
    workflow, policy = campaign(store, axis)
    outcome = run_wave(workflow, store, (item(), item("action:other")))
    assert held.is_set()
    assert outcome.promoted == 1
    assert any(
        f.predicate.name == "prevents"
        and f.args[1] == denied(Atom(value="action:other"))
        for f in outcome.graph.facts
    )
    writes = list(store.writes)
    workflow._finalizer.close_grounding_lifecycle()
    release.set()
    assert finished.wait(1)
    assert store.writes == writes
    assert policy.promoted_norms == 1


def test_close_waits_for_admitted_owner_commit_held_before_save():
    before_save = threading.Event()
    release_save = threading.Event()
    close_started = threading.Event()
    close_returned = threading.Event()

    class HeldStore(Store):
        def save(self, key, graph, **kwargs):
            before_save.set()
            assert release_save.wait(2)
            assert not close_returned.is_set(), "durable write followed completed close"
            super().save(key, graph, **kwargs)

    store, axis = HeldStore(), Axis()
    axis.release.set()
    runner = ThreadedGroundingRunner()
    workflow, policy = campaign(store, axis, runner)
    outcomes = []
    owner = threading.Thread(target=lambda: outcomes.append(run_wave(workflow, store)))
    owner.start()
    assert before_save.wait(1), "owner did not reach admitted commit"

    def close():
        close_started.set()
        runner.close()
        close_returned.set()

    closer = threading.Thread(target=close)
    closer.start()
    assert close_started.wait(1)
    try:
        assert not close_returned.wait(0.03), (
            "close returned while admitted save was held"
        )
        assert store.writes == []
    finally:
        release_save.set()
        owner.join(timeout=2)
        closer.join(timeout=2)
    assert not owner.is_alive()
    assert not closer.is_alive()
    assert close_returned.is_set()
    assert len(outcomes) == 1 and outcomes[0].promoted == 1
    assert len(store.writes) == 1
    assert policy.promoted_norms == 1
    writes = list(store.writes)
    assert run_wave(workflow, store).promoted == 0
    assert store.writes == writes


@pytest.mark.parametrize("recover", [False, True])
def test_missing_revision_after_commit_discards_remaining_wave(recover):
    class UnavailableAfterCommit(Store):
        failures = 0

        def load(self, key):
            if self.writes and (not recover or self.failures == 0):
                self.failures += 1
                raise OSError("source revision is temporarily unavailable")
            return super().load(key)

    assert Path(cloud_dast.__file__).resolve().is_relative_to(Path.cwd())
    store, axis = UnavailableAfterCommit(), Axis()
    axis.release.set()
    actions = ("action:get", "action:other", "action:third")
    store.graphs["contract:svc"] = QdlGraph(
        facts=tuple(
            fact("is", Atom(value=action), Atom(value="Action")) for action in actions
        )
    )
    policy = PromotionPolicy(enabled=True, max_norms=3)
    workflow, _ = campaign(store, axis, policy=policy)
    outcome = run_wave(workflow, store, tuple(item(action) for action in actions))
    assert outcome.promoted == 1
    assert len(store.writes) == 1
    assert policy.promoted_norms == 1
    assert store.failures >= 1
    assert len([f for f in outcome.graph.facts if f.predicate.name == "prevents"]) == 1
