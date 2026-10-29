from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.contracts.metrics import measure_component_activity
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Observation,
    TraceStep,
)
from cloud_dast.model.events import ComponentInvoked, DownstreamDecision
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Variable,
)
from cloud_dast.qdl.graph import field as field_term
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.campaign import (
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.consultation.evidence import key
from cloud_dast.runtime.consultation.outcomes import (
    AttemptKey,
)
from cloud_dast.runtime.deficits import (
    Deficit,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItemGrounding,
    single_deficit_work_item,
)
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.results import AxisResult


class EventLog:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def publish(self, event: Any) -> None:
        self.events.append(event)


class ScriptedGrounding:
    def __init__(self, result: QdlGraph | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.reactive_calls = 0
        self.reactive_capable = True

    def prepare_branch(self, *args: Any, **kwargs: Any) -> AxisResult:
        return self._answer()

    def prepare_reactive(self, *args: Any, **kwargs: Any) -> AxisResult:
        return self._answer()

    def _answer(self) -> AxisResult:
        self.reactive_calls += 1
        if self.error is not None:
            raise self.error
        return AxisResult("roles", self.result, 0, 1)

    def commit(self, service, source, axis, actions, proposal, **kwargs):
        return proposal.graph


def _request() -> LiveRequest:
    return LiveRequest(
        service="svc",
        principal_id="principal",
        resource_id="resource",
    )


def _workflow(grounding: ScriptedGrounding) -> tuple[LiveWorkflow, EventLog]:
    events = EventLog()
    return (
        assemble_workflow(
            None,
            SimpleNamespace(differential=object()),
            None,
            grounding=grounding,
            source=SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
            options=LiveWorkflowOptions(
                event_bus=events,
                reactive_budget=None,
                grounding_runner=ThreadedGroundingRunner(),
            ),
        ),
        events,
    )


def _response_deficit(observation_id: str, field_name: str = "email") -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field_term(
                    Variable(name="AnyResource"),
                    Variable(name="AnyField"),
                ),
            ),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="svc.Get",
        context=(
            ("fields", field_name),
            ("observation_id", observation_id),
        ),
    )


def _alternatives_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (
                Atom(value="svc.Get"),
                Variable(name="AnyEffect"),
            ),
        ),
        predicate_class="causes",
        axis="alternatives",
        action="svc.Get",
        context=(("path_id", "path-1"),),
    )


def _availability_deficit() -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (
                Atom(value="svc.Get"),
                Variable(name="AnyEffect"),
            ),
        ),
        predicate_class="causes",
        axis="availability",
        action="svc.Get",
        context=(("path_id", "path-1"),),
    )


def _observation(observation_id: str) -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id=f"check-{observation_id}",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        response_tree=(("email", "response-value"),),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id=f"step-{observation_id}",
                    method_id="svc.Get",
                    scenario_id="scenario",
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
    )


def _promoted_graph() -> QdlGraph:
    return QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:svc.Get"), Atom(value="Action")),
            ),
        )
    )


def _pop_item(deficits: DeficitQueue, deficit: Deficit):
    deficits.add((deficit,))
    return deficits.pop_wave()[0]


def _decision(events: EventLog) -> DownstreamDecision:
    return next(
        event
        for event in reversed(events.events)
        if isinstance(event, DownstreamDecision)
    )


def test_promoted_outcome_is_recorded_and_published() -> None:
    grounding = ScriptedGrounding(_promoted_graph())
    workflow, events = _workflow(grounding)
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _alternatives_deficit())

    execution = workflow._replanning._consultation._run_parallel_work_items(
        _request(),
        (work_item,),
        deficits,
        CampaignAccumulator.empty(),
    )

    assert execution.promoted == 1
    assert grounding.reactive_calls == 1
    key = AttemptKey("svc", work_item.work_item_id, ())
    assert workflow.consultation_outcomes[key] == "promoted"
    assert _decision(events).outcome == "promoted"


def test_parked_outcome_is_terminal_for_the_same_evidence() -> None:
    grounding = ScriptedGrounding(None)
    workflow, events = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _response_deficit("obs-1"))

    execution = workflow._replanning._consultation._run_parallel_work_items(
        _request(),
        (work_item,),
        deficits,
        accumulator,
    )

    assert execution.promoted == 0
    assert grounding.reactive_calls == 1
    key = AttemptKey("svc", work_item.work_item_id, ("observation_id=obs-1",))
    assert workflow.consultation_outcomes[key] == "parked"
    assert _decision(events).outcome == "parked"


def test_contract_error_is_rejected_without_retrying() -> None:
    grounding = ScriptedGrounding(error=ValueError("invalid contract"))
    workflow, events = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _response_deficit("obs-1"))

    workflow._replanning._consultation._run_parallel_work_items(
        _request(), (work_item,), deficits, accumulator
    )

    key = AttemptKey("svc", work_item.work_item_id, ("observation_id=obs-1",))
    assert workflow.consultation_outcomes[key] == "rejected"
    assert _decision(events).outcome == "rejected"


def test_infrastructure_error_is_transient_for_this_evidence() -> None:
    grounding = ScriptedGrounding(error=RuntimeError("model unavailable"))
    workflow, events = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _response_deficit("obs-1"))

    workflow._replanning._consultation._run_parallel_work_items(
        _request(), (work_item,), deficits, accumulator
    )

    key = AttemptKey("svc", work_item.work_item_id, ("observation_id=obs-1",))
    assert workflow.consultation_outcomes[key] == "transient_error"
    assert _decision(events).outcome == "transient_error"


def test_missing_evidence_gate_records_the_missing_evidence_outcome() -> None:
    grounding = ScriptedGrounding(None)
    workflow, events = _workflow(grounding)
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _response_deficit("missing-observation"))

    gated, observation, check = (
        workflow._replanning._consultation._committer.plan_observation(
            _request(),
            work_item,
            deficits,
            CampaignAccumulator.empty(),
        )
    )

    assert (gated, observation, check) == (True, None, None)
    key = AttemptKey(
        "svc",
        work_item.work_item_id,
        ("observation_id=missing-observation",),
    )
    assert workflow.consultation_outcomes[key] == "missing_evidence"
    assert grounding.reactive_calls == 0
    decision = _decision(events)
    assert decision.outcome == "missing_evidence"
    assert decision.component == "evidence_gate:observation_required"
    assert decision.kind == "gate"

    invocation = next(
        event
        for event in events.events
        if isinstance(event, ComponentInvoked)
        and event.component == "evidence_gate:observation_required"
    )
    assert invocation.kind == "gate"
    assert invocation.input_digest
    assert invocation.input_completeness["deficits"] == 1

    activity = measure_component_activity(events.events)[
        "evidence_gate:observation_required"
    ]
    assert activity.activation_proven is True
    assert activity.activation_failures == ()


def test_superseded_work_item_is_recorded_as_conflict() -> None:
    grounding = ScriptedGrounding(_promoted_graph())
    workflow, events = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    observation = _observation("obs-1")
    accumulator.observations.append(observation)
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _response_deficit("obs-1"))

    promoted = workflow._replanning._consultation._committer.record_outcome(
        _request(),
        work_item,
        WorkItemGrounding(
            work_item.work_item_id,
            _promoted_graph(),
            observation,
        ),
        deficits,
        conflict=True,
    )

    assert promoted == 0
    key = AttemptKey("svc", work_item.work_item_id, ("observation_id=obs-1",))
    assert workflow.consultation_outcomes[key] == "conflict"
    assert _decision(events).outcome == "conflict"


def test_deferred_latency_baseline_does_not_consume_consultation_budget() -> None:
    grounding = ScriptedGrounding(None)
    workflow, _ = _workflow(grounding)
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    work_item = _pop_item(deficits, _availability_deficit())

    promoted = workflow._replanning._consultation._ground_latency_work_item(
        _request(),
        work_item,
        deficits,
        CampaignAccumulator.empty(),
    )

    assert promoted == 0
    assert grounding.reactive_calls == 0
    assert deficits.saturated_count == 0
    assert deficits.pending_count == 1
    assert deficits.closed_count == 0
    assert deficits.dispatchable is False


def test_new_evidence_reopens_the_consultation_exactly_once() -> None:
    grounding = ScriptedGrounding(None)
    workflow, _ = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)

    workflow._replanning.drain_reactive(
        _request(), deficits, accumulator, graph=QdlGraph()
    )
    deficits.add((_response_deficit("obs-1"),))
    workflow._replanning.drain_reactive(
        _request(), deficits, accumulator, graph=QdlGraph()
    )
    assert grounding.reactive_calls == 1

    accumulator.observations.append(_observation("obs-2"))
    deficits.add((_response_deficit("obs-2"),))
    workflow._replanning.drain_reactive(
        _request(), deficits, accumulator, graph=QdlGraph()
    )
    assert grounding.reactive_calls == 2


def test_absorbed_outcome_does_not_consume_the_fair_budget() -> None:
    grounding = ScriptedGrounding(None)
    workflow, _ = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    absorbed = _response_deficit("obs-1")
    absorbed_item = single_deficit_work_item(absorbed)
    absorbed_key = key(
        "svc",
        absorbed_item,
        _observation("obs-1"),
    )
    workflow._replanning._consultation._consultation_outcomes.record(
        absorbed_key,
        "rejected",
    )
    ready = _alternatives_deficit()
    deficits = DeficitQueue(max_tasks=1, max_attempts=1)
    deficits.add((absorbed, ready))

    workflow._replanning.drain_reactive(
        _request(),
        deficits,
        accumulator,
        graph=QdlGraph(),
    )

    assert grounding.reactive_calls == 1
    assert deficits.dispatched == 1
    assert deficits.budget_exhausted is True


def test_separately_assembled_workflows_keep_absorbing_outcomes_independent():
    grounding = ScriptedGrounding(None)
    first, _ = _workflow(grounding)
    second, _ = _workflow(grounding)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(_observation("obs-1"))
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    item = _pop_item(deficits, _response_deficit("obs-1"))
    first._replanning._consultation.run_wave(
        _request(),
        (item,),
        deficits,
        accumulator,
    )
    assert grounding.reactive_calls == 1
    assert not first._replanning._consultation.work_item_ready("svc", item, accumulator)
    assert second._replanning._consultation.work_item_ready("svc", item, accumulator)
    assert first.consultation_outcomes
    assert not second.consultation_outcomes
