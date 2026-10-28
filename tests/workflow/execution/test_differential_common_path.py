"""Differential execution through the ordinary request and budget boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloud_dast.api import (
    LiveRequest,
    ScenarioBinding,
)
from cloud_dast.model import (
    AccessOutcome,
    Check,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ScenarioPosition,
)
from cloud_dast.model.events import EventScope
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign import (
    LiveWorkflow,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
)
from cloud_dast.runtime.execution.scenarios import (
    Checker,
    PartialExecutionError,
)
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.planning import QdlPlan
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast.verification.differential.contracts import (
    DifferentialSpec,
    ReadBackSpec,
)
from cloud_dast.verification.differential.modes import CONCURRENCY_PROBES
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[object] = []
        self._cursors: dict[str, int] = {}

    def publish(self, event: object) -> None:
        self.events.append(event)

    def append(self, event: object) -> None:
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[object, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class PairTarget:
    def __init__(self) -> None:
        self.executed = []

    def __call__(self, check):
        self.executed.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
        )


def _step(
    method: MethodSpec,
    scenario: ScenarioPosition,
    plan,
    invariant,
) -> QdlExecutionStep:
    return QdlExecutionStep(
        step_id="step:probe",
        goal_id="goal:test",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
        irreversible=False,
    )


def _runner(target: PairTarget) -> BoundPathRunner:
    events = EventLog()
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail(), events)
    service = checker
    return BoundPathRunner(
        service,
        events,
        events,
    )


def test_factor_pair_uses_the_shared_budget(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """A factor pair reserves and records both ordinary request legs."""

    target = PairTarget()
    runner = _runner(target)
    step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    owner = scenario_position.model_copy(
        update={
            "scenario_id": "owner-position",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    spec = DifferentialSpec(control=owner, treatment=scenario_position)
    budget = CallLimits(2)
    budget.begin_differential_round()

    control_check, treatment_check, control, treatment = (
        runner.differential.execute_step_pair(
            step,
            spec,
            budget,
        )
    )

    assert [check.method_id for check in target.executed] == [
        method_spec.method_id,
        method_spec.method_id,
    ]
    assert all(
        dict(check.request)["secret_id"] == "secret-victim" for check in target.executed
    )
    assert (control_check.check_id, treatment_check.check_id) == (
        control.check_id,
        treatment.check_id,
    )
    assert budget.live_calls == 2
    assert budget.diff_legs == 2


def test_factor_pair_does_not_spend_an_incomplete_pair(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """A budget too small for a complete pair executes no live call."""

    target = PairTarget()
    runner = _runner(target)
    step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    owner = scenario_position.model_copy(
        update={
            "scenario_id": "owner-position",
            "profile": scenario_position.profile.model_copy(
                update={"identity_class": "owner"}
            ),
        }
    )
    spec = DifferentialSpec(control=owner, treatment=scenario_position)
    budget = CallLimits(1)
    budget.begin_differential_round()

    with pytest.raises(PartialExecutionError):
        runner.differential.execute_step_pair(step, spec, budget)

    assert target.executed == []
    assert budget.live_calls == 0


def test_payload_pair_uses_the_shared_budget(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """Payload mutation preserves the grounded resource reference."""

    payload_method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="note", type="string"),
            )
        }
    )
    target = PairTarget()
    runner = _runner(target)
    step = _step(
        payload_method,
        scenario_position,
        verification_plan,
        invariant,
    )
    budget = CallLimits(2)
    budget.begin_differential_round()

    baseline_check, treatment_check, baseline, treatment = (
        runner.differential.execute_payload_pair(
            step,
            mutable_fields=("note",),
            canary="diff-canary",
            budget=budget,
        )
    )

    assert [check.method_id for check in target.executed] == [
        payload_method.method_id,
        payload_method.method_id,
    ]
    probe_requests = [dict(check.request) for check in target.executed]
    assert {request["secret_id"] for request in probe_requests} == {"secret-victim"}
    assert [request["note"] for request in probe_requests] == [
        "benign-diff-canary",
        "'diff-canary'",
    ]
    assert (baseline_check.check_id, treatment_check.check_id) == (
        baseline.check_id,
        treatment.check_id,
    )
    assert budget.live_calls == 2
    assert budget.diff_legs == 2


def test_readback_pair_uses_the_shared_budget(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """Read-back records and charges each of its three ordinary legs."""

    write_method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="note", type="string"),
            )
        }
    )
    read_method = method_spec.model_copy(
        update={
            "method_id": f"{method_spec.service}.Get",
            "name": "Get",
        }
    )
    target = PairTarget()
    runner = _runner(target)
    step = _step(
        write_method,
        scenario_position,
        verification_plan.model_copy(update={"resource_params": ("secret_id",)}),
        invariant,
    )
    spec = ReadBackSpec(
        write_method=write_method,
        read_method=read_method,
        resource_binding="secret_id",
        read_resource_types=(("secret_id", "lockbox.secret"),),
    )
    budget = CallLimits(3)
    budget.begin_differential_round()

    result = runner.differential.execute_readback(
        step,
        spec,
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        budget,
    )

    assert [check.method_id for check in target.executed] == [
        read_method.method_id,
        write_method.method_id,
        read_method.method_id,
    ]
    assert all(
        dict(check.request).get("secret_id") == "secret-victim"
        for check in target.executed
    )
    assert result.write.check_id == result.write_check.check_id
    assert budget.live_calls == 3
    assert budget.diff_legs == 3


def test_concurrency_step_uses_the_shared_budget(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """A concurrency batch charges each ordinary request to the shared budget."""

    target = PairTarget()
    runner = _runner(target)
    step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    budget = CallLimits(CONCURRENCY_PROBES)
    budget.begin_differential_round()

    result = runner.differential.execute_concurrency_step(
        step,
        read_method=None,
        max_workers=CONCURRENCY_PROBES,
        budget=budget,
    )

    assert [check.method_id for check in target.executed] == [
        *(method_spec.method_id for _ in range(CONCURRENCY_PROBES)),
    ]
    assert len(result.probes) == CONCURRENCY_PROBES
    assert all(
        dict(check.request)["secret_id"] == "secret-victim" for check in target.executed
    )
    assert budget.live_calls == CONCURRENCY_PROBES
    assert budget.diff_legs == CONCURRENCY_PROBES


def test_differential_dedup_is_scoped_to_action_and_scenario(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """The same action in another scenario is still a distinct pair."""

    second_position = scenario_position.model_copy(
        update={"scenario_id": "second-position"}
    )
    first_step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    repeated_step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    second_step = _step(
        method_spec,
        second_position,
        verification_plan.model_copy(
            update={"scenario_id": second_position.scenario_id}
        ),
        invariant,
    )
    paths = (
        QdlExecutionPath(
            path_id="path:first",
            goal_id="goal:test",
            kind="invariant",
            description="first",
            steps=(first_step,),
        ),
        QdlExecutionPath(
            path_id="path:repeat",
            goal_id="goal:test",
            kind="invariant",
            description="repeat",
            steps=(repeated_step,),
        ),
        QdlExecutionPath(
            path_id="path:second-scenario",
            goal_id="goal:test",
            kind="invariant",
            description="second scenario",
            steps=(second_step,),
        ),
    )
    binding = ScenarioBinding(
        scenario=scenario_position,
        graph=QdlGraph(),
        plan=QdlPlan(graph_hash="graph:test"),
        execution=QdlExecutionView(
            graph_hash="graph:test",
            paths=paths,
            invariants={invariant.invariant_id: invariant},
        ),
        invariants={invariant.invariant_id: invariant},
        methods=(method_spec,),
    )
    workflow = LiveWorkflow(
        None,
        SimpleNamespace(differential=ProbeExecutor(None, None)),
        None,
        diff_mode=True,
        diff_modes=frozenset({"factors"}),
    )
    recorded = []

    class RecordingRunner:
        def execute_step_pair(self, step, spec, budget, **kwargs):
            recorded.append((step.method.method_id, step.scenario.scenario_id))
            checks = tuple(
                Check(
                    invariant_id=step.invariant.invariant_id,
                    method_id=step.method.method_id,
                    scenario_id=step.scenario.scenario_id,
                    request=(),
                    identities=(identity,),
                )
                for identity in ("owner", "attacker")
            )
            observations = tuple(
                Observation(
                    check_id=check.check_id,
                    scenario_id=check.scenario_id,
                    observed_outcome=AccessOutcome.ALLOWED,
                    response_summary="local",
                    transport_status=HttpStatus(code=200),
                )
                for check in checks
            )
            return (*checks, *observations)

    workflow._differential._probes._executor = RecordingRunner()
    workflow._differential._probes._specs.control_position = (
        lambda request, step, treatment, graph, deficits: treatment.model_copy(
            update={
                "profile": treatment.profile.model_copy(
                    update={"identity_class": "owner"}
                )
            }
        )
    )
    budget = CallLimits(10)
    budget.begin_differential_round()

    workflow._differential._run_differential_round(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
        ),
        binding,
        CoverageDrivenScheduler(paths),
        CampaignAccumulator.empty(),
        DeficitQueue(),
        {},
        set(),
        budget,
        EventScope(campaign_id="campaign:test", run_id="run:test"),
    )

    assert recorded == [
        (method_spec.method_id, scenario_position.scenario_id),
        (method_spec.method_id, second_position.scenario_id),
    ]


def test_differential_budget_reserves_one_complete_pair(
    method_spec,
    scenario_position,
    verification_plan,
    invariant,
) -> None:
    """The protected differential share covers one complete ordinary pair."""

    step = _step(
        method_spec,
        scenario_position,
        verification_plan,
        invariant,
    )
    path = QdlExecutionPath(
        path_id="path:test",
        goal_id="goal:test",
        kind="invariant",
        description="test",
        steps=(step,),
    )
    workflow = LiveWorkflow(
        None,
        SimpleNamespace(differential=ProbeExecutor(None, None)),
        None,
        diff_mode=True,
        diff_modes=frozenset({"factors"}),
    )

    reserve = workflow._differential.budget_reserve(
        LiveRequest(
            service=method_spec.service,
            principal_id="principal-attacker",
            resource_id="secret-victim",
            max_checks=3,
        ),
        (path,),
    )

    assert reserve == 2
