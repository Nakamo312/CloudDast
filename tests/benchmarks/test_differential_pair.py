"""Differential pair mechanics against the real NSFy Bench service."""

from __future__ import annotations

from collections.abc import Iterable

from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import EXPORT_DATA, SERVICE, methods

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.model.events import DomainEvent
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.execution import BoundPathRunner
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionStep,
)
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.differential.contracts import (
    DifferentialSpec,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self) -> Iterable[DomainEvent]:
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _scenario(
    scenario_id: str,
    identity_class: str,
    principal: str,
) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id=scenario_id,
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class=identity_class,
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service=SERVICE,
                    resource_type="user",
                    resource_id="victim",
                ),
            ),
            principals=(PrincipalRef(principal_id=principal, principal_type="user"),),
        ),
    )


def test_execute_step_pair_runs_isolated_export_data_legs() -> None:
    service = BenchService(BenchState.seed())
    events = EventLog()
    bus = EventBus()
    checker = Checker(
        BenchTarget(service),
        TemplateGenerator(),
        AllowAllGuardrail(),
        bus,
    )
    workflow = checker
    runner = BoundPathRunner(workflow, bus, events)
    budget = CallLimits(2)

    control = _scenario("export-owner", "owner", "victim")
    treatment = _scenario("export-attacker", "attacker", "attacker")
    export_method = next(
        method for method in methods() if method.method_id == EXPORT_DATA
    )
    invariant = InvariantProjection(
        invariant_id="norm:authz-export-other",
        norm_id="norm:authz-export-other",
        statement="Only the profile owner may export profile data",
        severity=Severity.HIGH,
    )
    step = QdlExecutionStep(
        step_id="step:export-data",
        goal_id="goal:export-data",
        plan=VerificationPlan(
            plan_id="plan:export-data",
            invariant_id=invariant.invariant_id,
            method_id=EXPORT_DATA,
            scenario_id=control.scenario_id,
            resource_types=(("user_id", "user"),),
        ),
        method=export_method,
        scenario=control,
        invariant=invariant,
    )

    control_check, treatment_check, control_obs, treatment_obs = (
        runner.differential.execute_step_pair(
            step,
            DifferentialSpec(control, treatment),
            budget,
        )
    )

    # Both legs execute the same request under different principals.
    assert control_check.identities == ("victim",)
    assert treatment_check.identities == ("attacker",)
    assert dict(control_check.request)["user_id"] == "victim"
    assert dict(treatment_check.request)["user_id"] == "victim"
    assert treatment_check.request == control_check.request

    # The control response fields (user_id/data) never leak into the
    # treatment request: output forwarding is isolated between the legs.
    assert "data" not in dict(treatment_check.request)
    assert control_check.scenario_id == control.scenario_id
    assert treatment_check.scenario_id == treatment.scenario_id

    # authz-export-other: the bench exports the victim's data for both the
    # owner and the attacker, so both legs are allowed.
    assert control_obs.observed_outcome is AccessOutcome.ALLOWED
    assert treatment_obs.observed_outcome is AccessOutcome.ALLOWED
    assert control_obs.scenario_id == control.scenario_id
    assert treatment_obs.scenario_id == treatment.scenario_id

    # Pair legs are ordinary executed checks of the campaign projection.
    assert control_check in workflow.checks
    assert treatment_check in workflow.checks
    assert budget.checks == 2
    assert budget.diff_legs == 2
