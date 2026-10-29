"""Ordinary QDL predecessors share request budgets, guardrails and evidence."""

from __future__ import annotations

from dataclasses import replace

import pytest

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
)
from cloud_dast.model.events import DomainEvent, QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail
from tests.workflow.execution.test_causal_execution import _binding


class EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event) -> None:
        self.events.append(event)

    def publish(self, event) -> None:
        self.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _ordinary_runner(*, guardrail=None, repository=None, witness=True):
    graph, plan, view = _binding()
    calls = []
    events = EventLog()

    def target(check):
        calls.append(check)
        if check.method_id == "widgets.Use":
            assert dict(check.request)["widget_id"] == "observed-widget"
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            transport_status=HttpStatus(code=200),
            response_summary="ordinary action",
            output=ResponseData(fields=(("id", "observed-widget"),))
            if witness and check.method_id == "widgets.Make"
            else None,
        )

    service = Checker(
        target,
        TemplateGenerator(),
        guardrail or AllowAllGuardrail(),
        events,
    )
    runner = assemble_runner(service, events, events, formal_repository=repository)
    request = LiveRequest(
        service="widgets", principal_id="actor", resource_id="launch-context"
    )
    return runner, request, plan, view, calls, events


@pytest.mark.parametrize("limit,expected", [(0, 0), (1, 1), (2, 2)])
def test_causal_actions_each_spend_one_shared_request(limit, expected):
    runner, request, _, view, calls, _ = _ordinary_runner()
    budget = CallLimits(limit)
    result = runner.execute_round(
        request, CoverageDrivenScheduler(view.paths), budget=budget
    )
    assert len(calls) == len(result.checks) == len(result.observations) == expected
    assert budget.live_calls == budget.checks == expected
    assert [check.method_id for check in calls] == ["widgets.Make", "widgets.Use"][
        :expected
    ]


def test_causal_actions_respect_budget_already_spent_in_another_round():
    runner, request, _, view, calls, _ = _ordinary_runner()
    budget = CallLimits(2)
    budget.spend(1, kind="check")
    result = runner.execute_round(
        request, CoverageDrivenScheduler(view.paths), budget=budget
    )
    assert len(result.checks) == 1
    assert [check.method_id for check in calls] == ["widgets.Make"]
    assert budget.live_calls == 2


def test_exhausted_shared_budget_prevents_a_later_path():
    runner, request, _, view, calls, _ = _ordinary_runner()
    budget = CallLimits(2)
    first = runner.execute_round(
        request, CoverageDrivenScheduler(view.paths), budget=budget
    )
    second_path = replace(view.paths[0], path_id="another-causal-path")
    second = runner.execute_round(
        request, CoverageDrivenScheduler((second_path,)), budget=budget
    )
    assert len(first.checks) == 2
    assert second.checks == second.observations == ()
    assert len(calls) == budget.live_calls == 2


@pytest.mark.parametrize("blocked", ["widgets.Make", "widgets.Use"])
def test_every_causal_action_passes_the_same_guardrail(blocked):
    reviewed = []

    class Guardrail:
        def allows(self, check):
            reviewed.append(check)
            return check.method_id != blocked

    runner, request, plan, view, calls, _ = _ordinary_runner(guardrail=Guardrail())
    runner.execute_plan(request, plan, view)
    expected = [] if blocked == "widgets.Make" else ["widgets.Make"]
    assert [check.method_id for check in calls] == expected
    assert [check.method_id for check in reviewed] == expected + [blocked]
    if blocked == "widgets.Use":
        assert dict(reviewed[-1].request)["widget_id"] == "observed-widget"


def test_missing_causal_witness_blocks_the_dependent_request():
    runner, request, plan, view, calls, events = _ordinary_runner(witness=False)
    result = runner.execute_plan(request, plan, view)
    assert [check.method_id for check in calls] == ["widgets.Make"]
    assert len(result.observations) == 1
    outcomes = [e for e in events.events if isinstance(e, QdlPathEvaluated)]
    assert outcomes[-1].outcome == "blocked"


def test_causal_action_observations_have_events_and_durable_provenance(tmp_path):
    with SqliteFormalRepository(tmp_path / "causal.sqlite") as repository:
        runner, request, plan, view, calls, events = _ordinary_runner(
            repository=repository
        )
        result = runner.execute_plan(request, plan, view)
        assert len(calls) == len(result.observations) == 2
        evaluated = [e for e in events.events if isinstance(e, QdlStepEvaluated)]
        assert {e.step_id for e in evaluated} == {
            s.step_id for s in view.paths[0].steps
        }
        assert len(evaluated) == 2
        for observation in result.observations:
            assert repository.load(f"observation:{observation.observation_id}").facts
        outcomes = [e for e in events.events if isinstance(e, QdlPathEvaluated)]
        assert outcomes[-1].outcome == "completed"


def test_ordinary_seed_hints_skip_branch_and_fill_values(
    verification_plan,
    scenario_position,
) -> None:
    from cloud_dast.candidates import (
        apply_seed_hints,
    )
    from cloud_dast.model import FieldSpec

    setup = MethodSpec(
        method_id="grpc:create",
        service="service",
        name="Create",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(name="folder_id", type="string"),
            FieldSpec(name="name", type="string"),
            FieldSpec(name="password_payload_specification", type="message"),
            FieldSpec(name="password_payload_specification.length", type="int64"),
            FieldSpec(name="version_payload_entries", type="message", repeated=True),
            FieldSpec(name="version_payload_entries.key", type="string"),
            FieldSpec(name="version_payload_entries.text_value", type="string"),
        ),
    )
    seed = Check(
        invariant_id="inv",
        method_id=setup.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(
            ("folder_id", "folder-1"),
            ("name", None),
            ("password_payload_specification", None),
            ("password_payload_specification.length", None),
            ("version_payload_entries", (None,)),
            ("version_payload_entries.key", None),
            ("version_payload_entries.text_value", None),
        ),
        identities=("attacker",),
    )
    hints = (
        ("name", "setup_value"),
        ("password_payload_specification", "setup_skip"),
        ("version_payload_entries.key", "setup_value"),
        ("version_payload_entries.text_value", "setup_value"),
    )

    result = apply_seed_hints(seed, setup, hints)
    request = dict(result.request)

    assert request["name"] == "dast-fixture-name"
    assert request["version_payload_entries.key"] == "dast-fixture-key"
    assert request["version_payload_entries.text_value"] == ("dast-fixture-text_value")
    # The skipped branch is gone entirely, parent and children.
    assert "password_payload_specification" not in request
    assert "password_payload_specification.length" not in request
    assert request["folder_id"] == "folder-1"
