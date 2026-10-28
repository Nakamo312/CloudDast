from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given
from hypothesis import strategies as st

from cloud_dast.api import BindingDeficit
from cloud_dast.model import (
    AccessOutcome,
    Check,
    Observation,
)
from cloud_dast.model.events import CheckCompleted, CoverageUpdated
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.runtime.execution.projection import (
    contract_smoke_path as _contract_smoke_path,
)
from cloud_dast.runtime.execution.projection import (
    record_binding_deficit as _record_binding_deficit,
)
from cloud_dast.verification.action_runtime import (
    build_action_runtime_ledger,
)


def _build_graph(actions: tuple[str, ...]) -> QdlGraph:
    return QdlGraph(
        facts=tuple(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Atom(value=f"action:{action}"), Atom(value="Action")),
            )
            for action in actions
        )
    )


def _events(actions: set[str]) -> tuple[CheckCompleted | CoverageUpdated, ...]:
    result: list[CheckCompleted | CoverageUpdated] = []
    for action in sorted(actions):
        check = Check(
            invariant_id=f"invariant:{action}",
            method_id=action,
            scenario_id="scenario",
            request=(),
            identities=("attacker",),
        )
        observation = Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="executed",
        )
        result.extend(
            (
                CheckCompleted(
                    check=check,
                    method_id=action,
                    observation=observation,
                ),
                CoverageUpdated(
                    check_id=check.check_id,
                    method_id=action,
                    invariant_id=check.invariant_id,
                    scenario_id=check.scenario_id,
                ),
            )
        )
    return tuple(result)


@given(st.sets(st.sampled_from(("GetOrder", "PayOrder", "CancelOrder"))))
def test_declared_executed_deficit_closure_is_total(
    executed: set[str],
) -> None:
    """Every declared action ends with evidence or one typed terminal deficit."""

    actions = ("GetOrder", "PayOrder", "CancelOrder")
    ledger = build_action_runtime_ledger(
        _build_graph(actions),
        events=_events(executed),
        finalize=True,
    )

    assert ledger.closed
    assert {entry.action_id for entry in ledger.entries} == {
        f"action:{action}" for action in actions
    }
    assert all(
        entry.request_executed or entry.terminal_deficit is not None
        for entry in ledger.entries
    )
    assert all(
        entry.terminal_deficit is None
        or entry.terminal_deficit.deficit_kind
        in {"transport_not_executed", "incomplete_binding"}
        for entry in ledger.entries
        if not entry.request_executed
    )


def test_pay_order_like_blocked_path_is_not_transport_evidence() -> None:
    """A bound PayOrder path closes only through CheckCompleted evidence."""

    action = "PayOrder"
    logical_path = SimpleNamespace(path_id="planned-pay-order", actions=(action,))
    bound_path = SimpleNamespace(
        path_id="bound-pay-order",
        kind="invariant",
        steps=(SimpleNamespace(method=SimpleNamespace(method_id=action)),),
    )
    graph = _build_graph((action,))

    pending = build_action_runtime_ledger(
        graph,
        planned_paths=(logical_path,),
        paths=(bound_path,),
    )
    entry = pending.entries[0]
    assert entry.planned_path_ids == ("planned-pay-order",)
    assert entry.bound_path_ids == ("bound-pay-order",)
    assert entry.request_executed is False
    assert pending.closed is False

    terminal = pending.finalize()
    deficit = terminal.entries[0].terminal_deficit
    assert deficit is not None
    assert deficit.deficit_kind == "transport_not_executed"
    assert terminal.closed


def test_precise_structural_deficit_suppresses_generic_scenario_deficit() -> None:
    deficits = [
        BindingDeficit(
            action="orders.PayOrder",
            reason="missing_service_part_fact",
        )
    ]

    _record_binding_deficit(
        deficits,
        action="action:orders.PayOrder",
        reason="contract_scenario_missing",
        kind="scenario_missing",
        context=(("coverage", "contract_action"),),
    )

    assert [(deficit.action, deficit.reason) for deficit in deficits] == [
        ("orders.PayOrder", "missing_service_part_fact")
    ]


def test_smoke_is_recovery_and_requires_both_runtime_events(
    method_spec,
    scenario_position,
) -> None:
    action = f"action:{method_spec.method_id}"
    graph = _build_graph((method_spec.method_id,))
    smoke = _contract_smoke_path(
        action,
        method=method_spec,
        scenario=scenario_position,
    )

    pending = build_action_runtime_ledger(graph, paths=(smoke,))
    entry = pending.entries[0]
    assert smoke.recovery is True
    assert smoke.scoreable is False
    assert entry.recovery_work_item is True
    assert pending.closed is False

    completed_only = build_action_runtime_ledger(
        graph,
        paths=(smoke,),
        events=_events({method_spec.method_id})[:1],
        finalize=True,
    )
    assert completed_only.entries[0].terminal_deficit is not None
    assert completed_only.entries[0].terminal_deficit.deficit_kind == (
        "coverage_update_missing"
    )

    closed = build_action_runtime_ledger(
        graph,
        paths=(smoke,),
        events=_events({method_spec.method_id}),
        finalize=True,
    )
    assert closed.closed
    assert closed.entries[0].request_executed is True
    assert closed.entries[0].coverage_updated is True
