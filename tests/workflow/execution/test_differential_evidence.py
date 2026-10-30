from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from cloud_dast.contracts.execution import ExecutionResult, LiveRequest
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
    ResponseData,
    VerdictStatus,
)
from cloud_dast.model.events import CheckCompleted, EventScope, QdlStepEvaluated
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, changed
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.campaign.evaluation import FindingEvaluator
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.runner import EventProjection
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    ReadBackResult,
    ReadBackSpec,
)
from tests.test_review_C1 import EventLog, _runner, _step, _view
from tests.workflow.execution.test_differential_modes import (
    _get_method,
    _position,
    _update_method,
)


def _check(check_id: str) -> Check:
    return Check(
        check_id=check_id,
        invariant_id="invariant:test",
        method_id="method:test",
        scenario_id="scenario:test",
        request=(),
        identities=("attacker",),
    )


def _observation(observation_id: str, check_id: str) -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id=check_id,
        scenario_id="scenario:test",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


def _readback_result(suffix: str) -> ReadBackResult:
    write_check = _check(f"check:{suffix}:write")
    read_before_check = _check(f"check:{suffix}:before")
    read_after_check = _check(f"check:{suffix}:after")
    return ReadBackResult(
        write_check=write_check,
        read_before_check=read_before_check,
        read_after_check=read_after_check,
        write=_observation(f"observation:{suffix}:write", write_check.check_id),
        read_before=_observation(
            f"observation:{suffix}:before", read_before_check.check_id
        ),
        read_after=_observation(
            f"observation:{suffix}:after", read_after_check.check_id
        ),
    )


def _concurrency_result(suffix: str) -> ConcurrencyResult:
    before_check = _check(f"check:{suffix}:before")
    probe_check = _check(f"check:{suffix}:probe")
    after_check = _check(f"check:{suffix}:after")
    return ConcurrencyResult(
        read_before=(
            before_check,
            _observation(f"observation:{suffix}:before", before_check.check_id),
        ),
        probes=(
            (
                probe_check,
                _observation(f"observation:{suffix}:probe", probe_check.check_id),
            ),
        ),
        read_after=(
            after_check,
            _observation(f"observation:{suffix}:after", after_check.check_id),
        ),
    )


def _key(resource_id: str, invariant_id: str = "invariant:test") -> MeasurementKey:
    return MeasurementKey(
        method_id="method:test",
        scenario_id="scenario:test",
        resource_id=resource_id,
        invariant_id=invariant_id,
    )


def test_readback_put_get_overwrite_and_missing_are_keyed() -> None:
    store = Store[MeasurementKey]()
    key = _key("resource:one")
    replacement = _readback_result("replacement")

    store.put_readback(key, _readback_result("initial"))
    store.put_readback(key, replacement)

    assert store.get_readback(key) is replacement
    assert store.get_readback(_key("resource:missing")) is None


def test_iterators_are_sorted_snapshots_and_keep_namespaces_separate() -> None:
    store = Store[MeasurementKey]()
    late_key = _key("resource:two")
    early_key = _key("resource:one")
    concurrency = _concurrency_result("concurrency")

    store.put_readback(late_key, _readback_result("late"))
    readback_snapshot = store.iter_readbacks()
    store.put_readback(early_key, _readback_result("early"))
    store.put_concurrency(early_key, concurrency)

    assert tuple(key for key, _ in readback_snapshot) == (late_key,)
    assert tuple(key for key, _ in store.iter_readbacks()) == (
        early_key,
        late_key,
    )
    assert store.get_concurrency(early_key) is concurrency
    assert tuple(store.iter_concurrency()) == ((early_key, concurrency),)


def test_clear_can_remove_one_namespace_or_the_whole_campaign() -> None:
    store = Store[MeasurementKey]()
    key = _key("resource:one")
    readback = _readback_result("clear")
    concurrency = _concurrency_result("clear")

    store.put_readback(key, readback)
    store.put_concurrency(key, concurrency)
    store.clear_readbacks()

    assert store.get_readback(key) is None
    assert store.get_concurrency(key) is concurrency

    store.clear()

    assert store.get_concurrency(key) is None


def test_public_evidence_values_are_immutable_contracts() -> None:
    key = _key("resource:one")
    result = _readback_result("immutable")

    assert key._fields == (
        "method_id",
        "scenario_id",
        "resource_id",
        "invariant_id",
    )
    assert result.write_check.model_config["frozen"] is True
    assert result.read_before_check.model_config["frozen"] is True
    assert result.read_after_check.model_config["frozen"] is True


@pytest.fixture
def physical_readback(request, verification_plan, invariant):
    """Capture real read/write/read owner records against an in-memory target."""
    write_method, read_method, scenario = _update_method(), _get_method(), _position()
    plan = verification_plan.model_copy(
        update={
            "invariant_id": "physical:uninterpreted",
            "method_id": write_method.method_id,
            "scenario_id": scenario.scenario_id,
            "resource_types": (("order_id", "order"),),
        }
    )
    measured_norm = invariant.model_copy(
        update={
            "invariant_id": "physical:uninterpreted",
            "norm_fact": None,
        }
    )
    step = _step(plan, write_method, measured_norm, scenario)
    executed = []
    state = {"total": 10, "note": "before"}
    include_before_note = getattr(request, "param", True)

    def target(check):
        executed.append(check)
        if check.method_id == write_method.method_id:
            assert check.probe_marker
            state.update({key: value for key, value in check.request if key in state})
            values = {"order_id": "order-1001"}
        else:
            assert check.method_id == read_method.method_id
            values = dict(state)
            if len(executed) == 1 and not include_before_note:
                values.pop("note")
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=tuple(values.items())),
            response_tree=tuple(values.items()),
        )

    runner, events = _runner(target)
    live = LiveRequest(
        service=write_method.service,
        principal_id="attacker",
        resource_id="order-1001",
        max_checks=3,
    )
    store = Store[MeasurementKey]()
    budget = CallLimits.from_request(live)
    measured = runner.differential.execute_readback(
        step,
        ReadBackSpec(
            write_method,
            read_method,
            "order_id",
            read_resource_types=(("order_id", "order"),),
        ),
        live,
        budget,
        evidence_store=store,
    )
    physical = ExecutionResult(
        observations=(measured.read_before, measured.write, measured.read_after),
        checks=(
            measured.read_before_check,
            measured.write_check,
            measured.read_after_check,
        ),
        provenance={},
        policy_verdicts={},
    )
    norms = tuple(
        invariant.model_copy(
            update={
                "invariant_id": "accepted:" + field,
                "norm_id": "norm:" + field,
                "norm_fact": Fact(
                    context=Context.ACCEPTED,
                    predicate=Predicate.from_name("prevents"),
                    args=(
                        Atom(value="norm:" + field),
                        changed(Atom(value="resource:order"), Atom(value=field)),
                    ),
                ),
            }
        )
        for field in ("total", "note")
    )
    paths = tuple(
        _view(
            _step(
                plan.model_copy(update={"invariant_id": norm.invariant_id}),
                write_method,
                norm,
                scenario,
            )
        )[1].paths[0]
        for norm in norms
    )
    assert [check.method_id for check in executed] == [
        read_method.method_id,
        write_method.method_id,
        read_method.method_id,
    ]
    assert tuple(executed) == physical.checks
    assert budget.live_calls == 3 and budget.exhausted
    return SimpleNamespace(
        runner=runner,
        events=events,
        executed=executed,
        request=live,
        store=store,
        measured=measured,
        physical=physical,
        norms=norms,
        paths=paths,
    )


def _reinterpret_readback(captured, physical=None):
    return captured.runner.readback_reevaluation.reevaluate(
        captured.request,
        captured.paths,
        physical or captured.physical,
        scope=EventScope(campaign_id="equivalent:campaign", run_id="equivalent:run"),
        evidence_store=captured.store,
    )


def test_promoted_norms_share_one_physical_readback_without_target_reruns(
    physical_readback,
):
    captured = physical_readback
    assert dict(captured.measured.read_before.response_tree) == {
        "total": 10,
        "note": "before",
    }
    assert dict(captured.measured.read_after.response_tree) == {
        field: dict(captured.measured.write_check.request)[field]
        for field in ("total", "note")
    }
    metadata = _reinterpret_readback(captured)
    assert metadata.observations == metadata.checks == ()
    assert len(metadata.policy_verdicts) == len(metadata.provenance) == 2
    assert all(
        verdict.status is VerdictStatus.FAIL
        and verdict.grounded
        and verdict.deterministic
        for verdict in metadata.policy_verdicts.values()
    )
    accumulator = CampaignAccumulator.empty()
    accumulator.add(captured.physical)
    accumulator.add(metadata)
    execution = accumulator.as_result()
    assert execution.checks == captured.physical.checks
    assert execution.observations == captured.physical.observations
    assert not _reinterpret_readback(captured, execution).policy_verdicts
    logical = [
        event for event in captured.events.events if isinstance(event, QdlStepEvaluated)
    ]
    assert len(logical) == 2
    assert {event.norm_fact for event in logical} == {
        norm.norm_fact for norm in captured.norms
    }
    assert all(
        event.check_id == event.correlation_id == captured.measured.write_check.check_id
        and event.observation_id == captured.measured.write.observation_id
        and event.campaign_id == "equivalent:campaign"
        and event.run_id == "equivalent:run"
        and event.oracle == "differential"
        for event in logical
    )
    log = EventLog()
    log.publish(
        CheckCompleted(
            check=captured.measured.write_check.model_copy(
                update={
                    "request": (("redacted", "event"),),
                    "invariant_id": "wrong-hint",
                }
            ),
            observation=captured.measured.write,
        )
    )
    evaluator = FindingEvaluator(EventProjection(log, log))
    assert evaluator.evaluate(execution, {}).findings == ()
    findings = evaluator.evaluate(
        execution, {norm.invariant_id: norm for norm in captured.norms}
    ).findings
    assert {finding.norm_fact for finding in findings} == {
        norm.norm_fact for norm in captured.norms
    }
    assert len(findings) == 2
    assert {finding.invariant_id for finding in findings} == {
        norm.invariant_id for norm in captured.norms
    }
    for finding in findings:
        assert finding.observation_id == captured.measured.write.observation_id
        assert finding.minimal_poc == captured.measured.write_check.request
        assert finding.evidence_refs == tuple(
            o.observation_id for o in captured.physical.observations
        )
        assert finding.invariant_id != captured.measured.write_check.invariant_id
    assert len(captured.executed) == 3
    assert (
        len(
            [
                event
                for event in captured.events.events
                if isinstance(event, CheckCompleted)
            ]
        )
        == 3
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request", (("total", "foreign"),)),
        ("identities", ("foreign",)),
        ("probe_marker", "foreign"),
    ],
)
def test_readback_reinterpretation_rejects_foreign_actual_check(
    physical_readback, field, value
):
    captured = physical_readback
    foreign = captured.measured.write_check.model_copy(update={field: value})
    supplied = replace(
        captured.physical,
        checks=(
            captured.measured.read_before_check,
            foreign,
            captured.measured.read_after_check,
        ),
    )
    rejected = _reinterpret_readback(captured, supplied)
    assert rejected.policy_verdicts == rejected.provenance == {}
    rejected_execution = CampaignAccumulator.empty()
    rejected_execution.add(supplied)
    rejected_execution.add(rejected)
    log = EventLog()
    assert (
        FindingEvaluator(EventProjection(log, log))
        .evaluate(
            rejected_execution.as_result(),
            {norm.invariant_id: norm for norm in captured.norms},
        )
        .findings
        == ()
    )
    assert not any(
        isinstance(event, QdlStepEvaluated) for event in captured.events.events
    )
    # Rejection did not consume or poison the original measurement.
    assert len(_reinterpret_readback(captured).policy_verdicts) == 2
    assert len(captured.executed) == 3


@pytest.mark.parametrize("physical_readback", [False], indirect=True)
def test_missing_before_channel_blocks_only_second_promoted_norm(physical_readback):
    captured = physical_readback
    assert "note" not in dict(captured.measured.read_before.response_tree)
    assert "note" in dict(captured.measured.read_after.response_tree)
    metadata = _reinterpret_readback(captured)
    first, second = (
        metadata.policy_verdicts[
            (captured.measured.write.observation_id, norm.invariant_id)
        ]
        for norm in captured.norms
    )
    assert first.status is VerdictStatus.FAIL and first.grounded and first.deterministic
    assert second.status is VerdictStatus.UNSCOREABLE and not second.grounded
    accumulator = CampaignAccumulator.empty()
    accumulator.add(captured.physical)
    accumulator.add(metadata)
    log = EventLog()
    findings = (
        FindingEvaluator(EventProjection(log, log))
        .evaluate(
            accumulator.as_result(),
            {norm.invariant_id: norm for norm in captured.norms},
        )
        .findings
    )
    assert len(findings) == 1
    assert findings[0].norm_fact == captured.norms[0].norm_fact
    assert findings[0].minimal_poc == captured.measured.write_check.request
    assert len(captured.executed) == 3
