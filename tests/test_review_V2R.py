"""A promoted norm interprets the original physical readback measurement."""

from dataclasses import replace
from pathlib import Path

import pytest
from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import SERVICE, UPDATE_ORDER

import cloud_dast
from cloud_dast.model import Check
from cloud_dast.model.events import (
    CheckCompleted,
    DiffPairComputed,
    QdlStepEvaluated,
    canonical_action_id,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    changed,
)
from cloud_dast.runtime.execution.state import CampaignAccumulator
from tests.benchmarks.test_differential_modes import (
    _build_campaign,
    _changed_norm_payload,
)


@pytest.mark.parametrize("fields", [("total",), ("total", "note")])
def test_fullworkflow_positive_retains_original_write_and_formal_norm(fields):
    assert Path(cloud_dast.__file__).is_relative_to(Path.cwd())
    executed: list[Check] = []
    stand = BenchState.seed()

    class ReadNotesBenchService(BenchService):
        def get_order(self, principal, params):
            response = super().get_order(principal, params)
            order = stand.orders.get(str(params.get("order_id", "")))
            if order is None:
                return response
            return replace(response, fields=(*response.fields, ("note", order["note"])))

    service = ReadNotesBenchService(stand) if "note" in fields else BenchService(stand)
    target = BenchTarget(service)

    def record(check):
        executed.append(check)
        return target(check)

    payload = _changed_norm_payload()
    if "note" in fields:
        norm = Atom(value="norm:diff-mass-assign-note")
        payload["facts"].extend(
            fact.model_dump(mode="json")
            for fact in (
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("is"),
                    args=(norm, Atom(value="Norm")),
                ),
                Fact(
                    context=Context.PROPOSAL,
                    predicate=Predicate.from_name("prevents"),
                    args=(
                        norm,
                        changed(Atom(value="resource:order"), Atom(value="note")),
                    ),
                ),
            )
        )
    campaign = _build_campaign(
        target_method=UPDATE_ORDER,
        diff_mode=True,
        diff_modes=frozenset({"readback"}),
        variance_payload=payload,
        max_checks=3,
        target=record,
    )
    contract = campaign["repository"].load(f"contract:{SERVICE}")
    # BenchService.UpdateOrder actually writes both fields.  Declare the
    # second causal term explicitly, so the fixture also uses I1B's typed
    # action/effect binding rather than a field-name projection.
    note_cause = Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("causes"),
        args=(
            Atom(value=canonical_action_id(UPDATE_ORDER)),
            changed(Atom(value="resource:order"), Atom(value="note")),
        ),
    )
    if "note" in fields:
        contract = QdlGraph(facts=(*contract.facts, note_cause), rules=contract.rules)
        campaign["repository"].save(
            f"contract:{SERVICE}",
            contract,
            provenance={"source_kind": "test"},
            adapter_version="test",
            mapping_report={"mapped": len(contract.facts), "unmapped": 0},
        )
    for field in fields:
        assert any(
            fact.predicate.name == "causes"
            and fact.args
            == (
                Atom(value=canonical_action_id(UPDATE_ORDER)),
                changed(Atom(value="resource:order"), Atom(value=field)),
            )
            for fact in contract.facts
        )
    result = campaign["workflow"].execute(campaign["request"])
    (pair,) = (
        event
        for event in campaign["events"].events
        if isinstance(event, DiffPairComputed) and event.mode == "readback"
    )
    measured = {o.observation_id: o for o in result.observations}
    before = measured[pair.control_observation_id]
    after = measured[pair.treatment_observation_id]
    assert dict(before.output.fields)["total"] == 2500
    assert "dastpayload" in str(dict(after.output.fields)["total"])
    if "note" in fields:
        assert dict(before.output.fields)["note"] == ""
        assert dict(after.output.fields)["note"] == stand.orders["order-1001"]["note"]
        assert "dastpayload" in str(dict(after.output.fields)["note"])
    # No fourth call, regenerated check or extra write can become the PoC.
    assert len(executed) == len(result.observations) == len(measured) == 3
    assert (
        len([e for e in campaign["events"].events if isinstance(e, CheckCompleted)])
        == 3
    )
    original_write = executed[1]
    assert original_write.method_id == UPDATE_ORDER
    (original_observation,) = (
        o for o in result.observations if o.check_id == original_write.check_id
    )
    promoted = tuple(
        fact
        for saved in campaign["repository"].saved
        if saved["source_id"].startswith(f"diff:{SERVICE}:")
        and saved["provenance"]["source_kind"] == "diff-campaign"
        for fact in saved["graph"].facts
        if fact.predicate.name == "prevents"
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "changed"
    )
    assert {fact.args[1].args[1].value for fact in promoted} == set(fields)
    findings = [f for f in result.findings if f.norm_fact in promoted]
    assert len(findings) == len(fields)
    assert {finding.norm_fact for finding in findings} == set(promoted)
    assert len({f.invariant_id for f in findings}) == len(fields)
    logical_events = [
        event
        for event in campaign["events"].events
        if isinstance(event, QdlStepEvaluated)
        and event.observation_id == original_observation.observation_id
        and event.norm_fact in promoted
    ]
    assert len(logical_events) == len(fields)
    assert {event.norm_fact for event in logical_events} == set(promoted)
    for event in logical_events:
        assert event.check_id == event.correlation_id == original_write.check_id
        assert event.oracle == "differential"
        assert event.campaign_id and event.run_id
    for finding in findings:
        assert finding.observation_id == original_observation.observation_id
        assert finding.minimal_poc == original_write.request
        assert finding.method_id == original_write.method_id
        assert finding.scenario_id == original_write.scenario_id
        assert finding.norm_fact.args[0].value in finding.invariant_id
        assert finding.invariant_id != original_write.invariant_id
        assert finding.evidence_refs == (
            before.observation_id,
            original_observation.observation_id,
            after.observation_id,
        )
        (row,) = (
            r
            for r in result.norm_coverage
            if r.norm_id == finding.norm_fact.args[0].value
        )
        assert row.check_count == row.finding_count == 1
        assert row.oracle_called


@pytest.fixture
def captured(measurement, method_spec, scenario_position, verification_plan):
    from dataclasses import replace

    from cloud_dast.contracts.execution import ExecutionResult, LiveRequest
    from cloud_dast.model import VerdictStatus
    from cloud_dast.runtime.differential.executor import ProbeExecutor
    from cloud_dast.runtime.evidence_projection import Projection
    from cloud_dast.runtime.execution.runner import EventProjection
    from cloud_dast.runtime.observation_effects import Publisher
    from cloud_dast.runtime.readback_reevaluation import Reevaluation
    from cloud_dast.verification.projection import ObservationProjector
    from tests.test_review_C1 import EventLog, _step, _view

    services, base_norm, key, _, _ = measurement
    services.event_bus = EventLog()
    projection = EventProjection(services.event_bus, services.event_bus)
    publisher = Publisher(
        publish=projection.publish,
        evidence_projection=Projection(
            events=projection.refresh,
            path_lookup=lambda path_id: None,
            checks=lambda: (),
            find_check=lambda check_id: None,
            formal_repository=None,
            observation_projector=ObservationProjector(),
        ),
        executed_check_identities=lambda observation: (),
    )
    services.reevaluation = Reevaluation(
        norm_compiler=services.norm_compiler,
        build_evidence_key=ProbeExecutor.build_evidence_key,
        classify_observation=services.evaluator.evaluate,
        publish_step_event=publisher.publish_step_event,
    )
    original = services.evidence_store.get_readback(key)
    assert original is not None
    original = replace(
        original,
        read_before=original.read_before.model_copy(
            update={"response_tree": (("total", 10), ("note", "before"))}
        ),
        read_after=original.read_after.model_copy(
            update={"response_tree": (("total", 20), ("note", "after"))}
        ),
    )
    services.evidence_store.put_readback(key, original)
    norms = tuple(
        base_norm.model_copy(
            update={
                "invariant_id": "accepted:" + field,
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
        _view(_step(verification_plan, method_spec, norm, scenario_position))[1].paths[
            0
        ]
        for norm in norms
    )
    physical = ExecutionResult(
        observations=(original.read_before, original.write, original.read_after),
        checks=(
            original.read_before_check,
            original.write_check,
            original.read_after_check,
        ),
        provenance={},
        policy_verdicts={},
    )
    request = LiveRequest(
        service=method_spec.service,
        principal_id="attacker",
        resource_id=key.resource_id,
    )
    from cloud_dast.model.events import EventScope

    metadata = services.reevaluation.reevaluate(
        request,
        paths,
        physical,
        scope=EventScope(campaign_id="review:campaign", run_id="review:run"),
        evidence_store=services.evidence_store,
    )
    assert len(metadata.policy_verdicts) == len(metadata.provenance) == 2
    assert all(
        v.status is VerdictStatus.FAIL and v.grounded
        for v in metadata.policy_verdicts.values()
    )
    return services, request, paths, physical, metadata, norms


# Importing an existing marked fixture supplies the actual captured domain records.
from tests.test_review_V2 import measurement as measurement


def test_two_norms_share_the_original_measurement_without_overwriting(captured):
    from cloud_dast.verification.finding_evaluator import FindingEvaluator
    from tests.test_review_C1 import EventLog

    services, request, paths, physical, metadata, norms = captured
    accumulator = CampaignAccumulator.empty()
    accumulator.add(physical)
    accumulator.add(metadata)
    assert tuple(accumulator.observations) == physical.observations
    assert tuple(accumulator.checks) == physical.checks
    assert len(accumulator.policy_verdicts) == 2
    assert len(services.event_bus.events) == 2
    assert {
        (event.campaign_id, event.run_id) for event in services.event_bus.events
    } == {("review:campaign", "review:run")}
    assert {event.norm_fact for event in services.event_bus.events} == {
        n.norm_fact for n in norms
    }
    assert all(
        event.check_id == physical.checks[1].check_id
        for event in services.event_bus.events
    )
    assert (
        services.reevaluation.reevaluate(
            request,
            paths,
            accumulator.as_result(),
            evidence_store=services.evidence_store,
        ).policy_verdicts
        == {}
    )
    log = EventLog()
    evaluation = FindingEvaluator(log, log).evaluate(
        accumulator.as_result(), {n.invariant_id: n for n in norms}
    )
    assert len(evaluation.findings) == 2
    assert {f.invariant_id for f in evaluation.findings} == {
        n.invariant_id for n in norms
    }
    for finding in evaluation.findings:
        assert finding.observation_id == physical.observations[1].observation_id
        assert finding.minimal_poc == physical.checks[1].request
        assert finding.evidence_refs == tuple(
            o.observation_id for o in physical.observations
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request", (("total", 0),)),
        ("identities", ("foreign",)),
        ("probe_marker", "foreign"),
    ],
)
def test_reinterpretation_requires_the_original_actual_check(captured, field, value):
    from dataclasses import replace

    services, request, paths, physical, _, _ = captured
    foreign = physical.checks[1].model_copy(update={field: value})
    supplied = replace(
        physical, checks=(physical.checks[0], foreign, physical.checks[2])
    )
    assert not services.reevaluation.reevaluate(
        request,
        paths,
        supplied,
        evidence_store=services.evidence_store,
    ).policy_verdicts


def test_evaluator_uses_current_registry_and_owner_check_over_raw_event(captured):
    from cloud_dast.model.events import CheckCompleted
    from cloud_dast.verification.finding_evaluator import FindingEvaluator
    from tests.test_review_C1 import EventLog

    _, _, _, physical, metadata, norms = captured
    accumulator = CampaignAccumulator.empty()
    accumulator.add(physical)
    accumulator.add(metadata)
    log = EventLog()
    event_check = physical.checks[1].model_copy(
        update={"invariant_id": "wrong-hint", "request": (("redacted", "event"),)}
    )
    log.publish(CheckCompleted(check=event_check, observation=physical.observations[1]))
    evaluator = FindingEvaluator(log, log)
    assert evaluator.evaluate(accumulator.as_result(), {}).findings == ()
    findings = evaluator.evaluate(
        accumulator.as_result(), {n.invariant_id: n for n in norms}
    ).findings
    assert len(findings) == 2
    assert all(f.minimal_poc == physical.checks[1].request for f in findings)


def test_second_norm_without_before_channel_stays_unscoreable(captured):
    from cloud_dast.model import VerdictStatus
    from cloud_dast.verification.finding_evaluator import FindingEvaluator
    from tests.test_review_C1 import EventLog

    services, request, paths, physical, _, norms = captured
    key, measurement = next(services.evidence_store.iter_readbacks())
    measurement = replace(
        measurement,
        read_before=measurement.read_before.model_copy(
            update={"response_tree": (("total", 10),)}
        ),
    )
    services.evidence_store.put_readback(key, measurement)
    physical = replace(
        physical,
        observations=(
            measurement.read_before,
            measurement.write,
            measurement.read_after,
        ),
    )
    metadata = services.reevaluation.reevaluate(
        request,
        paths,
        physical,
        evidence_store=services.evidence_store,
    )
    assert len(metadata.policy_verdicts) == 2
    assert (
        metadata.policy_verdicts[
            (measurement.write.observation_id, norms[0].invariant_id)
        ].status
        is VerdictStatus.FAIL
    )
    assert (
        metadata.policy_verdicts[
            (measurement.write.observation_id, norms[1].invariant_id)
        ].status
        is VerdictStatus.UNSCOREABLE
    )
    accumulator = CampaignAccumulator.empty()
    accumulator.add(physical)
    accumulator.add(metadata)
    log = EventLog()
    findings = (
        FindingEvaluator(log, log)
        .evaluate(accumulator.as_result(), {n.invariant_id: n for n in norms})
        .findings
    )
    assert len(findings) == 1
    assert findings[0].invariant_id == norms[0].invariant_id
