from cloud_dast.composition.execution import assemble_runner
from cloud_dast.contracts.plan import InvariantProjection

"""F4/F5: partial snapshots and execution events are not negative witnesses."""

from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.model import (
    AccessOutcome,
    Check,
    ExecutionTrace,
    Observation,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    input_field,
)
from cloud_dast.runtime.execution.checks import bind_event_context, run_check
from cloud_dast.verification.coverage import build_coverage_matrix
from cloud_dast.verification.oracles import DifferentialOracle


def fact(predicate, *args, context=Context.CONTRACT):
    return Fact(context=context, predicate=Predicate.from_name(predicate), args=args)


def invariant():
    return InvariantProjection(
        invariant_id="i",
        norm_id="norm:i",
        statement="The resource total must not change",
        severity=Severity.HIGH,
        norm_fact=fact(
            "prevents",
            Atom(value="norm:i"),
            changed(Atom(value="resource:order"), Atom(value="total")),
            context=Context.ACCEPTED,
        ),
    )


def observation(name, tree=(), *, outcome=AccessOutcome.ALLOWED, before=(), after=()):
    return Observation(
        observation_id=name,
        check_id="check:" + name,
        scenario_id="s",
        observed_outcome=outcome,
        response_summary="synthetic",
        response_tree=tree,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=name,
                    step_id="step",
                    method_id="Update",
                    scenario_id="s",
                    status=outcome,
                    request_fields=("total",),
                    resource_state_before=before,
                    resource_state_after=after,
                ),
            )
        ),
    )


def test_import_is_isolated():
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )


@pytest.mark.parametrize("channel", ["response", "state"])
@pytest.mark.parametrize("partial_leg", ["before", "after", "both"])
@pytest.mark.parametrize("changed_value", [False, True])
def test_partial_snapshot_requires_completeness_for_absence(
    channel, partial_leg, changed_value
):
    before = (("items.0.total", 10),)
    after = (("items.0.total", 20 if changed_value else 10),)
    if partial_leg in {"before", "both"}:
        before += (("__truncated__", True),)
    if partial_leg in {"after", "both"}:
        after += (("__truncated__", True),)
    trace = (
        (observation("write", before=before, after=after),)
        if channel == "state"
        else (observation("before", before), observation("after", after))
    )
    verdict = DifferentialOracle().evaluate_policy(invariant(), trace)
    assert verdict.status is (
        VerdictStatus.FAIL if changed_value else VerdictStatus.UNSCOREABLE
    )
    if not changed_value:
        assert not verdict.negative_scope
        assert any(d.kind == "incomplete_negative_scope" for d in verdict.deficits)
    else:
        assert verdict.grounded
        assert verdict.evidence_refs


def test_path_missing_from_partial_snapshot_does_not_prove_change():
    before = observation("before", (("items.0.total", 10), ("items.1.total", 20)))
    after = observation("after", (("items.0.total", 10), ("__truncated__", True)))
    verdict = DifferentialOracle().evaluate_policy(invariant(), (before, after))
    assert verdict.status is VerdictStatus.UNSCOREABLE


def test_complete_snapshot_still_proves_unchanged_or_removed_values():
    before = observation("before", (("items.0.total", 10), ("items.1.total", 20)))
    oracle = DifferentialOracle()
    unchanged = oracle.evaluate_policy(
        invariant(), (before, observation("same", before.response_tree))
    )
    removed = oracle.evaluate_policy(
        invariant(), (before, observation("after", (("items.0.total", 10),)))
    )
    assert unchanged.status is VerdictStatus.PASS
    assert unchanged.negative_scope
    assert removed.status is VerdictStatus.FAIL
    assert removed.grounded


def test_complete_state_is_independent_of_truncated_response():
    write = observation(
        "write",
        (("__truncated__", True),),
        before=(("total", 10),),
        after=(("total", 10),),
    )
    verdict = DifferentialOracle().evaluate_policy(invariant(), (write,))
    assert verdict.status is VerdictStatus.PASS


class Log:
    def __init__(self):
        self.events = []
        self.cursors = {}

    def publish(self, event):
        self.events.append(event)

    def read_new(self, consumer):
        start = self.cursors.get(consumer, 0)
        self.cursors[consumer] = len(self.events)
        return tuple(self.events[start:])


@pytest.mark.parametrize("outcome", [AccessOutcome.ERROR, AccessOutcome.ALLOWED])
@pytest.mark.parametrize(
    "verdict_status",
    [None, VerdictStatus.UNSCOREABLE, VerdictStatus.PASS, VerdictStatus.FAIL],
)
@pytest.mark.parametrize(
    "binding",
    ["matching", "check", "observation", "action", "path", "step", "no_action"],
)
def test_execution_requires_scoreable_oracle_event_for_effect_coverage(
    outcome, verdict_status, binding
):
    inv = invariant()
    action = Atom(value="action:Update")
    effect = inv.norm_fact.args[1]
    request_field = input_field(action, Atom(value="total"))
    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", Atom(value="resource:order"), Atom(value="Resource")),
            fact("is", request_field, Atom(value="InputField")),
            fact("part", request_field, action),
            fact("causes", action, effect),
        )
    )
    check = Check(
        check_id="check:write",
        invariant_id="i",
        method_id="Update",
        scenario_id="s",
        request=(("total", 10),),
        identities=("attacker",),
    )
    log = Log()
    with bind_event_context(log, action_id="Update", path_id="path", step_id="step"):
        obs = run_check(check, lambda _: observation("write", outcome=outcome), log)
    if verdict_status is not None:
        log.publish(
            QdlStepEvaluated(
                path_id="other" if binding == "path" else "path",
                step_id="other" if binding == "step" else "step",
                verdict=verdict_status,
                norm_fact=inv.norm_fact,
                phase="blocked",
                reason="oracle result",
                step_index=0,
                check_id="other" if binding == "check" else check.check_id,
                observation_id="other"
                if binding == "observation"
                else obs.observation_id,
                action_id=None
                if binding == "no_action"
                else ("Other" if binding == "action" else "action:Update"),
                oracle="differential",
            )
        )
    matrix = build_coverage_matrix(graph, invariants={"i": inv}, events=log.events)
    request = next(cell for cell in matrix.fields if cell.field_kind == "input")
    assert request.request_executed
    effect_cell = matrix.effects[0]
    covered = binding == "matching" and verdict_status in {
        VerdictStatus.PASS,
        VerdictStatus.FAIL,
    }
    assert (effect_cell.status == "covered") == covered
    assert bool(effect_cell.observation_ids) == covered
    resource = next(cell for cell in matrix.fields if cell.field_kind == "resource")
    assert resource.oracle_witness_observed == covered


@pytest.mark.parametrize(
    "outcome, expected",
    [
        (AccessOutcome.DENIED, VerdictStatus.PASS),
        (AccessOutcome.ALLOWED, VerdictStatus.FAIL),
        (AccessOutcome.ERROR, VerdictStatus.UNSCOREABLE),
    ],
)
def test_real_runner_oracle_events_drive_coverage(
    scenario_position,
    verification_plan,
    tmp_path,
    outcome,
    expected,
):
    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.contracts.plan import (
        QdlExecutionPath,
        QdlExecutionStep,
        QdlExecutionView,
    )
    from cloud_dast.model import EndpointLayer, FieldSpec, MethodSpec
    from cloud_dast.qdl.graph import allowed
    from cloud_dast.qdl.reasoning import QdlPlan
    from cloud_dast.runtime.execution.scenarios import Checker
    from cloud_dast_fuzzing import TemplateGenerator
    from tests.support.guardrails import AllowAllGuardrail

    inv = invariant().model_copy(
        update={
            "norm_fact": fact(
                "prevents",
                Atom(value="norm:i"),
                allowed(Atom(value="action:Update")),
                context=Context.ACCEPTED,
            )
        }
    )
    method = MethodSpec(
        method_id="Update",
        service="synthetic",
        name="Update",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"orders.write"}),
        fields=(FieldSpec(name="total", type="integer"),),
    )
    scenario = scenario_position.model_copy(update={"scenario_id": "s"})
    plan = verification_plan.model_copy(
        update={
            "invariant_id": "i",
            "method_id": "Update",
            "scenario_id": "s",
            "resource_types": (),
        }
    )
    step = QdlExecutionStep(
        step_id="step",
        goal_id="goal",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=inv,
    )
    path = QdlExecutionPath(
        path_id="path",
        goal_id="goal",
        kind="invariant",
        description="Synthetic state witness",
        steps=(step,),
    )
    log = Log()

    def synthetic_response(check):
        return observation("write", outcome=outcome).model_copy(
            update={"check_id": check.check_id}
        )

    runner = assemble_runner(
        Checker(synthetic_response, TemplateGenerator(), AllowAllGuardrail(), log),
        log,
        log,
    )
    result = runner.execute_plan(
        LiveRequest(
            service="synthetic",
            principal_id="attacker",
            resource_id="order",
            max_checks=1,
        ),
        QdlPlan(graph_hash="synthetic"),
        QdlExecutionView(graph_hash="synthetic", paths=(path,), invariants={"i": inv}),
    )
    assert len(result.observations) == 1, [
        (type(e).__name__, getattr(e, "reason", "")) for e in log.events
    ]
    assert next(iter(result.policy_verdicts.values())).status is expected
    action = Atom(value="action:Update")
    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", Atom(value="resource:order"), Atom(value="Resource")),
            fact("causes", action, inv.norm_fact.args[1]),
        )
    )
    matrix = build_coverage_matrix(graph, invariants={"i": inv}, events=log.events)
    assert (matrix.effects[0].status == "covered") == (
        expected is not VerdictStatus.UNSCOREABLE
    )

    from cloud_dast.infrastructure.events import JsonlEventStore
    from cloud_dast.model.events import CheckCompleted, CoverageUpdated

    completed = next(e for e in log.events if isinstance(e, CheckCompleted))
    assert completed.check is None
    evaluated = next(e for e in log.events if isinstance(e, QdlStepEvaluated))
    assert evaluated.norm_fact == inv.norm_fact
    log.publish(
        CoverageUpdated(
            check_id=result.observations[0].check_id,
            method_id="Update",
            invariant_id="changed",
            scenario_id="s",
        )
    )
    changed_norm = invariant()
    graph = QdlGraph(
        facts=(*graph.facts, fact("causes", action, changed_norm.norm_fact.args[1]))
    )
    store_path = tmp_path / "events.jsonl"
    JsonlEventStore(store_path).append_many(log.events)
    replayed = tuple(JsonlEventStore(store_path).read())
    matrix = build_coverage_matrix(
        graph, invariants={"i": inv, "changed": changed_norm}, events=replayed
    )
    outcome_cell = next(c for c in matrix.effects if c.effect_kind == "allowed")
    changed_cell = next(c for c in matrix.effects if c.effect_kind == "changed")
    assert (outcome_cell.status == "covered") == (
        expected is not VerdictStatus.UNSCOREABLE
    )
    assert changed_cell.status != "covered"
    assert not changed_cell.observation_ids


@pytest.mark.parametrize(
    "total, expected", [(10, VerdictStatus.UNSCOREABLE), (20, VerdictStatus.FAIL)]
)
def test_concurrency_uses_same_snapshot_completeness(total, expected):
    before = observation("before", (("items.0.total", 10), ("__truncated__", True)))
    after = observation("after", (("items.0.total", total), ("__truncated__", True)))
    verdict = DifferentialOracle().evaluate_concurrency_policy(
        invariant(),
        read_before=before,
        read_after=after,
        probes=(observation("probe:1"), observation("probe:2")),
        method_id="Update",
    )
    assert verdict.status is expected
    assert bool(verdict.negative_scope) is False
    assert verdict.grounded == (expected is VerdictStatus.FAIL)


def test_safe_output_projection_cannot_supply_complete_negative_snapshot():
    from cloud_dast.model import ResponseData

    before = observation("before").model_copy(
        update={"output": ResponseData(fields=(("total", 10),))}
    )
    after = observation("after").model_copy(
        update={"output": ResponseData(fields=(("total", 10),))}
    )
    verdict = DifferentialOracle().evaluate_policy(invariant(), (before, after))
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.negative_scope


@pytest.mark.parametrize("proof", ["other_effect", "other_norm", "legacy", "matching"])
def test_scoreable_step_must_bind_exact_norm_and_effect(proof):
    from cloud_dast.model.events import CheckCompleted, CoverageUpdated
    from cloud_dast.qdl.graph import allowed

    target = invariant()
    if proof == "other_effect":
        proof_fact = fact(
            "prevents",
            Atom(value="norm:a"),
            allowed(Atom(value="action:Update")),
            context=Context.ACCEPTED,
        )
    elif proof == "other_norm":
        proof_fact = fact(
            "prevents",
            Atom(value="norm:a"),
            target.norm_fact.args[1],
            context=Context.ACCEPTED,
        )
    else:
        proof_fact = target.norm_fact if proof == "matching" else None
    check = Check(
        check_id="check:write",
        invariant_id="a",
        method_id="Update",
        scenario_id="s",
        request=(("total", 10),),
        identities=("attacker",),
    )
    log = Log()
    obs = run_check(check, lambda _: observation("write"), log)
    completed = next(e for e in log.events if isinstance(e, CheckCompleted))
    assert completed.check is None  # Request redaction must not invent proof binding.
    log.publish(
        QdlStepEvaluated(
            path_id="path",
            step_id="step",
            verdict=VerdictStatus.FAIL,
            phase="goal_reached",
            reason="scoreable norm A",
            step_index=0,
            action_id="Update",
            check_id=check.check_id,
            observation_id=obs.observation_id,
            norm_fact=proof_fact,
        )
    )
    # A second execution-coverage event cannot turn A's witness into B's proof.
    log.publish(
        CoverageUpdated(
            check_id=check.check_id,
            method_id="Update",
            invariant_id="i",
            scenario_id="s",
        )
    )
    action = Atom(value="action:Update")
    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", Atom(value="resource:order"), Atom(value="Resource")),
            fact("causes", action, target.norm_fact.args[1]),
        )
    )
    matrix = build_coverage_matrix(graph, invariants={"i": target}, events=log.events)
    assert (matrix.effects[0].status == "covered") == (proof == "matching")
    assert bool(matrix.effects[0].observation_ids) == (proof == "matching")


@pytest.mark.parametrize("with_proof", [False, True])
def test_step_proof_roundtrip_preserves_old_wire_contract(with_proof, tmp_path):
    from cloud_dast.infrastructure.events import JsonlEventStore

    event = QdlStepEvaluated(
        path_id="path",
        step_id="step",
        verdict=VerdictStatus.FAIL,
        phase="goal_reached",
        reason="scoreable result",
        step_index=0,
        norm_fact=invariant().norm_fact if with_proof else None,
    )
    payload = event.model_dump(mode="json")
    assert ("norm_fact" in payload) == with_proof
    restored = QdlStepEvaluated.model_validate(payload)
    assert restored.norm_fact == event.norm_fact
    assert restored.semantic_key == event.semantic_key
    store_path = tmp_path / "events.jsonl"
    JsonlEventStore(store_path).append(restored)
    assert tuple(JsonlEventStore(store_path).read()) == (restored,)


@pytest.mark.parametrize("unrelated", ["different_norm", "different_effect"])
def test_unrelated_proof_cannot_displace_coverage_in_any_event_order(unrelated):
    from itertools import permutations

    from cloud_dast.model.events import CheckCompleted, CoverageUpdated
    from cloud_dast.qdl.graph import allowed

    target = invariant()
    other_fact = fact(
        "prevents",
        Atom(value="norm:other")
        if unrelated == "different_norm"
        else target.norm_fact.args[0],
        target.norm_fact.args[1]
        if unrelated == "different_norm"
        else allowed(Atom(value="action:Update")),
        context=Context.ACCEPTED,
    )
    obs = observation("write")
    completed = CheckCompleted(observation=obs)
    coverage = CoverageUpdated(
        check_id=obs.check_id, method_id="Update", invariant_id="i", scenario_id="s"
    )
    witness = QdlStepEvaluated(
        path_id="path",
        step_id="step",
        verdict=VerdictStatus.FAIL,
        phase="goal_reached",
        reason="grounded effect",
        step_index=0,
        action_id="Update",
        check_id=obs.check_id,
        observation_id=obs.observation_id,
        norm_fact=target.norm_fact,
    )
    other = witness.model_copy(update={"norm_fact": other_fact})
    action = Atom(value="action:Update")
    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", Atom(value="resource:order"), Atom(value="Resource")),
            fact("causes", action, target.norm_fact.args[1]),
        )
    )
    expected = build_coverage_matrix(
        graph, invariants={"i": target}, events=(completed, coverage, witness)
    )
    assert expected.effects[0].status == "covered"
    for ordered in permutations((completed, coverage, witness, other)):
        actual = build_coverage_matrix(graph, invariants={"i": target}, events=ordered)
        assert actual.effects == expected.effects
        assert actual.fields == expected.fields
