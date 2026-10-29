from pathlib import Path
from types import SimpleNamespace

import pytest

import cloud_dast
from cloud_dast.contracts.execution import ObservationProvenance
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Check,
    ExecutionTrace,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
    ScenarioPosition,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, changed, transition
from cloud_dast.runtime.campaign.round import Runner
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.executor import ProbeExecutor
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    ReadBackResult,
)
from cloud_dast.verification.evaluation import ObservationEvaluator
from cloud_dast.verification.norms import NormCompiler
from cloud_dast.verification.oracles import PrimitiveOracleRouter
from cloud_dast.verification.projection import ObservationProjector


def _changed_invariant(base: InvariantProjection) -> InvariantProjection:
    return base.model_copy(
        update={
            "invariant_id": f"{base.invariant_id}:changed",
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="norm:immutable-total"),
                    changed(Atom(value="resource:order"), Atom(value="total")),
                ),
            ),
        }
    )


def _concurrency_result(
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> ConcurrencyResult:
    checks = tuple(
        _concurrency_check(index, method, scenario, invariant) for index in range(6)
    )
    return ConcurrencyResult(
        read_before=(
            checks[0],
            _concurrency_observation(0, method, scenario, value=10),
        ),
        probes=tuple(
            (
                checks[index],
                _concurrency_observation(index, method, scenario, value=10),
            )
            for index in range(1, 5)
        ),
        read_after=(
            checks[5],
            _concurrency_observation(5, method, scenario, value=20),
        ),
    )


def _concurrency_check(
    index: int,
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
) -> Check:
    return Check(
        check_id=f"check:concurrency:{index}",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=(("total", 10),),
        identities=("attacker",),
    )


def _concurrency_observation(
    index: int,
    method: MethodSpec,
    scenario: ScenarioPosition,
    *,
    value: int,
) -> Observation:
    return Observation(
        observation_id=f"observation:concurrency:{index}",
        check_id=f"check:concurrency:{index}",
        scenario_id=scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
        output=ResponseData(fields=(("total", value),)),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=f"observation:concurrency:{index}",
                    step_id=f"step:concurrency:{index}",
                    method_id=method.method_id,
                    scenario_id=scenario.scenario_id,
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
    )


@pytest.fixture
def measurement(method_spec, scenario_position, invariant):
    assert Path(cloud_dast.__file__).is_relative_to(Path.cwd())
    norm_compiler = NormCompiler()
    evaluator = ObservationEvaluator(
        primitive_oracle=PrimitiveOracleRouter(),
        observation_projector=ObservationProjector(),
        build_evidence_key=ProbeExecutor.build_evidence_key,
        norm_compiler=norm_compiler,
    )
    services = SimpleNamespace(
        norm_compiler=norm_compiler,
        evaluator=evaluator,
        evidence_store=Store[MeasurementKey](),
    )
    norm = _changed_invariant(invariant)
    batch = _concurrency_result(method_spec, scenario_position, norm)
    trace = (
        batch.read_before[1],
        batch.probes[0][1].model_copy(update={"probe_marker": "measured-marker"}),
        batch.read_after[1],
    )
    key = MeasurementKey(
        method_spec.method_id,
        scenario_position.scenario_id,
        "resource:one",
        norm.invariant_id,
    )
    services.evidence_store.put_readback(
        key,
        ReadBackResult(
            write_check=batch.probes[0][0],
            read_before_check=batch.read_before[0],
            read_after_check=batch.read_after[0],
            write=trace[1],
            read_before=trace[0],
            read_after=trace[2],
        ),
    )
    return services, norm, key, trace, batch


def classify(
    measurement, observation, method, scenario, *, trace=None, norm=None, key=None
):
    services, invariant, evidence_key, _, _ = measurement
    invariant = norm or invariant
    evidence_key = key or evidence_key
    if trace is None:
        trace = services.evaluator.trace_for_step(
            invariant,
            (observation,),
            evidence_key=evidence_key,
            evidence_store=services.evidence_store,
        )
    return services.evaluator.classify(
        invariant,
        observation,
        trace,
        method=method,
        scenario=scenario,
        evidence_key=evidence_key,
        evidence_store=services.evidence_store,
    )[1]


@pytest.mark.parametrize("outcome", [AccessOutcome.ALLOWED, AccessOutcome.DENIED])
@pytest.mark.parametrize(
    "reuse",
    ["fresh", "same_check", "same_marker", "different_marker", "different_scenario"],
)
def test_old_readback_cannot_prove_a_new_candidate(
    measurement, method_spec, scenario_position, outcome, reuse
):
    _, _, _, trace, _ = measurement
    updates = {
        "observation_id": "new-attempt",
        "check_id": "new-check",
        "observed_outcome": outcome,
    }
    if reuse == "same_check":
        updates["check_id"] = trace[1].check_id
    elif reuse == "same_marker":
        updates["probe_marker"] = trace[1].probe_marker
    elif reuse == "different_marker":
        updates = {"probe_marker": "new-marker"}
    elif reuse == "different_scenario":
        updates = {"scenario_id": "other-scenario"}
    fresh = trace[1].model_copy(update=updates)
    verdict = classify(measurement, fresh, method_spec, scenario_position)
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    assert not set(verdict.evidence_refs).intersection(
        (trace[0].observation_id, trace[2].observation_id)
    )


def test_classify_rejects_explicit_foreign_trace(
    measurement, method_spec, scenario_position
):
    trace = measurement[3]
    fresh = trace[1].model_copy(
        update={"observation_id": "new-attempt", "check_id": "new-check"}
    )
    verdict = classify(measurement, fresh, method_spec, scenario_position, trace=trace)
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded


def test_own_paired_write_is_a_grounded_positive(
    measurement, method_spec, scenario_position
):
    trace = measurement[3]
    verdict = classify(measurement, trace[1], method_spec, scenario_position)
    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded and verdict.deterministic
    assert verdict.evidence_refs == tuple(o.observation_id for o in trace)


def test_promoted_norm_reuses_only_its_measured_write(
    measurement, method_spec, scenario_position
):
    _, norm, key, trace, _ = measurement
    promoted = norm.model_copy(update={"invariant_id": "promoted"})
    promoted_key = key._replace(invariant_id=promoted.invariant_id)
    verdict = classify(
        measurement,
        trace[1],
        method_spec,
        scenario_position,
        norm=promoted,
        key=promoted_key,
    )
    assert verdict.status is VerdictStatus.FAIL
    fresh = trace[1].model_copy(
        update={"observation_id": "new-attempt", "check_id": "new-check"}
    )
    verdict = classify(
        measurement,
        fresh,
        method_spec,
        scenario_position,
        norm=promoted,
        key=promoted_key,
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE


def test_old_concurrency_batch_cannot_prove_new_check(
    measurement, method_spec, scenario_position
):
    services, _, key, trace, batch = measurement
    services.evidence_store.clear_readbacks()
    ProbeExecutor.record_concurrency_evidence(
        key, batch, evidence_store=services.evidence_store
    )
    fresh = trace[1].model_copy(
        update={"observation_id": "new-attempt", "check_id": "new-check"}
    )
    verdict = classify(measurement, fresh, method_spec, scenario_position)
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    own = classify(measurement, batch.probes[0][1], method_spec, scenario_position)
    assert own.status is VerdictStatus.FAIL
    assert own.grounded and own.model_id == "differential-concurrency"


def test_transition_does_not_receive_foreign_readback(measurement):
    services, norm, key, trace, _ = measurement
    norm = norm.model_copy(
        update={
            "norm_fact": norm.norm_fact.model_copy(
                update={
                    "args": (
                        norm.norm_fact.args[0],
                        transition(
                            Atom(value="state:before"), Atom(value="state:after")
                        ),
                    )
                }
            )
        }
    )
    fresh = trace[1].model_copy(
        update={"observation_id": "new-attempt", "check_id": "new-check"}
    )
    assert services.evaluator.trace_for_step(
        norm,
        (fresh,),
        evidence_key=key,
        evidence_store=services.evidence_store,
    ) == (fresh,)
    assert services.evaluator.trace_for_step(
        norm,
        (trace[1], fresh),
        evidence_key=key,
        evidence_store=services.evidence_store,
    ) == (fresh,)
    assert (
        services.evaluator.trace_for_step(
            norm,
            (trace[1],),
            evidence_key=key,
            evidence_store=services.evidence_store,
        )
        == trace
    )


@pytest.mark.parametrize("outcome", [AccessOutcome.ALLOWED, AccessOutcome.DENIED])
def test_shrinking_keeps_proven_seed_without_own_readback(
    measurement, method_spec, scenario_position, verification_plan, tmp_path, outcome
):
    from cloud_dast.contracts.execution import LiveRequest
    from cloud_dast.contracts.finding_examples import load_finding_examples
    from cloud_dast.infrastructure.events import JsonlExampleDatabase
    from cloud_dast.model import Check, Observation
    from cloud_dast.runtime.budget import CallLimits
    from tests.test_review_C1 import _runner, _step, _view

    _, norm, _, trace, _ = measurement
    seed = Check(
        check_id=trace[1].check_id,
        invariant_id=norm.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(("secret_id", "long-candidate-value"),),
        identities=("attacker",),
    )
    attempted = []

    def target(check):
        attempted.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=outcome,
            response_summary="synthetic shrink response",
        )

    database = JsonlExampleDatabase(tmp_path / "examples.jsonl")
    runner, _ = _runner(target, example_database=database)
    step = _step(verification_plan, method_spec, norm, scenario_position)
    request = LiveRequest(
        service=method_spec.service, principal_id="attacker", resource_id="resource:one"
    )
    evidence_store = Store[MeasurementKey]()
    measured = measurement[0].evidence_store.get_readback(measurement[2])
    assert measured is not None
    evidence_store.put_readback(
        ProbeExecutor.build_evidence_key(step, request),
        measured,
    )
    from cloud_dast.runtime.scheduler import CoverageDrivenScheduler

    state = Runner.replay_state(
        (),
        scheduler=CoverageDrivenScheduler(()),
        scope=None,
        blocked_reasons=None,
        evidence_store=evidence_store,
    )
    origin = trace[1]
    state.minimal_checks[(origin.observation_id, norm.invariant_id)] = seed
    state.provenance[(origin.observation_id, norm.invariant_id)] = (
        ObservationProvenance(
            step.goal_id, "path:test", step.step_id, norm.invariant_id
        )
    )
    from cloud_dast.runtime.execution.terminal import PathAttempt

    executor = runner._campaign_round._callbacks.execute_path.__self__
    path = _view(step)[1].paths[0]
    executor.shrinking.shrink_attempt_findings(
        request,
        PathAttempt(path, observations=[origin]),
        state,
        budget=CallLimits(3),
        scope=None,
    )

    assert attempted
    assert all(check.request != seed.request for check in attempted)
    assert state.minimal_checks[(origin.observation_id, norm.invariant_id)] == seed
    saved = load_finding_examples(
        database,
        method_id=seed.method_id,
        invariant_id=seed.invariant_id,
        scenario_id=seed.scenario_id,
    )
    assert tuple(check.request for check in saved) == (seed.request,)


def test_transition_candidate_cannot_inherit_a_previous_attempt(
    measurement, method_spec, scenario_position
):
    from cloud_dast.model import ExecutionTrace

    _, norm, _, trace, _ = measurement
    norm = norm.model_copy(
        update={
            "norm_fact": norm.norm_fact.model_copy(
                update={
                    "args": (
                        norm.norm_fact.args[0],
                        transition(Atom(value="before"), Atom(value="after")),
                    )
                }
            )
        }
    )
    old = trace[1].model_copy(
        update={
            "trace": ExecutionTrace(
                steps=(
                    trace[1]
                    .trace.steps[0]
                    .model_copy(
                        update={
                            "resource_state_before": (("state", "before"),),
                            "resource_state_after": (("state", "after"),),
                        }
                    ),
                )
            )
        }
    )
    positive = classify(
        measurement, old, method_spec, scenario_position, trace=(old,), norm=norm
    )
    assert positive.status is VerdictStatus.FAIL
    assert positive.grounded
    fresh = old.model_copy(
        update={"observation_id": "new-attempt", "check_id": "new-check", "trace": None}
    )
    verdict = classify(
        measurement,
        fresh,
        method_spec,
        scenario_position,
        trace=(old, fresh),
        norm=norm,
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
