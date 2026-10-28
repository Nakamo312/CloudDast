"""Contracts for robust timing and aggregate concurrency differential modes."""

from __future__ import annotations

import threading

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ResponseData,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.qdl.graph import Atom, input_field, output_field
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.differential.comparator import (
    compare_concurrency_measurements,
    compare_timing_measurements,
)
from cloud_dast_fuzzing import TemplateGenerator
from tests.support.guardrails import AllowAllGuardrail


def _observation(
    index: int,
    *,
    duration_ms: float = 10.0,
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    status_code: int = 200,
    value: str = "same",
) -> Observation:
    tree = (("value", value),)
    return Observation(
        check_id=f"check-{index}",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary="measured",
        transport_status=HttpStatus(code=status_code),
        duration_ms=duration_ms,
        response_tree=tree,
        response_digest=response_tree_digest(tree),
    )


def test_timing_does_not_infer_variance_from_two_isolated_calls() -> None:
    control = (_observation(1, duration_ms=10), _observation(2, duration_ms=11))
    treatment = (_observation(3, duration_ms=100), _observation(4, duration_ms=101))

    report = compare_timing_measurements("action:get", control, treatment)

    assert report is not None
    assert report.latency_class_differs is False
    assert "latency" not in report.dimensions
    assert report.timing_evidence is not None
    assert report.timing_evidence.control_samples == 2
    assert report.timing_evidence.treatment_samples == 2
    assert report.timing_evidence.control_median_ms is None


def test_timing_detects_a_robust_class_difference_with_three_samples() -> None:
    control = (
        _observation(1, duration_ms=10),
        _observation(2, duration_ms=11),
        _observation(3, duration_ms=12),
    )
    treatment = (
        _observation(4, duration_ms=100),
        _observation(5, duration_ms=101),
        _observation(6, duration_ms=102),
    )

    report = compare_timing_measurements("action:get", control, treatment)

    assert report is not None
    assert report.latency_class_differs is True
    assert report.dimensions == ("latency",)
    assert report.timing_evidence is not None
    assert report.timing_evidence.control_samples == 3
    assert report.timing_evidence.treatment_samples == 3
    assert report.timing_evidence.control_median_ms == 11
    assert report.timing_evidence.treatment_median_ms == 101


def test_concurrency_identical_successes_are_not_variance() -> None:
    probes = tuple(_observation(index) for index in range(4))

    report = compare_concurrency_measurements("action:get", probes)

    assert report is not None
    assert report.aggregate_differs is False
    assert report.dimensions == ()
    assert report.concurrency_evidence is not None
    assert report.concurrency_evidence.outcome_counts == (("allowed", 4),)
    assert report.concurrency_evidence.status_counts == ((HttpStatus(code=200), 4),)
    assert report.concurrency_evidence.unique_response_digests == 1
    assert report.concurrency_evidence.state_readback is False


def test_concurrency_aggregates_outcome_and_digest_variance() -> None:
    probes = (
        _observation(1),
        _observation(2),
        _observation(3, value="different"),
        _observation(4, outcome=AccessOutcome.ERROR, status_code=500),
    )

    report = compare_concurrency_measurements("action:get", probes)

    assert report is not None
    assert report.aggregate_differs is True
    assert "aggregate" in report.dimensions
    assert "outcome" in report.dimensions
    assert report.concurrency_evidence is not None
    assert report.concurrency_evidence.outcome_counts == (
        ("allowed", 3),
        ("error", 1),
    )
    assert report.concurrency_evidence.status_counts == (
        (HttpStatus(code=200), 3),
        (HttpStatus(code=500), 1),
    )
    assert report.concurrency_evidence.unique_response_digests == 2


def test_concurrency_readback_state_change_is_aggregate_variance() -> None:
    probes = tuple(_observation(index) for index in range(4))
    read_before = _observation(5, value="before")
    read_after = _observation(6, value="after")

    report = compare_concurrency_measurements(
        "action:get",
        probes,
        read_before=read_before,
        read_after=read_after,
    )

    assert report is not None
    assert report.aggregate_differs is True
    assert "aggregate" in report.dimensions
    assert "value" in report.dimensions
    assert report.concurrency_evidence is not None
    assert report.concurrency_evidence.state_readback is True
    assert report.concurrency_evidence.state_differs is True


class BarrierTarget:
    """Force four target calls to overlap and return distinct outputs."""

    def __init__(self, probe_count: int) -> None:
        self.barrier = threading.Barrier(probe_count, timeout=3.0)
        self.parallel = False
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def start_parallel(self) -> None:
        self.parallel = True

    def stop_parallel(self) -> None:
        self.parallel = False

    def __call__(self, check: Check) -> Observation:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.parallel:
                self.barrier.wait()
        finally:
            with self._lock:
                self.active -= 1
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="parallel probe",
            transport_status=HttpStatus(code=200),
            output=ResponseData(fields=(("forwarded", f"probe-{check.check_id}"),)),
        )


def _forwarded_check() -> Check:
    return Check(
        invariant_id="invariant",
        method_id="action:get",
        scenario_id="scenario",
        request=(("forwarded", None),),
        identities=("attacker",),
    )


def test_parallel_batch_overlaps_probes_and_restores_output_snapshot(
    scenario_position,
) -> None:
    target = BarrierTarget(4)
    checker = Checker(target, TemplateGenerator(), AllowAllGuardrail())

    scenario = scenario_position.model_copy(update={"scenario_id": "scenario"})
    coupling = (
        output_field(Atom(value="seed"), Atom(value="forwarded")),
        input_field(Atom(value="action:get"), Atom(value="forwarded")),
        "eq",
    )
    bindings = []
    for name in ("seed", "action:get"):
        method = MethodSpec(
            method_id=name,
            service="svc",
            name=name,
            layer=scenario.profile.endpoint_layer,
            fields=(FieldSpec(name="forwarded", type="string"),),
        )
        plan = VerificationPlan(
            plan_id=name,
            invariant_id="invariant",
            method_id=name,
            couplings=(coupling,),
        )
        bindings.append((plan, method, scenario))
    checker.set_coupling_context(tuple(bindings))
    seeded = checker.execute_check(
        _forwarded_check().model_copy(update={"method_id": "seed"})
    )
    assert seeded is not None
    seeded_output = f"probe-{seeded.check_id}"
    target.start_parallel()

    result = checker.execute_parallel_batch(
        tuple(_forwarded_check() for _ in range(4)),
        max_workers=4,
    )

    assert target.max_active == 4
    assert len(result.probes) == 4
    assert {dict(check.request)["forwarded"] for check, _ in result.probes} == {
        seeded_output
    }
    assert len(checker.checks) == 5

    target.stop_parallel()
    followup = checker.execute_check(_forwarded_check())
    assert followup is not None
    assert dict(checker.checks[-1].request)["forwarded"] == seeded_output
