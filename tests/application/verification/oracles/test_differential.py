from __future__ import annotations

import pytest

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    JsonValue,
    Observation,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, changed
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles import (
    DifferentialOracle,
    NormView,
    PrimitiveOracleRouter,
)


def _invariant(field: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:no-state-change",
        norm_id="norm:no-state-change",
        statement="The forbidden resource field must not change",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:no-state-change"),
                changed(
                    Atom(value="resource:order"),
                    Atom(value=field),
                ),
            ),
        ),
    )


def _observation(
    tree: tuple[tuple[str, JsonValue], ...],
    *,
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    error_reason: str | None = None,
) -> Observation:
    return Observation(
        check_id="check:differential",
        scenario_id="scenario:attacker",
        observed_outcome=outcome,
        response_summary="read-back",
        error_reason=error_reason,
        response_tree=tree,
    )


def _trace(
    before_tree: tuple[tuple[str, JsonValue], ...],
    after_tree: tuple[tuple[str, JsonValue], ...],
    *,
    write_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> tuple[Observation, Observation, Observation]:
    return (
        _observation(before_tree),
        _observation(write_tree),
        _observation(after_tree),
    )


def _state_observation(
    *,
    state_before: tuple[tuple[str, JsonValue], ...] = (),
    state_after: tuple[tuple[str, JsonValue], ...] = (),
    observation_id: str = "state-write",
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    error_reason: str | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id="check:differential",
        scenario_id="scenario:attacker",
        observed_outcome=outcome,
        response_summary="state evidence",
        error_reason=error_reason,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id="state-write",
                    method_id="UpdateOrder",
                    scenario_id="scenario:attacker",
                    status=outcome,
                    resource_state_before=state_before,
                    resource_state_after=state_after,
                ),
            )
        ),
    )


def _probe(
    index: int,
    *,
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    method_id: str = "UpdateOrder",
    state_before: tuple[tuple[str, JsonValue], ...] = (),
    state_after: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    observation_id = f"probe-{index}"
    return Observation(
        observation_id=observation_id,
        check_id=f"check:differential:{index}",
        scenario_id="scenario:attacker",
        observed_outcome=outcome,
        response_summary="parallel probe",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id=f"probe-{index}",
                    method_id=method_id,
                    scenario_id="scenario:attacker",
                    status=outcome,
                    resource_state_before=state_before,
                    resource_state_after=state_after,
                ),
            )
        ),
    )


def test_changed_field_fails_deterministically() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        _trace((("order.total", 10),), (("order.total", 20),)),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "order.total" in verdict.rationale
    assert len(verdict.evidence_refs) == 3


def test_unchanged_field_passes() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        _trace((("order.total", 10),), (("order.total", 10),)),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.deterministic is True
    assert verdict.grounded is True


def test_single_observation_without_state_projection_is_unscoreable() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (_observation((("order.total", 10),)),),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert "differential QDL norm has no complete write state projection" in (
        verdict.rationale
    )


def test_write_state_projection_scores_changed_field() -> None:
    write = _state_observation(
        state_before=(("total", 10),),
        state_after=(("total", 20),),
    )

    verdict = DifferentialOracle().evaluate_policy(_invariant("total"), (write,))

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert verdict.evidence_refs == (write.observation_id,)
    assert "one write's state projection" in verdict.rationale
    assert "resource_state_before" in verdict.rationale
    assert "resource_state_after" in verdict.rationale


def test_write_state_projection_requires_both_states() -> None:
    write = _state_observation(state_after=(("total", 20),))

    verdict = DifferentialOracle().evaluate_policy(_invariant("total"), (write,))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert "write state projection" in verdict.rationale


def test_changed_norm_routes_one_write_state_projection(
    method_spec,
    scenario_position,
) -> None:
    write = _state_observation(
        state_before=(("total", 10),),
        state_after=(("total", 20),),
    )

    verdict = PrimitiveOracleRouter().evaluate_policy(
        _invariant("total"),
        (write,),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "differential"
    assert verdict.grounded is True


@pytest.mark.parametrize(
    "outcome",
    [AccessOutcome.ERROR, AccessOutcome.UNKNOWN],
)
def test_transport_error_on_write_is_recovered_by_paired_reads(
    outcome: AccessOutcome,
) -> None:
    before = _observation((("order.total", 10),))
    write = _observation((), outcome=outcome, error_reason="transport unavailable")
    after = _observation((("order.total", 10),))

    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (before, write, after),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "transport-error recovery" in verdict.rationale


@pytest.mark.parametrize(
    "outcome",
    [AccessOutcome.ERROR, AccessOutcome.UNKNOWN],
)
def test_transport_error_on_write_does_not_hide_a_real_change(
    outcome: AccessOutcome,
) -> None:
    before = _observation((("order.total", 10),))
    write = _observation((), outcome=outcome, error_reason="transport unavailable")
    after = _observation((("order.total", 20),))

    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (before, write, after),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "order.total" in verdict.rationale
    assert "transport-error recovery" in verdict.rationale


def test_transport_error_without_state_evidence_remains_unscoreable() -> None:
    before = _observation((("order.total", 10),))
    write = _observation((), outcome=AccessOutcome.ERROR, error_reason="write failed")
    after = _observation(
        (),
        outcome=AccessOutcome.ERROR,
        error_reason="transport unavailable",
    )

    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (before, write, after),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "transport error" in verdict.rationale
    assert "recoverable state evidence" in verdict.rationale


def test_transport_error_on_read_is_recovered_from_trace_resource_state() -> None:
    before = _observation((("total", 10),))
    write = _state_observation(
        state_before=(("total", 10),),
        state_after=(("total", 20),),
    )
    after = _observation(
        (),
        outcome=AccessOutcome.ERROR,
        error_reason="transport unavailable",
    )

    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (before, write, after),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "resource_state_after" in verdict.rationale
    assert "transport-error recovery" in verdict.rationale
    assert "transport-error recovery" in verdict.rationale


def test_both_transport_errors_are_recovered_from_write_state() -> None:
    before = _observation(
        (),
        outcome=AccessOutcome.ERROR,
        error_reason="transport unavailable",
    )
    write = _state_observation(
        state_before=(("total", 10),),
        state_after=(("total", 20),),
    )
    after = _observation(
        (),
        outcome=AccessOutcome.ERROR,
        error_reason="transport unavailable",
    )

    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        (before, write, after),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "resource_state_before" in verdict.rationale
    assert "resource_state_after" in verdict.rationale


def test_nested_response_tree_path_is_supported() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("metadata.owner"),
        _trace(
            (("response.metadata.owner", "owner-a"),),
            (("response.metadata.owner", "attacker"),),
        ),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert "response.metadata.owner" in verdict.rationale


def test_multiple_suffix_matches_are_compared_deterministically() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        _trace(
            (
                ("a.total", 10),
                ("b.total", 10),
            ),
            (
                ("a.total", 10),
                ("b.total", 20),
            ),
        ),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert "b.total" in verdict.rationale


def test_missing_field_in_either_read_is_unscoreable() -> None:
    verdict = DifferentialOracle().evaluate_policy(
        _invariant("total"),
        _trace((("order.state", "open"),), (("order.total", 20),)),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "no corresponding response_tree or resource-state leaf" in verdict.rationale


def test_changed_norm_uses_differential_router_primitive(
    method_spec,
    scenario_position,
) -> None:
    invariant = _invariant("total")

    assert NormView.from_invariant(invariant).primitive == "differential"
    verdict = PrimitiveOracleRouter().evaluate_policy(
        invariant,
        _trace((("order.total", 10),), (("order.total", 20),)),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "differential"


def test_concurrency_state_change_fails_deterministically() -> None:
    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=tuple(_probe(index) for index in range(4)),
        read_after=_observation((("total", 20),)),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "4 successful concurrent probes" in verdict.rationale
    assert "order" not in verdict.rationale
    assert len(verdict.evidence_refs) == 6


def test_concurrency_unchanged_state_passes() -> None:
    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=tuple(_probe(index) for index in range(4)),
        read_after=_observation((("total", 10),)),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.deterministic is True
    assert verdict.grounded is True


def test_concurrency_transport_error_is_recovered_from_probe_state() -> None:
    probes = tuple(
        _probe(
            index,
            state_before=(("total", 10),),
            state_after=(("total", 20),),
        )
        for index in range(4)
    )

    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=probes,
        read_after=_observation(
            (),
            outcome=AccessOutcome.ERROR,
            error_reason="transport unavailable",
        ),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "resource_state_after" in verdict.rationale


def test_concurrency_read_errors_are_recovered_from_probe_state() -> None:
    probes = tuple(
        _probe(
            index,
            state_before=(("total", 10),),
            state_after=(("total", 20),),
        )
        for index in range(4)
    )

    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation(
            (),
            outcome=AccessOutcome.ERROR,
            error_reason="transport unavailable",
        ),
        probes=probes,
        read_after=_observation(
            (),
            outcome=AccessOutcome.ERROR,
            error_reason="transport unavailable",
        ),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert "resource_state_before" in verdict.rationale
    assert "resource_state_after" in verdict.rationale


def test_one_successful_concurrency_probe_is_not_a_race_witness() -> None:
    probes = (
        _probe(0),
        _probe(1, outcome=AccessOutcome.ERROR),
        _probe(2, outcome=AccessOutcome.ERROR),
        _probe(3, outcome=AccessOutcome.ERROR),
    )

    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=probes,
        read_after=_observation((("total", 20),)),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "fewer than 2 successful probes" in verdict.rationale


def test_concurrency_probe_must_align_with_the_norm_method() -> None:
    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=tuple(_probe(index, method_id="DeleteOrder") for index in range(4)),
        read_after=_observation((("total", 20),)),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "not aligned" in verdict.rationale


def test_concurrency_requires_a_method_id() -> None:
    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=tuple(_probe(index) for index in range(4)),
        read_after=_observation((("total", 20),)),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "requires a method id" in verdict.rationale


def test_duplicate_concurrency_observations_are_not_a_race_witness() -> None:
    probe = _probe(0)

    verdict = DifferentialOracle().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=(probe, probe),
        read_after=_observation((("total", 20),)),
        method_id="UpdateOrder",
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert "must be distinct" in verdict.rationale


def test_router_dispatches_concurrency_changed_norm(
    method_spec,
) -> None:
    update_method = method_spec.model_copy(update={"method_id": "UpdateOrder"})
    verdict = PrimitiveOracleRouter().evaluate_concurrency_policy(
        _invariant("total"),
        read_before=_observation((("total", 10),)),
        probes=tuple(_probe(index) for index in range(4)),
        read_after=_observation((("total", 20),)),
        method=update_method,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "differential-concurrency"
    assert verdict.deterministic is True
    assert verdict.grounded is True
