from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Observation,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    completed,
    transition,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles import (
    NormView,
    PrimitiveOracleRouter,
    SequenceOracle,
)


def _flow_invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:coupon-double",
        norm_id="norm:coupon-double",
        statement="A coupon must not be applied twice",
        severity=Severity.CRITICAL,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:coupon-double"),
                completed(Atom(value="flow:coupon-double")),
            ),
        ),
    )


def _observation(
    index: int,
    *,
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
) -> Observation:
    return Observation(
        observation_id=f"observation-{index}",
        check_id=f"check-{index}",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary=outcome.value,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=f"observation-{index}",
                    step_id=f"step-{index}",
                    method_id=f"method-{index}",
                    scenario_id="scenario",
                    status=outcome,
                ),
            )
        ),
    )


def _transition_invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant:approve-order",
        norm_id="norm:approve-order",
        statement="An order must not be approved from created state",
        severity=Severity.CRITICAL,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm:approve-order"),
                transition(Atom(value="created"), Atom(value="approved")),
            ),
        ),
    )


def _state_observation(
    index: int,
    *,
    before: str | None = None,
    after: str | None = None,
    method_id: str = "orders.Approve",
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
) -> Observation:
    return Observation(
        observation_id=f"observation-{index}",
        check_id=f"check-{index}",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary=outcome.value,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=f"observation-{index}",
                    step_id=f"step-{index}",
                    method_id=method_id,
                    scenario_id="scenario",
                    status=outcome,
                    resource_state_before=(("state", before),) if before else (),
                    resource_state_after=(("state", after),) if after else (),
                ),
            )
        ),
    )


def test_sequence_successes_do_not_prove_named_completion() -> None:
    trace = (_observation(1), _observation(2))

    verdict = SequenceOracle().evaluate_policy(_flow_invariant(), trace)

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False
    assert verdict.evidence_refs == ()


def test_sequence_denial_does_not_refute_named_completion() -> None:
    trace = (_observation(1), _observation(2, outcome=AccessOutcome.DENIED))

    verdict = SequenceOracle().evaluate_policy(_flow_invariant(), trace)

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False


def test_sequence_successes_after_denial_are_unscoreable() -> None:
    trace = (
        _observation(1, outcome=AccessOutcome.DENIED),
        _observation(2),
        _observation(3),
    )

    verdict = SequenceOracle().evaluate_policy(_flow_invariant(), trace)

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.evidence_refs == ()
    assert verdict.deficits[0].kind == "partial_sequence"


def test_sequence_contiguity_is_not_flow_state_evidence() -> None:
    trace = (
        _observation(1),
        _observation(2, outcome=AccessOutcome.DENIED),
        _observation(3),
    )

    verdict = SequenceOracle().evaluate_policy(_flow_invariant(), trace)

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.deficits[0].kind == "partial_sequence"


def test_sequence_oracle_is_unscoreable_without_observations() -> None:
    verdict = SequenceOracle().evaluate_policy(_flow_invariant(), ())

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False


def test_transition_norm_compiles_as_sequence_primitive() -> None:
    norm = NormView.from_invariant(_transition_invariant())

    assert norm is not None
    assert norm.primitive == "sequence"
    assert norm.action_id is None
    assert norm.from_state == "created"
    assert norm.to_state == "approved"


def test_transition_oracle_fails_when_transition_is_completed() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (_state_observation(1, before="created", after="approved"),),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert verdict.evidence_refs == ("observation-1",)
    assert "created -> approved" in verdict.rationale


def test_transition_oracle_passes_when_transition_is_absent() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (_state_observation(1, before="created", after="shipped"),),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True
    assert "absent from state evidence" in verdict.rationale


def test_transition_oracle_passes_when_transition_is_blocked() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(
                1,
                before="created",
                after="approved",
                outcome=AccessOutcome.DENIED,
            ),
        ),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True
    assert "not completed" in verdict.rationale


def test_transition_oracle_passes_when_authentication_fails() -> None:
    observation = _state_observation(
        1,
        before="created",
        after="approved",
    ).model_copy(update={"auth_failed": True})

    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (observation,),
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True
    assert "not completed" in verdict.rationale


def test_transition_oracle_is_unscoreable_without_state_evidence() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (_state_observation(1),),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "complete before/after state evidence" in verdict.rationale


def test_transition_oracle_scores_explicit_readback_state_evidence() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(1, after="created", method_id="orders.Get"),
            _state_observation(2, before="created", after="approved"),
            _state_observation(3, after="approved", method_id="orders.Get"),
        ),
        action_id="orders.Approve",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.deterministic is True
    assert verdict.grounded is True
    assert verdict.evidence_refs == ("observation-1", "observation-2", "observation-3")
    assert "created -> approved" in verdict.rationale


def test_transition_oracle_scores_concurrency_state_evidence() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(1, after="created", method_id="orders.Get"),
            _state_observation(2, before="created", after="approved"),
            _state_observation(
                3, before="created", after="approved", outcome=AccessOutcome.DENIED
            ),
            _state_observation(4, after="approved", method_id="orders.Get"),
        ),
        action_id="orders.Approve",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert verdict.evidence_refs == (
        "observation-1",
        "observation-2",
        "observation-3",
        "observation-4",
    )


def test_transition_oracle_passes_when_paired_write_is_denied() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(1, after="created", method_id="orders.Get"),
            _state_observation(
                2,
                before="created",
                after="approved",
                outcome=AccessOutcome.DENIED,
            ),
            _state_observation(3, after="approved", method_id="orders.Get"),
        ),
        action_id="orders.Approve",
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True
    assert "not completed" in verdict.rationale


def test_transition_oracle_rejects_unpaired_action_retries() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(1, after="created"),
            _state_observation(2, after="approved"),
            _state_observation(3, after="approved"),
        ),
        action_id="orders.Approve",
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "complete before/after state evidence" in verdict.rationale


def test_transition_oracle_rejects_paired_reads_without_the_norm_action() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _transition_invariant(),
        (
            _state_observation(1, after="created", method_id="orders.Get"),
            _state_observation(2, after="approved", method_id="orders.Audit"),
            _state_observation(3, after="approved", method_id="orders.Get"),
        ),
        action_id="orders.Approve",
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False


def test_sequence_one_success_is_unscoreable() -> None:
    verdict = SequenceOracle().evaluate_policy(
        _flow_invariant(),
        (_observation(1),),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.deficits[0].kind == "partial_sequence"
    assert [deficit.kind for deficit in verdict.deficits] == ["partial_sequence"]


def test_completed_flow_norm_is_not_bound_to_flow_identifier() -> None:
    norm = NormView.from_invariant(_flow_invariant())

    assert norm is not None
    assert norm.primitive == "sequence"
    assert norm.action_id is None


def test_primitive_router_dispatches_sequence_norm(
    method_spec,
    scenario_position,
) -> None:
    verdict = PrimitiveOracleRouter().evaluate_policy(
        _flow_invariant(),
        (_observation(1), _observation(2)),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.model_id == "sequence"


def test_primitive_router_binds_transition_to_the_executed_method(
    method_spec,
    scenario_position,
) -> None:
    observation = _state_observation(
        1,
        before="created",
        after="approved",
        method_id=method_spec.method_id,
    )

    verdict = PrimitiveOracleRouter().evaluate_policy(
        _transition_invariant(),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.model_id == "sequence"
