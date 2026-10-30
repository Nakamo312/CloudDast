from cloud_dast.contracts.plan import InvariantProjection

"""Sink effects and named flow completion require effect-specific witnesses."""

from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    HttpStatus,
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
    Struct,
    completed,
    reached,
    transition,
)
from cloud_dast.verification.oracles import marker, primitive_router, sequence


def _invariant(effect: Struct) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="review:V1",
        norm_id="norm:V1",
        statement="Source-declared forbidden effect",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:V1"), effect),
        ),
    )


def _observation(**changes) -> Observation:
    observation = Observation(
        observation_id="candidate",
        check_id="check:candidate",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        probe_marker="nonce:candidate",
    )
    return observation.model_copy(update=changes)


def _step(**changes) -> TraceStep:
    step = TraceStep(
        observation_id="candidate",
        step_id="step",
        method_id="Update",
        scenario_id="scenario",
        status=AccessOutcome.ALLOWED,
        sinks_reached=("sink:template",),
    )
    return step.model_copy(update=changes)


def test_imports_are_from_this_working_copy():
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )


@pytest.mark.parametrize("path", ["message", "rendered", "error_message", "payload"])
@pytest.mark.parametrize("sink_type", ["template_engine", "interpreter", "renderer"])
def test_reflection_with_carrier_and_source_type_is_not_sink_proof(path, sink_type):
    verdict = marker.Oracle().evaluate_policy(
        _invariant(reached(Atom(value="action:Update"), Atom(value="sink:template"))),
        (_observation(response_tree=((path, "nonce:candidate"),)),),
        method_id="Update",
        probe_fields=("payload",),
        sink_types={"payload": sink_type},
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    assert verdict.deficits[0].kind in {"echo_witness", "candidate_witness"}


@pytest.mark.parametrize("action", ["Update", "action:Update"])
def test_explicit_sink_channel_proves_exact_effect_without_type_or_echo(action):
    verdict = marker.Oracle().evaluate_policy(
        _invariant(reached(Atom(value=action), Atom(value="sink:template"))),
        (_observation(trace=ExecutionTrace(steps=(_step(),))),),
        method_id="Update",
        probe_fields=("payload",),
    )
    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded and verdict.deterministic
    assert verdict.evidence_refs == ("candidate",)


@pytest.mark.parametrize(
    "changes",
    [
        {"sinks_reached": ("sink:other",)},
        {"method_id": "Other"},
        {"scenario_id": "other"},
        {"observation_id": "old-candidate"},
        {"sinks_reached": ()},
    ],
)
def test_unrelated_or_missing_sink_trace_is_not_proof(changes):
    verdict = marker.Oracle().evaluate_policy(
        _invariant(reached(Atom(value="action:Update"), Atom(value="sink:template"))),
        (_observation(trace=ExecutionTrace(steps=(_step(**changes),))),),
        method_id="Update",
        probe_fields=("payload",),
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    assert verdict.deficits[0].kind == "incomplete_negative_scope"


def test_router_preserves_explicit_sink_proof(method_spec, scenario_position):
    observation = _observation(
        trace=ExecutionTrace(steps=(_step(method_id=method_spec.method_id),))
    )
    verdict = primitive_router.Oracle().evaluate_policy(
        _invariant(
            reached(Atom(value=method_spec.method_id), Atom(value="sink:template"))
        ),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
        probe_fields=("payload",),
    )
    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded
    assert verdict.evidence_refs == ("candidate",)


@pytest.mark.parametrize("sink_type,code", [("interpreter", 500), ("filesystem", 404)])
@pytest.mark.parametrize("corroborated", [False, True])
def test_error_diagnostics_require_explicit_sink_corroboration(
    sink_type, code, corroborated
):
    text = "file nonce:candidate not found" if code == 404 else "parse nonce:candidate"
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        response_summary=text,
        transport_status=HttpStatus(code=code),
        error_reason=text,
        trace=ExecutionTrace(steps=(_step(),)) if corroborated else None,
    )
    verdict = marker.Oracle().evaluate_policy(
        _invariant(reached(Atom(value="action:Update"), Atom(value="sink:template"))),
        (observation,),
        method_id="Update",
        probe_fields=("payload",),
        sink_types={"payload": sink_type},
    )
    if corroborated:
        assert verdict.status is VerdictStatus.FAIL
        assert verdict.grounded
        assert verdict.evidence_refs == ("candidate",)
    else:
        assert verdict.status is VerdictStatus.UNSCOREABLE
        assert not verdict.grounded
        assert verdict.deficits[0].kind == "echo_witness"


@pytest.mark.parametrize("outcome", list(AccessOutcome))
@pytest.mark.parametrize("count", [1, 2, 5])
def test_outcomes_and_success_counts_never_decide_named_flow(outcome, count):
    trace = tuple(
        _observation(
            observation_id=f"attempt:{i}",
            observed_outcome=outcome,
        )
        for i in range(count)
    )
    verdict = sequence.Oracle().evaluate_policy(
        _invariant(completed(Atom(value="flow:purchase"))),
        trace,
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    assert not verdict.negative_scope
    assert verdict.deficits[0].kind == "partial_sequence"


@pytest.mark.parametrize("outcome", [AccessOutcome.ERROR, AccessOutcome.UNKNOWN])
def test_uncertain_transition_outcome_is_not_grounded_pass(outcome):
    observation = _observation(
        observed_outcome=outcome,
        trace=ExecutionTrace(
            steps=(
                _step(
                    status=outcome,
                    resource_state_before=(("state", "created"),),
                    resource_state_after=(("state", "approved"),),
                ),
            )
        ),
    )
    verdict = sequence.Oracle().evaluate_policy(
        _invariant(transition(Atom(value="created"), Atom(value="approved"))),
        (observation,),
        action_id="Update",
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded


@pytest.mark.parametrize("sink_type", ["interpreter", "filesystem", "xml_parser"])
@pytest.mark.parametrize("code", [400, 404, 500])
def test_validation_diagnostic_reflection_is_not_sink_proof(sink_type, code):
    observation = _observation(
        observed_outcome=AccessOutcome.ERROR,
        error_reason="invalid candidate nonce:candidate",
        response_summary="validation rejected input before sink invocation",
        transport_status=HttpStatus(code=code),
    )
    verdict = marker.Oracle().evaluate_policy(
        _invariant(reached(Atom(value="action:Update"), Atom(value="sink:template"))),
        (observation,),
        method_id="Update",
        probe_fields=("payload",),
        sink_types={"payload": sink_type},
    )
    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert not verdict.grounded
    assert verdict.deficits[0].kind == "echo_witness"
