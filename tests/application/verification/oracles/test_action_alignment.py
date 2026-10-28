from __future__ import annotations

import pytest

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    MethodSpec,
    Observation,
    PrincipalRef,
    ResponseData,
    ScenarioPosition,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    Struct,
    allowed,
    duration,
    external_call,
    field,
    has,
    reached,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles import (
    FieldExposureOracle,
    LatencyBaseline,
    LatencyOracle,
    OobOracle,
    PrimitiveOracleRouter,
)
from cloud_dast.verification.oracles.action_alignment import (
    ACTION_MISMATCH_RATIONALE,
    actions_align,
)


class _ReadyEventStore:
    def __init__(self, event: EvidenceEvent | None) -> None:
        self._event = event
        self._blocked_reason: str | None = None

    def record(self, event: EvidenceEvent) -> None:
        self._event = event

    def wait_for(
        self,
        marker: str,
        timeout: float,
        *,
        channel: str | None = None,
    ) -> EvidenceEvent | None:
        del timeout
        return (
            self._event
            if self._event
            and self._event.correlation_id == marker
            and (channel is None or self._event.channel == channel)
            else None
        )

    def ready(self) -> bool:
        return True

    def set_ready(self, ready: bool) -> None:
        self._blocked_reason = None if ready else "listener is not ready"

    def block(self, reason: str) -> None:
        self._blocked_reason = reason

    def blocked_reason(self) -> str | None:
        return self._blocked_reason


@pytest.mark.parametrize(
    ("norm_action_id", "method_id", "expected"),
    [
        (None, "grpc:Service.Get", True),
        ("action:grpc:Service.Get", "grpc:Service.Get", True),
        ("grpc:Service.Get", "action:grpc:Service.Get", True),
        ("grpc:Service.Get", "grpc:Service.Get", True),
        ("action:grpc:Service.Get", "grpc:Service.Other", False),
    ],
)
def test_action_aliases_are_compared_deterministically(
    norm_action_id: str | None,
    method_id: str | None,
    expected: bool,
) -> None:
    assert actions_align(norm_action_id, method_id) is expected


@pytest.mark.parametrize(
    "primitive", ["outcome", "latency_bound", "marker", "oob_event"]
)
def test_router_rejects_action_mismatch_before_scoring(
    primitive: str,
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    effect, observation, router = _action_bound_case(primitive, method_spec)
    executed_method = method_spec.model_copy(
        update={"method_id": "grpc:another.Service.Method"}
    )

    verdict = router.evaluate_policy(
        _invariant(effect),
        (observation,),
        method=executed_method,
        scenario=scenario_position,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.rationale == ACTION_MISMATCH_RATIONALE


@pytest.mark.parametrize(
    "primitive", ["outcome", "latency_bound", "marker", "oob_event"]
)
def test_router_scores_action_bound_norm_for_the_executed_method(
    primitive: str,
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    effect, observation, router = _action_bound_case(primitive, method_spec)

    verdict = router.evaluate_policy(
        _invariant(effect),
        (observation,),
        method=method_spec,
        scenario=scenario_position,
        probe_fields=("template",) if primitive == "marker" else (),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True


def test_field_exposure_keeps_principal_scope_with_method_alignment(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
) -> None:
    effect = has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:secret"), Atom(value="private_key")),
    )
    observation = Observation(
        check_id="check",
        scenario_id=scenario_position.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        response_tree=(("private_key", "PEM"),),
    )
    oracle = FieldExposureOracle()

    scoped = oracle.evaluate_policy(
        _invariant(effect),
        (observation,),
        scenario=_scenario(scenario_position, "attacker"),
        method_id=method_spec.method_id,
    )
    other_principal = oracle.evaluate_policy(
        _invariant(effect),
        (observation,),
        scenario=_scenario(scenario_position, "victim"),
        method_id=method_spec.method_id,
    )

    assert scoped.status is VerdictStatus.FAIL
    assert other_principal.status is VerdictStatus.UNSCOREABLE
    assert other_principal.grounded is False
    assert "another principal" in other_principal.rationale
    assert [deficit.kind for deficit in other_principal.deficits] == ["principal_scope"]


def _action_bound_case(
    primitive: str,
    method: MethodSpec,
) -> tuple[Struct, Observation, PrimitiveOracleRouter]:
    action = Atom(value=f"action:{method.method_id}")
    if primitive == "outcome":
        return (
            allowed(action),
            _observation(),
            PrimitiveOracleRouter(),
        )
    if primitive == "latency_bound":
        baseline = LatencyBaseline.from_durations(
            method.method_id,
            (100.0, 100.0, 100.0),
        )
        return (
            duration(action, Atom(value=110)),
            _observation(duration_ms=111.0),
            PrimitiveOracleRouter(
                latency_oracle=LatencyOracle({method.method_id: baseline})
            ),
        )
    if primitive == "marker":
        observation = _observation(probe_marker="dast-marker-42")
        observation = observation.model_copy(
            update={
                "trace": ExecutionTrace(
                    steps=(
                        TraceStep(
                            observation_id=observation.observation_id,
                            step_id="step",
                            method_id=method.method_id,
                            scenario_id=observation.scenario_id,
                            status=AccessOutcome.ALLOWED,
                            sinks_reached=("dast-marker-42",),
                        ),
                    )
                )
            }
        )
        return (
            reached(action, Atom(value="dast-marker-42")),
            observation,
            PrimitiveOracleRouter(),
        )
    if primitive == "oob_event":
        event = EvidenceEvent(
            channel="oob", correlation_id="dast-oob-marker", source="10.0.0.8"
        )
        oracle = OobOracle(_ReadyEventStore(event), wait_seconds=0.0)
        return (
            external_call(action, Atom(value="dast-oob-marker")),
            _observation(probe_marker="dast-oob-marker"),
            PrimitiveOracleRouter(oob_oracle=oracle),
        )
    raise ValueError(f"unsupported primitive {primitive!r}")


def _invariant(effect: Struct) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="machine-checkable QDL norm",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:inv"), effect),
        ),
    )


def _observation(
    *,
    output: ResponseData | None = None,
    duration_ms: float | None = None,
    probe_marker: str | None = None,
) -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        output=output,
        duration_ms=duration_ms,
        probe_marker=probe_marker,
    )


def _scenario(
    scenario: ScenarioPosition,
    principal_id: str,
) -> ScenarioPosition:
    return scenario.model_copy(
        update={
            "stand": scenario.stand.model_copy(
                update={
                    "principals": (
                        PrincipalRef(principal_id=principal_id, principal_type="user"),
                    )
                }
            )
        }
    )
