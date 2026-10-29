from __future__ import annotations

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    HttpStatus,
    Observation,
    ResponseData,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, reached
from cloud_dast.verification.oracles import MarkerOracle


def _invariant(marker: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant",
        norm_id="norm",
        statement="marker sink must not be reached",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm"),
                reached(Atom(value="action:write"), Atom(value=marker)),
            ),
        ),
    )


def _observation(marker: str, value: str) -> Observation:
    field_name = f"request.{marker}"
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="structured response",
        output=ResponseData(fields=((field_name, value),)),
        response_tree=((field_name, value),),
        probe_marker=marker,
    )


def test_marker_ignores_structured_field_name_echo() -> None:
    marker = "dast-marker"
    observation = _observation(marker, "ordinary")

    verdict = MarkerOracle().evaluate_policy(
        _invariant(marker),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_ignores_structured_field_value_echo() -> None:
    marker = "dast-marker"
    observation = _observation(marker, marker)

    verdict = MarkerOracle().evaluate_policy(
        _invariant(marker),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale
    assert [deficit.kind for deficit in verdict.deficits] == ["echo_witness"]


def test_marker_without_grounded_probe_fields_is_unscoreable() -> None:
    marker = "dast-marker"
    observation = _observation(marker, marker)

    verdict = MarkerOracle().evaluate_policy(_invariant(marker), (observation,))

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "no grounded probe fields" in verdict.rationale


def test_filesystem_404_diagnostic_without_sink_trace_is_unscoreable() -> None:
    marker = "dast-marker"
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ERROR,
        response_summary=f"file {marker} not found",
        transport_status=HttpStatus(code=404),
        error_reason=f"file {marker} not found",
        probe_marker=marker,
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(marker),
        (observation,),
        probe_fields=("path",),
        sink_types={"path": "filesystem"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "not a grounded sink witness" in verdict.rationale


def test_marker_rejects_incomplete_response_evidence() -> None:
    marker = "dast-marker"
    observation = _observation(marker, marker).model_copy(
        update={
            "response_tree": (
                ("request.dast-marker", marker),
                ("__truncated__", True),
            )
        }
    )

    verdict = MarkerOracle().evaluate_policy(
        _invariant(marker),
        (observation,),
        probe_fields=("template",),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "incomplete response evidence" in verdict.rationale
