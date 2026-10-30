from __future__ import annotations

import pytest
from pydantic import ValidationError

import cloud_dast.verification.oracles.marker
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    Observation,
    PolicyVerdict,
    PrincipalRef,
    ResponseData,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    completed,
    field,
    has,
    reached,
)
from cloud_dast.verification.oracles import (
    WitnessRolePolicy,
    field_exposure,
    grounded,
    sequence,
)


def _invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant",
        norm_id="threat",
        statement="QDL witness norm",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm"), effect),
        ),
    )


def _marker_norm(marker: str) -> InvariantProjection:
    return _invariant(reached(Atom(value="action:render"), Atom(value=marker)))


def _observation(
    *,
    response_tree: tuple[tuple[str, object], ...] = (),
    output: ResponseData | None = None,
    marker: str | None = None,
) -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        response_tree=response_tree,
        output=output,
        probe_marker=marker,
    )


def _scenario(principal_id: str) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.CROSS_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="created",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            principals=(PrincipalRef(principal_id=principal_id, principal_type="user"),)
        ),
    )


def _possession_norm() -> InvariantProjection:
    return _invariant(
        has(
            Atom(value="principal:attacker"),
            field(Atom(value="resource:secret"), Atom(value="private_key")),
        )
    )


def test_response_reflection_is_not_a_sink_witness() -> None:
    marker = "dast-positive-witness"
    observation = _observation(
        response_tree=(("response.rendered", marker),),
        marker=marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _marker_norm(marker),
        (observation,),
        method_id="render",
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.deterministic is True
    assert verdict.grounded is False


def test_complete_response_is_not_complete_sink_scope() -> None:
    marker = "dast-negative-witness"
    observation = _observation(
        response_tree=(("response.rendered", "ordinary"),),
        marker=marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _marker_norm(marker),
        (observation,),
        method_id="render",
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.negative_scope == ()
    assert verdict.deficits[0].kind == "incomplete_negative_scope"
    assert verdict.deterministic is True
    assert verdict.grounded is False


def test_incomplete_negative_channel_maps_to_unscoreable() -> None:
    observation = _observation(output=ResponseData(fields=(("id", "safe"),)))

    verdict = field_exposure.Oracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario("attacker"),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == [
        "incomplete_negative_scope"
    ]


def test_marker_absence_without_complete_negative_scope_is_unscoreable() -> None:
    marker = "dast-absent-witness"
    observation = _observation(
        output=ResponseData(fields=(("response.rendered", "ordinary"),)),
        marker=marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle().evaluate_policy(
        _marker_norm(marker),
        (observation,),
        method_id="render",
        probe_fields=("template",),
        sink_types={"template": "interpreter"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == [
        "incomplete_negative_scope"
    ]


def test_field_exposure_principal_mismatch_is_unscoreable() -> None:
    observation = _observation(response_tree=(("private_key", "PEM"),))

    verdict = field_exposure.Oracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario("victim"),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == ["principal_scope"]
    assert verdict.deficits[0].context == (
        ("principal", "attacker"),
        ("field", "private_key"),
    )


def test_unknown_composition_does_not_become_pass() -> None:
    observation = Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )

    verdict = sequence.Oracle().evaluate_policy(
        _invariant(completed(Atom(value="flow:forbidden"))),
        (observation,),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == ["partial_sequence"]


def test_ungrounded_expectation_does_not_become_pass(
    method_spec,
    scenario_position,
    denied_observation,
) -> None:
    scenario = scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={"permissions_known": False}
            )
        }
    )
    invariant = _invariant(
        allowed(Atom(value=f"action:{method_spec.method_id}")),
    )

    verdict = grounded.Oracle().evaluate_outcome(
        invariant,
        denied_observation,
        method_spec,
        scenario,
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert [deficit.kind for deficit in verdict.deficits] == ["ungrounded_expectation"]


def test_candidate_sink_role_comes_from_witness_policy() -> None:
    marker = "dast-dom-candidate"
    policy = WitnessRolePolicy(
        sink_roles={"browser_dom": "candidate"},
    )
    observation = _observation(
        response_tree=(("response.rendered", marker),),
        marker=marker,
    )

    verdict = cloud_dast.verification.oracles.marker.Oracle(
        witness_policy=policy
    ).evaluate_policy(
        _marker_norm(marker),
        (observation,),
        method_id="render",
        probe_fields=("html",),
        sink_types={"html": "browser_dom"},
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert [deficit.kind for deficit in verdict.deficits] == ["candidate_witness"]


def test_pass_without_negative_scope_is_rejected() -> None:
    with pytest.raises(ValidationError, match="complete negative witness scope"):
        PolicyVerdict(
            status=VerdictStatus.PASS,
            confidence=1.0,
            rationale="invalid pass",
            model_id="contract",
            deterministic=True,
            grounded=True,
        )
