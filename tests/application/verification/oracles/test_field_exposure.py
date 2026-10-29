from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    JsonValue,
    Observation,
    PrincipalRef,
    ResponseData,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, field, has
from cloud_dast.verification.oracles import FieldExposureOracle


def _invariant(effect) -> InvariantProjection:
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
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    return Observation(
        check_id="check",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        output=output,
        response_tree=response_tree,
    )


def _scenario(principal_ids: tuple[str, ...]) -> ScenarioPosition:
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
            principals=tuple(
                PrincipalRef(principal_id=principal_id, principal_type="user")
                for principal_id in principal_ids
            )
        ),
    )


def _possession_norm() -> InvariantProjection:
    return _invariant(
        has(
            Atom(value="principal:attacker"),
            field(Atom(value="resource:secret"), Atom(value="private_key")),
        )
    )


def test_field_exposure_uses_full_tree_outside_safe_projection() -> None:
    observation = _observation(
        output=ResponseData(fields=(("id", "secret-1"),)),
        response_tree=(("metadata.private_key", "PEM"),),
    )

    verdict = FieldExposureOracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("attacker",)),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert "metadata.private_key" in verdict.rationale


def test_field_exposure_matches_nested_and_repeated_response_paths() -> None:
    observation = _observation(
        response_tree=(
            ("payload.public_key", "public"),
            ("deltas.0.private_key", "delta-secret"),
        )
    )

    verdict = FieldExposureOracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("attacker",)),
    )

    assert verdict.status is VerdictStatus.FAIL
    assert "deltas.0.private_key" in verdict.rationale


def test_field_exposure_matches_dotted_norm_field_by_path_suffix() -> None:
    effect = has(
        Atom(value="principal:attacker"),
        field(
            Atom(value="resource:secret"),
            Atom(value="payload.private_key"),
        ),
    )
    observation = _observation(response_tree=(("wrapper.payload.private_key", "PEM"),))

    verdict = FieldExposureOracle().evaluate_policy(
        _invariant(effect),
        (observation,),
        scenario=_scenario(("attacker",)),
    )

    assert verdict.status is VerdictStatus.FAIL


def test_field_exposure_passes_when_full_tree_has_no_forbidden_field() -> None:
    observation = _observation(
        output=ResponseData(fields=(("id", "secret-1"),)),
        response_tree=(("metadata.public_key", "public"),),
    )

    verdict = FieldExposureOracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("attacker",)),
    )

    assert verdict.status is VerdictStatus.PASS


def test_field_exposure_keeps_possession_principal_scope() -> None:
    observation = _observation(
        response_tree=(("private_key", "PEM"),),
    )
    oracle = FieldExposureOracle()

    scoped = oracle.evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("attacker",)),
    )
    other_principal = oracle.evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("victim",)),
    )

    assert scoped.status is VerdictStatus.FAIL
    assert other_principal.status is VerdictStatus.UNSCOREABLE
    assert other_principal.grounded is False
    assert "another principal" in other_principal.rationale
    assert [deficit.kind for deficit in other_principal.deficits] == ["principal_scope"]


@pytest.mark.parametrize(
    "incomplete_path",
    ["__truncated__", "not_available", "__response__.not_available"],
)
def test_field_exposure_rejects_incomplete_response(
    incomplete_path: str,
) -> None:
    observation = _observation(
        output=ResponseData(fields=(("id", "safe"),)),
        response_tree=((incomplete_path, True),),
    )

    verdict = FieldExposureOracle().evaluate_policy(
        _possession_norm(),
        (observation,),
        scenario=_scenario(("attacker",)),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert "incomplete response evidence" in verdict.rationale
