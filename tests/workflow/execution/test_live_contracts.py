"""Validation of the differential pairing contract."""

from __future__ import annotations

import pytest

from cloud_dast.model import (
    EndpointLayer,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScopeRelation,
    StandState,
)
from cloud_dast.verification.differential import contracts


def _with_profile(
    scenario: ScenarioPosition,
    **updates: object,
) -> ScenarioPosition:
    return scenario.model_copy(
        update={"profile": scenario.profile.model_copy(update=updates)}
    )


@pytest.mark.parametrize(
    ("factor", "value"),
    [
        ("scope_relation", ScopeRelation.CROSS_CLOUD),
        ("binding_level", "cloud"),
        ("endpoint_layer", EndpointLayer.GATEWAY),
        ("resource_state", "deleted"),
        ("identity_class", "owner"),
        ("addressing_mode", "inherited"),
    ],
)
def test_differential_spec_accepts_exactly_one_differing_factor(
    scenario_position: ScenarioPosition,
    factor: str,
    value: object,
) -> None:
    treatment = _with_profile(scenario_position, **{factor: value})

    spec = contracts.Spec(scenario_position, treatment)

    assert spec.factor == factor
    assert spec.control is scenario_position
    assert spec.treatment is treatment


def test_differential_spec_allows_identity_factor_with_different_stand(
    scenario_position: ScenarioPosition,
) -> None:
    treatment = _with_profile(scenario_position, identity_class="owner").model_copy(
        update={
            "stand": StandState(
                principals=(
                    PrincipalRef(principal_id="victim", principal_type="user"),
                ),
                resources=(
                    ResourceRef(
                        service="lockbox",
                        resource_type="secret",
                        resource_id="secret-victim",
                    ),
                ),
            )
        }
    )

    spec = contracts.Spec(scenario_position, treatment)

    assert spec.factor == "identity_class"


def test_differential_spec_rejects_equivalent_profiles(
    scenario_position: ScenarioPosition,
) -> None:
    with pytest.raises(ValueError, match="exactly one profile factor"):
        contracts.Spec(scenario_position, scenario_position.model_copy())


def test_differential_spec_rejects_multiple_differing_factors(
    scenario_position: ScenarioPosition,
) -> None:
    treatment = _with_profile(
        scenario_position,
        identity_class="owner",
        scope_relation=ScopeRelation.CROSS_CLOUD,
    )

    with pytest.raises(ValueError, match="exactly one profile factor"):
        contracts.Spec(scenario_position, treatment)
