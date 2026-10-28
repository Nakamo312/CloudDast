from __future__ import annotations

from cloud_dast.model import (
    EndpointLayer,
    MethodSpec,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
)
from cloud_dast.verification.scenarios import scenario_resource_matches


def _scenario(*resource_types: str) -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=tuple(
                ResourceRef(
                    service="test",
                    resource_type=resource_type,
                    resource_id=f"{resource_type}-1",
                )
                for resource_type in resource_types
            ),
        ),
    )


def _method(*resource_types: str) -> MethodSpec:
    return MethodSpec(
        method_id="test.Service.Get",
        service="test",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        resource_types=frozenset(resource_types),
    )


def test_scenario_resource_matches_canonical_type_exactly() -> None:
    assert scenario_resource_matches(
        _scenario("lockbox.secret"),
        _method("lockbox.secret"),
    )


def test_scenario_resource_does_not_match_same_short_suffix() -> None:
    """Two resource types sharing a suffix must not collapse into one."""

    assert not scenario_resource_matches(
        _scenario("kms.secret"),
        _method("lockbox.secret"),
    )
    assert not scenario_resource_matches(
        _scenario("lockbox.secret"),
        _method("kms.secret"),
    )


def test_scenario_resource_without_method_types_matches_any_stand() -> None:
    assert scenario_resource_matches(_scenario("kms.secret"), _method())
