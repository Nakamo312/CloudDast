from __future__ import annotations

from cloud_dast.model import EndpointLayer
from cloud_dast_reporting import ReportService


def _class_key(scenario):
    profile = scenario.profile
    return (
        profile.scope_relation,
        profile.binding_level,
        profile.endpoint_layer,
        profile.resource_state,
        profile.identity_class,
        profile.addressing_mode,
    )


def test_group_by_equivalence_preserves_all_positions(
    scenario_position,
) -> None:
    equivalent_position = scenario_position.model_copy(
        update={"scenario_id": "cross-folder-private-copy"}
    )
    gateway_position = scenario_position.model_copy(
        update={
            "scenario_id": "cross-folder-gateway",
            "profile": scenario_position.profile.model_copy(
                update={"endpoint_layer": EndpointLayer.GATEWAY}
            ),
        }
    )

    grouped = ReportService().scenarios(
        (scenario_position, equivalent_position, gateway_position)
    )

    assert grouped == {
        _class_key(scenario_position): (
            scenario_position,
            equivalent_position,
        ),
        _class_key(gateway_position): (gateway_position,),
    }
