"""Validate and identify typed scenario bindings for candidate generation."""

from __future__ import annotations

import json

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import MethodSpec, ScenarioPosition
from cloud_dast.verification.invariant_projection import InvariantProjection


def scenario_scope(scenario: ScenarioPosition) -> str:
    """Identify a typed scenario scope independently of action and state."""

    containers = sorted(
        {
            (
                binding.folder_id or "",
                binding.cloud_id or "",
                binding.organization_id or "",
            )
            for binding in scenario.stand.bindings
            if binding.folder_id or binding.cloud_id or binding.organization_id
        }
    )
    resources = (
        []
        if containers
        else sorted(
            {
                (resource.service, resource.resource_type, resource.resource_id)
                for resource in scenario.stand.resources
            }
        )
    )
    return json.dumps(
        {
            "profile": scenario.profile.model_dump(
                mode="json", exclude={"resource_state"}
            ),
            "containers": containers,
            "resources": resources,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def scenario_layer_matches(scenario: ScenarioPosition, method: MethodSpec) -> bool:
    """Return whether a scenario can execute the method's endpoint layer."""

    return scenario.profile.endpoint_layer == method.layer


def require_scenario_layer(scenario: ScenarioPosition, method: MethodSpec) -> None:
    """Reject a binding whose scenario and method endpoint layers differ."""

    if not scenario_layer_matches(scenario, method):
        raise ValueError(
            f"scenario {scenario.scenario_id} layer "
            f"{scenario.profile.endpoint_layer} "
            f"does not match method {method.method_id} layer {method.layer}"
        )


def validate_binding(
    plan: VerificationPlan,
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
) -> None:
    """Validate that one generated check uses one consistent QDL binding."""

    if plan.invariant_id != invariant.invariant_id:
        raise ValueError("verification plan does not belong to invariant")
    if plan.method_id != method.method_id:
        raise ValueError("verification plan does not belong to method")
    if plan.scenario_id is None or plan.scenario_id != scenario.scenario_id:
        raise ValueError("verification plan does not belong to scenario")
    require_scenario_layer(scenario, method)


__all__ = [
    "scenario_scope",
    "require_scenario_layer",
    "scenario_layer_matches",
    "validate_binding",
]
