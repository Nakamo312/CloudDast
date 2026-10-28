"""Pure matching rules for scenario capabilities."""

from __future__ import annotations

from cloud_dast.model import MethodSpec, ScenarioPosition


def scenario_resource_matches(
    scenario: ScenarioPosition,
    method: MethodSpec,
) -> bool:
    """Return whether the stand contains the method's target resource type."""

    if not method.resource_types:
        return True
    return any(
        resource.resource_type in method.resource_types
        for resource in scenario.stand.resources
    )


__all__ = ["scenario_resource_matches"]
