"""Pure scenario capability and resource matching rules."""

from cloud_dast.verification.scenarios.capability import (
    capability_closure,
    has_capabilities,
    missing_capabilities,
)
from cloud_dast.verification.scenarios.matching import scenario_resource_matches

__all__ = [
    "capability_closure",
    "has_capabilities",
    "missing_capabilities",
    "scenario_resource_matches",
]
