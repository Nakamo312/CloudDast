"""Shared runtime limits and workflow execution."""

from __future__ import annotations

from cloud_dast.binding import (
    require_scenario_layer,
    scenario_layer_matches,
)

__all__ = [
    "check_budget_exhausted",
    "require_scenario_layer",
    "scenario_layer_matches",
]


def check_budget_exhausted(observation_count: int, max_checks: int | None) -> bool:
    """Return whether a campaign reached its explicit check budget."""

    return max_checks is not None and observation_count >= max_checks
