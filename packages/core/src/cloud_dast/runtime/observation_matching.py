"""Stable identity matching for observations produced by live checks."""

from __future__ import annotations

from cloud_dast.model import Observation


def action_matches(observation: Observation, action: str) -> bool:
    """Match an observation to either method-id or ``action:`` spelling."""

    steps = observation.trace.steps if observation.trace is not None else ()
    method_id = next(
        (
            step.method_id
            for step in reversed(steps)
            if step.observation_id == observation.observation_id
        ),
        steps[-1].method_id if steps else None,
    )
    return method_id is not None and action in {
        method_id,
        f"action:{method_id}",
    }
