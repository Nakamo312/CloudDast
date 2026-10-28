"""Pure evidence lookup and identity projections for reactive consultations."""

from __future__ import annotations

from cloud_dast.model import Check, Observation
from cloud_dast.runtime.consultation.outcomes import (
    AttemptKey,
    AttemptObservation,
    error_kind,
)
from cloud_dast.runtime.deficits import Deficit
from cloud_dast.runtime.deficits.work_items import WorkItem, WorkItemGrounding
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.observation_matching import action_matches
from cloud_dast.verification.oracles.latency import LatencyOracle

EVIDENCE_REQUIRED_AXES: frozenset[str] = frozenset({"response_semantics", "variance"})


def key(
    service: str,
    work_item: WorkItem,
    observation: Observation | None = None,
) -> AttemptKey:
    """Return the evidence-signed identity of one consultation."""

    evidence_signature = set(work_item.evidence_signature)
    if observation is not None:
        evidence_signature.add(f"observation_id={observation.observation_id}")
    return AttemptKey(
        scope=service,
        work_item_id=work_item.work_item_id,
        evidence_signature=tuple(sorted(evidence_signature)),
    )


def observation(
    work_item: WorkItem,
    outcome: WorkItemGrounding,
    *,
    conflict: bool = False,
    evidence_available: bool | None = None,
) -> AttemptObservation:
    """Project one grounding call into the absorbing outcome alphabet."""

    return AttemptObservation(
        conflict=conflict,
        error_kind=error_kind(outcome.error),
        evidence_available=(
            evidence_available
            if evidence_available is not None
            else outcome.observation is not None
            or work_item.axis not in EVIDENCE_REQUIRED_AXES
        ),
        evidence_required=work_item.axis in EVIDENCE_REQUIRED_AXES,
        promoted=outcome.promoted,
    )


def observation_for_work_item(
    work_item: WorkItem,
    accumulator: CampaignAccumulator,
) -> Observation | None:
    """Return the freshest relevant live observation for one work item."""

    candidates: list[Observation] = []
    for deficit in work_item.deficits:
        observation = observation_for_deficit(deficit, accumulator)
        if observation is not None:
            candidates.append(observation)
    requires_pair = any(
        bool(dict(deficit.context).get("control"))
        and bool(dict(deficit.context).get("treatment"))
        for deficit in work_item.deficits
    )
    required_fields = frozenset(
        field_name
        for deficit in work_item.deficits
        for field_value in (
            dict(deficit.context).get("fields"),
            dict(deficit.context).get("field"),
        )
        if field_value
        for field_name in str(field_value).split(",")
        if field_name
    )
    if not requires_pair:
        candidates.extend(
            observation
            for observation in accumulator.observations
            if action_matches(observation, work_item.action)
            and (
                not required_fields
                or any(
                    path in required_fields
                    for path, _value in observation.response_tree or ()
                )
            )
        )
    if not candidates:
        return None
    positions = {
        observation.observation_id: index
        for index, observation in enumerate(accumulator.observations)
    }
    return max(
        candidates,
        key=lambda observation: (
            positions.get(observation.observation_id, -1),
            observation.observation_id,
        ),
    )


def update_latency_baseline(
    deficit: Deficit,
    accumulator: CampaignAccumulator,
    latency_oracle: LatencyOracle | None,
) -> bool:
    """Create a latency baseline from observations already collected."""

    if latency_oracle is None:
        return False
    if latency_oracle.has_baseline(deficit.action):
        return True
    observations = tuple(
        observation
        for observation in accumulator.observations
        if action_matches(observation, deficit.action)
    )
    return latency_oracle.update_baseline_from_observations(
        deficit.action,
        observations,
    )


def check_for_observation(
    observation: Observation | None,
    accumulator: CampaignAccumulator,
) -> Check | None:
    """Return the check that produced one reactive observation."""

    if observation is None:
        return None
    return next(
        (
            check
            for check in accumulator.checks
            if check.check_id == observation.check_id
        ),
        None,
    )


def observation_for_deficit(
    deficit: Deficit,
    accumulator: CampaignAccumulator,
) -> Observation | None:
    """Return the exact or most relevant observation referenced by a deficit."""

    context = dict(deficit.context)
    observation_id = context.get("observation_id")
    if observation_id is not None:
        return next(
            (
                observation
                for observation in accumulator.observations
                if observation.observation_id == observation_id
            ),
            None,
        )
    if deficit.axis == "variance":
        control_id = context.get("control")
        treatment_id = context.get("treatment")
        if control_id is None or treatment_id is None:
            return None
        observations_by_id = {
            observation.observation_id: observation
            for observation in accumulator.observations
        }
        control = observations_by_id.get(control_id)
        treatment = observations_by_id.get(treatment_id)
        if control is None or treatment is None:
            return None
        return treatment
    return last_path_observation(deficit, accumulator)


def last_path_observation(
    deficit: Deficit,
    accumulator: CampaignAccumulator,
) -> Observation | None:
    """Return the most recent observation of a deficit's blocked path."""

    path_id = dict(deficit.context).get("path_id")
    if path_id is None:
        return None
    for observation in reversed(accumulator.observations):
        if any(
            key[0] == observation.observation_id and provenance.path_id == path_id
            for key, provenance in accumulator.provenance.items()
        ):
            return observation
    return None


__all__ = [
    "EVIDENCE_REQUIRED_AXES",
    "check_for_observation",
    "key",
    "observation",
    "last_path_observation",
    "observation_for_deficit",
    "observation_for_work_item",
    "update_latency_baseline",
]
