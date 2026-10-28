"""Pure work-item dispatch policy for the reactive deficit queue."""

from __future__ import annotations

from collections.abc import Sequence

from cloud_dast.runtime.consultation.axes import DETERMINISTIC_AXES
from cloud_dast.runtime.deficits.model import PredicateClass
from cloud_dast.runtime.deficits.queue_state import DispatchState, WorkGroup
from cloud_dast.runtime.prioritization import ColdScore, InterestPrioritizer

__all__ = [
    "deterministic_slots",
    "interest_score",
    "priority",
    "select_next_group",
    "select_wave_groups",
]


def deterministic_slots(limit: int | None, dispatched: int) -> bool:
    """Return whether one more deterministic repair fits this drain."""

    return limit is None or dispatched < limit


def interest_score(
    group: WorkGroup,
    prioritizer: InterestPrioritizer,
) -> ColdScore:
    """Return the deterministic information-gain score for one work group."""

    entry = group.representative
    attempts = entry.successes + entry.failures
    return prioritizer.score(
        # Score by the representative consultation id so single-deficit
        # work items keep the exact pre-S30 advisory ordering; fan-out still
        # drives the deterministic priority.
        entry.deficit.consultation_id,
        coverage_gain=group.fan_out,
        bandit_prior=(entry.successes + 1) / (attempts + 2),
        reward_state=(entry.successes / attempts if attempts else 0.0),
        quarantined_features=entry.quarantined_features,
    )


def priority(
    group: WorkGroup,
    prioritizer: InterestPrioritizer,
) -> tuple[float, int, int, str]:
    """Return the stable ordering key used inside a fair class allocation."""

    cold_score = interest_score(group, prioritizer)
    return (
        -cold_score.interest,
        -group.fan_out,
        group.order,
        group.work_item_id,
    )


def select_wave_groups(
    groups: Sequence[WorkGroup],
    *,
    pending_groups: Sequence[WorkGroup],
    state: DispatchState,
    max_tasks: int | None,
    deterministic_dispatch_limit: int | None,
    prioritizer: InterestPrioritizer,
) -> tuple[WorkGroup, ...]:
    """Select one fair, information-maximizing independent wave."""

    ordered = sorted(groups, key=lambda group: priority(group, prioritizer))
    selected: list[WorkGroup] = []
    for group in ordered:
        if group.axis in DETERMINISTIC_AXES and deterministic_slots(
            deterministic_dispatch_limit,
            state.deterministic_dispatched,
        ):
            selected.append(group)
            state.apply(group)

    remaining = None if max_tasks is None else max_tasks - state.dispatched
    model_groups = [group for group in ordered if group.requires_model]
    pending_classes = {
        group.predicate_class for group in pending_groups if group.requires_model
    }
    one_class_each = len(pending_classes) > 1
    class_count = max(1, len(pending_classes))
    capacity = class_count if one_class_each and remaining is None else remaining
    if one_class_each and remaining is not None:
        capacity = min(remaining, class_count)
    selected.extend(
        _fair_model_order(
            model_groups,
            state,
            capacity,
            prioritizer=prioritizer,
            one_class_each=one_class_each,
        )
    )
    return tuple(selected)


def select_next_group(
    groups: Sequence[WorkGroup],
    *,
    state: DispatchState,
    max_tasks: int | None,
    deterministic_dispatch_limit: int | None,
    prioritizer: InterestPrioritizer,
) -> WorkGroup | None:
    """Select exactly one group under the same fair-share policy."""

    ordered = sorted(groups, key=lambda group: priority(group, prioritizer))
    deterministic = [
        group
        for group in ordered
        if group.axis in DETERMINISTIC_AXES
        and deterministic_slots(
            deterministic_dispatch_limit,
            state.deterministic_dispatched,
        )
    ]
    if deterministic:
        return deterministic[0]

    remaining = None if max_tasks is None else max_tasks - state.dispatched
    selected = _fair_model_order(
        [group for group in ordered if group.requires_model],
        state,
        remaining,
        prioritizer=prioritizer,
    )
    return selected[0] if selected else None


def _fair_model_order(
    groups: Sequence[WorkGroup],
    state: DispatchState,
    slots: int | None,
    *,
    prioritizer: InterestPrioritizer,
    one_class_each: bool = False,
) -> list[WorkGroup]:
    """Fill the least-served classes, maximizing gain among ties."""

    if slots is not None and slots <= 0:
        return []
    pending: dict[PredicateClass, list[WorkGroup]] = {}
    for group in sorted(groups, key=lambda item: priority(item, prioritizer)):
        pending.setdefault(group.predicate_class, []).append(group)
    selected: list[WorkGroup] = []
    selected_counts: dict[PredicateClass, int] = {}

    while pending and (slots is None or len(selected) < slots):
        service = {
            deficit_class: state.class_dispatches.get(deficit_class, 0)
            + selected_counts.get(deficit_class, 0)
            for deficit_class in pending
        }
        minimum = min(service.values())
        tied_classes = [
            deficit_class
            for deficit_class, level in service.items()
            if level == minimum
        ]
        deficit_class = min(
            tied_classes,
            key=lambda item: (priority(pending[item][0], prioritizer), item),
        )
        group = pending[deficit_class].pop(0)
        if one_class_each or not pending[deficit_class]:
            del pending[deficit_class]
        selected.append(group)
        selected_counts[deficit_class] = selected_counts.get(deficit_class, 0) + 1
    return selected
