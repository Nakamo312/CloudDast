"""Public deficit algebra and reactive queue contracts."""

from importlib import import_module

_EXPORTS = {
    "Deficit": (".model", "Deficit"),
    "DeficitAxis": (".model", "DeficitAxis"),
    "DeficitKey": (".model", "DeficitKey"),
    "PredicateClass": (".model", "PredicateClass"),
    "CONSULTATION_DEFICIT_KIND": (".model", "CONSULTATION_DEFICIT_KIND"),
    "RESPONSE_SEMANTICS_AXIS": (".model", "RESPONSE_SEMANTICS_AXIS"),
    "CLASSIFICATION_DEFICIT_KIND": (".classification", "CLASSIFICATION_DEFICIT_KIND"),
    "EVIDENCE_DEFICIT_KIND": (".detection", "EVIDENCE_DEFICIT_KIND"),
    "LATENCY_BASELINE_PREFIX": (".detection", "LATENCY_BASELINE_PREFIX"),
    "DeficitQueue": (".queue", "DeficitQueue"),
    "QueueEntry": (".queue_state", "QueueEntry"),
    "WorkItemState": (".queue_state", "WorkItemState"),
    "WorkGroup": (".queue_state", "WorkGroup"),
    "DispatchState": (".queue_state", "DispatchState"),
    "DeficitCollectionCallbacks": (".collection", "DeficitCollectionCallbacks"),
    "DeficitCollector": (".collection", "DeficitCollector"),
    "grounding_result_closes_deficit": (".closure", "grounding_result_closes_deficit"),
    "WorkItem": (".work_items", "WorkItem"),
    "WorkItemGraph": (".work_items", "WorkItemGraph"),
    "WorkItemGrounding": (".work_items", "WorkItemGrounding"),
    "WorkItemMerge": (".work_items", "WorkItemMerge"),
    "WorkItemPropagation": (".work_items", "WorkItemPropagation"),
    "WorkItemResult": (".work_items", "WorkItemResult"),
    "WorkItemWavePropagation": (".work_items", "WorkItemWavePropagation"),
    "merge_work_item_results": (".work_items", "merge_work_item_results"),
    "single_deficit_work_item": (".work_items", "single_deficit_work_item"),
}

for _name in (
    "axis_for_subgoal",
    "build_deficit",
    "blocked_step_deficit",
    "classify_step_event",
    "consultation_context",
    "consultation_deficit",
    "consultation_request",
    "evidence_deficit",
    "missing_irreversibility_deficit",
    "missing_role_deficit",
    "response_semantics_deficits",
    "signal_deficits",
    "unprovable_subgoal",
    "variance_deficit",
    "witness_deficit",
    "witness_deficits",
):
    _EXPORTS[_name] = (
        ".routing"
        if _name
        in {
            "axis_for_subgoal",
            "build_deficit",
            "consultation_context",
            "consultation_deficit",
            "consultation_request",
            "unprovable_subgoal",
        }
        else ".detection",
        _name,
    )

for _name in (
    "gap_for_invariant",
    "gaps_for_observations",
):
    _EXPORTS[_name] = (".classification", _name)

for _name in ("coverage_gaps", "reference_deficits"):
    _module_name = "gaps" if _name == "coverage_gaps" else _name
    _EXPORTS[_name] = (".coverage", _module_name)

for _name in (
    "action_aliases",
    "declared_actions",
    "deficit_is_stale",
    "effect_action",
    "effect_field",
    "grounded_output_paths",
    "has_exposed_output",
    "interpreted_signal_kinds",
    "is_transport_sentinel",
    "observation_action",
):
    _EXPORTS[_name] = (".closure", _name)

__all__ = tuple(_EXPORTS)


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value
