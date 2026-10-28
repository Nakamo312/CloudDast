"""Deterministic action alignment shared by primitive oracles."""

from __future__ import annotations

from cloud_dast.model.events import canonical_action_id

ACTION_MISMATCH_RATIONALE = "QDL norm action does not match the executed method"


def actions_align(norm_action_id: str | None, method_id: str | None) -> bool:
    """Return whether a norm action and an executed method refer to one action.

    Both identifiers are reduced to the canonical ``action:``-prefixed form
    before comparison, so alignment never depends on prefix guessing.  An
    actionless norm is aligned with any method because it is bound to an action
    elsewhere in the graph (for example, by an exposure or causal fact).
    """

    if norm_action_id is None or method_id is None:
        return True
    return canonical_action_id(norm_action_id) == canonical_action_id(method_id)


def action_alignment_rationale(
    norm_action_id: str | None,
    method_id: str | None,
) -> str | None:
    """Return the deterministic mismatch rationale, or ``None`` when aligned."""

    return (
        None if actions_align(norm_action_id, method_id) else ACTION_MISMATCH_RATIONALE
    )
