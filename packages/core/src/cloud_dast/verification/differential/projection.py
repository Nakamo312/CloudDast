"""Project measured control/treatment differences into QDL runtime facts.

The projector is deliberately syntax-only: it records WHICH safe dimensions
diverged between the paired legs, never the values behind them.  Every diff
fact references the action, so it stays inside the action-centric LLM slice;
the treatment observation carries the evidence while the control leg is
linked through ``paired``.
"""

from __future__ import annotations

from cloud_dast.qdl.graph import (
    Atom,
    Fact,
    QdlGraph,
    differs,
)
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.evidence_facts import runtime_fact

__all__ = ["project_diff"]


def project_diff(report: DiffReport) -> QdlGraph:
    """Return the runtime QDL facts for one measured difference report."""

    action = _action_atom(report.action_id)
    control = _observation_atom(report.control_observation_id)
    treatment = _observation_atom(report.treatment_observation_id)

    facts: list[Fact] = [
        runtime_fact("is", (action, Atom(value="Action"))),
        runtime_fact("is", (control, Atom(value="Observation"))),
        runtime_fact("is", (treatment, Atom(value="Observation"))),
        runtime_fact("paired", (control, treatment)),
    ]
    facts.extend(
        runtime_fact(
            "evidence",
            (treatment, differs(action, Atom(value=dimension))),
        )
        for dimension in dict.fromkeys(report.dimensions)
    )
    return QdlGraph(facts=tuple(facts))


def _action_atom(action_id: str) -> Atom:
    """Return the declared action atom for either action-id spelling."""

    value = action_id if action_id.startswith("action:") else f"action:{action_id}"
    return Atom(value=value)


def _observation_atom(observation_id: str) -> Atom:
    """Return the declared observation atom for either id spelling."""

    value = (
        observation_id
        if observation_id.startswith("observation:")
        else f"observation:{observation_id}"
    )
    return Atom(value=value)
