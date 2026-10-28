"""Deterministic projections of measured differential evidence."""

from __future__ import annotations

import hashlib

from cloud_dast.model import Check, Observation
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.projection import (
    _atom,
    _input_field,
    _runtime_fact,
    _unique_graph,
)
from cloud_dast.runtime.grounding.projection import (
    action_key as _action_key,
)
from cloud_dast.runtime.grounding.projection import (
    request_canary as _request_canary,
)
from cloud_dast.runtime.grounding.projection import (
    source_action_ids as _source_action_ids,
)
from cloud_dast.runtime.grounding.projection import (
    treatment_contains_canary as _treatment_contains_canary,
)
from cloud_dast.verification.differential.report import DiffReport


class MeasuredEvidencePolicy:
    """Project measured canary echoes without inventing sink witnesses.

    A control/treatment pair can deterministically prove that a request field
    reached a response or error channel. That observation is runtime evidence,
    not an executable security effect: this policy emits a runtime dataflow to
    a measured sink and never emits ``prevents`` or a sink classification.
    """

    def project(
        self,
        source: QdlGraph,
        action_id: str,
        *,
        control_check: Check | None,
        treatment_check: Check | None,
        treatment: Observation,
        report: DiffReport,
    ) -> QdlGraph:
        """Return runtime structural evidence for one measured echo."""

        if control_check is None or treatment_check is None:
            return QdlGraph()
        if control_check.scenario_id != treatment_check.scenario_id:
            # Factor pairs vary the caller or position; their request values
            # are not payload canaries and must remain an LLM semantic task.
            return QdlGraph()
        if control_check.method_id != treatment_check.method_id:
            return QdlGraph()
        action_value = (
            action_id if action_id.startswith("action:") else f"action:{action_id}"
        )
        if action_value not in _source_action_ids(source):
            return QdlGraph()
        if _action_key(control_check.method_id) != _action_key(action_id):
            return QdlGraph()

        control_request = dict(control_check.request)
        treatment_request = dict(treatment_check.request)
        facts: list = []
        for field_name, value in treatment_request.items():
            if control_request.get(field_name) == value:
                continue
            canary = _request_canary(value)
            if canary is None or not _treatment_contains_canary(
                treatment,
                report,
                canary,
            ):
                continue

            action = _atom(action_value)
            field_term = _input_field(action, field_name)
            sink_digest = hashlib.sha256(
                f"{action_value}|{field_name}|{canary}".encode("utf-8")
            ).hexdigest()[:12]
            sink = _atom(f"sink:canary-echo:{field_name}:{sink_digest}")
            facts.extend(
                (
                    _runtime_fact("is", (action, _atom("Action"))),
                    _runtime_fact("is", (field_term, _atom("Field"))),
                    _runtime_fact("is", (sink, _atom("measured"))),
                    _runtime_fact("reaches", (field_term, sink)),
                )
            )

        return _unique_graph(facts)


__all__ = ["MeasuredEvidencePolicy"]
