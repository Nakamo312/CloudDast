"""Bounded, model-facing projection of already captured runtime evidence.

``View`` is deliberately not a new world model: it is a lossy,
content-addressed view over the existing ``Check``, ``Observation``,
``DiffReport``, execution trace, and OOB-event objects.  The model receives
it as structured JSON in ``ModelRequest.context``; it never becomes the
source of truth.  Recorded verdicts may be attached as execution-feedback
metadata, but security decisions remain deterministic oracles.

Model contexts retain captured values within the byte, leaf and string budgets.
This projection does not decide which facts or security verdicts are accepted.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.model import (
    Check,
    Observation,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.ports import EvidenceEvent
from cloud_dast.verification.differential.report import DiffReport

_RESERVED_BUDGET_BYTES = 1024


@dataclass(frozen=True, slots=True)
class Budget:
    """Bounds for model-facing evidence, including a minimum 1 KiB envelope."""

    max_leaves: int = 1024
    max_string_chars: int = 1024
    max_total_bytes: int = 128 * 1024

    def __post_init__(self) -> None:
        if self.max_leaves <= 0:
            raise ValueError("max_leaves must be positive")
        if self.max_string_chars <= 0:
            raise ValueError("max_string_chars must be positive")
        if self.max_total_bytes <= 0:
            raise ValueError("max_total_bytes must be positive")
        if self.max_total_bytes < _RESERVED_BUDGET_BYTES:
            raise ValueError("max_total_bytes must be at least 1024")


DEFAULT_EVIDENCE_BUDGET = Budget()
_TRUNCATED_PREVIEW_CHARS = 256
_BINARY_PREVIEW_CHARS = 128


@dataclass(frozen=True, slots=True)
class View:
    """One bounded JSON projection with original and rendered digests."""

    data: Mapping[str, Any]
    original_digest: str
    digest: str = field(init=False)
    truncated: bool = field(init=False)

    def __post_init__(self) -> None:
        data = _json_copy(self.data)
        _enforce_budget(data)
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "digest", _sha256(_canonical_json(data)))
        object.__setattr__(
            self, "truncated", bool(data.get("budget", {}).get("truncated", False))
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached, JSON-safe copy of the bounded evidence."""

        return _json_copy(self.data)

    model_dump = to_dict


def response_fields(evidence: View | None) -> set[str]:
    """Return every response-leaf path projected to the model."""

    if evidence is None:
        return set()
    paths: set[str] = set()
    _collect_response_paths(evidence.data, paths)
    return paths


def _collect_response_paths(value: object, paths: set[str]) -> None:
    if isinstance(value, Mapping):
        leaves = value.get("leaves")
        if isinstance(leaves, Sequence) and not isinstance(leaves, (str, bytes)):
            paths.update(
                leaf["path"]
                for leaf in leaves
                if isinstance(leaf, Mapping) and isinstance(leaf.get("path"), str)
            )
        for child in value.values():
            _collect_response_paths(child, paths)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            _collect_response_paths(child, paths)


def build_evidence_view(
    *,
    check: Check | None = None,
    observation: Observation | None = None,
    oob_events: Sequence[EvidenceEvent] = (),
    label: str = "observation",
    budget: Budget = DEFAULT_EVIDENCE_BUDGET,
) -> View:
    """Build one bounded observation view.

    Values remain available to local consumers and model contexts under the
    same technical budgets.
    """

    raw = _observation_context(
        label=label,
        check=check,
        observation=observation,
        oob_events=oob_events,
    )
    return _bounded_view(raw, budget)


def build_paired_evidence_view(
    *,
    control_check: Check | None = None,
    control: Observation,
    treatment_check: Check | None = None,
    treatment: Observation,
    report: DiffReport | None = None,
    oob_events: Sequence[EvidenceEvent] = (),
    budget: Budget = DEFAULT_EVIDENCE_BUDGET,
) -> View:
    """Build a control/treatment view with value-bearing path differences."""

    control_context = _observation_context(
        label="control",
        check=control_check,
        observation=control,
        oob_events=(),
    )
    treatment_context = _observation_context(
        label="treatment",
        check=treatment_check,
        observation=treatment,
        oob_events=(),
    )
    raw: dict[str, Any] = {
        "kind": "paired_observation",
        "control": control_context,
        "treatment": treatment_context,
        "oob": _oob_context(
            oob_events,
            (control_check, treatment_check),
            (control, treatment),
        ),
    }
    if report is not None:
        raw["diff"] = _diff_context(control, treatment, report)
    return _bounded_view(raw, budget)


def build_execution_feedback_view(
    feedback: ExecutionFeedback,
    *,
    budget: Budget = DEFAULT_EVIDENCE_BUDGET,
) -> View:
    """Build a bounded history of executed candidates and their outcomes.

    The view contains the request, full projected response, trace/resource
    state, deterministic verdict, grounding flag, and goal proximity.  It is
    model-facing guidance only: the model does not author or override the
    verdict.
    """

    raw: dict[str, Any] = {
        "kind": "execution_feedback",
        "attempt_count": len(feedback.entries),
        "attempts": [
            {
                "index": index,
                "verdict": entry.verdict.value,
                "grounded": entry.grounded,
                "proximity": entry.proximity,
                "evidence": _observation_context(
                    label=f"attempt-{index + 1}",
                    check=entry.check,
                    observation=entry.observation,
                    oob_events=(),
                ),
            }
            for index, entry in enumerate(feedback.entries)
        ],
    }
    return _bounded_view(raw, budget)


def _observation_context(
    *,
    label: str,
    check: Check | None,
    observation: Observation | None,
    oob_events: Sequence[EvidenceEvent],
) -> dict[str, Any]:
    context: dict[str, Any] = {"kind": "observation", "label": label}
    if check is not None:
        context["method_id"] = check.method_id
        context["request"] = {
            "check_id": check.check_id,
            "method_id": check.method_id,
            "scenario_id": check.scenario_id,
            "identities": list(check.identities),
            "values": [{"name": name, "value": value} for name, value in check.request],
        }
    if observation is not None:
        context.update(
            {
                "check_id": observation.check_id,
                "scenario_id": observation.scenario_id,
                "response_summary": observation.response_summary,
                "status": _status_token(observation),
                "outcome": observation.observed_outcome.value,
                "duration_ms": observation.duration_ms,
                "error_reason": observation.error_reason,
                "probe_marker": observation.probe_marker,
                "response": _response_context(observation),
                "trace": _trace_context(observation.trace),
            }
        )
    context["oob"] = _oob_context(oob_events, (check,), (observation,))
    return context


def _status_token(observation: Observation) -> str | None:
    status = observation.transport_status
    return status.token if status is not None else None


def _response_context(observation: Observation) -> dict[str, Any]:
    if observation.response_tree:
        leaves = [
            {"path": path, "value": value} for path, value in observation.response_tree
        ]
        return {
            "source": "response_tree",
            "digest": observation.response_digest
            or response_tree_digest(observation.response_tree),
            "leaf_count": len(leaves),
            "leaves": leaves,
            "safe_fields": _safe_output_fields(observation),
        }
    output = observation.output
    if output is None:
        return {"source": "none", "digest": None, "leaf_count": 0, "leaves": []}
    leaves = [{"path": name, "value": value} for name, value in output.fields]
    return {
        "source": "output_fields",
        "digest": response_tree_digest(output.fields),
        "leaf_count": len(leaves),
        "leaves": leaves,
        "shape_only_paths": list(output.field_names),
    }


def _safe_output_fields(observation: Observation) -> list[dict[str, Any]]:
    """Project only codec-allowlisted response fields with their values."""

    if observation.output is None:
        return []
    return [{"path": name, "value": value} for name, value in observation.output.fields]


def _trace_context(trace) -> list[dict[str, Any]]:
    if trace is None:
        return []
    return [
        {
            "observation_id": step.observation_id,
            "step_id": step.step_id,
            "method_id": step.method_id,
            "scenario_id": step.scenario_id,
            "status": step.status.value,
            "response": (
                {
                    "fields": [
                        {"name": name, "value": value}
                        for name, value in step.response.fields
                    ],
                    "shape_only_paths": list(step.response.field_names),
                }
                if step.response is not None
                else None
            ),
            "resource_before": [
                {"name": name, "value": value}
                for name, value in step.resource_state_before
            ],
            "resource_after": [
                {"name": name, "value": value}
                for name, value in step.resource_state_after
            ],
            "permissions_checked": list(step.permissions_checked),
            "gates_passed": list(step.gates_passed),
            "sinks_reached": list(step.sinks_reached),
        }
        for step in trace.steps
    ]


def _oob_context(
    events: Sequence[EvidenceEvent],
    checks: tuple[Check | None, ...],
    observations: tuple[Observation | None, ...],
) -> dict[str, Any]:
    markers = {
        *(check.probe_marker for check in checks if check is not None),
        *(
            observation.probe_marker
            for observation in observations
            if observation is not None
        ),
    }
    markers.discard(None)
    selected = [
        event
        for event in events
        if event.channel == "oob" and (not markers or event.correlation_id in markers)
    ]
    return {
        "markers": sorted(marker for marker in markers if marker is not None),
        "event_count": len(selected),
        "events": [
            {
                "correlation_id": event.correlation_id,
                "channel": event.channel,
                "event_type": event.event_type,
                "source": event.source,
                "observed_at": event.observed_at,
                "attributes": {name: value for name, value in event.attributes},
            }
            for event in selected
        ],
    }


def _diff_context(
    control: Observation,
    treatment: Observation,
    report: DiffReport,
) -> dict[str, Any]:
    control_values = _response_values(control)
    treatment_values = _response_values(treatment)
    return {
        "action_id": report.action_id,
        "control_observation_id": report.control_observation_id,
        "treatment_observation_id": report.treatment_observation_id,
        "dimensions": list(report.dimensions),
        "signature": report.signature,
        "fields_only_control": [
            {"path": path, "control_value": control_values.get(path)}
            for path in report.fields_only_control
        ],
        "fields_only_treatment": [
            {"path": path, "treatment_value": treatment_values.get(path)}
            for path in report.fields_only_treatment
        ],
        "value_differs": [
            {
                "path": path,
                "control_value": control_values.get(path),
                "treatment_value": treatment_values.get(path),
            }
            for path in report.value_differs
        ],
        "outcome_differs": report.outcome_differs,
        "status_differs": report.status_differs,
        "error_differs": report.error_differs,
        "latency_class_differs": report.latency_class_differs,
    }


def _response_values(observation: Observation) -> dict[str, Any]:
    if observation.response_tree:
        return dict(observation.response_tree)
    if observation.output is None:
        return {}
    return dict(observation.output.fields)


def _bounded_view(
    raw: Mapping[str, Any],
    budget: Budget,
) -> View:
    original_json = _canonical_json(raw)
    original_digest = _sha256(original_json)
    working = _json_copy(raw)
    dropped = _enforce_leaf_budget(working, budget.max_leaves)

    bounded = _bound_value(working, budget)
    if not isinstance(bounded, dict):  # pragma: no cover - defensive branch
        bounded = {"value": bounded}
    metadata = {
        "version": 1,
        "max_leaves": budget.max_leaves,
        "max_string_chars": budget.max_string_chars,
        "max_total_bytes": budget.max_total_bytes,
        "original_sha256": original_digest,
        "original_bytes": len(original_json.encode("utf-8")),
        "truncated": False,
        "dropped_leaves": dropped,
    }
    bounded["budget"] = metadata
    _enforce_total_budget(bounded, budget, initial_dropped=dropped)
    metadata["truncated"] = bool(metadata["truncated"] or dropped)
    return View(
        data=bounded,
        original_digest=original_digest,
    )


def _enforce_leaf_budget(value: Any, max_leaves: int) -> int:
    """Cap response leaves globally, without inventing replacement values."""

    paths = _response_leaf_paths(value)
    total = sum(len(_leaf_list(value, path)) for path in paths)
    if total <= max_leaves:
        return 0

    dropped = total - max_leaves
    # Prefer dropping later treatment leaves: control evidence is the baseline.
    # Execution feedback is the opposite: the latest attempt is the most useful
    # signal for choosing the next candidate, so drop older attempts first.
    drop_order = (
        paths
        if isinstance(value, dict) and value.get("kind") == "execution_feedback"
        else reversed(paths)
    )
    for path in drop_order:
        leaves = _leaf_list(value, path)
        while total > max_leaves and leaves:
            leaves.pop()
            total -= 1
        if total <= max_leaves:
            break
    for path in paths:
        response = _at_path(value, path)
        response["truncated"] = len(response["leaves"]) < response["leaf_count"]
        response["leaf_count"] = len(response["leaves"])
    return dropped


def _response_leaf_paths(value: Any) -> list[tuple[Any, ...]]:
    """Return indexes to every response leaf list in a raw view."""

    paths: list[tuple[Any, ...]] = []

    def visit(item: Any, path: tuple[Any, ...]) -> None:
        if not isinstance(item, dict):
            if isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
                for index, child in enumerate(item):
                    visit(child, (*path, index))
            return
        response = item.get("response")
        is_response = isinstance(response, dict) and isinstance(
            response.get("leaves"), list
        )
        if is_response:
            paths.append((*path, "response"))
        for key, child in item.items():
            if key == "response" and is_response:
                continue
            visit(child, (*path, key))

    visit(value, ())
    return paths


def _leaf_list(value: Any, path: tuple[Any, ...]) -> list[Any]:
    return _at_path(value, path)["leaves"]


def _at_path(value: Any, path: tuple[Any, ...]) -> Any:
    container: Any = value
    for key in path:
        container = container[key]
    return container


def _bound_value(value: Any, budget: Budget) -> Any:
    if isinstance(value, str):
        if _is_binary(value):
            return _encoded_value(
                value,
                budget,
                encoding="binary",
                preview=_binary_preview(value),
            )
        if len(value) > budget.max_string_chars:
            return _encoded_value(
                value,
                budget,
                encoding="truncated",
                preview=value[:_TRUNCATED_PREVIEW_CHARS],
            )
        return value
    if isinstance(value, Mapping):
        return {
            _bound_key(key, budget): _bound_value(item, budget)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_bound_value(item, budget) for item in value]
    return value


def _encoded_value(
    value: str,
    budget: Budget,
    *,
    encoding: str,
    preview: str,
) -> dict[str, Any]:
    return {
        "evidence_encoding": encoding,
        "sha256": _sha256(value),
        "length": len(value),
        "preview": _bound_value(preview[: budget.max_string_chars], budget),
    }


def _bound_key(key: str, budget: Budget) -> str:
    if len(key) <= budget.max_string_chars and not _is_binary(key):
        return key
    encoded = _encoded_value(
        key,
        budget,
        encoding="key",
        preview=key[:_TRUNCATED_PREVIEW_CHARS],
    )
    return _canonical_json(encoded)


def _binary_preview(value: str) -> str:
    return value[:_BINARY_PREVIEW_CHARS].encode("unicode_escape").decode("ascii")


def _is_binary(value: str) -> bool:
    return any(character < " " and character not in "\t\n\r" for character in value)


def _enforce_total_budget(
    value: dict[str, Any],
    budget: Budget,
    *,
    initial_dropped: int,
) -> None:
    metadata = value["budget"]
    metadata["truncated"] = False
    target = max(0, budget.max_total_bytes - _RESERVED_BUDGET_BYTES)
    dropped = initial_dropped

    while (
        len(_canonical_json(value).encode("utf-8")) > target
        or len(
            json.dumps(
                {
                    **value,
                    "budget": {
                        **metadata,
                        "truncated": dropped > 0,
                        "dropped_leaves": dropped,
                    },
                },
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
        > budget.max_total_bytes
    ):
        removed = _drop_one_droppable_leaf(value)
        if removed:
            dropped += 1
            continue

        # Defensive last resort: retain a hash and bounded preview only.  This
        # still proves which evidence was present without exceeding the cap.
        original = _canonical_json(value)
        value.clear()
        value.update(
            {
                "kind": "oversized_evidence",
                "sha256": _sha256(original),
                "preview": original[: max(0, target // 2)],
                "budget": metadata,
            }
        )
        metadata["truncated"] = True
        metadata["dropped_leaves"] = dropped
        if (
            len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            > budget.max_total_bytes
        ):
            preview = value["preview"]
            value["preview"] = ""
            if (
                len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
                > budget.max_total_bytes
            ):
                raise ValueError("evidence budget cannot fit its metadata")
            low, high = 0, len(preview)
            while low < high:
                middle = (low + high + 1) // 2
                value["preview"] = preview[:middle]
                if (
                    len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
                    <= budget.max_total_bytes
                ):
                    low = middle
                else:
                    high = middle - 1
            value["preview"] = preview[:low]
        return

    metadata["truncated"] = dropped > 0
    metadata["dropped_leaves"] = dropped


def _drop_one_droppable_leaf(value: Any) -> bool:
    """Drop one low-priority list item, preferring later response leaves."""

    if not isinstance(value, dict):
        if isinstance(value, list):
            return any(_drop_one_droppable_leaf(item) for item in value)
        return False
    for key in (
        "treatment",
        "control",
        "response",
        "trace",
        "oob",
        "request",
        "attempts",
        "evidence",
    ):
        if _drop_one_droppable_leaf(value.get(key)):
            return True
    for key in ("leaves", "resource_after", "resource_before", "values", "events"):
        items = value.get(key)
        if isinstance(items, list) and items:
            items.pop()
            return True
    return False


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(_canonical_json(value))


def _enforce_budget(value: dict[str, Any]) -> None:
    """Validate declared metadata and normalize an oversized manual view once."""

    if "budget" not in value:
        return
    metadata = value["budget"]
    try:
        if not isinstance(metadata, dict):
            raise TypeError
        budget = Budget(
            max_leaves=int(metadata["max_leaves"]),
            max_string_chars=int(metadata["max_string_chars"]),
            max_total_bytes=int(metadata["max_total_bytes"]),
        )
        dropped = int(metadata["dropped_leaves"])
        if dropped < 0 or not isinstance(metadata.get("truncated", False), bool):
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("invalid evidence budget metadata") from None
    metadata.update(
        max_leaves=budget.max_leaves,
        max_string_chars=budget.max_string_chars,
        max_total_bytes=budget.max_total_bytes,
        dropped_leaves=dropped,
        truncated=metadata.get("truncated", False),
    )
    if (
        len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        > budget.max_total_bytes
    ):
        _enforce_total_budget(value, budget, initial_dropped=dropped)
