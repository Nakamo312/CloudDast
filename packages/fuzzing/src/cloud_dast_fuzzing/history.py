"""Bounded saturation history for adaptive payload-corpus consultation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.extensions import SaturatedHistory as SaturatedHistoryContract
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
)
from cloud_dast.verification.witness import WitnessSignal, extract_witness_signals


@dataclass(frozen=True, slots=True)
class SaturatedCandidate:
    """One already-tried candidate and its deterministic outcome."""

    signature: str
    method_id: str
    scenario_id: str
    generator: str
    request: tuple[tuple[str, JsonValue], ...]
    identities: tuple[str, ...]
    verdict: VerdictStatus | None
    grounded: bool | None
    proximity: float | None


@dataclass(frozen=True, slots=True)
class SaturatedDiffPair:
    """A shape-only comparison of two adjacent executed candidates."""

    control_signature: str
    treatment_signature: str
    request_changed_fields: tuple[str, ...]
    changed_response_paths: tuple[str, ...]
    duration_delta_ms: float | None
    response_digest_changed: bool


@dataclass(frozen=True, slots=True)
class SaturatedHistory(SaturatedHistoryContract):
    """The bounded model-facing evidence supplied after entropy saturation."""

    action_id: str
    invariant_id: str
    scenario_id: str
    sink_types: tuple[tuple[str, str], ...]
    dialects: tuple[tuple[str, str], ...]
    schema: tuple[FieldSpec, ...]
    candidates: tuple[SaturatedCandidate, ...]
    witness_signals: tuple[WitnessSignal, ...]
    diff_pairs: tuple[SaturatedDiffPair, ...]
    source_graph: QdlGraph

    @property
    def digest(self) -> str:
        payload = json.dumps(
            self.to_model_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_model_dict(self) -> dict[str, Any]:
        return {
            "kind": "saturated_payload_history",
            "action_id": self.action_id,
            "invariant_id": self.invariant_id,
            "scenario_id": self.scenario_id,
            "sink_types": [
                {"field": field, "sink_type": sink_type}
                for field, sink_type in self.sink_types
            ],
            "dialects": [
                {"field": field, "dialect": dialect} for field, dialect in self.dialects
            ],
            "schema": [field.model_dump(mode="json") for field in self.schema],
            "candidates": [
                {
                    "signature": candidate.signature,
                    "method_id": candidate.method_id,
                    "scenario_id": candidate.scenario_id,
                    "generator": candidate.generator,
                    "request": [
                        {"name": name, "value": value}
                        for name, value in candidate.request
                    ],
                    "identities": list(candidate.identities),
                    "verdict": (
                        candidate.verdict.value
                        if candidate.verdict is not None
                        else None
                    ),
                    "grounded": candidate.grounded,
                    "proximity": candidate.proximity,
                }
                for candidate in self.candidates
            ],
            "witness_signals": [asdict(signal) for signal in self.witness_signals],
            "diff_pairs": [asdict(pair) for pair in self.diff_pairs],
        }


def build_seed_enrichment_slice(
    plan: VerificationPlan,
    method: MethodSpec,
) -> QdlGraph:
    """Project the already-grounded schema and sink facts into a QDL slice."""

    action_id = method.method_id
    if not action_id.startswith("action:"):
        action_id = f"action:{action_id}"
    action = Atom(value=action_id)
    facts: list[Fact] = [
        _fact("is", (action, Atom(value="Action"))),
    ]
    field_terms = {
        field.name: Struct(
            name="input_field",
            args=(action, Atom(value=field.name)),
        )
        for field in method.request_schema.fields
    }
    for term in field_terms.values():
        facts.append(_fact("is", (term, Atom(value="InputField"))))
    for field_name, sink_type in plan.sink_types:
        term = field_terms.get(field_name)
        if term is None:
            continue
        sink = Atom(value=f"sink:{sink_type}")
        facts.append(_fact("is", (sink, Atom(value=sink_type))))
        facts.append(_fact("reaches", (term, sink)))
    for field_name, dialect in plan.grammar_dialects:
        sink_type = dict(plan.sink_types).get(field_name)
        term = field_terms.get(field_name)
        if term is None or sink_type is None:
            continue
        facts.append(
            _fact(
                "dialect",
                (Atom(value=f"sink:{sink_type}"), Atom(value=dialect)),
            )
        )
    for field_name, format_name in plan.grammar_formats:
        term = field_terms.get(field_name)
        if term is not None:
            facts.append(_fact("format", (term, Atom(value=format_name))))
    return QdlGraph(facts=tuple(facts))


def build_saturated_history(
    *,
    plan: VerificationPlan,
    method: MethodSpec,
    invariant: InvariantProjection,
    scenario: ScenarioPosition,
    candidates: tuple[Check, ...],
    feedback: ExecutionFeedback,
) -> SaturatedHistory:
    """Assemble the bounded history used by the entropy consultation."""

    feedback_by_check = {
        entry.check.check_id: entry for entry in reversed(feedback.entries)
    }
    saturated_candidates = tuple(
        SaturatedCandidate(
            signature=candidate_signature(candidate, scenario),
            method_id=candidate.method_id,
            scenario_id=candidate.scenario_id,
            generator=candidate.generator,
            request=candidate.request,
            identities=candidate.identities,
            verdict=(
                feedback_by_check[candidate.check_id].verdict
                if candidate.check_id in feedback_by_check
                else None
            ),
            grounded=(
                feedback_by_check[candidate.check_id].grounded
                if candidate.check_id in feedback_by_check
                else None
            ),
            proximity=(
                feedback_by_check[candidate.check_id].proximity
                if candidate.check_id in feedback_by_check
                else None
            ),
        )
        for candidate in candidates
    )
    observations = tuple(entry.observation for entry in feedback.entries)
    signals = extract_witness_signals(
        observations,
        method_id=method.method_id,
        probe_fields=plan.probe_fields,
        sink_types=dict(plan.sink_types),
    )
    signatures = {
        check.check_id: candidate_signature(check, scenario)
        for check in (
            *(entry.check for entry in feedback.entries),
            *candidates,
        )
    }
    diff_pairs = tuple(
        SaturatedDiffPair(
            control_signature=signatures.get(
                control.check.check_id,
                candidate_signature(control.check, scenario),
            ),
            treatment_signature=signatures.get(
                treatment.check.check_id,
                candidate_signature(treatment.check, scenario),
            ),
            request_changed_fields=_request_changed_fields(
                control.check.request,
                treatment.check.request,
            ),
            changed_response_paths=_changed_response_paths(
                control.observation,
                treatment.observation,
            ),
            duration_delta_ms=(
                treatment.observation.duration_ms - control.observation.duration_ms
                if control.observation.duration_ms is not None
                and treatment.observation.duration_ms is not None
                else None
            ),
            response_digest_changed=(
                _response_digest(control.observation)
                != _response_digest(treatment.observation)
            ),
        )
        for control, treatment in zip(feedback.entries, feedback.entries[1:])
    )
    return SaturatedHistory(
        action_id=method.method_id,
        invariant_id=invariant.invariant_id,
        scenario_id=scenario.scenario_id,
        sink_types=tuple(dict.fromkeys(plan.sink_types)),
        dialects=tuple(dict.fromkeys(plan.grammar_dialects)),
        schema=method.request_schema.fields,
        candidates=saturated_candidates,
        witness_signals=signals,
        diff_pairs=diff_pairs,
        source_graph=build_seed_enrichment_slice(plan, method),
    )


def candidate_signature(check: Check, scenario: ScenarioPosition) -> str:
    """Return a stable fingerprint of a candidate and scenario identity state."""

    payload = {
        "method_id": check.method_id,
        "scenario_id": check.scenario_id,
        "request": [list(item) for item in check.request],
        "identities": list(check.identities),
        "probe_marker": check.probe_marker,
        "principals": [
            item.model_dump(mode="json") for item in scenario.stand.principals
        ],
        "bindings": [item.model_dump(mode="json") for item in scenario.stand.bindings],
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fact(
    predicate: str,
    args: tuple[Atom | Struct, ...],
) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def _request_changed_fields(
    control: tuple[tuple[str, JsonValue], ...],
    treatment: tuple[tuple[str, JsonValue], ...],
) -> tuple[str, ...]:
    control_values = dict(control)
    treatment_values = dict(treatment)
    return tuple(
        sorted(
            {
                *control_values,
                *treatment_values,
            }
            - {
                name
                for name in {*control_values, *treatment_values}
                if control_values.get(name) == treatment_values.get(name)
            }
        )
    )


def _changed_response_paths(
    control: object,
    treatment: object,
) -> tuple[str, ...]:
    control_values = _response_values(control)
    treatment_values = _response_values(treatment)
    return tuple(
        sorted(
            path
            for path in {*control_values, *treatment_values}
            if control_values.get(path) != treatment_values.get(path)
        )
    )


def _response_values(observation: object) -> dict[str, JsonValue]:
    response_tree = getattr(observation, "response_tree", ())
    output = getattr(observation, "output", None)
    values = dict(response_tree or ())
    if output is not None:
        values.update(dict(output.fields))
    return values


def _response_digest(observation: object) -> str | None:
    digest = getattr(observation, "response_digest", None)
    if digest is not None:
        return digest
    values = getattr(observation, "response_tree", ())
    if not values and getattr(observation, "output", None) is not None:
        values = getattr(observation, "output", None).fields
    if not values:
        return None
    canonical = json.dumps(
        [list(item) for item in sorted(values, key=lambda item: item[0])],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "SaturatedCandidate",
    "SaturatedDiffPair",
    "SaturatedHistory",
    "build_saturated_history",
    "build_seed_enrichment_slice",
    "candidate_signature",
]
