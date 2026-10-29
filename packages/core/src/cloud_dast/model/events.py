from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model import (
    Check,
    Finding,
    JsonValue,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.checks import is_replayable_check
from cloud_dast.qdl.graph import Context, QdlGraph, Struct
from cloud_dast.qdl.graph import Fact as QdlFact
from cloud_dast.qdl.graph_ops import atom_value

_SEMANTIC_KEY_EXCLUDE = frozenset({"event_id", "occurred_at", "correlation_id"})


def normalize_action(value: object) -> str | None:
    """Return an action id without the optional ``action:`` namespace."""

    if not isinstance(value, str):
        return None
    return value.removeprefix("action:")


def canonical_action_id(value: str) -> str:
    """Return an action id in the canonical ``action:`` namespace."""

    return value if value.startswith("action:") else f"action:{value}"


def action_aliases(value: str) -> frozenset[str]:
    """Return both supported spellings of one non-empty action id."""

    if not value:
        return frozenset()
    normalized = normalize_action(value)
    assert normalized is not None
    return frozenset({value, normalized, canonical_action_id(normalized)})


def normalize_principal(value: object) -> str | None:
    """Return a principal id without its ``principal:`` namespace."""

    if not isinstance(value, str):
        return None
    if value.startswith(("principal:", "subject:")):
        return value.split(":", 1)[1]
    return value


@dataclass(frozen=True, slots=True)
class EventScope:
    """Campaign/run boundary used to replay only relevant events.

    ``campaign_id`` is stable across replays of one campaign; ``run_id``
    changes for each execution.  Legacy unscoped events are excluded by
    default; a migration may opt in explicitly with ``accept_legacy_unscoped``
    and still uses the baseline to exclude historical records.
    """

    campaign_id: str
    run_id: str
    baseline_event_ids: frozenset[str] = field(default_factory=frozenset)
    accept_legacy_unscoped: bool = False

    def apply(self, event: DomainEvent) -> DomainEvent:
        """Return a copy of ``event`` tagged with this scope."""

        return event.model_copy(
            update={"campaign_id": self.campaign_id, "run_id": self.run_id}
        )

    def contains_campaign(self, event: DomainEvent) -> bool:
        """Whether an event belongs to this campaign."""

        return (
            event.campaign_id == self.campaign_id and event.run_id is not None
        ) or self._is_current_unscoped(event)

    def contains_run(self, event: DomainEvent) -> bool:
        """Whether an event belongs to the current run."""

        return (
            event.run_id == self.run_id and event.campaign_id is not None
        ) or self._is_current_unscoped(event)

    def campaign_events(self, events: Iterable[DomainEvent]) -> tuple[DomainEvent, ...]:
        """Return only events belonging to this campaign."""

        return tuple(event for event in events if self.contains_campaign(event))

    def run_events(self, events: Iterable[DomainEvent]) -> tuple[DomainEvent, ...]:
        """Return only events belonging to the current run."""

        return tuple(event for event in events if self.contains_run(event))

    def _is_current_unscoped(self, event: DomainEvent) -> bool:
        return (
            self.accept_legacy_unscoped
            and event.campaign_id is None
            and event.run_id is None
            and event.event_id not in self.baseline_event_ids
        )


class DomainEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    campaign_id: str | None = None
    run_id: str | None = None
    # Durable execution links.  The legacy ``correlation_id`` remains the
    # compact join key; these explicit fields make the full action → path →
    # step → check → observation → oracle chain replayable without relying on
    # in-memory path definitions.
    action_id: str | None = None
    path_id: str | None = None
    step_id: str | None = None
    check_id: str | None = None
    observation_id: str | None = None
    oracle: str | None = None

    @property
    def semantic_key(self) -> str:
        """Return the full SHA-256 key of the event's replay semantics."""

        payload = self.model_dump(mode="json", exclude=_SEMANTIC_KEY_EXCLUDE)
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalAuditRecord(BaseModel):
    """Immutable operator decision over a parked classification."""

    model_config = ConfigDict(frozen=True)

    action: Literal["approved"] = "approved"
    service: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")
    fact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator: str = Field(pattern=r"^[A-Za-z0-9_.@:-]{1,128}$")
    reason: str = Field(min_length=1, max_length=2000)
    accepted_graph_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    promoted_facts: int = Field(ge=0)
    recorded_at: str = Field(min_length=20, max_length=64)


def measure_event_time_bounds(
    events: Iterable[DomainEvent],
) -> tuple[datetime, datetime] | None:
    """Return the earliest and latest timestamps in an event stream."""

    timestamps = [event.occurred_at for event in events]
    if not timestamps:
        return None
    return min(timestamps), max(timestamps)


class CheckCompleted(DomainEvent):
    event_type: Literal["check_completed"] = "check_completed"
    check: Check | None = None
    check_redacted: bool = False
    # Top-level method identity survives request redaction.
    method_id: str | None = Field(default=None, min_length=1)
    observation: Observation

    @model_validator(mode="after")
    def protect_request(self) -> CheckCompleted:
        if self.check_id is None:
            object.__setattr__(
                self, "check_id", self.check.check_id if self.check else None
            )
        if self.observation_id is None:
            object.__setattr__(self, "observation_id", self.observation.observation_id)
        if self.method_id is None and self.check is not None:
            object.__setattr__(self, "method_id", self.check.method_id)
        if self.check is not None and not is_replayable_check(self.check):
            object.__setattr__(self, "check", None)
            object.__setattr__(self, "check_redacted", True)
        return self


class CoverageUpdated(DomainEvent):
    event_type: Literal["coverage_updated"] = "coverage_updated"
    check_id: str
    method_id: str
    invariant_id: str
    scenario_id: str


class FindingRaised(DomainEvent):
    event_type: Literal["finding_raised"] = "finding_raised"
    finding: Finding


class InvestigationIntent(BaseModel):
    """One guarded, isolated investigation request carried by an event."""

    model_config = ConfigDict(frozen=True)

    intent_id: str = Field(default_factory=lambda: uuid4().hex)
    method_id: str
    payload: tuple[tuple[str, JsonValue], ...]
    identity: str
    reason: str

    @model_validator(mode="after")
    def validate_payload_names(self) -> InvestigationIntent:
        names = tuple(name for name, _ in self.payload)
        if len(names) != len(set(names)):
            raise ValueError("payload field names must be unique")
        return self


class InvestigationActionExecuted(DomainEvent):
    event_type: Literal["investigation_action_executed"] = (
        "investigation_action_executed"
    )
    intent: InvestigationIntent
    observation: Observation


class FactVerified(DomainEvent):
    event_type: Literal["fact_verified"] = "fact_verified"
    fact: QdlFact

    @model_validator(mode="after")
    def validate_runtime_fact(self) -> FactVerified:
        if self.fact.context is not Context.RUNTIME:
            raise ValueError("FactVerified fact must use the runtime context")
        if self.fact.predicate.name != "is":
            raise ValueError("FactVerified fact must declare a verified fact")
        if len(self.fact.args) != 2:
            raise ValueError("FactVerified fact must have two arguments")
        fact_id, fact_type = self.fact.args
        if atom_value(fact_id) is None or atom_value(fact_type) != "VerifiedFact":
            raise ValueError("FactVerified fact must declare a VerifiedFact")
        return self


class IntentProposed(DomainEvent):
    event_type: Literal["intent_proposed"] = "intent_proposed"
    intent: QdlGraph

    @model_validator(mode="after")
    def validate_proposal_graph(self) -> IntentProposed:
        if self.intent.rules:
            raise ValueError("IntentProposed graph must not contain rules")
        if not self.intent.facts:
            raise ValueError("IntentProposed graph must declare an intent")

        intent_ids: set[str] = set()
        fact_ids: set[str] = set()
        for fact in self.intent.facts:
            if fact.context is not Context.PROPOSAL:
                raise ValueError("IntentProposed graph must use the proposal context")
            if fact.predicate.name not in {
                "is",
                "intent_prerequisite",
                "intent_effect",
                "intent_assumption",
            }:
                raise ValueError("IntentProposed graph has an unknown predicate")

            if fact.predicate.name == "is":
                if len(fact.args) != 2:
                    raise ValueError(
                        "IntentProposed declaration must have two arguments"
                    )
                identifier, type_name = fact.args
                identifier_value = atom_value(identifier)
                type_value = atom_value(type_name)
                if identifier_value is None or type_value not in {"Intent", "Fact"}:
                    raise ValueError("IntentProposed graph has an invalid declaration")
                if type_value == "Intent":
                    intent_ids.add(identifier_value)
                else:
                    fact_ids.add(identifier_value)
                continue

            if len(fact.args) != 2:
                raise ValueError("IntentProposed edge must have two arguments")

        if not intent_ids:
            raise ValueError("IntentProposed graph must declare an Intent")
        if intent_ids & fact_ids:
            raise ValueError(
                "IntentProposed graph cannot declare an identifier as both "
                "Intent and Fact"
            )

        for fact in self.intent.facts:
            if fact.predicate.name == "is":
                continue
            subject, target = fact.args
            if (
                atom_value(subject) not in intent_ids
                or atom_value(target) not in fact_ids
            ):
                raise ValueError("IntentProposed edge is not closed")
        return self


class EvidenceRecorded(DomainEvent):
    event_type: Literal["evidence_recorded"] = "evidence_recorded"
    fact: QdlFact

    @model_validator(mode="after")
    def validate_runtime_evidence(self) -> EvidenceRecorded:
        if self.fact.context is not Context.RUNTIME:
            raise ValueError("EvidenceRecorded fact must use the runtime context")
        if self.fact.predicate.name != "evidence":
            raise ValueError("EvidenceRecorded fact must use the evidence predicate")
        if len(self.fact.args) != 2:
            raise ValueError("EvidenceRecorded fact must have two arguments")
        observation_id, provenance = self.fact.args
        if atom_value(observation_id) is None:
            raise ValueError("EvidenceRecorded fact must reference an observation")
        if (
            not isinstance(provenance, Struct)
            or provenance.name != "source"
            or len(provenance.args) != 2
            or atom_value(provenance.args[0]) is None
            or atom_value(provenance.args[1]) is None
        ):
            raise ValueError("EvidenceRecorded fact must carry source provenance")
        return self


class QdlStepEvaluated(DomainEvent):
    """One deterministic QDL execution step result."""

    event_type: Literal["qdl_step_evaluated"] = "qdl_step_evaluated"
    path_id: str
    step_id: str
    verdict: VerdictStatus
    phase: Literal["active", "blocked", "goal_reached", "unscoreable"]
    reason: str
    step_index: int = Field(ge=0)
    completed_steps: tuple[str, ...] = ()
    # Old logs remain readable, but an unbound step is not oracle evidence.
    # Omit absent proof to preserve their wire shape and semantic identity.
    norm_fact: QdlFact | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


class QdlPathEvaluated(DomainEvent):
    """Terminal outcome of one QDL path, including paths with no probe.

    ``previous_outcome`` preserves the outcome restored by replay, while
    ``retry_policy`` records whether a blocked path may be retried.
    """

    event_type: Literal["qdl_path_evaluated"] = "qdl_path_evaluated"
    path_id: str
    outcome: Literal["completed", "blocked"]
    evidence_signature: str | None = None
    previous_outcome: Literal["completed", "blocked", "retryable"] | None = None
    retry_policy: Literal["none", "bounded"] = "none"
    attempted_steps: int = Field(ge=0)
    step_count: int = Field(ge=1)
    probe_count: int = Field(ge=0)
    reason: str


def is_replay_idempotent(event: DomainEvent) -> bool:
    """Return whether an event represents replay-idempotent engine state."""

    return isinstance(
        event,
        (
            FactVerified,
            IntentProposed,
            EvidenceRecorded,
            QdlStepEvaluated,
            QdlPathEvaluated,
        ),
    )


class DiffPairComputed(DomainEvent):
    """One differential control/treatment pair evaluated by the comparator."""

    event_type: Literal["diff_pair_computed"] = "diff_pair_computed"
    action_id: str
    mode: str = "factors"
    control_observation_id: str | None = None
    treatment_observation_id: str | None = None
    dimensions: tuple[str, ...] = ()
    has_variance: bool = False


CampaignPhase = Literal["qdl_planning", "executing", "evaluating", "finished"]

# A component's activation semantics: a producer emits candidates that flow
# downstream, while a gate renders admission decisions on the work it is
# offered.  Rejection is a gate's successful output, not inactivity.
ComponentKind = Literal["producer", "gate"]


class PhaseChanged(DomainEvent):
    """One campaign phase transition."""

    event_type: Literal["phase_changed"] = "phase_changed"
    phase: CampaignPhase


class ComponentLifecycleEvent(DomainEvent):
    """Base identity and correlation fields for component telemetry."""

    component: str = Field(min_length=1)
    kind: ComponentKind = "producer"
    invocation_id: str | None = None
    check_id: str | None = None
    observation_id: str | None = None
    path_id: str | None = None

    @model_validator(mode="after")
    def validate_component_correlation(self) -> ComponentLifecycleEvent:
        for name in ("invocation_id", "check_id", "observation_id", "path_id"):
            if getattr(self, name) == "":
                raise ValueError(f"component event {name} must not be empty")
        return self


class ComponentInvoked(ComponentLifecycleEvent):
    """One component invocation with a digest and input completeness counts."""

    event_type: Literal["component_invoked"] = "component_invoked"
    input_digest: str = Field(min_length=1)
    input_completeness: Mapping[str, int] = Field(default_factory=dict)
    fallback_modes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_input_counts(self) -> ComponentInvoked:
        if any(count < 0 for count in self.input_completeness.values()):
            raise ValueError("component input counts must not be negative")
        return self


class ComponentSkipped(ComponentLifecycleEvent):
    """One component that was considered but did not run."""

    event_type: Literal["component_skipped"] = "component_skipped"
    reason: str = Field(min_length=1)
    input_digest: str = ""
    input_completeness: Mapping[str, int] = Field(default_factory=dict)
    fallback_modes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_input_counts(self) -> ComponentSkipped:
        if any(count < 0 for count in self.input_completeness.values()):
            raise ValueError("component input counts must not be negative")
        return self


class ComponentOutput(ComponentLifecycleEvent):
    """One component output summary, keyed by pipeline stage."""

    event_type: Literal["component_output"] = "component_output"
    summary: Mapping[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_summary_counts(self) -> ComponentOutput:
        if any(count < 0 for count in self.summary.values()):
            raise ValueError("component output counts must not be negative")
        return self


class DownstreamDecision(ComponentLifecycleEvent):
    """One downstream consumer's decision about a component output."""

    event_type: Literal["downstream_decision"] = "downstream_decision"
    consumed: bool
    by: str = Field(min_length=1)
    outcome: str = Field(min_length=1)


Event = (
    CheckCompleted
    | CoverageUpdated
    | DiffPairComputed
    | PhaseChanged
    | FindingRaised
    | InvestigationActionExecuted
    | FactVerified
    | IntentProposed
    | EvidenceRecorded
    | QdlStepEvaluated
    | QdlPathEvaluated
    | ComponentInvoked
    | ComponentSkipped
    | ComponentOutput
    | DownstreamDecision
)
