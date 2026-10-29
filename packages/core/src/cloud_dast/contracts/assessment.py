"""Canonical coverage read models shared by verification and its consumers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import Atom, canonical_json, transition
from cloud_dast.qdl.norms import Primitive

ActionDeficitKind = Literal[
    "method_missing",
    "scenario_missing",
    "transport_not_executed",
    "coverage_update_missing",
    "invariant_missing",
    "forbidden_transition_missing",
    "ambiguous_forbidden_transition",
    "incomplete_binding",
]


@dataclass(frozen=True, slots=True)
class BindingDeficit:
    """Typed explanation for an action that cannot satisfy its contract."""

    action: str
    reason: str
    context: tuple[tuple[str, str], ...] = ()
    kind: ActionDeficitKind | None = None

    def __post_init__(self) -> None:
        if self.kind is None:
            object.__setattr__(
                self,
                "kind",
                _DEFICIT_KIND_BY_REASON.get(self.reason, "incomplete_binding"),
            )

    @property
    def deficit_kind(self) -> ActionDeficitKind:
        """Return the stable typed kind, including for legacy reasons."""

        return self.kind or "incomplete_binding"


_DEFICIT_KIND_BY_REASON: Mapping[str, ActionDeficitKind] = {
    "contract_method_missing": "method_missing",
    "contract_scenario_missing": "scenario_missing",
    "missing_setup_method": "incomplete_binding",
    "setup unavailable": "incomplete_binding",
    "setup_unavailable": "incomplete_binding",
    "fixture_unavailable": "incomplete_binding",
    "identity_deficit": "incomplete_binding",
    "missing_refers_to": "incomplete_binding",
    "missing_invariant": "invariant_missing",
    "forbidden_transition_missing": "forbidden_transition_missing",
    "ambiguous_forbidden_transition": "ambiguous_forbidden_transition",
}


@dataclass(frozen=True, slots=True)
class ActionRuntimeEntry:
    """Runtime ledger row for one declared contract action."""

    action_id: str
    method_id: str | None = None
    planned_path_ids: tuple[str, ...] = ()
    bound_path_ids: tuple[str, ...] = ()
    recovery_path_ids: tuple[str, ...] = ()
    request_execution_ids: tuple[str, ...] = ()
    coverage_update_ids: tuple[str, ...] = ()
    terminal_deficit: BindingDeficit | None = None

    @property
    def declared(self) -> bool:
        return True

    @property
    def request_executed(self) -> bool:
        return bool(self.request_execution_ids)

    @property
    def coverage_updated(self) -> bool:
        return bool(self.coverage_update_ids)

    @property
    def recovery_work_item(self) -> bool:
        return bool(self.recovery_path_ids)

    @property
    def closed(self) -> bool:
        """Whether the action has execution evidence or a terminal deficit."""

        if self.terminal_deficit is not None:
            return True
        if not self.request_executed:
            return False
        # Smoke is a recovery work item.  It is closed only after both event
        # projections produced by the actual check runner are present.
        return not self.recovery_work_item or self.coverage_updated


@dataclass(frozen=True, slots=True)
class ActionRuntimeLedger:
    """Action/method runtime projection; never a QDL term matrix."""

    entries: tuple[ActionRuntimeEntry, ...] = ()

    @property
    def closed(self) -> bool:
        return all(entry.closed for entry in self.entries)

    @property
    def pending_actions(self) -> tuple[str, ...]:
        return tuple(entry.action_id for entry in self.entries if not entry.closed)

    @property
    def deficits(self) -> tuple[BindingDeficit, ...]:
        return tuple(
            entry.terminal_deficit
            for entry in self.entries
            if entry.terminal_deficit is not None
        )

    def for_action(self, action_id: str) -> ActionRuntimeEntry | None:
        canonical = canonical_action_id(action_id)
        return next(
            (entry for entry in self.entries if entry.action_id == canonical),
            None,
        )

    def finalize(self) -> "ActionRuntimeLedger":
        """Turn unresolved actions into typed terminal deficits."""

        finalized: list[ActionRuntimeEntry] = []
        for entry in self.entries:
            if entry.closed:
                finalized.append(entry)
                continue
            if entry.request_executed and entry.recovery_work_item:
                reason = "smoke coverage update not observed"
                kind: ActionDeficitKind = "coverage_update_missing"
            elif not entry.bound_path_ids:
                reason = "declared action has no bound execution path"
                kind = "incomplete_binding"
            else:
                reason = "declared action has no CheckCompleted evidence"
                kind = "transport_not_executed"
            finalized.append(
                replace(
                    entry,
                    terminal_deficit=BindingDeficit(
                        action=entry.action_id,
                        reason=reason,
                        context=(
                            (("coverage", "action_runtime"), ("work_item", "recovery"))
                            if entry.recovery_work_item
                            else (("coverage", "action_runtime"),)
                        ),
                        kind=kind,
                    ),
                )
            )
        return ActionRuntimeLedger(entries=tuple(finalized))


CoverageStatus = Literal["covered", "not_applicable", "unresolved", "blind"]
CoverageSource = Literal["qdl"]
TargetFieldKind = Literal["input", "output", "resource"]
CoverageFactor = Literal["semantic", "setup", "oracle", "runtime"]
COVERAGE_FACTORS: tuple[CoverageFactor, ...] = get_args(CoverageFactor)
TermCoverageKind = Literal[
    "field",
    "effect",
    "state",
    "transition",
    "forbidden_state",
]
BlindDeficitType = Literal[
    "semantic_blind",
    "capability_blind",
    "setup_blind",
    "evidence_blind",
    "oracle_blind",
]
BLIND_DEFICIT_TYPES: tuple[BlindDeficitType, ...] = get_args(BlindDeficitType)
type StateTransition = tuple[str, str, str]
type ForbiddenState = tuple[str, str]


class TermFactors(BaseModel):
    """S24R factor state for one term coverage unit.

    ``coverage(term) = semantic × setup × oracle × runtime`` where the
    oracle factor decomposes into a derivation channel and a deterministic
    primitive: ``oracle = channel × primitive``.  Every factor is witnessed
    either by a static QDL derivation or by runtime evidence; a missing
    factor — never a missing action or path — is the deficit.

    ``required=False`` marks runtime counter-evidence (for example an
    observed transition absent from the specification): such units are
    informational and carry no coverage deficit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    semantic: bool
    setup: bool
    oracle_channel: bool
    oracle_primitive: bool
    runtime: bool
    required: bool = True

    @property
    def oracle(self) -> bool:
        """Return whether the oracle factor holds."""

        return self.oracle_channel and self.oracle_primitive

    @property
    def covered(self) -> bool:
        """Return the product of every factor."""

        return (
            self.required
            and self.semantic
            and self.setup
            and self.oracle
            and self.runtime
        )


@dataclass(frozen=True, slots=True)
class TermCoverageEvaluation:
    """The algebraic verdict for one term coverage unit."""

    status: CoverageStatus
    deficit: BlindDeficitType | None
    missing_factor: CoverageFactor | None
    rationale: str


class FieldCoverageCell(BaseModel):
    """One field × semantic-role × primitive coverage unit (S24 v2).

    S51R keeps request execution outside the oracle algebra:
    ``∀ f ∈ declared_input_fields: requested(f) ∨ request_deficit(f)``.
    ``request_deficit`` is therefore a separate witness, never a factor that
    can turn an unresolved oracle cell into a covered one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field_id: str
    field_name: str
    field_kind: TargetFieldKind
    semantic_role: str
    primitive: Primitive
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    action_ids: tuple[str, ...] = ()
    norm_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    request_executed: bool = False
    request_execution_ids: tuple[str, ...] = ()
    request_deficit: bool = False
    oracle_witness_observed: bool = False
    plan_path_ids: tuple[str, ...] = ()
    rationale: str = ""
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None


class EffectCoverageCell(BaseModel):
    """One causal-effect coverage unit (S24 v2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    effect_id: str
    effect_kind: str
    primitive: Primitive
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    action_ids: tuple[str, ...] = ()
    norm_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    plan_path_ids: tuple[str, ...] = ()
    rationale: str = ""
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None


class TermCoverageCell(BaseModel):
    """One generic term-level coverage unit (S24R).

    The unit is a QDL term — never an action or path.  ``term_kind``
    annotates how the term participates in coverage; ``factors`` carries
    the four-factor algebra state and ``missing_factor`` the first failing
    leaf.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    term_id: str
    term_kind: TermCoverageKind
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None
    rationale: str = ""


class StateMachineStateCoverage(BaseModel):
    """Coverage of one QDL state-machine state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state_id: str
    initial: bool = False
    reachable: bool = False
    incoming_transition_ids: tuple[str, ...] = ()
    outgoing_transition_ids: tuple[str, ...] = ()
    forbidden_norm_ids: tuple[str, ...] = ()
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    rationale: str = ""
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None


class StateMachineTransitionCoverage(BaseModel):
    """Coverage of one specified or observed state-machine transition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    transition_id: str
    action_id: str
    from_state: str
    to_state: str
    in_specification: bool
    observed: bool = False
    norm_ids: tuple[str, ...] = ()
    plan_path_ids: tuple[str, ...] = ()
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    rationale: str = ""
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None


class ForbiddenStateCoverage(BaseModel):
    """Coverage of one QDL forbidden-state norm."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    norm_id: str
    state_id: str
    reachable: bool = False
    witness_initial_state: str = ""
    witness_actions: tuple[str, ...] = ()
    status: CoverageStatus
    deficit: BlindDeficitType | None = None
    rationale: str = ""
    missing_factor: CoverageFactor | None = None
    factors: TermFactors | None = None


class StateMachineMismatchCoverage(BaseModel):
    """One runtime transition absent from the QDL specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    from_state: str
    to_state: str


class StateMachineCoverage(BaseModel):
    """First-class QDL state-machine coverage projection (S24 v2).

    Coverage is state-level: states, transitions, and forbidden states.
    There is deliberately no action-level projection.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    states: tuple[StateMachineStateCoverage, ...] = ()
    transitions: tuple[StateMachineTransitionCoverage, ...] = ()
    forbidden_states: tuple[ForbiddenStateCoverage, ...] = ()
    mismatches: tuple[StateMachineMismatchCoverage, ...] = ()
    initial_states: tuple[str, ...] = ()
    reachable_states: tuple[str, ...] = ()

    @property
    def statuses(self) -> tuple[CoverageStatus, ...]:
        return (
            *(item.status for item in self.states),
            *(item.status for item in self.transitions),
            *(item.status for item in self.forbidden_states),
        )

    @property
    def deficits(self) -> tuple[BlindDeficitType, ...]:
        return (
            *(item.deficit for item in self.states if item.deficit is not None),
            *(item.deficit for item in self.transitions if item.deficit is not None),
            *(
                item.deficit
                for item in self.forbidden_states
                if item.deficit is not None
            ),
        )

    @property
    def summary(self) -> CoverageSummary:
        return _summarize(self.statuses)


class CoverageSummary(BaseModel):
    """Aggregate counts for a coverage projection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total: int = Field(ge=0)
    covered: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    unresolved: int = Field(ge=0)
    blind: int = Field(ge=0)


class CoverageMatrix(BaseModel):
    """Derivation-based QDL coverage projection (S24 v2).

    The source of truth is the QDL graph.  The matrix reports fields,
    causal effects, and state-machine states — never action-level cells.
    ``campaign_id`` and ``run_id`` identify the event scope from which
    runtime evidence was selected.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    source: CoverageSource = "qdl"
    plan_hash: str = ""
    campaign_id: str | None = None
    run_id: str | None = None
    fields: tuple[FieldCoverageCell, ...] = ()
    effects: tuple[EffectCoverageCell, ...] = ()
    state_machine: StateMachineCoverage | None = None
    action_runtime: ActionRuntimeLedger | None = None

    @property
    def has_qdl_projection(self) -> bool:
        return bool(self.fields) or bool(self.effects) or self.state_machine is not None

    def qdl_statuses(self) -> tuple[CoverageStatus, ...]:
        state_machine = self.state_machine
        return (
            *(cell.status for cell in self.fields),
            *(cell.status for cell in self.effects),
            *(state_machine.statuses if state_machine is not None else ()),
        )

    @property
    def summary(self) -> CoverageSummary:
        """Aggregate the QDL coverage source of truth."""

        return _summarize(self.qdl_statuses())

    @property
    def field_summary(self) -> CoverageSummary:
        return _summarize(cell.status for cell in self.fields)

    @property
    def effect_summary(self) -> CoverageSummary:
        return _summarize(cell.status for cell in self.effects)

    @property
    def state_machine_summary(self) -> CoverageSummary | None:
        return self.state_machine.summary if self.state_machine is not None else None

    def coverage_cells(self) -> tuple[FieldCoverageCell | EffectCoverageCell, ...]:
        """Return every field and effect coverage unit."""

        return (*self.fields, *self.effects)

    @property
    def terms(self) -> tuple[TermCoverageCell, ...]:
        """Project every coverage unit as one generic QDL term (S24R).

        Field and effect identities are the canonical JSON of their QDL
        terms; states and transitions are projected onto their state atoms
        and ``transition(From, To)`` terms.  No row is keyed by action or
        path — those remain provenance columns of the kind-specific views.
        """

        state_machine = self.state_machine
        states = state_machine.states if state_machine is not None else ()
        transitions = state_machine.transitions if state_machine is not None else ()
        forbidden_states = (
            state_machine.forbidden_states if state_machine is not None else ()
        )
        return (
            *(
                TermCoverageCell(
                    term_id=cell.field_id,
                    term_kind="field",
                    status=cell.status,
                    deficit=cell.deficit,
                    missing_factor=cell.missing_factor,
                    factors=cell.factors,
                    rationale=cell.rationale,
                )
                for cell in self.fields
            ),
            *(
                TermCoverageCell(
                    term_id=cell.effect_id,
                    term_kind="effect",
                    status=cell.status,
                    deficit=cell.deficit,
                    missing_factor=cell.missing_factor,
                    factors=cell.factors,
                    rationale=cell.rationale,
                )
                for cell in self.effects
            ),
            *(
                TermCoverageCell(
                    term_id=canonical_json(Atom(value=cell.state_id)),
                    term_kind="state",
                    status=cell.status,
                    deficit=cell.deficit,
                    missing_factor=cell.missing_factor,
                    factors=cell.factors,
                    rationale=cell.rationale,
                )
                for cell in states
            ),
            *(
                TermCoverageCell(
                    term_id=canonical_json(
                        transition(
                            Atom(value=cell.from_state),
                            Atom(value=cell.to_state),
                        )
                    ),
                    term_kind="transition",
                    status=cell.status,
                    deficit=cell.deficit,
                    missing_factor=cell.missing_factor,
                    factors=cell.factors,
                    rationale=cell.rationale,
                )
                for cell in transitions
            ),
            *(
                TermCoverageCell(
                    term_id=canonical_json(Atom(value=cell.state_id)),
                    term_kind="forbidden_state",
                    status=cell.status,
                    deficit=cell.deficit,
                    missing_factor=cell.missing_factor,
                    factors=cell.factors,
                    rationale=cell.rationale,
                )
                for cell in forbidden_states
            ),
        )

    @property
    def gaps(self) -> tuple[FieldCoverageCell | EffectCoverageCell, ...]:
        return tuple(
            cell
            for cell in self.coverage_cells()
            if cell.status in {"unresolved", "blind"}
        )

    @property
    def blind_spots(self) -> tuple[FieldCoverageCell | EffectCoverageCell, ...]:
        return tuple(cell for cell in self.coverage_cells() if cell.status == "blind")

    @property
    def deficit_counts(self) -> dict[str, int]:
        """Count every typed blind deficit across fields, effects, and states."""

        counts = Counter(
            deficit
            for deficit in (
                *(cell.deficit for cell in self.coverage_cells()),
                *(self.state_machine.deficits if self.state_machine else ()),
            )
            if deficit is not None
        )
        return {deficit: counts.get(deficit, 0) for deficit in BLIND_DEFICIT_TYPES}

    @property
    def missing_factor_counts(self) -> dict[str, int]:
        """Count term coverage gaps by their first missing S24R factor."""

        counts = Counter(
            cell.missing_factor
            for cell in self.terms
            if cell.missing_factor is not None
        )
        return {factor: counts.get(factor, 0) for factor in COVERAGE_FACTORS}

    @property
    def request_deficit_count(self) -> int:
        """Count declared request fields with no executed request projection."""

        return len(
            {
                cell.field_id
                for cell in self.fields
                if cell.field_kind == "input" and cell.request_deficit
            }
        )

    @property
    def action_runtime_deficits(self) -> tuple[BindingDeficit, ...]:
        """Return action/method deficits without mixing them into S24R terms."""

        return self.action_runtime.deficits if self.action_runtime is not None else ()


def _summarize(statuses: Iterable[CoverageStatus]) -> CoverageSummary:
    counts = Counter(statuses)
    return CoverageSummary(
        total=sum(counts.values()),
        covered=counts["covered"],
        not_applicable=counts["not_applicable"],
        unresolved=counts["unresolved"],
        blind=counts["blind"],
    )


@dataclass(frozen=True, slots=True)
class NormCoverageRow:
    """Where one executable norm stopped in the live pipeline."""

    norm_id: str
    effect: str
    path_count: int
    scheduled: bool
    selected: bool
    executed: bool
    oracle_called: bool
    verdict: str
    blocked_reason: str
    action_ids: tuple[str, ...]
    path_ids: tuple[str, ...]
    check_count: int
    finding_count: int
    effect_id: str = ""
    deficit: BlindDeficitType | None = None
    missing_factor: CoverageFactor | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
