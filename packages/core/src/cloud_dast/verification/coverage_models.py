"""Derivation-based QDL coverage (S24R term coverage algebra).

The QDL graph is the single source of truth.  Coverage is computed per
QDL term — field, causal effect, state, or transition — never per action
or path.

``field_role`` and ``supports_primitive`` are derived views over
``has``/``refers_to``/``exposes``/``causes``/``is`` (materialized by
:mod:`cloud_dast.qdl.semantic_norm_compiler`),
and every requirement is re-checked through the S21 derivation algebra
(``QdlSubgoal`` + ``derivable``) before a cell is reported.

S24R defines one generic algebra over terms:

.. math::

    coverage(term) = semantic(term) × setup(term) × oracle(term) × runtime(term)

with ``oracle = channel × primitive``.  Each factor is a total predicate
over ``(graph, runtime evidence)``; the deficit of a term is its first
missing leaf in the canonical prerequisite order
``semantic ≺ setup ≺ channel ≺ primitive ≺ runtime`` — a fixture for an
uninterpretable term is meaningless, an oracle without a fixture can never
fire, and runtime evidence without an oracle is uninterpretable.  A
missing structural leaf (semantic/setup/oracle) is *blind*: no amount of
runtime work can close it.  A missing runtime leaf is *unresolved*: the
term is coverable but not yet exercised.

Every gap carries one typed deficit, keyed by the missing factor:

- ``semantic_blind`` — no ``field_role``/semantic fact is derivable;
- ``setup_blind`` — the fixture for the target is not derivable;
- ``capability_blind`` — the oracle channel leaf: no ``supports_primitive``
  derivation exists;
- ``oracle_blind`` — the oracle primitive leaf: no deterministic oracle
  primitive scores the term;
- ``evidence_blind`` — the runtime leaf: structural factors hold but no
  runtime observation (witness or verdict) exists.

Request-field execution and oracle-witness observation are separate runtime
evidence projections: a field that was actually present in an executed request
is ``request_executed`` even when no oracle witness has observed it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    PredicateSchema,
    Struct,
    Term,
    TermKind,
    Variable,
    canonical_json,
    transition,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    EXPOSURE_WITNESS_NAMES,
)
from cloud_dast.verification.action_runtime import (
    ActionRuntimeEntry,  # noqa: F401 — compatibility re-export
    ActionRuntimeLedger,
    BindingDeficit,
)
from cloud_dast.verification.norms import Primitive

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

_PRIMITIVES: frozenset[str] = frozenset(get_args(Primitive))
# Kept as an internal import surface for the existing coverage builder.
_EXPOSURE_WITNESS_NAMES = EXPOSURE_WITNESS_NAMES


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


_FACTOR_LEAVES: tuple[tuple[str, CoverageFactor, BlindDeficitType], ...] = (
    ("semantic", "semantic", "semantic_blind"),
    ("setup", "setup", "setup_blind"),
    ("oracle_channel", "oracle", "capability_blind"),
    ("oracle_primitive", "oracle", "oracle_blind"),
    ("runtime", "runtime", "evidence_blind"),
)
_FACTOR_RATIONALES: Mapping[str, str] = {
    "semantic": "no field_role or semantic fact is derivable",
    "setup": "fixture for this coverage target is not derivable",
    "oracle_channel": "no supports_primitive derivation exists",
    "oracle_primitive": (
        "no deterministic oracle primitive scores this coverage target"
    ),
    "runtime": "coverage target is derivable but not observed at runtime",
}


def evaluate_term_coverage(
    factors: TermFactors,
    *,
    rationale: str = "",
) -> TermCoverageEvaluation:
    """Evaluate ``coverage(term) = semantic × setup × oracle × runtime``.

    Leaves are checked in the canonical prerequisite order
    ``semantic ≺ setup ≺ channel ≺ primitive ≺ runtime``; the first missing
    leaf types the deficit by its factor.  A missing structural leaf makes
    the unit *blind* — no runtime work can close it — while a missing
    runtime leaf leaves it *unresolved*: coverable, not yet exercised.
    Units outside the required coverage universe stay informational.
    """

    if not factors.required:
        return TermCoverageEvaluation(
            status="unresolved",
            deficit=None,
            missing_factor=None,
            rationale=rationale
            or "runtime evidence is outside the required coverage universe",
        )
    for leaf, factor, deficit in _FACTOR_LEAVES:
        if not getattr(factors, leaf):
            return TermCoverageEvaluation(
                status="blind" if factor != "runtime" else "unresolved",
                deficit=deficit,
                missing_factor=factor,
                rationale=rationale or _FACTOR_RATIONALES[leaf],
            )
    return TermCoverageEvaluation(
        status="covered",
        deficit=None,
        missing_factor=None,
        rationale=rationale or "all coverage factors are satisfied",
    )


_ANY_ACTION = Variable(name="AnyAction")
_ANY_EFFECT = Variable(name="AnyEffect")
_ANY_ROLE = Variable(name="AnyRole")
_ANY_TARGET = Variable(name="AnyTarget")


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


def _reference(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
        reference=True,
    )


def _string(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
    )


def _field_argument(name: str = "field") -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.STRUCT,),
        struct_names=("input_field", "output_field", "output_header", "field"),
        reference=True,
    )


COVERAGE_PREDICATE_SCHEMAS: tuple[PredicateSchema, ...] = (
    PredicateSchema(
        name="evidence_target",
        arguments=(
            _reference("observation"),
            _reference("action"),
            _field_argument(),
            _string("role"),
            _string("primitive"),
        ),
    ),
)

_COVERAGE_PREDICATES = {
    schema.name: Predicate.from_schema(schema) for schema in COVERAGE_PREDICATE_SCHEMAS
}


def evidence_target_fact(
    observation: Atom,
    action: Atom,
    field_term: Struct,
    role: str,
    primitive: Primitive,
    context: Context = Context.RUNTIME,
) -> Fact:
    """Bind one runtime observation to an exact field coverage unit."""

    if not role.strip():
        raise ValueError("field role must not be empty")
    if primitive not in _PRIMITIVES:
        raise ValueError(f"unknown primitive: {primitive}")
    return _coverage_fact(
        "evidence_target",
        (
            observation,
            action,
            field_term,
            Atom(value=role),
            Atom(value=primitive),
        ),
        context,
    )


def _coverage_fact(
    predicate_name: str, args: tuple[Term, ...], context: Context
) -> Fact:
    return Fact(
        context=context,
        predicate=_COVERAGE_PREDICATES[predicate_name],
        args=args,
    )
