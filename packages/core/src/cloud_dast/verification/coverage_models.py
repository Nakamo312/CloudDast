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

from collections.abc import Mapping
from typing import get_args

from cloud_dast.contracts.assessment import (
    BlindDeficitType,
    CoverageFactor,
    TermCoverageEvaluation,
    TermFactors,
)
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
)
from cloud_dast.qdl.norms import Primitive
from cloud_dast.qdl.semantic_norm_compiler import (
    EXPOSURE_WITNESS_NAMES,
)

_PRIMITIVES: frozenset[str] = frozenset(get_args(Primitive))
# Kept as an internal import surface for the existing coverage builder.
_EXPOSURE_WITNESS_NAMES = EXPOSURE_WITNESS_NAMES


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
