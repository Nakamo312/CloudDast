"""Immutable Quad/Contextual Datalog (QDL) core.

QDL is a small formal substrate for Cloud DAST.  This module intentionally has
no workflow, contract-graph, Neo4j, or LLM dependencies.  Adapters in later
phases translate their own models into these terms and facts.

The term language is intentionally recursive.  A graph, however, is grounded:
every reference must be declared by an ``is`` fact in that graph.  Causal
effect arguments that identify graph nodes are marked as references, including
the value of ``has`` and both states of ``transition``.  This keeps the
grounded effect universe finite for a fixed graph while the underlying term
language remains infinite.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.qdl.ontology import (
    _STRUCT_SCHEMA_BY_NAME,
    CAUSAL_EFFECT_CONSTRUCTORS,
    EVIDENCE_EFFECT_CONSTRUCTORS,
    PREDICATE_SCHEMAS,
    RECURSIVE_PREDICATES,
    STRUCT_SCHEMAS,
    WITNESS_CONSTRUCTORS,
    ArgumentSchema,
    AtomType,
    Predicate,
    PredicateSchema,
    PredicateVerificationClass,
    StructSchema,
    TermKind,
)

type Term = Annotated["Atom | Variable | Struct", Field(discriminator="kind")]

# Compatibility exports: ontology symbols historically lived in graph.py.
__all__ = [
    "AtomType",
    "ArgumentSchema",
    "CAUSAL_EFFECT_CONSTRUCTORS",
    "EVIDENCE_EFFECT_CONSTRUCTORS",
    "PREDICATE_SCHEMAS",
    "Predicate",
    "PredicateSchema",
    "PredicateVerificationClass",
    "RECURSIVE_PREDICATES",
    "STRUCT_SCHEMAS",
    "StructSchema",
    "TermKind",
    "WITNESS_CONSTRUCTORS",
]


class Context(StrEnum):
    """Strict provenance context of a fact."""

    CONTRACT = "contract"
    PROPOSAL = "proposal"
    ACCEPTED = "accepted"
    RUNTIME = "runtime"
    REPORT = "report"


class Atom(BaseModel):
    """A typed ground literal.

    String atoms carry logical identifiers and scalar names.  They are never
    derived from storage-specific IDs such as a Neo4j element ID.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    kind: Literal["atom"] = "atom"
    value: str | int | float | bool
    literal_type: AtomType

    @model_validator(mode="before")
    @classmethod
    def infer_literal_type(cls, data: object) -> object:
        if isinstance(data, dict) and "literal_type" not in data:
            value = data.get("value")
            if isinstance(value, bool):
                data["literal_type"] = "boolean"
            elif isinstance(value, int):
                data["literal_type"] = "integer"
            elif isinstance(value, float):
                data["literal_type"] = "float"
            else:
                data["literal_type"] = "string"
        return data

    @model_validator(mode="after")
    def validate_literal(self) -> Self:
        if isinstance(self.value, bool):
            actual: AtomType = "boolean"
        elif isinstance(self.value, int):
            actual = "integer"
        elif isinstance(self.value, float):
            actual = "float"
        else:
            actual = "string"
        if actual != self.literal_type:
            raise ValueError(
                f"atom literal_type must be {actual}, got {self.literal_type}"
            )
        return self


class Variable(BaseModel):
    """A rule variable."""

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    kind: Literal["variable"] = "variable"
    name: str = Field(pattern=r"^[A-Z_][A-Za-z0-9_]*$")


class Struct(BaseModel):
    """A structural term with a validated constructor and arguments."""

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    kind: Literal["struct"] = "struct"
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    args: tuple[Term, ...] = ()

    @model_validator(mode="after")
    def validate_constructor(self) -> Self:
        schema = _STRUCT_SCHEMA_BY_NAME.get(self.name)
        if schema is None:
            raise ValueError(f"unknown term constructor: {self.name}")
        minimum = schema.arity
        maximum = len(schema.all_arguments)
        if not minimum <= len(self.args) <= maximum:
            expected = str(minimum) if minimum == maximum else f"{minimum}..{maximum}"
            raise ValueError(
                f"{self.name} expects {expected} arguments, got {len(self.args)}"
            )
        for term, argument in zip(
            self.args, schema.all_arguments[: len(self.args)], strict=True
        ):
            _validate_term(term, argument, path=f"{self.name}.{argument.name}")
        return self


Struct.model_rebuild()


def field(action: Term, name: Term) -> Struct:
    """Build a typed field term."""

    return Struct(name="field", args=(action, name))


def status(action: Term) -> Struct:
    """Build a typed status-channel witness term."""

    return Struct(name="status", args=(action,))


def error(action: Term, reason: Term | None = None) -> Struct:
    """Build a typed error-channel witness term."""

    args = (action,) if reason is None else (action, reason)
    return Struct(name="error", args=args)


def differs(action: Term, dimension: Term) -> Struct:
    """Build a typed differential-evidence term."""

    return Struct(name="differs", args=(action, dimension))


def latency(action: Term) -> Struct:
    """Build a typed latency-channel witness term."""

    return Struct(name="latency", args=(action,))


def callback(action: Term, marker: Term) -> Struct:
    """Build a typed outbound-call witness term."""

    return Struct(name="callback", args=(action, marker))


def trace(action: Term) -> Struct:
    """Build a typed trace-channel witness term."""

    return Struct(name="trace", args=(action,))


def marker(action: Term, probe_marker: Term) -> Struct:
    """Build a typed runtime marker evidence term."""

    return Struct(name="marker", args=(action, probe_marker))


def allowed(action: Term) -> Struct:
    """Build a typed action-allowed effect."""

    return Struct(name="allowed", args=(action,))


def has(principal: Term, value: Term) -> Struct:
    """Build a typed possession effect."""

    return Struct(name="has", args=(principal, value))


def input_field(action: Term, name: Term) -> Struct:
    """Build a typed action input-field term."""

    return Struct(name="input_field", args=(action, name))


def output_field(action: Term, name: Term) -> Struct:
    """Build a typed action output-field term."""

    return Struct(name="output_field", args=(action, name))


def output_header(action: Term, name: Term) -> Struct:
    """Build a typed action output-header term."""

    return Struct(name="output_header", args=(action, name))


def changed(resource: Term, field_name: Term) -> Struct:
    """Build a typed state-change effect."""

    return Struct(name="changed", args=(resource, field_name))


def create(resource_type: Term) -> Struct:
    """Build a typed object-registry creation effect."""

    return Struct(name="create", args=(resource_type,))


def transition(from_state: Term, to_state: Term) -> Struct:
    """Build a typed control-state transition effect."""

    return Struct(name="transition", args=(from_state, to_state))


def remove(resource: Term) -> Struct:
    """Build a typed object-registry removal effect."""

    return Struct(name="remove", args=(resource,))


def denied(action: Term) -> Struct:
    """Build a typed action-denied effect."""

    return Struct(name="denied", args=(action,))


def external_call(action: Term, marker: Term) -> Struct:
    """Build a typed downstream-call effect."""

    return Struct(name="external_call", args=(action, marker))


def duration(action: Term, milliseconds: Term) -> Struct:
    """Build a typed duration effect."""

    return Struct(name="duration", args=(action, milliseconds))


def reached(action: Term, sink: Term) -> Struct:
    """Build a typed reached-sink effect."""

    return Struct(name="reached", args=(action, sink))


def completed(flow: Term) -> Struct:
    """Build a typed completed-flow effect."""

    return Struct(name="completed", args=(flow,))


def identity(attacker: Term, victim: Term) -> Struct:
    """Build a typed identity-confusion effect."""

    return Struct(name="identity", args=(attacker, victim))


def missing(effect: Term) -> Struct:
    """Build a typed missing-effect term."""

    return Struct(name="missing", args=(effect,))


def response_status(action: Term, status: Term) -> Struct:
    """Build a typed runtime response-status evidence term.

    ``status`` is a symbolic status name such as ``grpc.OK`` or the canonical
    string form of a numeric transport code.
    """

    return Struct(name="response_status", args=(action, status))


def outcome(action: Term, result: Term) -> Struct:
    """Build a typed runtime action-outcome evidence term."""

    return Struct(name="outcome", args=(action, result))


def source(kind: Term, id: Term) -> Struct:
    """Build a typed source-provenance evidence term.

    ``kind``/``id`` describe the upstream system and its logical identifier.
    They are provenance data, not graph references, so they do not require an
    ``is`` declaration.
    """

    return Struct(name="source", args=(kind, id))


def unmapped(kind: Term, id: Term, reason: Term) -> Struct:
    """Build a typed adapter evidence term for an unmapped source element."""

    return Struct(name="unmapped", args=(kind, id, reason))


def ambiguous(kind: Term, id: Term, candidates: Term) -> Struct:
    """Build a typed adapter evidence term for an ambiguous mapping.

    ``candidates`` is a string atom with a canonical candidate encoding: unique
    logical identifiers, sorted, joined with ``|``.  Adapters are responsible
    for canonicalization so that the content hash remains stable.
    """

    return Struct(name="ambiguous", args=(kind, id, candidates))


def canonical_json(value: BaseModel | Sequence[BaseModel]) -> str:
    """Render a QDL model or sequence in canonical JSON form."""

    return json.dumps(
        _canonical_data(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def hash_content(value: BaseModel | Sequence[BaseModel]) -> str:
    """Return a stable SHA-256 hash of canonical QDL content."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_data(value: BaseModel | Sequence[BaseModel]) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple | list):
        return [_canonical_data(item) for item in value]
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def _validate_term(term: Term, schema: ArgumentSchema, path: str) -> None:
    if isinstance(term, Variable):
        return
    if isinstance(term, Atom):
        if (
            (schema.reference or schema.declaration)
            and term.literal_type == "string"
            and not term.value.strip()
        ):
            raise ValueError(f"{path} identifier must not be blank")
        if TermKind.ATOM not in schema.ground_types:
            raise ValueError(f"{path} must be a struct or variable, got atom")
        if schema.atom_types is not None and term.literal_type not in schema.atom_types:
            allowed = ", ".join(schema.atom_types)
            raise ValueError(f"{path} must be {allowed} atom, got {term.literal_type}")
        return
    if TermKind.STRUCT not in schema.ground_types:
        raise ValueError(f"{path} must be an atom or variable, got struct")
    if schema.struct_names is not None and term.name not in schema.struct_names:
        allowed = ", ".join(schema.struct_names)
        raise ValueError(f"{path} must be {allowed} struct, got {term.name}")


def _walk_terms(term: Term) -> tuple[Term, ...]:
    if isinstance(term, Struct):
        return (
            term,
            *(child for argument in term.args for child in _walk_terms(argument)),
        )
    return (term,)


def _collect_variables(term: Term) -> set[str]:
    if isinstance(term, Variable):
        return {term.name}
    if isinstance(term, Struct):
        return {
            variable
            for argument in term.args
            for variable in _collect_variables(argument)
        }
    return set()


def _contains_variable(term: Term) -> bool:
    if isinstance(term, Variable):
        return True
    if isinstance(term, Struct):
        return any(_contains_variable(argument) for argument in term.args)
    return False


def _reject_duplicates(keys: Sequence[str], kind: str) -> None:
    for previous, current in zip(keys, keys[1:], strict=False):
        if previous == current:
            raise ValueError(f"duplicate {kind}: {current}")


def _collect_declarations(facts: Sequence[Fact]) -> set[str]:
    declarations: set[str] = set()
    for fact in facts:
        if fact.predicate.name != "is":
            continue
        entity = fact.args[0]
        if not isinstance(entity, Variable):
            declarations.add(canonical_json(entity))
    return declarations


def collect_references(term: Term, schema: ArgumentSchema) -> set[str]:
    """Return reference keys using the canonical argument/constructor schemas."""
    if isinstance(term, Variable):
        return set()
    if isinstance(term, Atom):
        return {canonical_json(term)} if schema.reference else set()
    if isinstance(term, Struct):
        references = {canonical_json(term)} if schema.reference else set()
        struct_schema = _STRUCT_SCHEMA_BY_NAME[term.name]
        for argument, argument_schema in zip(
            term.args,
            struct_schema.all_arguments[: len(term.args)],
            strict=True,
        ):
            references.update(collect_references(argument, argument_schema))
        return references
    return set()


def _validate_references(literal: Fact, declarations: set[str]) -> None:
    references: set[str] = set()
    for term, schema in zip(
        literal.args, literal.predicate.definition.arguments, strict=True
    ):
        references.update(collect_references(term, schema))
    unknown = sorted(references - declarations)
    if unknown:
        raise ValueError("unknown reference: " + ", ".join(unknown))


def _predicate_dependencies(rules: Sequence[Rule]) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for rule in rules:
        for head in rule.head:
            edges.setdefault(head.predicate.name, set()).update(
                body.predicate.name for body in rule.body
            )
    return edges


def _find_disallowed_cycle(edges: dict[str, set[str]]) -> tuple[str, ...] | None:
    for node in sorted(edges):
        if node in RECURSIVE_PREDICATES:
            continue
        cycle = _find_cycle_through(node, edges)
        if cycle is not None:
            return cycle
    return None


def _find_cycle_through(
    start: str, edges: dict[str, set[str]]
) -> tuple[str, ...] | None:
    stack: list[tuple[str, tuple[str, ...]]] = [(start, (start,))]
    visited = {start}

    while stack:
        node, path = stack.pop()
        for dependency in sorted(edges.get(node, ()), reverse=True):
            if dependency == start:
                return (*path, start)
            if dependency not in visited:
                visited.add(dependency)
                stack.append((dependency, (*path, dependency)))
    return None


from cloud_dast.qdl.facts import Fact, QdlGraph, Rule  # noqa: E402, I001


__all__ = [
    "ArgumentSchema",
    "Atom",
    "AtomType",
    "Context",
    "Fact",
    "Predicate",
    "PredicateSchema",
    "PREDICATE_SCHEMAS",
    "QdlGraph",
    "RECURSIVE_PREDICATES",
    "Rule",
    "STRUCT_SCHEMAS",
    "Struct",
    "StructSchema",
    "Term",
    "TermKind",
    "Variable",
    "allowed",
    "callback",
    "canonical_json",
    "changed",
    "completed",
    "create",
    "duration",
    "differs",
    "error",
    "external_call",
    "field",
    "has",
    "hash_content",
    "identity",
    "denied",
    "input_field",
    "marker",
    "missing",
    "output_field",
    "output_header",
    "reached",
    "remove",
    "status",
    "trace",
    "transition",
    "latency",
]
