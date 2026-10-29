"""Deterministic compilation of grounded semantics into candidate norms.

This module is the semantic counterpart of
:mod:`cloud_dast.runtime.payload_hints`: the model
grounds primary facts, while this compiler projects those facts onto QDL
effect constructors.  It deliberately contains neither an LLM client nor a
vulnerability-class catalogue.  Every emitted norm is evidence-backed and
uses only constructors already present in the formal basis.  Only contract and
accepted facts are eligible for executable synthetic semantics.
Runtime duration evidence is used only to calibrate a bound; it is never
promoted into semantic facts by itself.
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from statistics import median
from typing import Literal

import clingo

from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.asp import decode_term
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.field_roles import resolve_field_roles
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Term,
    Variable,
    allowed,
    canonical_json,
    changed,
    create,
    duration,
    external_call,
    has,
    reached,
    transition,
)
from cloud_dast.qdl.graph import (
    field as resource_field,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.norms import (
    EFFECT_PRIMITIVES,
    Primitive,
)
from cloud_dast.qdl.roles import (
    SEMANTIC_ROLE_NAMES,
    SEMANTIC_ROLES,
    SemanticRoleViolation,
    semantic_role_violation,
)

_SENSITIVE_ROLES = frozenset(role.name for role in SEMANTIC_ROLES if role.sensitive)
_PRIVILEGED_ROLE = next(role.name for role in SEMANTIC_ROLES if role.privileged)
type SetupAspect = Literal["resource", "input", "output", "effect"]
_INTERPRETER_TYPE = "interpreter"
_FILESYSTEM_TYPE = "filesystem"
_EXTERNAL_NET_TYPE = "external_net"
_REACHED_SINK_TYPES = frozenset({_INTERPRETER_TYPE, _FILESYSTEM_TYPE})
_STATE_EFFECTS = frozenset({"completed", "changed", "transition"})
_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})
_DURATION_BASELINE_SAMPLES = 3

# S24 v2 (remediation plan 6.9): ``field_role`` and ``supports_primitive``
# are derived views over ``has``/``refers_to``/``exposes``/``causes``/``is``,
# never extensional facts and never hardcoded field lists.
FIELD_ROLE_VIEW_CONTEXTS: tuple[Context, ...] = (Context.CONTRACT, Context.ACCEPTED)
OBJECT_REFERENCE_DERIVED_ROLE = "object_ref"
STATE_TRANSITION_DERIVED_ROLE = "state_transition"
UNCLASSIFIED_FIELD_ROLE = "unclassified"
_ROLE_HOLDER_DIRECTIONS = {"input_field": "input", "output_field": "output"}
_DIRECT_ROLE_HOLDERS = frozenset({"field", "output_header"})
_REFERENCE_WITNESSES = frozenset({"input_field", "output_field", "output_header"})
EXPOSURE_WITNESS_NAMES = frozenset({"field", "output_field", "output_header"})

logger = logging.getLogger("cloud_dast.formal.semantic_norm_compiler")


class FormalCompilationError(RuntimeError):
    """A formal compilation failed and must not be treated as an empty result."""


class SemanticNormCompiler:
    """Compile grounded semantic facts into accepted candidate norms."""

    def compile(self, graph: QdlGraph) -> tuple[Fact, ...]:
        """Return a self-contained bundle of synthetic ``prevents`` facts."""

        source = filter_executable_graph(graph)
        effects = (
            *_permission_gap_effects(source),
            *sensitive_exposure_effects(source),
            *reached_effects(source),
            *external_call_effects(source),
            *privileged_change_effects(source),
            *_declared_duration_effects(duration_effects(graph), source),
            *_state_machine_effects(source),
        )
        unique_effects = _unique_effects(effects)

        facts: dict[str, Fact] = {}
        for effect in unique_effects:
            for fact in synthetic_norm_facts(
                source,
                effect,
            ):
                facts.setdefault(canonical_json(fact), fact)
        return tuple(facts[key] for key in sorted(facts))


def filter_semantic_roles(
    graph: QdlGraph,
) -> tuple[QdlGraph | None, tuple[SemanticRoleViolation, ...]]:
    """Drop proposal facts and rules that use a non-semantic role."""

    violations: list[SemanticRoleViolation] = []
    facts: list[Fact] = []
    for fact in graph.facts:
        violation = semantic_role_violation(fact.predicate.name, fact.args)
        if violation is None:
            facts.append(fact)
        else:
            violations.append(violation)

    rules: list[Rule] = []
    for rule in graph.rules:
        rule_violations = [
            violation
            for literal in (*rule.body, *rule.head)
            if (
                violation := semantic_role_violation(
                    literal.predicate.name,
                    literal.args,
                )
            )
            is not None
        ]
        if rule_violations:
            violations.extend(rule_violations)
        else:
            rules.append(rule)

    if not violations:
        return graph, ()
    if not facts and not rules:
        return None, tuple(violations)
    try:
        return QdlGraph(facts=tuple(facts), rules=tuple(rules)), tuple(violations)
    except ValueError:
        return None, tuple(violations)


def sensitive_exposure_effects(
    graph: QdlGraph,
    action_id: str | None = None,
) -> tuple[Struct, ...]:
    """Return possession effects for sensitive exposed response fields."""

    direct_roles: dict[str, set[str]] = defaultdict(set)
    output_roles: dict[tuple[str, str], set[str]] = defaultdict(set)
    # ProposalPromoter also uses this query for parked proposal leads; its caller
    # controls the trust view. Executable compilation filters the graph first.
    for row in derive_field_roles(graph, contexts=tuple(Context)):
        if row.source_predicate == "has":
            direct_roles[canonical_json(row.field_term)].add(row.role)
            if row.field_term.name == "output_field":
                action, field_name = (atom_value(arg) for arg in row.field_term.args)
                if action is not None and field_name is not None:
                    for alias in action_aliases(action):
                        output_roles[(alias, field_name)].add(row.role)
    exposures = tuple(_exposure_rows(graph, action_id))
    roles_by_witness: dict[str, set[str | None]] = {}
    for _action, witness, field_name in _exposure_rows(graph):
        roles = roles_by_witness.setdefault(canonical_json(witness), set())
        alias = output_roles.get((atom_value(_action), field_name), set())
        direct = direct_roles.get(canonical_json(witness), set())
        semantic_roles = (alias or direct) & SEMANTIC_ROLE_NAMES
        roles.update(semantic_roles or {None})

    effects: set[Struct] = set()
    attackers = _attackers(graph)
    for _action, witness, _field_name in exposures:
        roles = roles_by_witness.get(canonical_json(witness), set())
        if not roles or not all(role in _SENSITIVE_ROLES for role in roles):
            continue
        effects.update(has(attacker, witness) for attacker in attackers)
    return _unique_effects(effects)


def _exposure_rows(
    graph: QdlGraph,
    action_id: str | None = None,
):
    for fact in graph.facts:
        if fact.predicate.name != "exposes" or len(fact.args) != 2:
            continue
        action, witness = fact.args
        if not isinstance(witness, Struct) or witness.name != "field":
            continue
        if len(witness.args) != 2:
            continue
        if action_id is not None and not _action_matches(action, action_id):
            continue
        field_name = atom_value(witness.args[1])
        if field_name is not None:
            yield action, witness, field_name


def _attackers(graph: QdlGraph) -> tuple[Atom, ...]:
    """Resolve the attacker principal from the graph, not a fixed literal."""

    explicit = sorted(
        {
            atom_value(fact.args[0])
            for fact in graph.facts
            if fact.predicate.name == "attacker"
            and len(fact.args) == 1
            and atom_value(fact.args[0]) is not None
        }
    )
    if explicit:
        return tuple(Atom(value=principal) for principal in explicit)

    principals = sorted(
        {
            atom_value(fact.args[0])
            for fact in graph.facts
            if fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Principal"
            and atom_value(fact.args[0]) is not None
        }
    )
    if len(principals) == 1:
        return (Atom(value=principals[0]),)
    return (Atom(value="attacker"),)


def reached_effects(
    graph: QdlGraph,
    action_id: str | None = None,
) -> tuple[Struct, ...]:
    """Return sink-reach effects for input fields reaching executable sinks."""

    sink_types = {
        identifier
        for sink_type in _REACHED_SINK_TYPES
        for identifier in _typed_identifiers(graph, sink_type)
    }
    effects: set[Struct] = set()
    for source, sink in ClingoEngine().reaches_plus_pairs(graph):
        action, _field_name = _input_field(source)
        if action is None:
            continue
        if action_id is not None and not _action_matches(action, action_id):
            continue
        if not isinstance(sink, Atom) or atom_value(sink) not in sink_types:
            continue
        effects.add(reached(action, sink))
    return _unique_effects(effects)


def external_call_effects(
    graph: QdlGraph,
    action_id: str | None = None,
) -> tuple[Struct, ...]:
    """Return downstream-call effects grounded in reach and causal evidence."""

    external_sinks = _typed_identifiers(graph, _EXTERNAL_NET_TYPE)
    caused_calls: set[tuple[Atom, Atom]] = set()
    for action, effect in derive_causal_effects(graph, "external_call"):
        if len(effect.args) != 2:
            continue
        marker = effect.args[1]
        if isinstance(marker, Atom):
            caused_calls.add((action, marker))
    effects: set[Struct] = set()

    for source, marker in ClingoEngine().reaches_plus_pairs(graph):
        action, _field_name = _input_field(source)
        if action is None:
            continue
        if action_id is not None and not _action_matches(action, action_id):
            continue
        if not isinstance(marker, Atom) or atom_value(marker) not in external_sinks:
            continue
        if (action, marker) not in caused_calls:
            continue
        effects.add(external_call(action, marker))
    return _unique_effects(effects)


def privileged_change_effects(
    graph: QdlGraph,
    action_id: str | None = None,
) -> tuple[Struct, ...]:
    """Return state-change effects for privileged fields on target resources."""

    effects: set[Struct] = set()
    for row in derive_field_roles(graph):
        if row.role != _PRIVILEGED_ROLE or row.field_term.name != "input_field":
            continue
        action, field = row.field_term.args
        if not isinstance(action, Atom):
            continue
        if action_id is not None and not _action_matches(action, action_id):
            continue
        for resource in _target_resources(graph, action):
            effects.add(changed(resource, field))
    return _unique_effects(effects)


def duration_effects(
    graph: QdlGraph,
    action_id: str | None = None,
) -> tuple[Struct, ...]:
    """Return duration effects calibrated from runtime duration samples.

    A static number is a service-specific guess, not a baseline.  Synthetic
    duration norms are emitted only after an action has enough runtime samples,
    and their bound is the median plus a robust MAD-derived spread.  Samples
    come from idempotent ``observed_duration`` aggregates; the legacy
    ``evidence(_, duration(...))`` shape is still read so hand-built and
    historically persisted graphs keep calibrating.  One action/value pair is
    one sample: multiplicity lives in the observation event log, not in the
    QDL graph.
    """

    samples: dict[str, list[float]] = {}
    action_terms: dict[str, Atom] = {}
    for action, value_term in _duration_samples(graph):
        if action_id is not None and not _action_matches(action, action_id):
            continue
        _record_duration_sample(samples, action_terms, action, value_term)

    effects: set[Struct] = set()
    for action_key, values in samples.items():
        if len(values) < _DURATION_BASELINE_SAMPLES:
            continue
        effects.add(
            duration(
                action_terms[action_key],
                Atom(value=_duration_threshold(values)),
            )
        )
    return _unique_effects(effects)


def _duration_samples(graph: QdlGraph) -> Iterator[tuple[Atom, Atom]]:
    """Yield distinct runtime duration samples from both projection shapes."""

    seen: set[tuple[str, float]] = set()
    for fact in graph.facts:
        if fact.context is not Context.RUNTIME:
            continue
        pairs: tuple[tuple[object, object], ...] = ()
        if fact.predicate.name == "observed_duration" and len(fact.args) == 2:
            pairs = (fact.args,)
        elif fact.predicate.name == "evidence" and len(fact.args) == 2:
            effect = fact.args[1]
            if (
                isinstance(effect, Struct)
                and effect.name == "duration"
                and len(effect.args) == 2
            ):
                pairs = (effect.args,)
        for action, value_term in pairs:
            if not isinstance(action, Atom) or not _positive_number(value_term):
                continue
            if not isinstance(value_term, Atom):
                continue
            value = value_term.value
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            action_key = atom_value(action)
            if action_key is None:
                continue
            key = (action_key.removeprefix("action:"), float(value))
            if key in seen:
                continue
            seen.add(key)
            yield action, value_term


def synthetic_norm_facts(
    graph: QdlGraph,
    effect: Struct,
) -> tuple[Fact, ...]:
    """Build one effect-addressed norm and its self-contained declarations."""

    source = filter_executable_graph(graph)

    digest = hashlib.sha256(canonical_json(effect).encode("utf-8")).hexdigest()[:12]
    norm = Atom(value=f"norm:synthetic:{effect.name}:{digest}")
    facts: dict[str, Fact] = {}

    def add(fact: Fact) -> None:
        facts.setdefault(canonical_json(fact), fact)

    add(_declaration(norm, "Norm"))
    for term, fallback_type in _effect_references(effect):
        declaration = _existing_declaration(source, term)
        add(declaration or _declaration(term, fallback_type))
    for term in _field_terms(effect):
        declaration = _existing_declaration(source, term)
        add(declaration or _declaration(term, "Field"))
    add(
        Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(norm, effect),
        )
    )
    return tuple(facts[key] for key in sorted(facts))


def norm_requirement(norm: Fact) -> Struct | None:
    """Return the causal effect whose producibility one norm requires.

    ``prevents(NormId, Effect)`` is executable only while the campaign can
    produce ``Effect`` somewhere in an attack chain.  This is the
    requirement half of ``deficit(R, G) :- requirement(R, G),
    not derivable(R, G)``: the deficit layer turns an underivable
    requirement into a ``causes``-class subgoal
    ``causes(AnyAction, Effect)``.  Norms without the two-argument
    ``prevents`` shape carry no chain requirement.
    """

    if norm.predicate.name != "prevents" or len(norm.args) != 2:
        return None
    effect = norm.args[1]
    return effect if isinstance(effect, Struct) else None


def filter_executable_graph(graph: QdlGraph) -> QdlGraph:
    """Keep executable facts and rules, or fail if that view is invalid."""

    try:
        return graph.select_contexts(_EXECUTABLE_CONTEXTS)
    except ValueError as error:
        raise FormalCompilationError(
            "executable context filter produced an invalid QDL graph"
        ) from error


@dataclass(frozen=True, slots=True)
class DerivedFieldRole:
    """One ``field_role(Field, Role)`` row derived from base QDL facts.

    S24 v2: a field role is a view, never an extensional fact.  Each row
    records the base fact (predicate and arguments) that derives it, so the
    coverage layer can re-run the derivation algebraically and explain the
    provenance without any hardcoded field list.
    """

    field_term: Struct
    role: str
    source_predicate: str
    source_args: tuple[Term, ...]


@dataclass(frozen=True, slots=True)
class DerivedPrimitiveSupport:
    """One ``supports_primitive`` row derived from base QDL facts.

    S24 v2: detector capability is a view over ``exposes``/``has``/``causes``.
    The row keeps the deriving fact and the scored effect (when the support
    comes from a causal effect), plus every accepted norm that scores the
    same effect.
    """

    field_term: Struct
    role: str
    primitive: Primitive
    effect: Struct | None = None
    source_predicate: str = "causes"
    source_args: tuple[Term, ...] = ()
    norm_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DerivedSetupRequirement:
    """One fixture-requirement subgoal for the S24R setup factor.

    A requirement is a single predicate application with existential
    ``Variable`` positions.  The requirement set of one term is a
    disjunction: the setup factor holds when at least one requirement is
    derivable from the QDL graph, or when runtime evidence already proved
    the term producible.
    """

    predicate: str
    args: tuple[Term, ...]


_SETUP_ANY_ACTION = Variable(name="AnyAction")
_SETUP_ANY_WITNESS = Variable(name="AnyWitness")
_SETUP_ANY_TYPE = Variable(name="AnyType")
_REQUEST_RESPONSE_ASPECTS = frozenset({"input", "output"})
_MUTATION_TERM_NAMES = frozenset({"changed", "field"})


def derive_setup_requirements(
    term: Term,
    *,
    aspect: SetupAspect,
) -> tuple[DerivedSetupRequirement, ...]:
    """Return the fixture requirements of one QDL term (S24R setup factor).

    ``setup(term)`` is a total function over the QDL term algebra.  Every
    structural term maps to the disjunction of fixture facts that make it
    producible for its coverage aspect:

    .. code-block:: prolog

        setup(field(R, F))    :- refers_to(_, R) | causes(_, create(R)).
        setup(changed(R, F))  :- refers_to(_, R) | causes(_, create(R)).
        setup(has(_, W))      :- exposes(_, W).
        setup(effect(S, ..))  :- is(S, _Type).

    Request and response positions carry no fixture obligation: the empty
    disjunction is vacuously satisfiable.  The derivation is purely
    structural — it dispatches on constructors and arities, never on field
    names, service vocabulary, or vulnerability classes — so it stays
    compatible with the S21R total consultation algebra, which owns the
    orthogonal ``axis(subgoal)`` mapping.
    """

    if aspect in _REQUEST_RESPONSE_ASPECTS or not isinstance(term, Struct):
        return ()
    if term.name in _MUTATION_TERM_NAMES and len(term.args) == 2:
        resource = term.args[0]
        return (
            DerivedSetupRequirement(
                predicate="refers_to",
                args=(_SETUP_ANY_WITNESS, resource),
            ),
            DerivedSetupRequirement(
                predicate="causes",
                args=(_SETUP_ANY_ACTION, create(resource)),
            ),
        )
    if term.name == "has" and len(term.args) == 2:
        return (
            DerivedSetupRequirement(
                predicate="exposes",
                args=(_SETUP_ANY_ACTION, term.args[1]),
            ),
        )
    if term.args:
        subject = term.args[0]
        if isinstance(subject, Atom | Struct):
            return (
                DerivedSetupRequirement(
                    predicate="is",
                    args=(subject, _SETUP_ANY_TYPE),
                ),
            )
    return ()


def derive_field_roles(
    graph: QdlGraph,
    *,
    contexts: Iterable[Context] = FIELD_ROLE_VIEW_CONTEXTS,
) -> tuple[DerivedFieldRole, ...]:
    """Project semantic field roles as a derived view (S24 v2).

    The derivation rules are:

    .. code-block:: prolog

        field_role(Field, Role) :- current_has(_, Field, Role).
        field_role(Field, object_ref) :- refers_to(Field, _Resource).
        field_role(field(R, F), state_transition) :- current_effect(_, _, changed(R, F)).

    Explicit roles use Clingo current_has and the shared field-role resolver;
    mutation roles use current_effect. No extensional field_role fact is read.
    """

    context_set = frozenset(contexts)
    policy = resolve_field_roles(graph)
    rows: dict[tuple[str, str, str], DerivedFieldRole] = {}

    def add(
        field_term: Struct,
        role: str,
        predicate: str,
        args: tuple[Term, ...],
    ) -> None:
        key = (canonical_json(field_term), role, predicate)
        rows.setdefault(
            key,
            DerivedFieldRole(
                field_term=field_term,
                role=role,
                source_predicate=predicate,
                source_args=args,
            ),
        )

    # Role validity belongs to the canonical Clingo current_has projection.
    # Keep the input graph intact: historical has facts remain provenance.
    solutions = ClingoEngine().solve(graph, closures={"current_has"})
    if not solutions:
        raise FormalCompilationError("field-role derivation returned no model")
    for atom_repr in solutions[0].atoms:
        if not atom_repr.startswith("current_has("):
            continue
        symbol = clingo.parse_term(atom_repr)
        context, holder, role_term = (decode_term(arg) for arg in symbol.arguments)
        if atom_value(context) not in context_set:
            continue
        if not isinstance(holder, Struct) or len(holder.args) != 2:
            continue
        role = atom_value(role_term)
        if role is None:
            continue
        direction = _ROLE_HOLDER_DIRECTIONS.get(holder.name)
        if direction is not None:
            action = atom_value(holder.args[0])
            field_name = atom_value(holder.args[1])
            if role in policy.roles(action, field_name, direction=direction):
                add(holder, role, "has", (holder, role_term))
        elif holder.name in _DIRECT_ROLE_HOLDERS:
            add(holder, role, "has", (holder, role_term))

    for fact in graph.facts:
        if fact.context not in context_set:
            continue
        if fact.predicate.name == "refers_to" and len(fact.args) == 2:
            witness = fact.args[0]
            if isinstance(witness, Struct) and witness.name in _REFERENCE_WITNESSES:
                add(witness, OBJECT_REFERENCE_DERIVED_ROLE, "refers_to", fact.args)
    for action, effect in derive_causal_effects(graph, "changed", contexts=context_set):
        witness = resource_field(effect.args[0], effect.args[1])
        add(witness, STATE_TRANSITION_DERIVED_ROLE, "causes", (action, effect))
    return tuple(rows[key] for key in sorted(rows))


def derive_primitive_supports(
    graph: QdlGraph,
    *,
    contexts: Iterable[Context] = FIELD_ROLE_VIEW_CONTEXTS,
) -> tuple[DerivedPrimitiveSupport, ...]:
    """Project primitive capability as a derived view (S24 v2).

    The derivation rules are:

    .. code-block:: prolog

        supports_primitive(_, W, R, response_field) :- exposes(_, W), field_role(W, R).
        supports_primitive(A, F, R, differential) :- has(input_field(A, F), R).
        supports_primitive(A, W, R, P) :-
            causes(A, Effect), witness(Effect, W), field_role(W, R),
            effect_primitive(Effect, P).

    ``effect_primitive`` is the public effect-constructor table shared with
    the norm compiler; accepted ``prevents`` norms attach to the effect they
    score.  Transition effects are excluded: the state-machine projection
    owns state and transition coverage.
    """

    context_set = frozenset(contexts)
    roles_by_field: dict[str, set[str]] = defaultdict(set)
    field_roles = derive_field_roles(graph, contexts=context_set)
    for row in field_roles:
        roles_by_field[canonical_json(row.field_term)].add(row.role)
    norms_by_effect = _norm_ids_by_effect(graph)

    rows: dict[tuple[str, str, str, str], DerivedPrimitiveSupport] = {}

    def add(
        field_term: Struct,
        role: str,
        primitive: Primitive,
        effect: Struct | None,
        predicate: str,
        args: tuple[Term, ...],
        norm_ids: tuple[str, ...] = (),
    ) -> None:
        key = (canonical_json(field_term), role, primitive, predicate)
        existing = rows.get(key)
        if existing is None:
            rows[key] = DerivedPrimitiveSupport(
                field_term=field_term,
                role=role,
                primitive=primitive,
                effect=effect,
                source_predicate=predicate,
                source_args=args,
                norm_ids=norm_ids,
            )
        elif norm_ids:
            rows[key] = DerivedPrimitiveSupport(
                field_term=existing.field_term,
                role=existing.role,
                primitive=existing.primitive,
                effect=existing.effect,
                source_predicate=existing.source_predicate,
                source_args=existing.source_args,
                norm_ids=tuple(sorted({*existing.norm_ids, *norm_ids})),
            )

    def roles_for(field_term: Struct) -> tuple[str, ...]:
        roles = roles_by_field.get(canonical_json(field_term))
        if roles:
            return tuple(sorted(roles))
        return (UNCLASSIFIED_FIELD_ROLE,)

    for fact in graph.facts:
        if fact.context not in context_set:
            continue
        if fact.predicate.name == "exposes" and len(fact.args) == 2:
            witness = fact.args[1]
            if (
                not isinstance(witness, Struct)
                or witness.name not in EXPOSURE_WITNESS_NAMES
            ):
                continue
            for role in roles_for(witness):
                add(witness, role, "response_field", None, "exposes", fact.args)
    for row in field_roles:
        if row.source_predicate == "has" and row.field_term.name == "input_field":
            add(row.field_term, row.role, "differential", None, "has", row.source_args)
    for action, effect in derive_causal_effects(graph, contexts=context_set):
        if effect.name == "transition":
            continue
        primitive = EFFECT_PRIMITIVES.get(effect.name, "unknown")
        norm_ids = norms_by_effect.get(canonical_json(effect), ())
        for witness in _effect_witnesses(effect):
            for role in roles_for(witness):
                add(
                    witness,
                    role,
                    primitive,
                    effect,
                    "causes",
                    (action, effect),
                    norm_ids,
                )
    return tuple(rows[key] for key in sorted(rows))


def _norm_ids_by_effect(graph: QdlGraph) -> dict[str, tuple[str, ...]]:
    """Index accepted ``prevents`` norms by the effect they score."""

    norms: dict[str, set[str]] = defaultdict(set)
    for fact in graph.facts:
        if fact.context is not Context.ACCEPTED:
            continue
        if fact.predicate.name != "prevents" or len(fact.args) != 2:
            continue
        norm, effect = fact.args
        if not isinstance(effect, Struct):
            continue
        norm_id = atom_value(norm)
        if norm_id is not None:
            norms[canonical_json(effect)].add(norm_id)
    return {effect: tuple(sorted(ids)) for effect, ids in norms.items()}


def _effect_witnesses(effect: Struct) -> tuple[Struct, ...]:
    """Return the field witness carried by one causal effect."""

    if effect.name == "changed" and len(effect.args) == 2:
        return (resource_field(effect.args[0], effect.args[1]),)
    if effect.name == "has" and len(effect.args) == 2:
        value = effect.args[1]
        if isinstance(value, Struct):
            return (value,)
    return ()


def _permission_gap_effects(graph: QdlGraph) -> tuple[Struct, ...]:
    """Detect action permission gaps, preferring the modeled attacker."""

    attackers = {
        atom_value(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == "attacker" and len(fact.args) == 1
    }
    permission_types = _declared_identifiers(graph, "Permission")
    engine = ClingoEngine()
    requirements = _derived_permission_requirements(graph, engine, permission_types)
    if not requirements:
        return ()

    try:
        permitted = set(engine.derive_may_pairs(graph))
    except Exception as error:
        logger.error("permission_gap_derivation_failed reason=%s", error)
        raise FormalCompilationError(
            "permission-gap Clingo derivation failed"
        ) from error

    effects: set[Struct] = set()
    for action, _requirement in requirements:
        action_id = atom_value(action)
        permitted_principals = {
            principal
            for principal, permitted_action in permitted
            if permitted_action == action_id
        }
        if attackers:
            has_gap = not (permitted_principals & attackers)
        else:
            has_gap = not permitted_principals
        if not has_gap:
            continue
        effects.add(allowed(action))
    return _unique_effects(effects)


def _derived_permission_requirements(
    graph: QdlGraph,
    engine: ClingoEngine,
    permission_types: set[str],
) -> tuple[tuple[Atom, Atom], ...]:
    """Return permission requirements, including rule-derived ``requires``.

    Requirement discovery and IAM permission derivation intentionally use the
    same Clingo engine instance.  The semantic compiler does not maintain a
    second Python-only interpretation of QDL rules, so a rule-derived
    requirement cannot silently disappear from the permission-gap analysis.
    """

    try:
        solutions = engine.solve(graph)
    except Exception as error:
        logger.error("permission_requirement_derivation_failed reason=%s", error)
        raise FormalCompilationError(
            "permission requirement derivation failed"
        ) from error
    if not solutions:
        raise FormalCompilationError(
            "permission requirement derivation returned no model"
        )

    requirements: set[tuple[Atom, Atom]] = set()
    for atom_repr in solutions[0].atoms:
        if not atom_repr.startswith("requires("):
            continue
        symbol = clingo.parse_term(atom_repr)
        if (
            symbol.type != clingo.SymbolType.Function
            or symbol.name != "requires"
            or len(symbol.arguments) != 3
        ):
            continue
        action = decode_term(symbol.arguments[1])
        requirement = decode_term(symbol.arguments[2])
        if not isinstance(action, Atom) or not isinstance(requirement, Atom):
            continue
        requirement_id = atom_value(requirement)
        if requirement_id is None:
            continue
        if requirement_id in permission_types or requirement_id.startswith(
            "permission:"
        ):
            requirements.add((action, requirement))
    return tuple(
        sorted(
            requirements,
            key=lambda pair: (canonical_json(pair[0]), canonical_json(pair[1])),
        )
    )


def _state_machine_effects(graph: QdlGraph) -> tuple[Struct, ...]:
    """Project state-machine causes onto effects supported by the oracle basis."""

    state_actions = {
        atom_value(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == "transition" and len(fact.args) == 3
    }
    state_actions.update(
        atom_value(action)
        for action, effect in derive_causal_effects(graph, "transition")
    )
    if not state_actions:
        return ()

    effects: set[Struct] = set()
    for action, effect in derive_causal_effects(graph):
        if atom_value(action) not in state_actions:
            continue
        if effect.name not in _STATE_EFFECTS:
            continue
        if effect.name in EFFECT_PRIMITIVES:
            effects.add(effect)

    # A bare transition maps to transition(From, To).  The action remains in
    # the state-machine fact (or the bound execution path); the effect itself
    # is the state pair scored by the sequence oracle.
    for fact in graph.facts:
        if fact.predicate.name != "transition" or len(fact.args) != 3:
            continue
        from_state, to_state = fact.args[1], fact.args[2]
        if not isinstance(from_state, Atom) or not isinstance(to_state, Atom):
            continue
        effect = transition(from_state, to_state)
        if effect.name in EFFECT_PRIMITIVES:
            effects.add(effect)
    return _unique_effects(effects)


def _target_resources(graph: QdlGraph, action: Atom) -> tuple[Atom, ...]:
    action_id = atom_value(action)
    resources: set[Atom] = set()
    for fact in graph.facts:
        if fact.predicate.name != "targets" or len(fact.args) != 2:
            continue
        target_action, resource = fact.args
        if _action_matches(target_action, action_id) and isinstance(resource, Atom):
            resources.add(resource)
    for fact_action, effect in derive_causal_effects(graph, "changed"):
        if _action_matches(fact_action, action_id):
            resources.add(effect.args[0])
    return tuple(sorted(resources, key=canonical_json))


def derive_causal_effects(
    graph: QdlGraph,
    effect_name: str | None = None,
    *,
    contexts: Iterable[Context] = _EXECUTABLE_CONTEXTS,
) -> tuple[tuple[Atom, Struct], ...]:
    context_set = frozenset(contexts)
    pairs: set[tuple[Atom, Struct]] = set()
    solutions = ClingoEngine().solve(graph, closures={"current_reached"})
    if not solutions:
        raise FormalCompilationError("current-effect derivation returned no model")
    for atom_repr in solutions[0].atoms:
        if not atom_repr.startswith("current_effect("):
            continue
        symbol = clingo.parse_term(atom_repr)
        context, action, effect = (decode_term(arg) for arg in symbol.arguments)
        if atom_value(context) not in context_set:
            continue
        if not isinstance(action, Atom) or not isinstance(effect, Struct):
            continue
        if effect_name is not None and effect.name != effect_name:
            continue
        pairs.add((action, effect))
    return tuple(sorted(pairs, key=lambda item: canonical_json(item)))


def _record_duration_sample(
    samples: dict[str, list[float]],
    action_terms: dict[str, Atom],
    action: Atom,
    value_term: object,
) -> None:
    action_id = atom_value(action)
    if action_id is None or not _positive_number(value_term):
        return
    if not isinstance(value_term, Atom):
        return
    value = value_term.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return
    action_key = action_id.removeprefix("action:")
    samples.setdefault(action_key, []).append(float(value))
    action_terms.setdefault(action_key, action)


def _duration_threshold(values: Sequence[float]) -> int:
    center = median(values)
    deviation = median(tuple(abs(value - center) for value in values))
    spread = max(3.0 * deviation, 0.1 * center, 1.0)
    return max(1, math.ceil(center + spread))


def _declared_duration_effects(
    effects: Iterable[Struct],
    source: QdlGraph,
) -> tuple[Struct, ...]:
    """Keep runtime-calibrated bounds only for executable graph actions."""

    declared_actions = {
        action_id.removeprefix("action:")
        for action_id in _typed_identifiers(source, "Action")
    }
    return tuple(
        effect
        for effect in effects
        if (action_id := atom_value(_atom_arg(effect, 0))) is not None
        and action_id.removeprefix("action:") in declared_actions
    )


def _typed_identifiers(graph: QdlGraph, type_name: str) -> frozenset[str]:
    return frozenset(_declared_identifiers(graph, type_name))


def _declared_identifiers(graph: QdlGraph, type_name: str) -> set[str]:
    return {
        atom_value(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and atom_value(fact.args[1]) == type_name
        and atom_value(fact.args[0]) is not None
    }


def _input_field(term: object) -> tuple[Atom | None, str | None]:
    if not isinstance(term, Struct) or term.name != "input_field":
        return None, None
    if len(term.args) != 2:
        return None, None
    action = term.args[0]
    if not isinstance(action, Atom):
        return None, None
    return action, atom_value(term.args[1])


def _action_matches(term: object, action_id: str | None) -> bool:
    if action_id is None:
        return True
    value = atom_value(term)
    if value is None:
        return False
    aliases = {value, value.removeprefix("action:")}
    expected = {action_id, action_id.removeprefix("action:")}
    return bool(aliases & expected)


def _positive_number(term: object) -> bool:
    if not isinstance(term, Atom):
        return False
    if isinstance(term.value, bool) or not isinstance(term.value, int | float):
        return False
    return math.isfinite(term.value) and term.value > 0


def _unique_effects(effects: Iterable[Struct]) -> tuple[Struct, ...]:
    unique: dict[str, Struct] = {canonical_json(effect): effect for effect in effects}
    return tuple(unique[key] for key in sorted(unique))


def _effect_references(effect: Struct) -> tuple[tuple[Atom, str], ...]:
    references: tuple[tuple[Atom, str], ...]
    if effect.name in {"allowed", "denied", "duration"}:
        references = ((_atom_arg(effect, 0), "Action"),)
    elif effect.name == "reached":
        references = (
            (_atom_arg(effect, 0), "Action"),
            (_atom_arg(effect, 1), "Sink"),
        )
    elif effect.name == "external_call":
        references = (
            (_atom_arg(effect, 0), "Action"),
            (_atom_arg(effect, 1), "Marker"),
        )
    elif effect.name == "changed":
        references = ((_atom_arg(effect, 0), "Resource"),)
    elif effect.name == "completed":
        references = ((_atom_arg(effect, 0), "Flow"),)
    elif effect.name == "has":
        value = effect.args[1] if len(effect.args) == 2 else None
        resource = value.args[0] if isinstance(value, Struct) and value.args else None
        references = (
            (_atom_arg(effect, 0), "Subject"),
            (resource if isinstance(resource, Atom) else None, "Resource"),
        )
    elif effect.name == "identity":
        references = (
            (_atom_arg(effect, 0), "Subject"),
            (_atom_arg(effect, 1), "Subject"),
        )
    elif effect.name == "transition":
        references = (
            (_atom_arg(effect, 0), "State"),
            (_atom_arg(effect, 1), "State"),
        )
    else:
        references = ()
    return tuple((term, fallback) for term, fallback in references if term is not None)


def _field_terms(effect: Struct) -> tuple[Struct, ...]:
    if effect.name != "has" or len(effect.args) != 2:
        return ()
    value = effect.args[1]
    if isinstance(value, Struct) and value.name == "field":
        return (value,)
    return ()


def _atom_arg(effect: Struct, index: int) -> Atom | None:
    if len(effect.args) <= index:
        return None
    term = effect.args[index]
    return term if isinstance(term, Atom) else None


def _declaration(term: Atom | Struct, type_name: str) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("is"),
        args=(term, Atom(value=type_name)),
    )


def _existing_declaration(
    graph: QdlGraph,
    term: Atom | Struct,
) -> Fact | None:
    for fact in graph.facts:
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        if canonical_json(fact.args[0]) == canonical_json(term):
            return _declaration(term, atom_value(fact.args[1]) or "Term")
    return None


__all__ = [
    "DerivedFieldRole",
    "DerivedPrimitiveSupport",
    "DerivedSetupRequirement",
    "EXPOSURE_WITNESS_NAMES",
    "FormalCompilationError",
    "FIELD_ROLE_VIEW_CONTEXTS",
    "SemanticNormCompiler",
    "SEMANTIC_ROLES",
    "SEMANTIC_ROLE_NAMES",
    "SemanticRoleViolation",
    "duration_effects",
    "derive_field_roles",
    "derive_primitive_supports",
    "derive_setup_requirements",
    "external_call_effects",
    "filter_semantic_roles",
    "filter_executable_graph",
    "privileged_change_effects",
    "reached_effects",
    "sensitive_exposure_effects",
    "semantic_role_violation",
    "norm_requirement",
    "synthetic_norm_facts",
]
