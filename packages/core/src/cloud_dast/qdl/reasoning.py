"""Pure QDL reasoning values and derivability queries.

The module owns immutable planning views and graph algebra used by runtime and
verification. It has no campaign lifecycle or external I/O.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

import clingo

from cloud_dast.qdl.asp import decode_term, encode_atom
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Atom,
    Context,
    Fact,
    QdlGraph,
    Struct,
    Term,
    Variable,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.norms import Primitive
from cloud_dast.qdl.semantic_norm_compiler import filter_executable_graph

SUPPORTED_SINK_TYPES = frozenset(
    {"interpreter", "external_net", "filesystem", "sql", "command", "command_shell"}
)
_PRIVILEGED_ROLE = "privileged"


def compile_probe_fields(graph: QdlGraph) -> dict[str, tuple[str, ...]]:
    """Project executable carrier semantics onto declared input fields."""

    source = filter_executable_graph(graph)
    solutions = ClingoEngine().solve(source, closures={"reaches_plus", "current_has"})
    if not solutions:
        return {}
    rows: list[tuple[str, tuple[Term, ...]]] = []
    for encoded in solutions[0].atoms:
        symbol = clingo.parse_term(encoded)
        if symbol.name in {"is", "current_has", "reaches_plus"}:
            rows.append(
                (symbol.name, tuple(decode_term(arg) for arg in symbol.arguments[1:]))
            )
    actions: dict[str, str] = {}
    declared: set[tuple[str, str]] = set()
    sink_types: dict[str, set[str]] = {}
    for predicate, args in rows:
        if predicate != "is" or len(args) != 2:
            continue
        holder, kind = args
        type_name = atom_value(kind)
        identifier = atom_value(holder)
        if type_name == "Action" and identifier is not None:
            key = identifier.removeprefix("action:")
            if key not in actions or identifier.startswith("action:"):
                actions[key] = identifier
        if type_name in {"Field", "InputField"}:
            action, field = read_input_field(holder)
            if action is not None and field is not None:
                declared.add((action.removeprefix("action:"), field))
        if identifier is not None and type_name in SUPPORTED_SINK_TYPES:
            sink_types.setdefault(identifier, set()).add(type_name)
    fields: dict[str, set[str]] = {}
    for predicate, args in rows:
        if len(args) != 2:
            continue
        if predicate == "reaches_plus":
            collect_reach_hint(*args, sink_types, fields)
        elif predicate == "current_has":
            collect_role_hint(
                *args,
                fields,
                roles=frozenset({"probe_target", "oob_target", "privileged"}),
            )
    projected: dict[str, set[str]] = {}
    for action, values in fields.items():
        key = action.removeprefix("action:")
        if key in actions:
            for field in values:
                if (key, field) in declared:
                    projected.setdefault(actions[key], set()).add(field)
    return {
        action: tuple(sorted(values)) for action, values in sorted(projected.items())
    }


def index_sinks(graph: QdlGraph) -> dict[str, set[str]]:
    """Map each sink identifier to its declared sink types."""

    types: dict[str, set[str]] = {}
    for fact in graph.facts:
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        identifier = atom_value(fact.args[0])
        type_name = atom_value(fact.args[1])
        if identifier is None or type_name not in SUPPORTED_SINK_TYPES:
            continue
        types.setdefault(identifier, set()).add(type_name)
    return types


def collect_reach_hint(
    source,
    target,
    sink_types: dict[str, set[str]],
    fields: dict[str, set[str]],
) -> None:
    action, field = read_input_field(source)
    if action is None or field is None:
        return
    sink = atom_value(target)
    if sink is None:
        return
    if sink_types.get(sink):
        fields.setdefault(action, set()).add(field)


def collect_role_hint(
    term,
    role,
    fields: dict[str, set[str]],
    *,
    roles: frozenset[str] = frozenset({_PRIVILEGED_ROLE}),
) -> None:
    if atom_value(role) not in roles:
        return
    action, field = read_input_field(term)
    if action is None or field is None:
        return
    fields.setdefault(action, set()).add(field)


def read_input_field(term: object) -> tuple[str | None, str | None]:
    if not isinstance(term, Struct) or term.name != "input_field":
        return None, None
    if len(term.args) != 2:
        return None, None
    action = atom_value(term.args[0])
    field = atom_value(term.args[1])
    if not isinstance(action, str) or not isinstance(field, str):
        return None, None
    return action, field


@dataclass(frozen=True, slots=True)
class QdlAttackPath:
    """Bound action occurrences derived from causal and value dependencies.

    Repeated action identifiers denote separate occurrences in sequence order.
    ``edge_effects`` carries real obligations immediately gating the next step;
    empty entries denote value/order edges, never implicit effect proofs. It is not
    the complete set of each action's own (possibly nonadjacent) requirements:
    execution must validate those against the current scoped evidence.
    ``supported`` is Clingo's nominal whole-path support, not observed proof;
    manually constructed diagnostic paths default to unsupported.
    """

    path_id: str
    context: Context
    actions: tuple[str, ...]
    edge_effects: tuple[tuple[Struct, ...], ...] = ()
    supported: bool = False

    def __post_init__(self) -> None:
        if len(self.edge_effects) != max(0, len(self.actions) - 1):
            raise ValueError("attack path edge effects must match its actions")

    @property
    def depth(self) -> int:
        return max(0, len(self.actions) - 1)


@dataclass(frozen=True, slots=True)
class QdlStatePath:
    """A bound path through QDL state-machine transitions."""

    path_id: str
    context: Context
    initial_state: str
    final_state: str
    actions: tuple[str, ...]

    @property
    def depth(self) -> int:
        return len(self.actions)


@dataclass(frozen=True, slots=True)
class QdlResourceStatePath:
    """A bound per-resource path through QDL state transitions."""

    path_id: str
    context: Context
    resource: str
    initial_state: str
    final_state: str
    actions: tuple[str, ...]
    states: tuple[str, ...]

    @property
    def depth(self) -> int:
        return len(self.actions)


@dataclass(frozen=True, slots=True)
class QdlForbiddenPath:
    """A witness path to a state forbidden by an accepted norm."""

    path_id: str
    norm: str
    path: QdlStatePath


@dataclass(frozen=True, slots=True)
class QdlClosure:
    """One materialized recursive QDL relation."""

    context: Context
    relation: str
    source: str
    target: str


@dataclass(frozen=True, slots=True)
class QdlRevealEdge:
    """One create-to-observation edge derived from QDL exposure facts."""

    context: Context
    create_action: str
    observe_action: str
    resource_type: str
    witness: Struct


@dataclass(frozen=True, slots=True)
class QdlInvariant:
    """An accepted ``prevents`` fact compiled into an executable oracle view."""

    norm: str
    effect: Struct
    primitive: Primitive
    required_evidence: tuple[str, ...]
    verdict_policy: str
    fact: Fact


type QdlBoundPath = (
    QdlAttackPath | QdlStatePath | QdlResourceStatePath | QdlForbiddenPath
)


@dataclass(frozen=True, slots=True)
class QdlSubgoal:
    """One QDL subgoal query: a predicate application over terms.

    S21 v2 (remediation plan 6.9) defines a deficit as an unprovable QDL
    subgoal, never an action/reason string:

    ``deficit(R, G) :- requirement(R, G), not derivable(R, G)``

    A subgoal is the requirement ``R`` rendered as one predicate application.
    ``Variable`` arguments mark existential positions, so
    ``causes(AnyAction, Effect)`` asks whether *some* action causes the
    effect while ``causes(Action, Effect)`` asks about one exact action.
    """

    predicate: str
    args: tuple[Term, ...] = ()

    @property
    def key(self) -> tuple[str, ...]:
        """Return the canonical identity components of the subgoal."""

        return (self.predicate, *(canonical_json(arg) for arg in self.args))

    @property
    def effect_constructor(self) -> str | None:
        """Return the causal-effect constructor this requirement targets.

        S21R routes a deficit by predicate class and evidence context; the
        targeted constructor (``duration``, ``create``, ``remove``) is the
        requirement-shaped half of that context.  Witness structs such as
        ``input_field`` and evidence structs such as ``differs`` are not
        causal effects and carry no routing channel.
        """

        return next(
            (
                term.name
                for term in self.args
                if isinstance(term, Struct) and term.name in CAUSAL_EFFECT_CONSTRUCTORS
            ),
            None,
        )

    def render(self) -> str:
        """Render the subgoal in QDL syntax for logs and prompts."""

        return f"{self.predicate}({', '.join(_render_term(arg) for arg in self.args)})"


def term_from_canonical_json(payload: str) -> Term | None:
    """Decode one canonical-JSON QDL term (Atom, Struct, or Variable)."""

    try:
        data = json.loads(payload)
    except (TypeError, ValueError):
        return None
    kind = data.get("kind") if isinstance(data, dict) else None
    try:
        if kind == "atom":
            return Atom.model_validate(data)
        if kind == "struct":
            return Struct.model_validate(data)
        if kind == "variable":
            return Variable.model_validate(data)
    except ValueError:
        return None
    return None


def derivable(
    subgoal: QdlSubgoal,
    graph: QdlGraph,
    *,
    contexts: Iterable[Context] | None = None,
    engine: ClingoEngine | None = None,
) -> bool:
    """Return whether one QDL subgoal is derivable from a QDL graph.

    This is the ``derivable`` half of
    ``deficit(R, G) :- requirement(R, G), not derivable(R, G)``.
    Every context present in ``graph`` participates unless ``contexts``
    narrows the check.  Extensional predicates use a fast direct-fact
    check.  Two intensional
    classes use Clingo: ``reaches`` adds the ``reaches_plus`` closure and
    action-level effect-edge participation (``chain_plus``), and ``may``
    uses the replaceable policy rule pack.  Variables in the subgoal unify
    with any ground term; action identifiers unify across their raw and
    ``action:``-prefixed spellings, matching the planner's alias handling.
    ``probe_carrier`` queries the authoritative carrier projection, which
    always restricts proof to current contract/accepted input-field semantics.
    """

    context_set = (
        frozenset(literal.context for fact in graph.facts for literal in (fact,))
        | frozenset(
            literal.context
            for rule in graph.rules
            for literal in (*rule.body, *rule.head)
        )
        if contexts is None
        else frozenset(contexts)
    )
    try:
        scoped_graph = graph.select_contexts(context_set)
    except ValueError:
        return False
    if subgoal.predicate == "probe_carrier":
        if len(subgoal.args) != 2:
            return False
        return any(
            term_unifies(subgoal.args[0], Atom(value=action))
            and term_unifies(subgoal.args[1], Atom(value=field))
            for action, fields in compile_probe_fields(scoped_graph).items()
            for field in fields
        )
    if _direct_fact_derivable(subgoal, scoped_graph, context_set):
        return True
    if subgoal.predicate == "reaches":
        return _reaches_derivable(subgoal, scoped_graph, engine)
    if subgoal.predicate == "may":
        return _may_derivable(subgoal, scoped_graph, engine)
    if subgoal.predicate == "requires":
        return any(
            len(subgoal.args) == len(args)
            and all(
                term_unifies(pattern, value)
                for pattern, value in zip(subgoal.args, args, strict=True)
            )
            for args in derive_requirements(scoped_graph, engine=engine)
        )
    return False


def _render_term(term: Term) -> str:
    """Render one QDL term in canonical QDL syntax."""

    if isinstance(term, Variable):
        return term.name
    if isinstance(term, Atom):
        return encode_atom(term)
    return f"{term.name}({', '.join(_render_term(arg) for arg in term.args)})"


def _direct_fact_derivable(
    subgoal: QdlSubgoal,
    graph: QdlGraph,
    contexts: frozenset[Context],
) -> bool:
    """Check the subgoal against extensional facts in the graph."""

    for fact in graph.facts:
        if fact.context not in contexts:
            continue
        if fact.predicate.name != subgoal.predicate:
            continue
        if len(fact.args) != len(subgoal.args):
            continue
        if all(
            term_unifies(pattern, value)
            for pattern, value in zip(subgoal.args, fact.args, strict=True)
        ):
            return True
    return False


def _reaches_derivable(
    subgoal: QdlSubgoal,
    graph: QdlGraph,
    engine: ClingoEngine | None,
) -> bool:
    """Check dataflow reachability through the Clingo closures."""

    solver = engine or ClingoEngine()
    try:
        solutions = solver.solve(graph, closures={"reaches_plus", "chain_plus"})
    except RuntimeError:
        return False
    if not solutions:
        return False
    for atom in solutions[0].atoms:
        if atom.startswith("reaches_plus("):
            symbol = clingo.parse_term(atom)
            if (
                symbol.type == clingo.SymbolType.Function
                and len(symbol.arguments) == 3
                and _symbols_unify(subgoal.args, symbol.arguments[1:])
            ):
                return True
        elif atom.startswith("chain_plus("):
            symbol = clingo.parse_term(atom)
            if (
                symbol.type == clingo.SymbolType.Function
                and len(symbol.arguments) == 3
                and _chain_participates(subgoal.args, symbol.arguments[1:])
            ):
                return True
    return False


def _may_derivable(
    subgoal: QdlSubgoal,
    graph: QdlGraph,
    engine: ClingoEngine | None,
) -> bool:
    """Check policy-decision derivability through the Clingo algebra layer."""

    solver = engine or ClingoEngine()
    try:
        solutions = solver.solve(graph, algebra=True)
    except RuntimeError:
        return False
    if not solutions:
        return False
    for atom in solutions[0].atoms:
        if not atom.startswith("may("):
            continue
        symbol = clingo.parse_term(atom)
        if (
            symbol.type == clingo.SymbolType.Function
            and symbol.name == "may"
            and len(symbol.arguments) == 4
            and _symbols_unify(subgoal.args, symbol.arguments[1:])
        ):
            return True
    return False


def derive_requirements(
    graph: QdlGraph,
    *,
    contexts: Iterable[Context] | None = None,
    engine: ClingoEngine | None = None,
) -> tuple[tuple[Term, ...], ...]:
    """Materialize the same direct/rule-derived relation used by ``derivable``.

    Batch consumers reuse decoded core terms within one binding. An
    intensional result need not be a persistable extensional Fact: rules
    may bind a data literal into a reference position. Direct facts remain
    proofs when a solve cannot complete, as in ``derivable``.
    """

    if contexts is not None:
        try:
            graph = graph.select_contexts(frozenset(contexts))
        except ValueError:
            return ()
    rows = {
        canonical_json(fact.args): fact.args for fact in graph.facts_for("requires")
    }
    try:
        solutions = (engine or ClingoEngine()).solve(graph)
    except RuntimeError:
        return tuple(rows[key] for key in sorted(rows))
    if solutions:
        for atom in solutions[0].atoms:
            if not atom.startswith("requires("):
                continue
            symbol = clingo.parse_term(atom)
            if symbol.type != clingo.SymbolType.Function or len(symbol.arguments) != 3:
                continue
            args = tuple(map(decode_term, symbol.arguments[1:]))
            rows.setdefault(canonical_json(args), args)
    return tuple(rows[key] for key in sorted(rows))


def term_unifies(pattern: Term, value: Term) -> bool:
    """Return whether one term satisfies one (possibly nested) subgoal pattern."""

    if isinstance(pattern, Variable):
        return True
    if (
        isinstance(pattern, Atom)
        and isinstance(value, Atom)
        and isinstance(pattern.value, str)
        and isinstance(value.value, str)
    ):
        return pattern.value == value.value or _action_alias_pair(
            pattern.value,
            value.value,
        )
    if isinstance(pattern, Struct) and isinstance(value, Struct):
        return (
            pattern.name == value.name
            and len(pattern.args) == len(value.args)
            and all(
                term_unifies(sub_pattern, sub_value)
                for sub_pattern, sub_value in zip(
                    pattern.args,
                    value.args,
                    strict=True,
                )
            )
        )
    return canonical_json(pattern) == canonical_json(value)


def _action_alias_pair(left: str, right: str) -> bool:
    """Return whether two action spellings name the same action."""

    return left == f"action:{right}" or right == f"action:{left}"


def _symbols_unify(
    pattern_args: tuple[Term, ...],
    value_symbols: tuple[clingo.Symbol, ...],
) -> bool:
    """Unify subgoal positions against decoded Clingo symbol arguments."""

    if len(pattern_args) != len(value_symbols):
        return False
    return all(
        term_unifies(pattern, decode_term(symbol))
        for pattern, symbol in zip(pattern_args, value_symbols, strict=True)
    )


def _chain_participates(
    pattern_args: tuple[Term, ...],
    endpoint_symbols: tuple[clingo.Symbol, ...],
) -> bool:
    """Check participation of ground subgoal terms in one effect edge.

    Action-level QDL dataflow is the effect-edge relation: an action that
    causes or requires one side of an edge participates in the dataflow
    graph on either side, exactly like a bounded walk node.
    """

    endpoints = [decode_term(symbol) for symbol in endpoint_symbols]
    ground = [term for term in pattern_args if not isinstance(term, Variable)]
    if not ground:
        return bool(endpoints)
    return all(
        any(term_unifies(term, endpoint) for endpoint in endpoints) for term in ground
    )


@dataclass(frozen=True, slots=True)
class QdlPlan:
    """A derived execution view over one QDL graph."""

    graph_hash: str
    attack_paths: tuple[QdlAttackPath, ...] = ()
    state_paths: tuple[QdlStatePath, ...] = ()
    resource_state_paths: tuple[QdlResourceStatePath, ...] = ()
    forbidden_paths: tuple[QdlForbiddenPath, ...] = ()
    invariants: tuple[QdlInvariant, ...] = ()
    closures: tuple[QdlClosure, ...] = ()
    reveal_edges: tuple[QdlRevealEdge, ...] = ()

    @property
    def bound_paths(self) -> tuple[QdlBoundPath, ...]:
        return (
            *self.attack_paths,
            *self.state_paths,
            *self.resource_state_paths,
            *self.forbidden_paths,
        )


__all__ = [
    "SUPPORTED_SINK_TYPES",
    "index_sinks",
    "collect_reach_hint",
    "collect_role_hint",
    "read_input_field",
    "QdlAttackPath",
    "QdlBoundPath",
    "QdlClosure",
    "QdlForbiddenPath",
    "QdlInvariant",
    "QdlPlan",
    "QdlRevealEdge",
    "QdlResourceStatePath",
    "QdlStatePath",
    "QdlSubgoal",
    "compile_probe_fields",
    "derive_requirements",
    "derivable",
    "term_from_canonical_json",
    "term_unifies",
]
