"""Library-backed Clingo execution for QDL graphs.

The engine compiles a QDL graph into an ASP program and delegates all model
generation to Clingo.  Contexts are preserved as the first predicate argument,
so context separation remains explicit in the solver.

The closure layer is opt-in.  It adds the recursive QDL extension predicates
allowed by the domain model and a bounded path-search query without changing
compilation of ordinary QDL rules.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import clingo

from cloud_dast.qdl.asp import (
    asp_string,
    decode_term,
    encode_term,
)
from cloud_dast.qdl.graph import (
    RECURSIVE_PREDICATES,
    Atom,
    Context,
    Fact,
    QdlGraph,
    Rule,
    Term,
    canonical_json,
)

CLOSURE_PREDICATES: frozenset[str] = RECURSIVE_PREDICATES | {
    "current_reached",
    "current_has",
    "superseded_has",
}

CLOSURE_RULES: dict[str, tuple[str, ...]] = {
    # Bi-temporal supersession: base facts are never retracted, while
    # ``supersedes(New, Old)`` marks an old artifact as logically current-free.
    # ``current_effect`` is the generalized projection over causal effects;
    # ``reached`` is the first explicit ``current_*`` consumer.
    "current_effect": (
        "superseded_effect(C,Action,Effect) :- "
        "causes(C,Action,Effect), supersedes(C,New,Old), Old = Effect.",
        "current_effect(C,Action,Effect) :- "
        "causes(C,Action,Effect), "
        "not superseded_effect(C,Action,Effect).",
    ),
    "current_reached": (
        'reached(C,Action,Sink) :- is(C,reached(Action,Sink),"Effect").',
        "reached(C,Action,Sink) :- current_effect(C,Action,reached(Action,Sink)).",
        "superseded_reached(C,Action,Sink) :- supersedes(C,New,reached(Action,Sink)).",
        "current_reached(C,Action,Sink) :- "
        "reached(C,Action,Sink), "
        "not superseded_reached(C,Action,Sink).",
    ),
    "superseded_has": (
        "superseded_has(C,Holder,Value) :- "
        "has(C,Holder,Value), "
        "supersedes(C,replacement(Holder,New),replacement(Holder,Old)), "
        "Old = Value.",
    ),
    "current_has": (
        "current_has(C,Holder,Value) :- "
        "has(C,Holder,Value), not superseded_has(C,Holder,Value).",
    ),
    # IAM resource containment is reflexive: an ON_RESOURCE binding scopes
    # a resource to itself even without a projected self-part edge.
    "part_plus": (
        "part_plus(C,Child,Parent) :- part(C,Child,Parent).",
        'part_plus(C,Resource,Resource) :- is(C,Resource,"Resource").',
        "part_plus(C,Child,Grandparent) :- "
        "part(C,Child,Parent), part_plus(C,Parent,Grandparent).",
    ),
    "requires_plus": (
        "requires_plus(C,Action,Requirement) :- requires(C,Action,Requirement).",
        "requires_plus(C,Action,Transitive) :- "
        "requires(C,Action,Requirement), "
        "requires_plus(C,Requirement,Transitive).",
    ),
    "chain_plus": (
        "chain_plus(C,Action,Next) :- "
        "current_effect(C,Action,Effect), requires(C,Next,Effect).",
        "chain_plus(C,Action,Transitive) :- "
        "current_effect(C,Action,Effect), requires(C,Next,Effect), "
        "chain_plus(C,Next,Transitive).",
    ),
    "may_plus": (
        "may_plus(C,Principal,Action) :- may(C,Principal,Action,Resource).",
        "may_plus(C,Principal,Next) :- "
        "may_plus(C,Principal,Action), chain_plus(C,Action,Next).",
    ),
    "affected_plus": (
        "affected_plus(C,Action,Resource) :- "
        "current_effect(C,Action,changed(Resource,Field)).",
        "affected_plus(C,Action,Parent) :- "
        "affected_plus(C,Action,Resource), "
        "part_plus(C,Resource,Parent).",
    ),
    "reachable": (
        "reachable(C,Source,Target) :- part(C,Source,Target).",
        "reachable(C,Source,Target) :- requires(C,Source,Target).",
        "reachable(C,Source,Target) :- "
        "current_effect(C,Source,Effect), requires(C,Target,Effect).",
        "reachable(C,Source,Transitive) :- "
        "part(C,Source,Target), reachable(C,Target,Transitive).",
        "reachable(C,Source,Transitive) :- "
        "requires(C,Source,Target), reachable(C,Target,Transitive).",
        "reachable(C,Source,Transitive) :- "
        "current_effect(C,Source,Effect), requires(C,Target,Effect), "
        "reachable(C,Target,Transitive).",
    ),
    "reaches_plus": (
        "reaches_plus(C,Source,Target) :- reaches(C,Source,Target).",
        "reaches_plus(C,Source,Transitive) :- "
        "reaches(C,Source,Target), reaches_plus(C,Target,Transitive).",
    ),
}

_CLOSURE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "current_effect": (),
    "current_reached": ("current_effect",),
    "current_has": ("superseded_has",),
    "superseded_has": (),
    "part_plus": (),
    "requires_plus": (),
    "chain_plus": ("current_effect",),
    "may_plus": ("chain_plus",),
    "affected_plus": ("part_plus", "current_effect"),
    "reachable": ("current_effect",),
    "reaches_plus": (),
}

_PATH_EDGE_BODIES: dict[str, tuple[str, ...]] = {
    "part": ("part({context},{source},{target})",),
    "part_plus": ("part({context},{source},{target})",),
    "requires": ("requires({context},{source},{target})",),
    "requires_plus": ("requires({context},{source},{target})",),
    "chain": (
        "current_effect({context},{source},Effect), requires({context},{target},Effect)",
    ),
    "chain_plus": (
        "current_effect({context},{source},Effect), requires({context},{target},Effect)",
    ),
    "reachable": (
        "part({context},{source},{target})",
        "requires({context},{source},{target})",
        "current_effect({context},{source},Effect), requires({context},{target},Effect)",
    ),
    "reaches": ("reaches({context},{source},{target})",),
}


"""Security algebra layer (docs/qdl-algebra.md).

The letters negate only base predicates or the positive-recursive
``reaches_plus`` closure, so the whole program stays stratified.  The corpus
rules are positive over the letters.  Adding this layer never changes the
meaning of base facts: it only derives classified witnesses.
"""

_ALGEBRA_CLOSURES: tuple[str, ...] = (
    "reaches_plus",
    "part_plus",
    "current_effect",
    "superseded_has",
    "current_has",
)


# Policy derivation is separate from the fixed threat algebra so an integration
# can replace RBAC/DAC rules without changing threat hypotheses.
@dataclass(frozen=True, slots=True)
class PolicyRulePack:
    """Replaceable ASP rules that derive the common ``may`` interface."""

    name: str
    rules: tuple[str, ...]


DEFAULT_POLICY_RULE_PACK = PolicyRulePack(
    name="generic-rbac-dac",
    rules=(
        # RBAC.
        "may(C,Subject,Action,Resource) :- "
        "binding(C,Subject,Role,Scope), grants(_,Role,Permission), "
        "requires(_,Action,Permission), targets(_,Action,ResourceType), "
        "applies_to(_,Permission,ResourceType), "
        "is(_,Resource,ResourceType), part_plus(_,Resource,Scope).",
        # DAC.
        "may(C,Subject,Action,Resource) :- "
        "owner(C,Resource,Subject), requires(_,Action,Permission), "
        "targets(_,Action,ResourceType), "
        "applies_to(_,Permission,ResourceType), "
        "is(_,Resource,ResourceType).",
    ),
)


@dataclass(frozen=True, slots=True)
class ThreatRulePack:
    """Replaceable ASP rules that interpret runtime signals as threats."""

    name: str
    rules: tuple[str, ...]


DEFAULT_THREAT_RULE_PACK = ThreatRulePack(
    name="signal-first-threats",
    rules=(
        # Signal interpretation is declarative: a runtime signal, a reachable
        # sink, an effect-grounding mapping, and a QDL norm must all join.
        # No vulnerability name is embedded here; an integration supplies the
        # signal/sink/effect mapping in its replaceable rule-pack facts.
        "signal_finding(Action,Signal,Norm,Sink) :- "
        "signal(_,Action,Signal), "
        "signal_grounds(_,Signal,Effect), "
        "prevents(_,Norm,Effect), "
        "current_effect(_,Action,Effect), "
        "sink_interprets(_,Signal,Sink), "
        "reaches_plus(_,Input,Sink).",
        "_signal_interpretation(Action,Signal) :- "
        "signal(_,Action,Signal), "
        "signal_grounds(_,Signal,Effect), "
        "prevents(_,Norm,Effect), "
        "current_effect(_,Action,Effect), "
        "sink_interprets(_,Signal,_).",
        "uninterpreted_signal(Action,Signal) :- "
        "signal(_,Action,Signal), "
        "not _signal_interpretation(Action,Signal).",
    ),
)

# Security algebra layer (docs/qdl-algebra.md).
#
# Threat modeling, not violation assertion: the rules derive THREATS as
# hypotheses over the merged model.  ``executes``/``observes`` for the
# attacker are modeling assumptions ("the attacker attempts every action;
# if a call returns, the witness is observed"), ``may``/``owner`` come from
# explicit policy facts or the selected policy rule-pack.  Runtime
# probes then confirm or refute each derived threat.
#
# Rules are context-agnostic: model facts live in contract/accepted/stand
# contexts and must join within one rule, so bodies use anonymous context
# variables and derived atoms carry no context.  Negation goes through
# context-erasing helpers to stay safe.

_ALGEBRA_RULES: tuple[str, ...] = (
    # Data-format mapping: the state machine stores transitions as
    # transition(Action, From, To); the algebra speaks causes(A, effect).
    # This is a projection of ingestion format into basis format, not a
    # new language element (transition is a spec'd effect constructor).
    "causes(C,Action,transition(From,To)) :- transition(C,Action,From,To).",
    # Threat hypotheses for the campaign attacker.
    'executes(C,Subject,Action) :- attacker(C,Subject), is(_,Action,"Action").',
    "observes(C,Subject,Witness) :- attacker(C,Subject), exposes(_,Action,Witness).",
    # Context-erasing helpers for safe negation.
    "_algebra_permitted(Subject,Action,Resource) :- may(_,Subject,Action,Resource).",
    "_algebra_bound(Witness,Subject) :- binds(_,Witness,Subject).",
    "_algebra_reachable(User,Resource) :- reaches_plus(_,User,Resource).",
    "_algebra_audited(Action) :- "
    'observes(_,Auditor,trace(Action)), is(_,Auditor,"auditor").',
    # STRIDE letters — threat hypotheses over the model.
    "spoofing(Action,Witness,Subject) :- "
    "accepts(_,Action,Witness,Subject), "
    "not _algebra_bound(Witness,Subject).",
    "tampering(Action,Subject) :- "
    "executes(_,Subject,Action), targets(_,Action,Resource), "
    "current_effect(_,Action,Effect), "
    "not _algebra_permitted(Subject,Action,Resource).",
    "repudiation(Action,Subject) :- "
    "executes(_,Subject,Action), not _algebra_audited(Action).",
    "disclosure(Subject,Action,Witness) :- "
    "exposes(_,Action,Witness), observes(_,Subject,Witness), "
    "targets(_,Action,Resource), "
    "not _algebra_permitted(Subject,Action,Resource).",
    "denial(User,Resource) :- "
    "required(_,User,Resource), "
    "not _algebra_reachable(User,Resource).",
    "elevation(Subject,Action) :- "
    "executes(_,Subject,Action), targets(_,Action,Resource), "
    "not _algebra_permitted(Subject,Action,Resource).",
    # OWASP API Top 10.
    "owasp_api1_bola(Action,Subject) :- "
    "elevation(Subject,Action), "
    'current_has(_,input_field(Action,Field),"object_ref"), '
    "targets(_,Action,Object), owner(_,Object,Owner), Subject != Owner.",
    "owasp_api2_broken_auth(Action,Witness,Subject) :- "
    "spoofing(Action,Witness,Subject).",
    "owasp_api2_broken_auth(Subject,Action,Witness) :- "
    'disclosure(Subject,Action,Witness), current_has(_,Witness,"credential").',
    "owasp_api3_mass_assignment(Action,Subject) :- "
    "tampering(Action,Subject), "
    'current_has(_,input_field(Action,Field),"privileged").',
    "owasp_api4_resource_consumption(User,Resource) :- "
    'denial(User,Resource), current_has(_,Resource,"unbounded").',
    "owasp_api5_function_authz(Action,Subject) :- "
    'elevation(Subject,Action), is(_,Action,"function").',
    "owasp_api6_business_flows(Action,Subject) :- "
    "tampering(Action,Subject), "
    "current_effect(_,Action,transition(_,_)).",
    "owasp_api7_ssrf(Action,Subject) :- "
    "elevation(Subject,Action), "
    "current_effect(_,Action,external_call(Action,Marker)), "
    'is(_,Marker,"external_net").',
    "owasp_api8_misconfig(Subject,Action,Witness) :- "
    'disclosure(Subject,Action,Witness), current_has(_,Witness,"verbose").',
    "owasp_api9_inventory(Action,Subject) :- "
    'elevation(Subject,Action), is(_,Action,"deprecated").',
    "owasp_api10_unsafe_consumption(Action,Subject) :- "
    'tampering(Action,Subject), current_has(_,Action,"downstream_trust").',
    "owasp_a01_access_control(Action,Subject) :- elevation(Subject,Action).",
    "owasp_a02_crypto(Subject,Action,Witness) :- "
    'disclosure(Subject,Action,Witness), current_has(_,Witness,"sensitive").',
    "owasp_a02_crypto(Action,Witness,Subject) :- "
    'spoofing(Action,Witness,Subject), current_has(_,Witness,"weak_binding").',
    "owasp_a03_injection(Action,Subject,Sink) :- "
    "tampering(Action,Subject), "
    'current_has(_,input_field(Action,Field),"attacker_controlled"), '
    "reaches_plus(_,input_field(Action,Field),Sink), "
    'is(_,Sink,"interpreter").',
    "owasp_a05_misconfig(Subject,Action,Witness) :- "
    "owasp_api8_misconfig(Subject,Action,Witness).",
    "owasp_a06_components(Action,Subject) :- "
    'tampering(Action,Subject), current_has(_,Action,"component").',
    "owasp_a07_auth(Action,Witness,Subject) :- spoofing(Action,Witness,Subject).",
    "owasp_a08_integrity(Action,Subject) :- "
    'tampering(Action,Subject), current_has(_,Action,"unverified_source").',
    "owasp_a09_logging(Action,Subject) :- repudiation(Action,Subject).",
    "owasp_a10_ssrf(Action,Subject) :- owasp_api7_ssrf(Action,Subject).",
)


@dataclass(frozen=True, slots=True)
class ClingoSolution:
    """One stable model produced by Clingo."""

    atoms: tuple[str, ...]

    def contains(self, atom: str) -> bool:
        return atom in self.atoms


@dataclass(frozen=True, slots=True)
class ClingoLimits:
    """Search bounds for one in-process Clingo solve.

    The library ``Control`` API exposes conflict/restart limits, but not the
    command-line application's process-wide time and memory limits.
    """

    max_conflicts: int = 100_000
    max_restarts: int = 100_000

    def __post_init__(self) -> None:
        if self.max_conflicts <= 0:
            raise ValueError("max_conflicts must be positive")
        if self.max_restarts <= 0:
            raise ValueError("max_restarts must be positive")

    @property
    def solve_limit(self) -> str:
        return f"{self.max_conflicts},{self.max_restarts}"


DEFAULT_CLINGO_LIMITS = ClingoLimits()


class ClingoEngine:
    """Evaluate a QDL graph with the Clingo ASP solver."""

    def __init__(
        self,
        policy_rule_pack: PolicyRulePack = DEFAULT_POLICY_RULE_PACK,
        *,
        limits: ClingoLimits = DEFAULT_CLINGO_LIMITS,
        threat_rule_pack: ThreatRulePack = DEFAULT_THREAT_RULE_PACK,
    ) -> None:
        self._policy_rule_pack = policy_rule_pack
        self._limits = limits
        self._threat_rule_pack = threat_rule_pack

    def compile(
        self,
        graph: QdlGraph,
        *,
        closures: str | Iterable[str] | None = None,
        algebra: bool = False,
        threat_rules: bool = False,
    ) -> str:
        """Compile a QDL graph and optionally its closure/algebra layers."""
        if algebra and threat_rules:
            raise ValueError("algebra and threat rules are separate solve layers")
        lines: list[str] = []

        if algebra:
            facts, rules = _algebra_view(graph)
        elif threat_rules:
            facts, rules = _threat_view(graph)
        else:
            facts, rules = graph.facts, graph.rules

        for fact in facts:
            lines.append(f"{_fact_atom(fact)}.")
        for rule in rules:
            lines.append(f"{_rule_statement(rule)}.")
        for name in sorted(resolve_closures(closures)):
            lines.extend(CLOSURE_RULES[name])
        if threat_rules:
            lines.extend(CLOSURE_RULES["reaches_plus"])
            for name in sorted(resolve_closures({"current_reached", "current_has"})):
                lines.extend(CLOSURE_RULES[name])
        if algebra:
            for name in _ALGEBRA_CLOSURES:
                lines.extend(CLOSURE_RULES[name])
            lines.extend(self._policy_rule_pack.rules)
            lines.extend(_ALGEBRA_RULES)
        if threat_rules:
            lines.extend(self._threat_rule_pack.rules)

        return "\n".join(lines) + ("\n" if lines else "")

    def compile_statements(
        self,
        facts: Iterable[Fact] = (),
        rules: Iterable[Rule] = (),
    ) -> str:
        """Compile bare facts and rules without graph validation.

        Incremental grounding appends statements from an already validated
        graph to an existing program; references may be declared in the
        base program rather than in this fragment.
        """

        lines = [f"{_fact_atom(fact)}." for fact in facts]
        lines.extend(f"{_rule_statement(rule)}." for rule in rules)
        return "\n".join(lines) + ("\n" if lines else "")

    def solve(
        self,
        graph: QdlGraph,
        *,
        max_models: int = 1,
        closures: str | Iterable[str] | None = None,
        algebra: bool = False,
        threat_rules: bool = False,
        query_rules: Iterable[str] = (),
    ) -> tuple[ClingoSolution, ...]:
        """Evaluate a graph and optionally materialize closure predicates."""
        if max_models < 0:
            raise ValueError("max_models must not be negative")

        program = self.compile(
            graph,
            closures=closures,
            algebra=algebra,
            threat_rules=threat_rules,
        )
        program += "\n".join(query_rules)
        return self.solve_program(program, max_models=max_models)

    def solve_program(
        self,
        program: str,
        *,
        max_models: int = 1,
    ) -> tuple[ClingoSolution, ...]:
        """Solve a generated ASP query through the single QDL engine.

        Query layers such as the deterministic state-machine verifier may add
        bounded rules to a graph program.  They still go through this method,
        rather than constructing a second ``clingo.Control`` themselves.  The
        method deliberately accepts only already-generated program text; it
        does not become a second surface language or a persistence boundary.
        """

        if max_models < 0:
            raise ValueError("max_models must not be negative")
        session = self.program_session(max_models=max_models)
        session.add("base", program)
        session.ground([("base", [])])
        return session.solve()

    def program_session(self, *, max_models: int = 1) -> ClingoProgramSession:
        """Create a bounded incremental program session.

        Application query projections may need to ground a base and a rule
        part separately, or rebuild them after a graph revision.  They receive
        this narrow session instead of reaching into the Clingo API directly.
        """

        if max_models < 0:
            raise ValueError("max_models must not be negative")
        return ClingoProgramSession(self, max_models=max_models)

    def _solve_control(
        self,
        control: clingo.Control,
        *,
        max_models: int,
    ) -> tuple[ClingoSolution, ...]:
        """Collect stable models from a control owned by this engine."""

        models: list[ClingoSolution] = []
        with control.solve(yield_=True) as handle:
            for model in handle:
                atoms = tuple(
                    sorted(str(symbol) for symbol in model.symbols(atoms=True))
                )
                models.append(ClingoSolution(atoms))
                if max_models and len(models) >= max_models:
                    break
            result = handle.get()
        if result.unknown:
            raise RuntimeError("Clingo solve limit reached before completion")
        return tuple(models)

    def reaches_plus_pairs(self, graph: QdlGraph) -> tuple[tuple[Term, Term], ...]:
        """Return direct and transitive QDL dataflow pairs from Clingo."""

        solutions = self.solve(graph, closures={"reaches_plus"})
        if not solutions:
            return ()

        pairs: set[tuple[Term, Term]] = set()
        for atom in solutions[0].atoms:
            symbol = clingo.parse_term(atom)
            if (
                symbol.type != clingo.SymbolType.Function
                or symbol.name != "reaches_plus"
                or len(symbol.arguments) != 3
            ):
                continue
            source = decode_term(symbol.arguments[1])
            target = decode_term(symbol.arguments[2])
            pairs.add((source, target))
        return tuple(
            sorted(
                pairs,
                key=lambda pair: (
                    canonical_json(pair[0]),
                    canonical_json(pair[1]),
                ),
            )
        )

    def derive_may_triples(self, graph: QdlGraph) -> tuple[tuple[str, str, str], ...]:
        """Return exact principal/action/resource decisions from QDL policy.

        A successfully returned empty tuple is a completed negative query.
        Solver errors and absence of a stable model propagate to consumers;
        neither establishes absence of permission.
        """

        solutions = self.solve(graph, algebra=True)
        if not solutions:
            raise RuntimeError("clingo returned no stable model")

        triples: set[tuple[str, str, str]] = set()
        for atom in solutions[0].atoms:
            symbol = clingo.parse_term(atom)
            if (
                symbol.type != clingo.SymbolType.Function
                or symbol.name != "may"
                or len(symbol.arguments) != 4
            ):
                continue
            principal = decode_term(symbol.arguments[1])
            action = decode_term(symbol.arguments[2])
            resource = decode_term(symbol.arguments[3])
            if not all(
                isinstance(term, Atom) for term in (principal, action, resource)
            ):
                continue
            triples.add((str(principal.value), str(action.value), str(resource.value)))
        return tuple(sorted(triples))

    def derive_may_pairs(self, graph: QdlGraph) -> tuple[tuple[str, str], ...]:
        """Project permitted principal/action pairs for action-level consumers."""

        return tuple(
            sorted(
                {
                    (principal, action)
                    for principal, action, _resource in self.derive_may_triples(graph)
                }
            )
        )

    def find_path(
        self,
        graph: QdlGraph,
        relation: str,
        start: str,
        target: str,
        *,
        context: Context = Context.CONTRACT,
        max_depth: int | None = None,
    ) -> tuple[str, ...] | None:
        """Find the shortest deterministic path in one QDL context.

        ``relation`` may name a base binary relation (``part``, ``requires``,
        or ``chain``), its closure alias, or the mixed-edge ``reachable``
        relation.  The result contains the source, every intermediate node,
        and the target.  A missing endpoint or unreachable target returns
        ``None``.
        """
        edges = _PATH_EDGE_BODIES.get(relation)
        if edges is None:
            supported = ", ".join(sorted(_PATH_EDGE_BODIES))
            raise ValueError(
                f"unsupported path relation: {relation}; expected one of {supported}"
            )

        declared = _declared_terms(graph, context)
        if (
            canonical_json(Atom(value=start)) not in declared
            or canonical_json(Atom(value=target)) not in declared
        ):
            return None

        if max_depth is None:
            depth = max(1, len(declared) - 1)
        else:
            if max_depth <= 0:
                raise ValueError("max_depth must be positive")
            depth = max_depth

        context_term = _string(context.value)
        start_term = _string(start)
        program = self.compile(graph)
        program += "\n".join(CLOSURE_RULES["current_effect"]) + "\n"
        program += f"#const max_depth={depth}.\n"
        program += f"_clingo_path({context_term},{start_term},{start_term},nil,0).\n"
        for edge in edges:
            program += (
                "_clingo_path("
                f"{context_term},{start_term},Target,cons(Target,Path),Depth+1"
                ") :- "
                f"_clingo_path({context_term},{start_term},Middle,Path,Depth), "
                f"{edge.format(context=context_term, source='Middle', target='Target')}, "
                "Depth < max_depth.\n"
            )

        paths: list[tuple[int, tuple[str, ...], str]] = []
        for symbol in self._first_model(program):
            if symbol.name != "_clingo_path" or len(symbol.arguments) != 5:
                continue
            symbol_context, symbol_start, symbol_target, path, depth_symbol = (
                symbol.arguments
            )
            if (
                _value(symbol_context) != context.value
                or _value(symbol_start) != start
                or _value(symbol_target) != target
            ):
                continue
            path_depth = depth_symbol.number
            nodes = (start,) if path_depth == 0 else path_nodes(path)
            if path_depth > 0 and nodes is not None:
                nodes = (start, *nodes)
            if nodes is not None:
                paths.append((path_depth, nodes, str(path)))

        if not paths:
            return None
        return min(paths, key=lambda item: (item[0], item[1], item[2]))[1]

    def _first_model(self, program: str) -> tuple[clingo.Symbol, ...]:
        solutions = self.solve_program(program, max_models=1)
        if not solutions:
            return ()
        return tuple(clingo.parse_term(atom) for atom in solutions[0].atoms)

    def _create_control(self, *, models: int) -> clingo.Control:
        control = clingo.Control()
        control.configuration.solve.solve_limit = self._limits.solve_limit
        control.configuration.solve.models = models
        return control


class ClingoProgramSession:
    """Small incremental program API owned by :class:`ClingoEngine`."""

    def __init__(self, engine: ClingoEngine, *, max_models: int) -> None:
        self._engine = engine
        self._max_models = max_models
        self._control: clingo.Control | None = None
        self.reset()

    def reset(self) -> None:
        """Discard the current grounded program and create a fresh one."""

        self._control = self._engine._create_control(models=self._max_models)

    def add(self, name: str, program: str) -> None:
        """Add one named non-ground program part."""

        assert self._control is not None
        self._control.add(name, [], program)

    def ground(self, parts: Iterable[tuple[str, Iterable[object]]]) -> None:
        """Ground named program parts in the underlying Clingo instance."""

        assert self._control is not None
        self._control.ground(parts)

    def solve(self) -> tuple[ClingoSolution, ...]:
        """Return stable models through the owning engine."""

        assert self._control is not None
        return self._engine._solve_control(
            self._control,
            max_models=self._max_models,
        )


def _fact_atom(fact: Fact) -> str:
    arguments = [
        _string(fact.context.value),
        *(encode_term(term) for term in fact.args),
    ]
    return _application(fact.predicate.name, arguments)


def _rule_statement(rule: Rule) -> str:
    body = ", ".join(_fact_atom(literal) for literal in rule.body)
    head = ", ".join(_fact_atom(literal) for literal in rule.head)
    return f"{head} :- {body}"


def _string(value: str) -> str:
    return asp_string(value)


def _application(name: str, arguments: list[str]) -> str:
    return f"{name}({','.join(arguments)})"


def resolve_closures(closures: str | Iterable[str] | None) -> set[str]:
    if closures is None:
        requested: set[str] = set()
    elif isinstance(closures, str):
        requested = {closures} if closures else set()
    else:
        requested = set(closures)

    unknown = requested - CLOSURE_PREDICATES
    if unknown:
        raise ValueError("unknown closure predicate(s): " + ", ".join(sorted(unknown)))

    resolved: set[str] = set()
    pending = list(requested)
    while pending:
        name = pending.pop()
        if name in resolved:
            continue
        resolved.add(name)
        pending.extend(_CLOSURE_DEPENDENCIES[name])
    return resolved


def _declared_terms(graph: QdlGraph, context: Context) -> set[str]:
    return {
        canonical_json(fact.args[0])
        for fact in graph.facts
        if fact.context == context and fact.predicate.name == "is"
    }


def _value(symbol: clingo.Symbol) -> object:
    term = decode_term(symbol)
    if isinstance(term, Atom):
        return term.value
    return str(symbol)


def _algebra_view(graph: QdlGraph) -> tuple[tuple[Fact, ...], tuple[Rule, ...]]:
    """Keep only contexts that may participate in executable algebra."""

    contexts = {Context.CONTRACT, Context.ACCEPTED}
    facts = tuple(fact for fact in graph.facts if fact.context in contexts)
    rules = tuple(
        rule
        for rule in graph.rules
        if all(literal.context in contexts for literal in (*rule.body, *rule.head))
    )
    return facts, rules


def _threat_view(graph: QdlGraph) -> tuple[tuple[Fact, ...], tuple[Rule, ...]]:
    """Keep contract, accepted, and runtime facts for post-observation rules."""

    contexts = {Context.CONTRACT, Context.ACCEPTED, Context.RUNTIME}
    facts = tuple(fact for fact in graph.facts if fact.context in contexts)
    rules = tuple(
        rule
        for rule in graph.rules
        if all(literal.context in contexts for literal in (*rule.body, *rule.head))
    )
    return facts, rules


def path_nodes(path: clingo.Symbol) -> tuple[str, ...] | None:
    """Decode a ``cons``/``nil`` walk term into its node sequence."""

    nodes: list[str] = []
    while path.type == clingo.SymbolType.Function and path.name == "cons":
        if len(path.arguments) != 2:
            return None
        nodes.append(str(_value(path.arguments[0])))
        path = path.arguments[1]
    if path.type != clingo.SymbolType.Function or path.name != "nil":
        return None
    return tuple(reversed(nodes))
