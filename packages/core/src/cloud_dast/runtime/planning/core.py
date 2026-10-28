"""Build runtime-owned executable views directly from a QDL graph.

The ordinary planner is a pure runtime projection service; the optional
incremental variant reuses unchanged Clingo snapshots with the same projection.  It accepts one immutable QDL graph,
uses the formal Clingo and state-machine engines for reasoning, and returns a
derived ``QdlPlan``.  The plan never becomes a second source of truth.
The input graph may contain contract, proposal, accepted, and runtime facts.
By default only contract and accepted contexts produce bound paths; proposal
and runtime facts remain non-executable provenance unless explicitly selected.
``PLANNING_CONTEXTS``, the ``QdlPlan`` fields, and the planner defaults are
the runtime surface projected into the S22R documentation invariant.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

import clingo

from cloud_dast.config import QDL_MAX_DEPTH
from cloud_dast.qdl.engine import (
    CLOSURE_PREDICATES,
    CLOSURE_RULES,
    ClingoEngine,
    resolve_closures,
)
from cloud_dast.qdl.graph import (
    Context,
    QdlGraph,
    canonical_json,
)
from cloud_dast.qdl.reasoning import (
    QdlClosure,
    QdlPlan,
)
from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
)
from cloud_dast.runtime.planning.attacks import (
    _attack_paths_from_symbols,
    _reveal_edges,
)
from cloud_dast.runtime.planning.invariants import compile_invariants
from cloud_dast.runtime.planning.rules import _CHAIN_RULES, _WALK_RULES
from cloud_dast.runtime.planning.states import (
    find_resource_state_paths,
    find_state_paths,
)
from cloud_dast.runtime.planning.symbols import _closure_symbols
from cloud_dast.verification.norms import NormCompiler

PLANNING_CONTEXTS: tuple[Context, ...] = (Context.CONTRACT, Context.ACCEPTED)
ATTACK_CLOSURE = "chain_plus"


class QdlPlanner:
    """Build attack, state-machine, and invariant views from QDL facts."""

    def __init__(
        self,
        *,
        max_depth: int = QDL_MAX_DEPTH,
        closure_relations: Iterable[str] = (ATTACK_CLOSURE,),
        contexts: Iterable[Context] = PLANNING_CONTEXTS,
        clingo_engine: ClingoEngine | None = None,
        state_machine_engine: StateMachineEngine | None = None,
        norm_compiler: NormCompiler | None = None,
    ) -> None:
        if max_depth <= 0:
            raise ValueError("max_depth must be positive")

        relations = tuple(dict.fromkeys(closure_relations))
        unknown = set(relations) - CLOSURE_PREDICATES
        if unknown:
            raise ValueError(
                "unknown closure predicate(s): " + ", ".join(sorted(unknown))
            )

        self._max_depth = max_depth
        self._closure_relations = relations
        self._contexts = tuple(
            sorted(dict.fromkeys(contexts), key=lambda context: context.value)
        )
        self._clingo = clingo_engine or ClingoEngine()
        self._state_machine = state_machine_engine or StateMachineEngine(
            max_depth=max_depth
        )
        self._norm_compiler = norm_compiler or NormCompiler()

    def plan(self, graph: QdlGraph) -> QdlPlan:
        """Return all bounded execution views for one QDL graph."""

        symbols = self._solve_walk_edges(graph)
        pairs = sorted(_closure_symbols(symbols))
        state_paths, forbidden_paths = find_state_paths(
            graph,
            self._contexts,
            self._state_machine,
        )
        resource_state_paths = find_resource_state_paths(
            graph,
            self._contexts,
            self._state_machine,
        )
        return QdlPlan(
            graph_hash=graph.content_hash,
            attack_paths=_attack_paths_from_symbols(
                graph, symbols, self._contexts, PLANNING_CONTEXTS
            ),
            state_paths=state_paths,
            resource_state_paths=resource_state_paths,
            forbidden_paths=forbidden_paths,
            invariants=compile_invariants(graph, self._norm_compiler),
            reveal_edges=_reveal_edges(symbols, self._contexts),
            closures=tuple(
                QdlClosure(
                    context=context,
                    relation=relation,
                    source=source,
                    target=target,
                )
                for context, relation, source, target in pairs
                if relation in self._closure_relations and context in self._contexts
            ),
        )

    def _solve_walk_edges(self, graph: QdlGraph) -> tuple[clingo.Symbol, ...]:
        """Materialize the bounded walk and its derived edges with Clingo."""

        program = self._clingo.compile(graph)
        for name in sorted(
            resolve_closures({ATTACK_CLOSURE, "current_has", *self._closure_relations})
        ):
            rules = _CHAIN_RULES if name == ATTACK_CLOSURE else CLOSURE_RULES[name]
            program += "\n".join(rules) + "\n"
        program += f"#const qdl_max_depth={self._max_depth}.\n"
        program += "\n".join(_WALK_RULES) + "\n"
        solutions = self._clingo.solve_program(program, max_models=1)
        if solutions:
            return tuple(clingo.parse_term(atom) for atom in solutions[0].atoms)
        raise RuntimeError("Clingo returned no model for the QDL graph")


logger = logging.getLogger("cloud_dast.runtime.incremental_planning")


class IncrementalQdlPlanner(QdlPlanner):
    """Reuse unchanged Clingo snapshots while sharing the complete plan projection.

    Any fact or rule change rebuilds the session: append-only input can still
    retract conclusions through default negation or supersession.
    """

    def __init__(
        self,
        *,
        max_depth: int = QDL_MAX_DEPTH,
        closure_relations: Iterable[str] = (ATTACK_CLOSURE,),
        contexts: Iterable[Context] = PLANNING_CONTEXTS,
        state_machine_engine: StateMachineEngine | None = None,
        norm_compiler: NormCompiler | None = None,
        clingo_engine: ClingoEngine | None = None,
    ) -> None:
        super().__init__(
            max_depth=max_depth,
            closure_relations=closure_relations,
            contexts=contexts,
            state_machine_engine=state_machine_engine,
            norm_compiler=norm_compiler,
            clingo_engine=clingo_engine,
        )
        self._program_session = self._clingo.program_session(max_models=1)
        self._closure_names = resolve_closures(
            {ATTACK_CLOSURE, "current_has", *self._closure_relations}
        )
        self._grounded_facts: set[str] = set()
        self._grounded_rules: set[str] = set()
        self._version = 0
        self._started = False

    def _solve_walk_edges(self, graph: QdlGraph) -> tuple[clingo.Symbol, ...]:
        if not self._started:
            self._ground_base(graph)
        else:
            self._rebuild_changed(graph)
        return self._solve()

    @property
    def grounded_batches(self) -> int:
        """Number of appended snapshot revisions since the last input retraction."""

        return self._version

    def _ground_base(self, graph: QdlGraph) -> None:
        self._program_session.reset()
        program = self._clingo.compile_statements(graph.facts)
        program += f"#const qdl_max_depth={self._max_depth}.\n"
        self._program_session.add("base", program)
        rules = self._clingo.compile_statements(rules=graph.rules)
        for name in sorted(self._closure_names):
            closure = _CHAIN_RULES if name == ATTACK_CLOSURE else CLOSURE_RULES[name]
            rules += "\n".join(closure) + "\n"
        rules += "\n".join(_WALK_RULES) + "\n"
        self._program_session.add("rules", rules)
        self._program_session.ground([("base", []), ("rules", [])])
        self._grounded_facts = {canonical_json(fact) for fact in graph.facts}
        self._grounded_rules = {canonical_json(rule) for rule in graph.rules}
        self._started = True

    def _rebuild_changed(self, graph: QdlGraph) -> None:
        """Invalidate changed snapshots, including append-only revisions.

        Grounding may simplify a negated premise to true when its atom is
        absent. Later additions cannot retract that old rule instance.
        Rebuild for any input change, including arbitrary QDL rule premises,
        rather than guessing which additions invalidate current projections.
        """

        fact_keys = {canonical_json(fact) for fact in graph.facts}
        rule_keys = {canonical_json(rule) for rule in graph.rules}
        missing_facts = sorted(self._grounded_facts - fact_keys)
        missing_rules = sorted(self._grounded_rules - rule_keys)
        if fact_keys == self._grounded_facts and rule_keys == self._grounded_rules:
            return

        if missing_facts or missing_rules:
            logger.warning(
                "qdl_planner_non_monotonic_rebuild missing_facts=%d "
                "missing_rules=%d examples=%s",
                len(missing_facts),
                len(missing_rules),
                "; ".join((*missing_facts[:5], *missing_rules[:2]))[:500],
            )
            self._version = 0
        else:
            self._version += 1
        self._ground_base(graph)

    def _solve(self) -> tuple[clingo.Symbol, ...]:
        solutions = self._program_session.solve()
        if solutions:
            return tuple(clingo.parse_term(atom) for atom in solutions[0].atoms)
        raise RuntimeError("Clingo returned no model for the incremental program")
