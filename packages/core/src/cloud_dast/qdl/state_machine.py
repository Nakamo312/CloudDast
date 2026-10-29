"""QDL state-machine semantics and business-logic violation search.

A state machine is not a second source of truth.  States, actions, norms,
initial states, transitions, and forbidden states are ordinary QDL facts.
This module only adds a Clingo-backed query layer that computes reachability,
bounded paths, runtime-grounded forbidden states, and stratified mismatches.
Depth-limited solves report ``bounded_incomplete`` instead of presenting a
truncated search as a complete absence result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

import clingo

from cloud_dast.config import QDL_MAX_DEPTH
from cloud_dast.qdl.asp import asp_string
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    PredicateSchema,
    QdlGraph,
    TermKind,
)


@dataclass(frozen=True, slots=True)
class StatePath:
    """One bounded path through a QDL state machine."""

    initial_state: str
    final_state: str
    actions: tuple[str, ...]
    depth: int


@dataclass(frozen=True, slots=True)
class ResourceTransition:
    """One resource-specific transition derived from QDL facts.

    The persisted basis keeps the action-level ``transition(A, Q0, Q)`` edge
    and the resource binding ``precondition(A, R, Q0)`` separate.  The query
    layer joins them into the resource-aware relation
    ``transition(A, R, Q0, Q)``; it never persists a second source of truth.
    """

    action: str
    resource: str
    from_state: str
    to_state: str


@dataclass(frozen=True, slots=True)
class ResourceStatePath:
    """One bounded path for one resource's state."""

    resource: str
    initial_state: str
    final_state: str
    actions: tuple[str, ...]
    states: tuple[str, ...]
    depth: int


class StateMachineStatus(StrEnum):
    """Completeness of one bounded state-machine solve."""

    COMPLETE = "complete"
    BOUNDED_INCOMPLETE = "bounded_incomplete"


@dataclass(frozen=True, slots=True)
class StateMachineViolation:
    """A forbidden state, with runtime evidence when one is available."""

    norm: str
    state: str
    path: StatePath
    grounded: bool = False
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StateMachineSolution:
    """Reachability and violation results for one state-machine graph."""

    reachable_states: tuple[str, ...]
    violations: tuple[StateMachineViolation, ...]
    status: StateMachineStatus = StateMachineStatus.COMPLETE

    @property
    def grounded_violations(self) -> tuple[StateMachineViolation, ...]:
        return tuple(violation for violation in self.violations if violation.grounded)


@dataclass(frozen=True, slots=True)
class ResourceStateMachineSolution:
    """Resource-indexed reachability and bounded witnesses."""

    states: Mapping[str, tuple[str, ...]]
    transitions: tuple[ResourceTransition, ...]
    paths: tuple[ResourceStatePath, ...]
    status: StateMachineStatus = StateMachineStatus.COMPLETE


@dataclass(frozen=True, slots=True)
class StateMachineMismatch:
    """An observed transition absent from the specification."""

    action: str
    from_state: str
    to_state: str


@dataclass(frozen=True, slots=True)
class StateMachineLearningMismatch:
    """A learned transition that conflicts with a declared specification edge."""

    action: str
    from_state: str
    learned_to_state: str
    declared_to_state: str


@dataclass(frozen=True, slots=True)
class StateMachineLearningReview:
    """Mismatches and deficits produced by comparing a learned FSM proposal."""

    mismatches: tuple[StateMachineLearningMismatch, ...]
    deficits: tuple[Fact, ...]


def _reference(name: str) -> ArgumentSchema:
    return ArgumentSchema(
        name=name,
        ground_types=(TermKind.ATOM,),
        atom_types=("string",),
        reference=True,
    )


STATE_MACHINE_PREDICATE_SCHEMAS: tuple[PredicateSchema, ...] = (
    PredicateSchema(
        name="state",
        arguments=(
            _reference("resource"),
            _reference("state"),
        ),
    ),
    PredicateSchema(
        name="precondition",
        arguments=(
            _reference("action"),
            _reference("resource"),
            _reference("state"),
        ),
    ),
)

_PREDICATES = {
    **{
        name: Predicate.from_name(name)
        for name in ("transition", "initial", "forbidden")
    },
    **{
        schema.name: Predicate.from_schema(schema)
        for schema in STATE_MACHINE_PREDICATE_SCHEMAS
    },
}
_PARTIAL_SOURCE_STATE = "unknown"
INSUFFICIENT_TRACE_EVIDENCE = "insufficient_trace_evidence"
LEARNED_TRANSITION_CONFLICT = "learned_transition_conflict"
STATE_SEMANTICS_DEFICIT = Predicate.from_schema(
    PredicateSchema(
        name="state_semantics_deficit",
        arguments=(
            ArgumentSchema(
                name="action",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
                reference=True,
            ),
            ArgumentSchema(
                name="reason",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
            ),
        ),
    )
)


def state_semantics_deficit_fact(
    action_id: str,
    reason: str,
    *,
    context: Context = Context.PROPOSAL,
) -> Fact:
    """Build one action-scoped state-semantics deficit fact."""

    if not action_id.strip():
        raise ValueError("state semantics deficit action must not be empty")
    if not reason.strip():
        raise ValueError("state semantics deficit reason must not be empty")
    return Fact(
        context=context,
        predicate=STATE_SEMANTICS_DEFICIT,
        args=(Atom(value=action_id), Atom(value=reason)),
    )


def state_fact(state_id: str, context: Context = Context.CONTRACT) -> Fact:
    return _is_fact(state_id, "State", context)


def action_fact(action_id: str, context: Context = Context.CONTRACT) -> Fact:
    return _is_fact(action_id, "Action", context)


def norm_fact(norm_id: str, context: Context = Context.CONTRACT) -> Fact:
    return _is_fact(norm_id, "Norm", context)


def initial_fact(state_id: str, context: Context = Context.CONTRACT) -> Fact:
    return _fact("initial", (state_id,), context)


def transition_fact(
    action_id: str,
    from_state_id: str,
    to_state_id: str,
    context: Context = Context.CONTRACT,
) -> Fact:
    return _fact("transition", (action_id, from_state_id, to_state_id), context)


def observed_transition_fact(
    action_id: str,
    from_state_id: str,
    to_state_id: str,
    context: Context = Context.RUNTIME,
) -> Fact:
    """Build a runtime transition fact for specification comparison."""

    return transition_fact(action_id, from_state_id, to_state_id, context)


def resource_fact(resource_id: str, context: Context = Context.CONTRACT) -> Fact:
    """Declare one resource type that owns a state."""

    return _is_fact(resource_id, "ResourceType", context)


def resource_state_fact(
    resource_id: str,
    state_id: str,
    context: Context = Context.CONTRACT,
) -> Fact:
    """Build the ``state(Resource, State)`` QDL fact."""

    return _fact("state", (resource_id, state_id), context)


def precondition_fact(
    action_id: str,
    resource_id: str,
    state_id: str,
    context: Context = Context.CONTRACT,
) -> Fact:
    """Build the ``precondition(Action, Resource, State)`` QDL fact."""

    return _fact("precondition", (action_id, resource_id, state_id), context)


def resource_transition_facts(
    action_id: str,
    resource_id: str,
    from_state_id: str,
    to_state_id: str,
    context: Context = Context.CONTRACT,
) -> tuple[Fact, Fact]:
    """Build the persisted basis of one resource transition.

    QDL's built-in action edge is three-ary.  Resource identity is represented
    by the explicit precondition fact, and the state-machine query derives the
    four-ary ``transition(Action, Resource, Q0, Q)`` relation from that join.
    """

    return (
        transition_fact(action_id, from_state_id, to_state_id, context),
        precondition_fact(action_id, resource_id, from_state_id, context),
    )


def forbidden_fact(
    norm_id: str,
    state_id: str,
    context: Context = Context.CONTRACT,
) -> Fact:
    return _fact("forbidden", (norm_id, state_id), context)


def state_machine_graph(
    *,
    states: tuple[str, ...] = (),
    actions: tuple[str, ...] = (),
    norms: tuple[str, ...] = (),
    initial_states: tuple[str, ...] = (),
    transitions: tuple[tuple[str, str, str], ...] = (),
    forbidden_states: tuple[tuple[str, str], ...] = (),
    observed_transitions: tuple[tuple[str, str, str], ...] = (),
    context: Context = Context.CONTRACT,
    observed_context: Context = Context.RUNTIME,
) -> QdlGraph:
    """Build a closed QDL state-machine graph for tests and adapters.

    The builder is not persisted as a separate model.  It emits ordinary QDL
    facts and declares every referenced state, action, and norm through ``is``.
    ``observed_transitions`` are emitted in a separate context so they can be
    compared with the specification by :meth:`StateMachineEngine.mismatches`.
    """

    context_states = {
        *states,
        *initial_states,
        *(from_state for _, from_state, _ in transitions),
        *(to_state for _, _, to_state in transitions),
        *(state for _, state in forbidden_states),
    }
    context_actions = {
        *actions,
        *(action for action, _, _ in transitions),
    }
    context_norms = {
        *norms,
        *(norm for norm, _ in forbidden_states),
    }

    observed_states = {
        *(from_state for _, from_state, _ in observed_transitions),
        *(to_state for _, _, to_state in observed_transitions),
    }
    observed_actions = {action for action, _, _ in observed_transitions}

    if observed_context == context:
        context_states.update(observed_states)
        context_actions.update(observed_actions)

    facts: list[Fact] = [
        *(state_fact(state_id, context) for state_id in sorted(context_states)),
        *(action_fact(action_id, context) for action_id in sorted(context_actions)),
        *(norm_fact(norm_id, context) for norm_id in sorted(context_norms)),
        *(initial_fact(state_id, context) for state_id in initial_states),
        *(
            transition_fact(action_id, from_state_id, to_state_id, context)
            for action_id, from_state_id, to_state_id in transitions
        ),
        *(
            forbidden_fact(norm_id, state_id, context)
            for norm_id, state_id in forbidden_states
        ),
    ]

    if observed_context != context:
        facts.extend(
            state_fact(state_id, observed_context)
            for state_id in sorted(observed_states)
        )
        facts.extend(
            action_fact(action_id, observed_context)
            for action_id in sorted(observed_actions)
        )

    facts.extend(
        observed_transition_fact(
            action_id,
            from_state_id,
            to_state_id,
            observed_context,
        )
        for action_id, from_state_id, to_state_id in observed_transitions
    )

    return QdlGraph(facts=tuple(facts))


def resource_state_machine_graph(
    *,
    resources: tuple[str, ...] = (),
    actions: tuple[str, ...] = (),
    resource_states: Mapping[str, str] = MappingProxyType({}),
    resource_transitions: tuple[tuple[str, str, str, str], ...] = (),
    context: Context = Context.CONTRACT,
) -> QdlGraph:
    """Build a closed per-resource state-machine graph.

    ``resource_states`` is the initial ``Resource -> State`` map.  Each
    transition contributes the action-level edge and its resource-specific
    precondition.  The graph remains ordinary QDL; resource-aware transitions
    are derived by :class:`StateMachineEngine`, not stored as a parallel model.
    """

    context_resources = {
        *resources,
        *resource_states,
        *(
            resource
            for _action, resource, _from_state, _to_state in resource_transitions
        ),
    }
    context_actions = {
        *actions,
        *(action for action, _resource, _from_state, _to_state in resource_transitions),
    }
    context_states = {
        *resource_states.values(),
        *(
            state
            for _action, _resource, from_state, to_state in resource_transitions
            for state in (from_state, to_state)
        ),
    }

    base_transitions = tuple(
        dict.fromkeys(
            (action, from_state, to_state)
            for action, _resource, from_state, to_state in resource_transitions
        )
    )
    preconditions = tuple(
        dict.fromkeys(
            (action, resource, from_state)
            for action, resource, from_state, _to_state in resource_transitions
        )
    )

    facts: list[Fact] = [
        *(resource_fact(resource, context) for resource in sorted(context_resources)),
        *(action_fact(action, context) for action in sorted(context_actions)),
        *(state_fact(state, context) for state in sorted(context_states)),
        *(
            resource_state_fact(resource, state, context)
            for resource, state in sorted(resource_states.items())
        ),
        *(
            transition_fact(action, from_state, to_state, context)
            for action, from_state, to_state in base_transitions
        ),
        *(
            precondition_fact(action, resource, from_state, context)
            for action, resource, from_state in preconditions
        ),
    ]
    return QdlGraph(facts=tuple(facts))


class StateMachineEngine:
    """Compute state reachability with the library-backed Clingo solver."""

    def __init__(self, *, max_depth: int = QDL_MAX_DEPTH) -> None:
        if max_depth <= 0:
            raise ValueError("max_depth must be positive")
        self._max_depth = max_depth
        self._clingo = ClingoEngine()

    def solve(
        self,
        graph: QdlGraph,
        *,
        context: Context = Context.CONTRACT,
        observed_context: Context = Context.RUNTIME,
    ) -> StateMachineSolution:
        """Return reachability, witnesses, and runtime-grounded violations."""

        program = self._program(graph, context, observed_context)
        model = self._first_model(program)

        reachable: set[str] = set()
        violations: dict[tuple[str, str], StateMachineViolation] = {}
        runtime: dict[tuple[str, str], StatePath] = {}
        bounded_incomplete = False
        for symbol in model:
            if symbol.name == "reachable" and len(symbol.arguments) == 2:
                reachable.add(_string(symbol.arguments[1]))
            elif symbol.name == "spec_violation" and len(symbol.arguments) == 6:
                arguments = symbol.arguments
                norm = _string(arguments[1])
                state = _string(arguments[2])
                path = StatePath(
                    initial_state=_string(arguments[3]),
                    final_state=state,
                    actions=_path_actions(arguments[4]),
                    depth=_integer(arguments[5]),
                )
                candidate = StateMachineViolation(
                    norm=norm,
                    state=state,
                    path=path,
                    grounded=False,
                )
                key = (norm, state)
                existing = violations.get(key)
                if existing is None or _path_order(path) < _path_order(existing.path):
                    violations[key] = candidate
            elif symbol.name == "grounded_violation" and len(symbol.arguments) == 4:
                arguments = symbol.arguments
                norm = _string(arguments[0])
                state = _string(arguments[1])
                action = _string(arguments[2])
                initial_state = _string(arguments[3])
                path = StatePath(
                    initial_state=initial_state,
                    final_state=state,
                    actions=(action,),
                    depth=1,
                )
                key = (norm, state)
                existing_path = runtime.get(key, path)
                runtime[key] = min(existing_path, path, key=_path_order)
            elif symbol.name == "bounded_incomplete" and not symbol.arguments:
                bounded_incomplete = True

        for (norm, state), path in runtime.items():
            violations[(norm, state)] = StateMachineViolation(
                norm=norm,
                state=state,
                path=path,
                grounded=True,
                # Per-observation witnesses live in the append-only event
                # log; the graph only carries idempotent observed_* aggregates.
                evidence_refs=(),
            )

        return StateMachineSolution(
            reachable_states=tuple(sorted(reachable)),
            violations=tuple(
                sorted(
                    violations.values(),
                    key=lambda item: (item.norm, item.state),
                )
            ),
            status=(
                StateMachineStatus.BOUNDED_INCOMPLETE
                if bounded_incomplete
                else StateMachineStatus.COMPLETE
            ),
        )

    def find_paths(
        self,
        graph: QdlGraph,
        target_state: str,
        *,
        context: Context = Context.CONTRACT,
        initial_state: str | None = None,
    ) -> tuple[StatePath, ...]:
        """Return every bounded action path from initial states to a target.

        Paths are ordered by depth, action sequence, and initial state.  The
        bound is the engine's ``max_depth``; cyclic machines can therefore
        return repeated-action walks up to that bound.
        """

        program = self._paths_program(
            graph,
            target_state,
            context=context,
            initial_state=initial_state,
        )
        model = self._first_model(program)

        paths: set[StatePath] = set()
        for symbol in model:
            if symbol.name != "target_path" or len(symbol.arguments) != 5:
                continue
            arguments = symbol.arguments
            paths.add(
                StatePath(
                    initial_state=_string(arguments[1]),
                    final_state=_string(arguments[2]),
                    actions=_path_actions(arguments[3]),
                    depth=_integer(arguments[4]),
                )
            )
        return tuple(sorted(paths, key=_path_order))

    def find_path(
        self,
        graph: QdlGraph,
        target_state: str,
        *,
        context: Context = Context.CONTRACT,
        initial_state: str | None = None,
    ) -> StatePath | None:
        """Return the shortest deterministic path to a target state."""

        paths = self.find_paths(
            graph,
            target_state,
            context=context,
            initial_state=initial_state,
        )
        return paths[0] if paths else None

    def solve_resources(
        self,
        graph: QdlGraph,
        *,
        context: Context = Context.CONTRACT,
    ) -> ResourceStateMachineSolution:
        """Return resource-indexed reachability and bounded witnesses."""

        model = self._first_model(self._resource_program(graph, context))
        states: dict[str, set[str]] = {}
        transitions: set[ResourceTransition] = set()
        paths: set[ResourceStatePath] = set()
        bounded_incomplete = False
        for symbol in model:
            if symbol.name == "_resource_reachable" and len(symbol.arguments) == 3:
                resource = _string(symbol.arguments[1])
                states.setdefault(resource, set()).add(_string(symbol.arguments[2]))
            elif symbol.name == "transition" and len(symbol.arguments) == 5:
                arguments = symbol.arguments
                transitions.add(
                    ResourceTransition(
                        action=_string(arguments[1]),
                        resource=_string(arguments[2]),
                        from_state=_string(arguments[3]),
                        to_state=_string(arguments[4]),
                    )
                )
            elif symbol.name == "_resource_path" and len(symbol.arguments) == 6:
                path = _resource_path(symbol)
                if path is not None:
                    paths.add(path)
            elif symbol.name == "_resource_bounded_incomplete" and not symbol.arguments:
                bounded_incomplete = True

        return ResourceStateMachineSolution(
            states=MappingProxyType(
                {resource: tuple(sorted(values)) for resource, values in states.items()}
            ),
            transitions=tuple(
                sorted(
                    transitions,
                    key=lambda item: (
                        item.resource,
                        item.action,
                        item.from_state,
                        item.to_state,
                    ),
                )
            ),
            paths=tuple(sorted(paths, key=_resource_path_order)),
            status=(
                StateMachineStatus.BOUNDED_INCOMPLETE
                if bounded_incomplete
                else StateMachineStatus.COMPLETE
            ),
        )

    def find_resource_paths(
        self,
        graph: QdlGraph,
        resource: str,
        target_state: str,
        *,
        context: Context = Context.CONTRACT,
    ) -> tuple[ResourceStatePath, ...]:
        """Return bounded paths for one resource to one target state."""

        model = self._first_model(
            self._resource_paths_program(
                graph,
                resource,
                target_state,
                context=context,
            )
        )
        paths: set[ResourceStatePath] = set()
        for symbol in model:
            if symbol.name != "_target_resource_path" or len(symbol.arguments) != 6:
                continue
            path = _resource_path(symbol)
            if path is not None:
                paths.add(path)
        return tuple(sorted(paths, key=_resource_path_order))

    def find_resource_path(
        self,
        graph: QdlGraph,
        resource: str,
        target_state: str,
        *,
        context: Context = Context.CONTRACT,
    ) -> ResourceStatePath | None:
        """Return the shortest resource-specific path to a target state."""

        paths = self.find_resource_paths(graph, resource, target_state, context=context)
        return paths[0] if paths else None

    def mismatches(
        self,
        graph: QdlGraph,
        *,
        specification_context: Context = Context.CONTRACT,
        observed_context: Context = Context.RUNTIME,
    ) -> tuple[StateMachineMismatch, ...]:
        """Return observed transitions absent from the specification.

        The query-layer sentinel ``unknown`` means a missing source state only
        when the specification does not declare that identifier as a state.  A
        real state named ``unknown`` keeps ordinary transition semantics.
        For a partial observation without a source state, the target state is
        compared with specification reachability from the initial states, not
        with the existence of an action-specific edge.
        Negation is confined to this Clingo query.  No recursive or negated
        rule is persisted in the QDL graph, so the query remains stratified.
        """

        specification_context_atom = _clingo_string(specification_context.value)
        observed_context_atom = _clingo_string(observed_context.value)
        partial_source_atom = _clingo_string(_PARTIAL_SOURCE_STATE)
        program = self._clingo.compile(graph)
        program += self._reachability_rules(specification_context)
        program += (
            "_state_machine_full_source(S) :- "
            f"transition({observed_context_atom},_,S,_), "
            f"S != {partial_source_atom}.\n"
            "_state_machine_full_source(S) :- "
            f'is({specification_context_atom},S,"State").\n'
            f"mismatch(A,S,T) :- "
            f"transition({observed_context_atom},A,S,T), "
            "_state_machine_full_source(S), "
            f"not transition({specification_context_atom},A,S,T).\n"
            "% Partial transition (undeclared unknown before-state): mismatch\n"
            "% TARGET state is not reachable from a specification initial state.\n"
            "mismatch(A,S,T) :- "
            f"transition({observed_context_atom},A,S,T), "
            "not _state_machine_full_source(S), "
            "not _state_machine_reachable(T).\n"
        )
        model = self._first_model(program)
        mismatches = [
            StateMachineMismatch(
                action=_string(symbol.arguments[0]),
                from_state=_string(symbol.arguments[1]),
                to_state=_string(symbol.arguments[2]),
            )
            for symbol in model
            if symbol.name == "mismatch" and len(symbol.arguments) == 3
        ]
        return tuple(
            sorted(
                mismatches,
                key=lambda item: (item.action, item.from_state, item.to_state),
            )
        )

    def review_learned_transitions(
        self,
        graph: QdlGraph,
        *,
        specification_context: Context = Context.CONTRACT,
        learned_context: Context = Context.PROPOSAL,
    ) -> StateMachineLearningReview:
        """Compare learned proposal transitions with declared specification edges.

        A differing target state is a mismatch and a state-semantics deficit.
        The method never rewrites or suppresses either QDL context; operators
        receive both facts and decide whether the specification or observation
        is authoritative.
        """

        specification_atom = _clingo_string(specification_context.value)
        learned_atom = _clingo_string(learned_context.value)
        program = self._clingo.compile(graph)
        program += (
            "learned_conflict(A,S,T,U) :- "
            f"transition({learned_atom},A,S,T), "
            f"transition({specification_atom},A,S,U), "
            "T != U.\n"
        )
        model = self._first_model(program)

        mismatches: list[StateMachineLearningMismatch] = []
        conflicted_actions: set[str] = set()
        for symbol in model:
            if symbol.name != "learned_conflict" or len(symbol.arguments) != 4:
                continue
            arguments = symbol.arguments
            action = _string(arguments[0])
            from_state = _string(arguments[1])
            learned_to_state = _string(arguments[2])
            declared_to_state = _string(arguments[3])
            if (
                action is None
                or from_state is None
                or learned_to_state is None
                or declared_to_state is None
            ):
                continue
            mismatches.append(
                StateMachineLearningMismatch(
                    action=action,
                    from_state=from_state,
                    learned_to_state=learned_to_state,
                    declared_to_state=declared_to_state,
                )
            )
            conflicted_actions.add(action)

        mismatches.sort(
            key=lambda item: (
                item.action,
                item.from_state,
                item.learned_to_state,
                item.declared_to_state,
            )
        )
        deficits = tuple(
            state_semantics_deficit_fact(action, LEARNED_TRANSITION_CONFLICT)
            for action in sorted(conflicted_actions)
        )
        return StateMachineLearningReview(
            mismatches=tuple(mismatches),
            deficits=deficits,
        )

    def _program(
        self,
        graph: QdlGraph,
        context: Context,
        observed_context: Context,
    ) -> str:
        context_atom = _clingo_string(context.value)
        observed_context_atom = _clingo_string(observed_context.value)
        return (
            self._clingo.compile(graph)
            + f"#const max_depth={self._max_depth}.\n"
            + f"reachable_step(C,S,0) :- initial(C,S), C = {context_atom}.\n"
            + "reachable_step(C,T,D+1) :- "
            + "reachable_step(C,S,D), transition(C,A,S,T), D < max_depth.\n"
            + "reachable(C,S) :- reachable_step(C,S,D).\n"
            + self._path_rules(context)
            + "spec_violation(C,N,S,I,R,D) :- "
            + "forbidden(C,N,S), path(C,I,S,R,D), initial(C,I).\n"
            + "bounded_incomplete :- "
            + "reachable_step(C,S,max_depth), transition(C,_,S,_).\n"
            + "grounded_violation(N,S,A,I) :- "
            + f"forbidden({context_atom},N,S), "
            + f"observed_transition({observed_context_atom},A,I,S), "
            + f"observed_outcome({observed_context_atom},A,_).\n"
        )

    def _reachability_rules(self, context: Context) -> str:
        context_atom = _clingo_string(context.value)
        return (
            "_state_machine_reachable(S) :- "
            + f"initial({context_atom},S).\n"
            + "_state_machine_reachable(T) :- "
            + "_state_machine_reachable(S), "
            + f"transition({context_atom},_,S,T).\n"
        )

    def _paths_program(
        self,
        graph: QdlGraph,
        target_state: str,
        *,
        context: Context,
        initial_state: str | None,
    ) -> str:
        constraints = (
            f"T = {_clingo_string(target_state)}, C = {_clingo_string(context.value)}"
        )
        if initial_state is not None:
            constraints += f", I = {_clingo_string(initial_state)}"

        return (
            self._clingo.compile(graph)
            + f"#const max_depth={self._max_depth}.\n"
            + self._path_rules(context)
            + f"target_path(C,I,T,R,D) :- path(C,I,T,R,D), {constraints}.\n"
        )

    def _resource_program(self, graph: QdlGraph, context: Context) -> str:
        context_atom = _clingo_string(context.value)
        return (
            self._clingo.compile(graph)
            + f"#const max_depth={self._max_depth}.\n"
            + "% Resource-aware transition is a query-layer join of the\n"
            + "% action edge and its resource precondition.\n"
            + "transition(C,A,R,Q0,Q) :- "
            + "transition(C,A,Q0,Q), precondition(C,A,R,Q0).\n"
            + "_resource_reachable_step(C,R,Q,0) :- state(C,R,Q), "
            + f"C = {context_atom}.\n"
            + "_resource_reachable_step(C,R,T,D+1) :- "
            + "_resource_reachable_step(C,R,S,D), transition(C,A,R,S,T), "
            + "D < max_depth.\n"
            + "_resource_reachable(C,R,Q) :- _resource_reachable_step(C,R,Q,_).\n"
            + self._resource_path_rules(context)
            + "_resource_bounded_incomplete :- "
            + "_resource_reachable_step(C,R,S,max_depth), "
            + "transition(C,_,R,S,_).\n"
        )

    def _resource_paths_program(
        self,
        graph: QdlGraph,
        resource: str,
        target_state: str,
        *,
        context: Context,
    ) -> str:
        constraints = (
            f"C = {_clingo_string(context.value)}, "
            f"R = {_clingo_string(resource)}, "
            f"T = {_clingo_string(target_state)}"
        )
        return (
            self._clingo.compile(graph)
            + f"#const max_depth={self._max_depth}.\n"
            + "transition(C,A,R,Q0,Q) :- "
            + "transition(C,A,Q0,Q), precondition(C,A,R,Q0).\n"
            + self._resource_path_rules(context)
            + "_target_resource_path(C,R,I,T,P,D) :- "
            + f"_resource_path(C,R,I,T,P,D), {constraints}.\n"
        )

    def _resource_path_rules(self, context: Context) -> str:
        context_atom = _clingo_string(context.value)
        return (
            "_resource_path(C,R,I,I,nil,0) :- "
            + f"state(C,R,I), C = {context_atom}.\n"
            + "_resource_path(C,R,I,T,cons(step(A,T),P),D+1) :- "
            + "_resource_path(C,R,I,M,P,D), transition(C,A,R,M,T), "
            + "D < max_depth.\n"
        )

    def _path_rules(self, context: Context) -> str:
        context_atom = _clingo_string(context.value)
        return (
            f"path(C,I,I,nil,0) :- initial(C,I), C = {context_atom}.\n"
            + "path(C,I,T,cons(A,R),D+1) :- "
            + "path(C,I,M,R,D), transition(C,A,M,T), D < max_depth.\n"
        )

    def _first_model(self, program: str) -> tuple[clingo.Symbol, ...]:
        solutions = self._clingo.solve_program(program, max_models=1)
        if not solutions:
            return ()
        return tuple(clingo.parse_term(atom) for atom in solutions[0].atoms)


def _is_fact(identifier: str, type_name: str, context: Context) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name("is"),
        args=(Atom(value=identifier), Atom(value=type_name)),
    )


def _fact(
    predicate_name: str,
    args: tuple[str, ...],
    context: Context,
) -> Fact:
    return Fact(
        context=context,
        predicate=_PREDICATES[predicate_name],
        args=tuple(Atom(value=value) for value in args),
    )


def _value(symbol: clingo.Symbol) -> object:
    if symbol.type == clingo.SymbolType.String:
        return symbol.string
    if symbol.type == clingo.SymbolType.Number:
        return symbol.number
    if symbol.type == clingo.SymbolType.Function and not symbol.arguments:
        return symbol.name
    return str(symbol)


def _string(symbol: clingo.Symbol) -> str:
    value = _value(symbol)
    if not isinstance(value, str):
        raise ValueError(f"expected a string symbol, got {value!r}")
    return value


def _integer(symbol: clingo.Symbol) -> int:
    value = _value(symbol)
    if not isinstance(value, int):
        raise ValueError(f"expected an integer symbol, got {value!r}")
    return value


def _path_actions(symbol: clingo.Symbol) -> tuple[str, ...]:
    actions: list[str] = []
    while (
        symbol.type == clingo.SymbolType.Function
        and symbol.name == "cons"
        and len(symbol.arguments) == 2
    ):
        actions.append(_string(symbol.arguments[0]))
        symbol = symbol.arguments[1]

    if (
        symbol.type == clingo.SymbolType.Function
        and symbol.name == "nil"
        and not symbol.arguments
    ):
        return tuple(reversed(actions))
    return ()


def _resource_path(symbol: clingo.Symbol) -> ResourceStatePath | None:
    arguments = symbol.arguments
    initial_state = _string(arguments[2])
    final_state = _string(arguments[3])
    decoded = _resource_path_steps(arguments[4])
    if decoded is None:
        return None
    actions, states = decoded
    states = (initial_state, *states)
    if len(states) != len(actions) + 1 or states[0] != initial_state:
        return None
    if states[-1] != final_state:
        return None
    return ResourceStatePath(
        resource=_string(arguments[1]),
        initial_state=initial_state,
        final_state=final_state,
        actions=actions,
        states=states,
        depth=_integer(arguments[5]),
    )


def _resource_path_steps(
    path_symbol: clingo.Symbol,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Decode action/state pairs from a resource path witness."""

    actions: list[str] = []
    states: list[str] = []
    symbol = path_symbol
    while (
        symbol.type == clingo.SymbolType.Function
        and symbol.name == "cons"
        and len(symbol.arguments) == 2
    ):
        step = symbol.arguments[0]
        if (
            step.type != clingo.SymbolType.Function
            or step.name != "step"
            or len(step.arguments) != 2
        ):
            return None
        actions.append(_string(step.arguments[0]))
        states.append(_string(step.arguments[1]))
        symbol = symbol.arguments[1]
    if symbol.type != clingo.SymbolType.Function or symbol.name != "nil":
        return None
    return tuple(reversed(actions)), tuple(reversed(states))


def _path_order(path: StatePath) -> tuple[int, tuple[str, ...], str, str]:
    return (path.depth, path.actions, path.initial_state, path.final_state)


def _resource_path_order(
    path: ResourceStatePath,
) -> tuple[int, tuple[str, ...], str, str, str]:
    return (
        path.depth,
        path.actions,
        path.resource,
        path.initial_state,
        path.final_state,
    )


def _clingo_string(value: str) -> str:
    return asp_string(value)
