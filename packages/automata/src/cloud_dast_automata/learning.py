"""AALpy adapter for passive deterministic automata learning.

The adapter reads only explicit QDL ``observed_transition`` facts, builds a
trace set from the declared initial state, and lets AALpy construct its prefix
tree and run RPNI or EDSM.  Its result is always a proposal-context QDL graph:
it never writes accepted facts and never evaluates a security verdict.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from typing import Literal

from aalpy.learning_algs import run_EDSM, run_RPNI

from cloud_dast.extensions import (
    INSUFFICIENT_TRACE_EVIDENCE,
    state_semantics_deficit_fact,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    transition,
)

LearningAlgorithm = Literal["rpni", "edsm"]


@dataclass(frozen=True, slots=True)
class _ObservedTransition:
    action: str
    from_state: str
    to_state: str


@dataclass(frozen=True, slots=True)
class _Trace:
    actions: tuple[str, ...]
    final_state: str


class AALpyAutomataLearningAdapter:
    """Learn a Moore-machine proposal with AALpy passive state merging."""

    def __init__(self, *, algorithm: LearningAlgorithm = "rpni") -> None:
        if algorithm not in {"rpni", "edsm"}:
            raise ValueError("algorithm must be 'rpni' or 'edsm'")
        self._algorithm = algorithm

    def learn(self, graph: QdlGraph) -> QdlGraph:
        """Return an evidence-grounded FSM proposal or a state-semantics deficit."""

        observed = _observed_transitions(graph)
        observed_states = {
            state for item in observed for state in (item.from_state, item.to_state)
        }
        initial_states = _initial_states(graph)

        if (
            not observed
            or len(initial_states) != 1
            or initial_states[0] not in observed_states
        ):
            return _deficit_graph(graph, observed, INSUFFICIENT_TRACE_EVIDENCE)

        initial_state = initial_states[0]
        paths = _shortest_paths(initial_state, observed)
        if any(item.from_state not in paths for item in observed):
            return _deficit_graph(graph, observed, INSUFFICIENT_TRACE_EVIDENCE)

        trace_data: list[tuple[tuple[str, ...], str]] = [((), initial_state)]
        traces: dict[_ObservedTransition, _Trace] = {}
        for item in observed:
            actions = (*paths[item.from_state], item.action)
            trace = _Trace(actions=actions, final_state=item.to_state)
            trace_data.append((trace.actions, trace.final_state))
            traces[item] = trace

        model = self._learn_model(trace_data)
        if model is None:
            return _deficit_graph(graph, observed, INSUFFICIENT_TRACE_EVIDENCE)

        learned = _project_model(model, observed_states)
        if learned is None or learned != frozenset(observed):
            return _deficit_graph(graph, observed, INSUFFICIENT_TRACE_EVIDENCE)

        return _proposal_graph(
            observed=observed,
            observed_states=observed_states,
            initial_state=initial_state,
            traces=traces,
            forbidden=_declared_forbidden(graph, observed_states),
        )

    def _learn_model(self, data: list[tuple[tuple[str, ...], str]]) -> object | None:
        if self._algorithm == "rpni":
            return run_RPNI(
                data,
                automaton_type="moore",
                algorithm="classic",
                print_info=False,
            )
        return run_EDSM(data, automaton_type="moore", print_info=False)


def _observed_transitions(graph: QdlGraph) -> tuple[_ObservedTransition, ...]:
    transitions: set[_ObservedTransition] = set()
    for fact in graph.facts:
        if fact.context is not Context.RUNTIME:
            continue
        if fact.predicate.name != "observed_transition" or len(fact.args) != 3:
            continue
        action = _string(fact.args[0])
        from_state = _string(fact.args[1])
        to_state = _string(fact.args[2])
        if action is None or from_state is None or to_state is None:
            continue
        transitions.add(
            _ObservedTransition(
                action=action,
                from_state=from_state,
                to_state=to_state,
            )
        )
    return tuple(
        sorted(
            transitions,
            key=lambda item: (item.action, item.from_state, item.to_state),
        )
    )


def _initial_states(graph: QdlGraph) -> tuple[str, ...]:
    states: set[str] = set()
    for fact in graph.facts:
        if fact.context is Context.REPORT:
            continue
        if fact.predicate.name != "initial" or len(fact.args) != 1:
            continue
        state = _string(fact.args[0])
        if state is not None:
            states.add(state)
    return tuple(sorted(states))


def _declared_forbidden(
    graph: QdlGraph,
    learned_states: set[str],
) -> tuple[tuple[str, str], ...]:
    forbidden: set[tuple[str, str]] = set()
    for fact in graph.facts:
        if fact.context not in {Context.CONTRACT, Context.ACCEPTED}:
            continue
        if fact.predicate.name != "forbidden" or len(fact.args) != 2:
            continue
        norm = _string(fact.args[0])
        state = _string(fact.args[1])
        if norm is not None and state in learned_states:
            forbidden.add((norm, state))
    return tuple(sorted(forbidden))


def _shortest_paths(
    initial_state: str,
    observed: tuple[_ObservedTransition, ...],
) -> dict[str, tuple[str, ...]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for item in observed:
        adjacency.setdefault(item.from_state, []).append((item.action, item.to_state))
    for edges in adjacency.values():
        edges.sort()

    predecessor: dict[str, tuple[str, str] | None] = {initial_state: None}
    queue: deque[str] = deque((initial_state,))
    while queue:
        state = queue.popleft()
        for action, target in adjacency.get(state, ()):
            if target in predecessor:
                continue
            predecessor[target] = (state, action)
            queue.append(target)

    paths: dict[str, tuple[str, ...]] = {}
    for state in predecessor:
        actions: list[str] = []
        cursor = state
        while cursor != initial_state:
            previous = predecessor[cursor]
            if previous is None:
                break
            parent, action = previous
            actions.append(action)
            cursor = parent
        paths[state] = tuple(reversed(actions))
    return paths


def _project_model(
    model: object,
    observed_states: set[str],
) -> frozenset[_ObservedTransition] | None:
    states = getattr(model, "states", None)
    if not isinstance(states, list):
        return None

    transitions: set[_ObservedTransition] = set()
    for state in states:
        from_state = _string(getattr(state, "output", None))
        state_transitions = getattr(state, "transitions", None)
        if from_state not in observed_states or not isinstance(state_transitions, dict):
            return None
        for action, target in state_transitions.items():
            action_id = _string(action)
            to_state = _string(getattr(target, "output", None))
            if action_id is None or to_state not in observed_states:
                return None
            transitions.add(
                _ObservedTransition(
                    action=action_id,
                    from_state=from_state,
                    to_state=to_state,
                )
            )
    return frozenset(transitions)


def _proposal_graph(
    *,
    observed: tuple[_ObservedTransition, ...],
    observed_states: set[str],
    initial_state: str,
    traces: dict[_ObservedTransition, _Trace],
    forbidden: tuple[tuple[str, str], ...],
) -> QdlGraph:
    actions = {item.action for item in observed}
    facts: list[Fact] = [
        *(_declaration_fact(action, "Action") for action in sorted(actions)),
        *(_declaration_fact(state, "State") for state in sorted(observed_states)),
        _fact("initial", (initial_state,)),
    ]
    facts.extend(
        _fact("transition", (item.action, item.from_state, item.to_state))
        for item in observed
    )

    for item in observed:
        trace = traces[item]
        trace_id = _trace_id(trace)
        facts.append(_declaration_fact(trace_id, "Observation"))
        facts.append(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("evidence"),
                args=(
                    Atom(value=trace_id),
                    transition(Atom(value=item.from_state), Atom(value=item.to_state)),
                ),
            )
        )

    facts.extend(_declaration_fact(norm_id, "Norm") for norm_id, _state in forbidden)
    facts.extend(_fact("forbidden", (norm_id, state)) for norm_id, state in forbidden)
    return QdlGraph(facts=tuple(facts))


def _deficit_graph(
    graph: QdlGraph,
    observed: tuple[_ObservedTransition, ...],
    reason: str,
) -> QdlGraph:
    actions = {item.action for item in observed} or _declared_actions(graph)
    states = {state for item in observed for state in (item.from_state, item.to_state)}
    facts: list[Fact] = [
        *(_declaration_fact(action, "Action") for action in sorted(actions)),
        *(_declaration_fact(state, "State") for state in sorted(states)),
        *(state_semantics_deficit_fact(action, reason) for action in sorted(actions)),
    ]
    return QdlGraph(facts=tuple(facts))


def _declared_actions(graph: QdlGraph) -> set[str]:
    return {action for action in graph.declared_identifiers("Action") if action}


def _declaration_fact(identifier: str, type_name: str) -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("is"),
        args=(Atom(value=identifier), Atom(value=type_name)),
    )


def _fact(predicate_name: str, args: tuple[str, ...]) -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name(predicate_name),
        args=tuple(Atom(value=value) for value in args),
    )


def _trace_id(trace: _Trace) -> str:
    payload = json.dumps(
        {"actions": trace.actions, "final_state": trace.final_state},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"trace:{digest}"


def _string(value: object) -> str | None:
    if isinstance(value, Atom):
        value = value.value
    return value if isinstance(value, str) and value else None
