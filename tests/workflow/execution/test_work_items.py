"""S30 v2 acceptance: deficit work-item graph and algebraic coalescing.

Stages 1-5 are covered here: deterministic grouping (stdlib only), the
supplies/needs dependency DAG, parallel waves of independent work items,
the deterministic merge/supersedes policy for conflicts, closure propagation,
and stale invalidation.  Stage 6 (Clingo SCC / set-cover / budget
optimization) remains outside this stdlib v1 scope.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import cloud_dast.runtime.deficits as _deficits_module
import cloud_dast_fuzzing.corpus.compiler as _compiler_module
from cloud_dast.composition.execution import assemble_runner
from cloud_dast.composition.runtime import assemble_workflow
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.graphs import (
    strongly_connected_components,
    wave_layers,
)
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Observation,
    TraceStep,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    Variable,
    canonical_json,
    changed,
    differs,
    field,
    input_field,
)
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.campaign import (
    LiveWorkflow,
)
from cloud_dast.runtime.campaign.runtime import LiveWorkflowOptions
from cloud_dast.runtime.deficits import (
    Deficit,
    missing_role_deficit,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import (
    WorkItemGraph,
    WorkItemGrounding,
    single_deficit_work_item,
)
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)

_EFFECT = changed(Atom(value="resource:order"), Atom(value="state"))
_EFFECT_JSON = canonical_json(_EFFECT)
_OTHER_EFFECT = changed(Atom(value="resource:order"), Atom(value="total"))
_ANY_ACTION = Variable(name="AnyAction")
_ANY_NORM = Variable(name="AnyNorm")
_ANY_DIMENSION = Variable(name="AnyDimension")
_ANY_FIELD = Variable(name="AnyField")
_ANY_RESOURCE = Variable(name="AnyResource")
_ANY_TARGET = Variable(name="AnyTarget")


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _extension_fact(
    predicate: str,
    args: tuple[object, ...],
) -> Fact:
    schema = next(
        schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == predicate
    )
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_schema(schema),
        args=args,  # type: ignore[arg-type]
    )


def _fixture_graph(action: str) -> QdlGraph:
    action_atom = Atom(value=f"action:{action}")
    witness = input_field(action_atom, Atom(value="order_id"))
    resource_type = Atom(value="resource:order")
    return QdlGraph(
        facts=(
            _action_declaration(action),
            _fact("is", (witness, Atom(value="Field"))),
            _fact("is", (resource_type, Atom(value="ResourceType"))),
            _extension_fact("refers_to", (witness, resource_type)),
        )
    )


def _irreversibility_deficit(
    path_id: str,
    action: str = "svc.Update",
    effect: Struct = _EFFECT,
) -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal("causes", (Atom(value=action), effect)),
        predicate_class="causes",
        axis="alternatives",
        action=action,
        context=(
            ("path_id", path_id),
            ("step_id", f"step:{path_id}"),
            ("reason", "missing_irreversibility_fact"),
            ("effect", canonical_json(effect)),
        ),
    )


def _blocked_deficit(
    path_id: str,
    action: str = "svc.Delete",
    effect: Struct = _EFFECT,
) -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal("causes", (_ANY_ACTION, effect)),
        predicate_class="causes",
        axis="alternatives",
        action=action,
        context=(
            ("origin", "blocked_step"),
            ("path_id", path_id),
            ("step_id", f"step:{path_id}"),
            ("reason", "QDL effect chain was not verified"),
            ("effect", canonical_json(effect)),
        ),
    )


def _variance_deficit(diff: str, fields: str) -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "prevents",
            (
                _ANY_NORM,
                differs(Atom(value="svc.Get"), _ANY_DIMENSION),
            ),
        ),
        predicate_class="prevents",
        axis="variance",
        action="svc.Get",
        context=(
            ("diff", diff),
            ("control", "obs-control"),
            ("treatment", "obs-treatment"),
            ("variance_fields", fields),
        ),
    )


def _action_declaration(action: str) -> Fact:
    return _fact("is", (Atom(value=f"action:{action}"), Atom(value="Action")))


def _closing_graph(action: str = "svc.Update") -> QdlGraph:
    """A promoted graph whose mutation effect closes the setup deficit."""

    return QdlGraph(
        facts=(
            _action_declaration(action),
            _fact("is", (Atom(value="resource:order"), Atom(value="Resource"))),
            _fact("causes", (Atom(value=f"action:{action}"), _EFFECT)),
        )
    )


def _exposure_graph(action: str, field_name: str) -> QdlGraph:
    """A promoted graph that exposes exactly one response field."""

    witness = field(Atom(value="resource:user"), Atom(value=field_name))
    return QdlGraph(
        facts=(
            _action_declaration(action),
            _fact("is", (Atom(value="resource:user"), Atom(value="Resource"))),
            _fact("is", (witness, Atom(value="Witness"))),
            _fact("exposes", (Atom(value=f"action:{action}"), witness)),
        )
    )


@st.composite
def _directed_graphs(draw: st.DrawFn) -> tuple[tuple[str, ...], dict[str, set[str]]]:
    size = draw(st.integers(min_value=0, max_value=8))
    nodes = tuple(f"n{index:02}" for index in range(size))
    if not nodes:
        return nodes, {}
    edges = {
        node: draw(st.sets(st.sampled_from(nodes), max_size=size)) for node in nodes
    }
    return nodes, edges


def _previous_scc(
    nodes: tuple[str, ...],
    edges: dict[str, set[str]],
) -> tuple[tuple[str, ...], ...]:
    """Old iterative Tarjan used before S39."""

    index_counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[tuple[str, ...]] = []
    for root in nodes:
        if root in indices:
            continue
        indices[root] = lowlinks[root] = index_counter
        index_counter += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, Iterator[str]]] = [
            (root, iter(sorted(edges.get(root, ()))))
        ]
        while work:
            node, successors = work[-1]
            advanced = False
            for successor in successors:
                if successor not in indices:
                    indices[successor] = lowlinks[successor] = index_counter
                    index_counter += 1
                    stack.append(successor)
                    on_stack.add(successor)
                    work.append((successor, iter(sorted(edges.get(successor, ())))))
                    advanced = True
                    break
                if successor in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[successor])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlinks[parent] = min(lowlinks[parent], lowlinks[node])
            if lowlinks[node] == indices[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(tuple(reversed(component)))
    return tuple(components)


def _previous_waves(
    nodes: tuple[str, ...],
    edges: dict[str, set[str]],
    rank: dict[str, int],
) -> tuple[tuple[str, ...], ...]:
    """Old Kahn/condensation wave planner used before S39."""

    components = _previous_scc(nodes, edges)
    component_of = {
        node: index for index, component in enumerate(components) for node in component
    }
    component_members = [
        sorted(component, key=lambda node: rank[node]) for component in components
    ]
    predecessors = {index: set() for index in range(len(components))}
    for source, targets in edges.items():
        for target in targets:
            source_component = component_of[source]
            target_component = component_of[target]
            if source_component != target_component:
                predecessors[target_component].add(source_component)
    indegree = {index: len(preds) for index, preds in predecessors.items()}
    ready = [index for index, degree in indegree.items() if degree == 0]
    topological: list[int] = []
    while ready:
        index = min(ready)
        ready.remove(index)
        topological.append(index)
        for successor in range(len(components)):
            if index in predecessors[successor]:
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    ready.append(successor)
    depth: dict[int, int] = {}
    for index in topological:
        depth[index] = max(
            (
                depth[pred] + len(component_members[pred])
                for pred in predecessors[index]
            ),
            default=0,
        )
    wave_of: dict[str, int] = {}
    for index, members in enumerate(component_members):
        for position, node in enumerate(members):
            wave_of[node] = depth[index] + position
    if not wave_of:
        return ()
    waves: list[list[str]] = [[] for _ in range(max(wave_of.values()) + 1)]
    for node, wave_index in wave_of.items():
        waves[wave_index].append(node)
    return tuple(tuple(sorted(wave, key=lambda node: rank[node])) for wave in waves)


def test_path_fanout_deficits_coalesce_into_one_work_item() -> None:
    """Twenty path-fanout events over one subgoal are one LLM call.

    S21 v2: the deficit is the unprovable subgoal, so every blocked setup
    path over the same action/effect requirement coalesces into one queue
    entry whose fan-out records how many paths required it.
    """

    queue = DeficitQueue()
    deficits = tuple(_irreversibility_deficit(f"path-{index}") for index in range(20))
    assert queue.add(deficits) == 1

    wave = queue.pop_wave(graph_snapshot="snapshot-1")

    assert len(wave) == 1
    item = wave[0]
    assert item.predicate_class == "causes"
    assert item.action == "svc.Update"
    assert item.graph_snapshot == "snapshot-1"
    assert item.fan_out == 20
    assert len(item.deficit_ids) == 1
    assert queue.dispatched == 1
    # Every member of the work item is in flight behind the single call.
    assert queue.pending_count == 0

    result = queue.record_work_item_result(item, _closing_graph())

    assert len(result.closed_deficit_ids) == 1
    assert queue.closed_count == 1
    assert queue.pending_count == 0


def test_new_path_id_without_new_effect_keeps_work_item() -> None:
    """A fresh path id joins the existing subgoal, not a new model call."""

    queue = DeficitQueue()
    queue.add(tuple(_irreversibility_deficit(f"path-{index}") for index in range(5)))
    wave = queue.pop_wave(graph_snapshot="snapshot-1")
    assert len(wave) == 1
    item = wave[0]

    # The grounding call produced nothing that closes the gap.
    queue.record_work_item_result(item, None)
    assert queue.pending_count == 1

    queue.add(
        tuple(_irreversibility_deficit(f"path-new-{index}") for index in range(5))
    )
    next_wave = queue.pop_wave(graph_snapshot="snapshot-2")

    assert len(next_wave) == 1
    assert next_wave[0].work_item_id == item.work_item_id
    assert len(next_wave[0].deficit_ids) == 1
    assert next_wave[0].fan_out == 10


@pytest.mark.parametrize("ready", (False, True))
@pytest.mark.parametrize("budget", (0, 1, 2))
def test_wave_dispatch_charges_only_selected_ready_items(
    ready: bool, budget: int
) -> None:
    queue = DeficitQueue(max_tasks=budget)
    queue.add(
        (
            _blocked_deficit("delete", action="svc.Delete"),
            _blocked_deficit("get", action="svc.Get", effect=_OTHER_EFFECT),
        )
    )
    wave = queue.pop_wave(graph_snapshot="snapshot", ready=lambda item: ready)

    selected = budget if ready else 0
    assert len(wave) == queue.dispatched == selected
    assert queue.pending_count == 2 - selected
    assert all(
        item.graph_snapshot == "snapshot" and item.attempts == 0 for item in wave
    )
    for item in wave:
        queue.record_work_item_failure(item)
        assert item.attempts == 0
    assert queue.pending_count == 2


def test_independent_work_items_share_one_wave() -> None:
    """Independent questions on different actions are planned together."""

    queue = DeficitQueue()
    queue.add(
        (
            _blocked_deficit("path-delete", action="svc.Delete"),
            _blocked_deficit(
                "path-get",
                action="svc.Get",
                effect=_OTHER_EFFECT,
            ),
        )
    )

    wave = queue.pop_wave(graph_snapshot="snapshot")

    assert len(wave) == 2
    graph = WorkItemGraph.build(wave)
    assert graph.relation(wave[0].work_item_id, wave[1].work_item_id) == "independent"
    assert graph.waves == (wave,)


@pytest.mark.parametrize("attempts", (0, 1))
@pytest.mark.parametrize("shared", ("facts", "evidence"))
def test_shared_inputs_serialize_only_until_priority_item_is_probed(
    attempts: int, shared: str
) -> None:
    items = tuple(
        replace(
            single_deficit_work_item(_blocked_deficit(name, action=action)),
            consultation_kind=None,
            missing_fact_signature=frozenset({"shared" if shared == "facts" else name}),
            evidence_signature=frozenset({"observed"})
            if shared == "evidence"
            else frozenset(),
            attempts=attempts,
        )
        for name, action in (("first", "svc.Get"), ("second", "svc.Delete"))
    )
    priority = tuple(item.work_item_id for item in reversed(items))
    graph = WorkItemGraph.build(items, dispatch_order=priority)

    assert graph.supersedes == ()
    assert all(graph.needs(item.work_item_id) == () for item in items)
    if attempts == 0:
        assert graph.waves == ((items[1],), (items[0],))
    else:
        assert graph.waves == ((items[1], items[0]),)


def test_dependent_work_items_are_ordered() -> None:
    """An exposures answer supplies the response-semantics question."""

    exposures = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, Atom(value="email")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="svc.Get",
        context=(("field", "email"),),
    )
    response = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, _ANY_FIELD),
            ),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="svc.Get",
        context=(("fields", "email"), ("observation_id", "obs-1")),
    )
    items = (single_deficit_work_item(exposures), single_deficit_work_item(response))
    graph = WorkItemGraph.build(items)
    exposures_id = items[0].work_item_id
    response_id = items[1].work_item_id

    assert graph.relation(exposures_id, response_id) == "dependent"
    assert graph.supplies(exposures_id) == (response_id,)
    assert graph.needs(response_id) == (exposures_id,)
    assert [len(wave) for wave in graph.waves] == [1, 1]
    assert graph.waves[0][0].work_item_id == exposures_id
    assert graph.waves[1][0].work_item_id == response_id


def test_conflicting_work_items_serialize_with_deterministic_supersedes() -> None:
    """Same-axis/same-action questions serialize with a deterministic winner."""

    items = (
        single_deficit_work_item(_variance_deficit("diff-1", "email")),
        single_deficit_work_item(_variance_deficit("diff-2", "payment_token")),
    )
    graph = WorkItemGraph.build(items)
    first_id, second_id = items[0].work_item_id, items[1].work_item_id
    winner, loser = sorted((first_id, second_id))

    assert graph.relation(first_id, second_id) == "conflict"
    assert [len(wave) for wave in graph.waves] == [1, 1]
    assert graph.supersedes == ((winner, loser),)


def test_cycles_collapse_into_an_scc_macro() -> None:
    """Mutual supplies edges form one SCC macro executed serially."""

    first = single_deficit_work_item(_blocked_deficit("path-1", action="svc.Delete"))
    second = single_deficit_work_item(
        _irreversibility_deficit(
            "path-1",
            action="svc.Delete",
            effect=_OTHER_EFFECT,
        )
    )
    graph = WorkItemGraph.build((first, second))
    blocked_id = first.work_item_id
    irreversibility_id = second.work_item_id

    # Each alternatives question produces the exact effect fact the other
    # one is missing: a dependency cycle that must not recurse.
    assert graph.supplies(blocked_id) == (irreversibility_id,)
    assert graph.supplies(irreversibility_id) == (blocked_id,)
    assert [len(wave) for wave in graph.waves] == [1, 1]


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_directed_graphs())
def test_scc_components_match_previous_implementation(
    graph: tuple[tuple[str, ...], dict[str, set[str]]],
) -> None:
    """NetworkX SCCs match the old Tarjan component order and members."""

    nodes, edges = graph
    assert strongly_connected_components(nodes, edges) == _previous_scc(nodes, edges)


def test_work_item_waves_preserve_deterministic_order() -> None:
    """A mixed cycle/DAG graph keeps the old wave ordering."""

    nodes = ("a", "b", "c", "d")
    edges = {"a": {"b"}, "b": {"a"}, "c": {"d"}, "d": set()}
    rank = {node: index for index, node in enumerate(nodes)}

    assert wave_layers(nodes, edges, rank.__getitem__) == (("a", "c"), ("b", "d"))


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_directed_graphs())
def test_random_digraph_property_waves_are_stable(
    graph: tuple[tuple[str, ...], dict[str, set[str]]],
) -> None:
    """Random digraphs keep the pre-S39 SCC/wave semantics."""

    nodes, edges = graph
    rank = {node: index for index, node in enumerate(nodes)}
    assert wave_layers(nodes, edges, rank.__getitem__) == _previous_waves(
        nodes,
        edges,
        rank,
    )


def test_hand_rolled_tarjan_functions_removed() -> None:
    """S39 removes both hand-rolled Tarjan implementations."""

    assert not hasattr(_deficits_module, "_strongly_connected_components")
    assert not hasattr(_compiler_module, "_strongly_connected_components")


def test_fan_out_prioritizes_work_items() -> None:
    """A path-fanout batch outranks a single question in the same class."""

    queue = DeficitQueue()
    single = _blocked_deficit(
        "path-single",
        action="svc.Get",
        effect=_OTHER_EFFECT,
    )
    batch = tuple(_blocked_deficit(f"path-{index}") for index in range(3))
    queue.add((single, *batch))

    wave = queue.pop_wave(graph_snapshot="snapshot")

    assert [item.action for item in wave] == ["svc.Delete", "svc.Get"]
    assert wave[0].fan_out == 3
    assert wave[1].fan_out == 1


def test_record_work_item_result_checks_each_deficit_semantics() -> None:
    """One promotion closes exactly the deficits it semantically closes."""

    queue = DeficitQueue()
    email = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, Atom(value="email")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="svc.Get",
        context=(("field", "email"),),
    )
    token = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, Atom(value="payment_token")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="svc.Get",
        context=(("field", "payment_token"),),
    )
    queue.add((email, token))

    wave = queue.pop_wave(graph_snapshot="snapshot")
    assert len(wave) == 1
    item = wave[0]
    assert len(item.deficit_ids) == 2

    result = queue.record_work_item_result(item, _exposure_graph("svc.Get", "email"))

    assert result.closed_deficit_ids == (email.consultation_id,)
    assert queue.closed_count == 1
    # The ungrounded field keeps its pending deficit with one attempt.
    assert queue.pending_count == 1


def test_wave_closure_recomputes_every_pending_subgoal_once() -> None:
    """S30 v3 evaluates one merged wave graph, not each worker result."""

    queue = DeficitQueue(max_tasks=None)

    def exposure_deficit(action: str, field_name: str) -> Deficit:
        return Deficit(
            subgoal=QdlSubgoal(
                "exposes",
                (
                    Atom(value=action),
                    field(_ANY_RESOURCE, Atom(value=field_name)),
                ),
            ),
            predicate_class="exposes",
            axis="exposures",
            action=action,
            context=(("field", field_name),),
        )

    email = exposure_deficit("svc.Get", "email")
    token = exposure_deficit("svc.List", "payment_token")
    response = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (Atom(value="svc.Get"), field(_ANY_RESOURCE, _ANY_FIELD)),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="svc.Get",
        context=(("fields", "email"), ("observation_id", "obs-1")),
    )
    queue.add((email, token, response))

    wave = queue.pop_wave(graph_snapshot="snapshot")
    assert {item.action for item in wave} == {"svc.Get", "svc.List"}
    assert response not in wave

    outcomes = {
        item.work_item_id: WorkItemGrounding(
            item.work_item_id,
            _exposure_graph(
                item.action,
                "email" if item.action == "svc.Get" else "payment_token",
            ),
        )
        for item in wave
    }
    for item in wave:
        queue.record_work_item_result(item, outcomes[item.work_item_id].result)

    propagation = queue.propagate_wave_results(
        outcomes,
        base_graph=QdlGraph(),
    )

    assert propagation.closed_deficit_ids == (response.consultation_id,)
    assert propagation.stale_deficit_ids == ()
    assert propagation.unchanged_count == 0
    assert queue.pending_count == 0


def test_setup_gap_drains_through_fixture_consultation() -> None:
    """A fixture-typing gap gets an LLM call, not a permanent block."""

    grounding = FixtureReactiveGrounding()
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding,
        source=SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
        options=LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    )
    deficits = DeficitQueue(max_tasks=None)
    deficit = Deficit(
        subgoal=QdlSubgoal(
            "refers_to",
            (
                input_field(Atom(value="action:svc.submit"), _ANY_FIELD),
                _ANY_TARGET,
            ),
        ),
        predicate_class="refers_to",
        axis="fixture",
        action="action:svc.submit",
        context=(("reason", "missing_refers_to"),),
    )
    deficits.add((deficit,))

    promoted = workflow._replanning.drain_reactive(
        _request(),
        deficits,
        CampaignAccumulator.empty(),
        graph=QdlGraph(),
    )

    assert promoted == 1
    assert len(grounding.calls) == 1
    axis, actions, context = grounding.calls[0]
    assert axis == "fixture"
    assert actions == ("action:svc.submit",)
    assert context["unprovable_subgoal"].startswith("refers_to(")
    assert context["reason"] == "missing_refers_to"
    assert deficits.closed_count == 1
    assert deficits.pending_count == 0


def _roles_graph(action: str) -> QdlGraph:
    return _roles_graph_for_fields(action, ("secret_id",))


def _roles_graph_for_fields(action: str, fields: tuple[str, ...]) -> QdlGraph:
    action_atom = Atom(value=f"action:{action}")
    return QdlGraph(
        facts=(
            _action_declaration(action),
            *(
                _fact(
                    "is",
                    (
                        input_field(action_atom, Atom(value=field_name)),
                        Atom(value="Field"),
                    ),
                )
                for field_name in fields
            ),
            *(
                _fact(
                    "has",
                    (
                        input_field(action_atom, Atom(value=field_name)),
                        Atom(value="object_ref"),
                    ),
                )
                for field_name in fields
            ),
        )
    )


class FakeReactiveGrounding:
    """Grounding double that answers roles consultations deterministically."""

    def __init__(self, fields: tuple[str, ...] = ("secret_id",)) -> None:
        self.reactive_calls: list[tuple[str, tuple[str, ...]]] = []
        self._fields = fields
        self._lock = threading.Lock()
        self._active = 0
        self.max_active = 0

    @property
    def reactive_capable(self) -> bool:
        return True

    def prepare_reactive(
        self,
        service,
        axis,
        action_ids,
        *,
        observation=None,
        check=None,
        **kwargs,
    ):
        with self._lock:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        time.sleep(0.05)
        with self._lock:
            self._active -= 1
            self.reactive_calls.append((axis, tuple(action_ids)))
        return AxisResult(
            axis,
            _roles_graph_for_fields(action_ids[0], self._fields),
            0,
            len(action_ids),
        )

    def commit(self, service, source, axis, actions, proposal, **kwargs):
        return proposal.graph


class FailingReactiveGrounding:
    """Grounding double that records calls but promotes nothing."""

    def __init__(self) -> None:
        self.reactive_calls: list[tuple[str, tuple[str, ...]]] = []

    @property
    def reactive_capable(self) -> bool:
        return True

    def prepare_reactive(
        self,
        service,
        axis,
        action_ids,
        *,
        observation=None,
        check=None,
        **kwargs,
    ):
        self.reactive_calls.append((axis, tuple(action_ids)))
        return None

    def commit(self, service, source, axis, actions, proposal, **kwargs):
        return proposal.graph


class ExposureReactiveGrounding:
    """Grounding double that exposes one deterministic response field."""

    def __init__(self) -> None:
        self.reactive_calls: list[tuple[str, tuple[str, ...]]] = []

    @property
    def reactive_capable(self) -> bool:
        return True

    def prepare_reactive(
        self,
        service,
        axis,
        action_ids,
        *,
        observation=None,
        check=None,
        **kwargs,
    ):
        self.reactive_calls.append((axis, tuple(action_ids)))
        return AxisResult(
            axis, _exposure_graph(action_ids[0], "email"), 0, len(action_ids)
        )

    def commit(self, service, source, axis, actions, proposal, **kwargs):
        return proposal.graph


class FixtureReactiveGrounding:
    """Grounding double for one bounded fixture-typing consultation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], dict]] = []

    @property
    def reactive_capable(self) -> bool:
        return True

    def prepare_reactive(
        self,
        service,
        axis,
        action_ids,
        *,
        context=None,
        **kwargs,
    ):
        self.calls.append((axis, tuple(action_ids), dict(context or {})))
        return AxisResult(axis, _fixture_graph(action_ids[0]), 0, len(action_ids))

    def commit(self, service, source, axis, actions, proposal, **kwargs):
        return proposal.graph


def _drain_workflow(*, source=None) -> tuple[LiveWorkflow, FakeReactiveGrounding]:
    grounding = FakeReactiveGrounding(
        fields=tuple(f"field_{index}" for index in range(20))
    )
    return assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding,
        source=source or SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
        options=LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    ), grounding


def _request() -> LiveRequest:
    return LiveRequest(
        service="svc",
        principal_id="principal-attacker",
        resource_id="resource:victim",
    )


@pytest.mark.parametrize("unchanged_reads", (1, 2))
def test_changed_source_blocks_wave_promotion(unchanged_reads: int) -> None:
    source = SimpleNamespace(
        load=Mock(
            side_effect=[QdlGraph()] * unchanged_reads + [_roles_graph("svc.Get")]
        )
    )
    workflow, grounding = _drain_workflow(source=source)
    grounding.commit = Mock()
    deficits = DeficitQueue()
    deficits.add((missing_role_deficit("svc.Get", (("coverage", "input_roles"),)),))
    wave = deficits.pop_wave(graph_snapshot="snapshot")

    execution = workflow._replanning._consultation._run_parallel_work_items(
        _request(), wave, deficits, CampaignAccumulator.empty()
    )

    assert grounding.reactive_calls == [("roles", ("svc.Get",))]
    grounding.commit.assert_not_called()
    assert execution.promoted == 0
    assert tuple(workflow.consultation_outcomes.values()) == ("transient_error",)


def test_drain_reactive_coalesces_field_fanout_into_one_model_call() -> None:
    """Twenty per-field role deficits on one action make one consultation."""

    workflow, grounding = _drain_workflow()
    deficits = DeficitQueue()
    added = deficits.add(
        tuple(
            missing_role_deficit(
                "svc.Get",
                (("coverage", "input_roles"),),
                field=f"field_{index}",
            )
            for index in range(20)
        )
    )
    assert added == 20

    promoted = workflow._replanning.drain_reactive(
        _request(),
        deficits,
        CampaignAccumulator.empty(),
        graph=QdlGraph(),
    )

    assert promoted == 1
    assert grounding.reactive_calls == [("roles", ("svc.Get",))]
    assert deficits.closed_count == 20
    assert deficits.pending_count == 0


def test_independent_work_items_run_in_parallel() -> None:
    """Two independent work items execute concurrently in one wave."""

    workflow, grounding = _drain_workflow()
    deficits = DeficitQueue()
    deficits.add(
        (
            missing_role_deficit(
                "svc.Get",
                (("coverage", "input_roles"),),
            ),
            missing_role_deficit(
                "svc.Delete",
                (("coverage", "input_roles"),),
            ),
        )
    )

    promoted = workflow._replanning.drain_reactive(
        _request(),
        deficits,
        CampaignAccumulator.empty(),
        graph=QdlGraph(),
    )

    assert promoted == 2
    assert sorted(grounding.reactive_calls) == [
        ("roles", ("svc.Delete",)),
        ("roles", ("svc.Get",)),
    ]
    assert grounding.max_active == 2
    assert deficits.closed_count == 2


def test_work_item_outcome_is_absorbing_until_new_evidence(
    caplog,
) -> None:
    """A consultation outcome stays silent until new evidence arrives."""

    grounding = FailingReactiveGrounding()
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding,
        source=SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
        options=LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    )
    deficits = DeficitQueue(max_tasks=None, max_attempts=3)
    accumulator = CampaignAccumulator.empty()
    accumulator.observations.append(
        Observation(
            observation_id="obs-1",
            check_id="check-obs-1",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            response_tree=(("email", "response-value"),),
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id="obs-1",
                        step_id="step-obs-1",
                        method_id="svc.Get",
                        scenario_id="scenario",
                        status=AccessOutcome.ALLOWED,
                    ),
                )
            ),
        )
    )

    def response_deficit(observation_id: str, field_name: str) -> Deficit:
        return Deficit(
            subgoal=QdlSubgoal(
                "exposes",
                (
                    Atom(value="svc.Get"),
                    field(_ANY_RESOURCE, _ANY_FIELD),
                ),
            ),
            predicate_class="exposes",
            axis="response_semantics",
            action="svc.Get",
            context=(
                ("fields", field_name),
                ("observation_id", observation_id),
            ),
        )

    deficits.add((response_deficit("obs-1", "email"),))
    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime.deficits"):
        promoted = workflow._replanning.drain_reactive(
            _request(),
            deficits,
            accumulator,
            graph=QdlGraph(),
        )

    assert promoted == 0
    assert (
        grounding.reactive_calls
        == [
            ("response_semantics", ("svc.Get",)),
        ]
        * 1
    )
    assert deficits.saturated_count == 1
    assert deficits.dispatchable is False
    assert any("work_item_absorbed" in message for message in caplog.messages)

    # A new field with the same observation is not new evidence.
    deficits.add((response_deficit("obs-1", "payment_token"),))
    workflow._replanning.drain_reactive(
        _request(),
        deficits,
        accumulator,
        graph=QdlGraph(),
    )
    assert len(grounding.reactive_calls) == 1

    # A new observation reopens the same consultation identity.
    accumulator.observations.append(
        Observation(
            observation_id="obs-2",
            check_id="check-obs-2",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="allowed",
            response_tree=(("email", "response-value"),),
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id="obs-2",
                        step_id="step-obs-2",
                        method_id="svc.Get",
                        scenario_id="scenario",
                        status=AccessOutcome.ALLOWED,
                    ),
                )
            ),
        )
    )
    deficits.add((response_deficit("obs-2", "email"),))
    workflow._replanning.drain_reactive(
        _request(),
        deficits,
        accumulator,
        graph=QdlGraph(),
    )
    assert len(grounding.reactive_calls) == 2
    assert deficits.saturated_count == 1


@pytest.mark.parametrize("action", ("svc.Get", "action:svc.Get"))
@pytest.mark.parametrize(
    "state", ("missing", "existing", "updated", "deferred", "empty")
)
def test_latency_work_item_baseline_branches(action: str, state: str, caplog) -> None:
    oracle = Mock(spec=["has_baseline", "update_baseline_from_observations"])
    oracle.has_baseline.return_value = state == "existing"
    oracle.update_baseline_from_observations.return_value = state == "updated"
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        options=LiveWorkflowOptions(
            latency_oracle=None if state == "missing" else oracle,
            grounding_runner=ThreadedGroundingRunner(),
        ),
    )
    deficits = DeficitQueue(max_tasks=None, max_attempts=1)
    deficits.add(
        (
            Deficit(
                subgoal=QdlSubgoal("causes", (Atom(value=action), _ANY_DIMENSION)),
                predicate_class="causes",
                axis="availability",
                action=action,
            ),
        )
    )
    (work_item,) = deficits.pop_wave(graph_snapshot="snapshot")
    accumulator = CampaignAccumulator.empty()
    if state != "empty":
        for observation_id, method_id in (
            ("obs-z", "svc.Get"),
            ("obs-other", "svc.Other"),
            ("obs-a", "svc.Get"),
        ):
            accumulator.observations.append(
                Observation(
                    observation_id=observation_id,
                    check_id=f"check-{observation_id}",
                    scenario_id="scenario",
                    observed_outcome=AccessOutcome.ALLOWED,
                    response_summary="allowed",
                    trace=ExecutionTrace(
                        steps=(
                            TraceStep(
                                observation_id=observation_id,
                                step_id=f"step-{observation_id}",
                                method_id=method_id,
                                scenario_id="scenario",
                                status=AccessOutcome.ALLOWED,
                            ),
                        )
                    ),
                )
            )
    with caplog.at_level(logging.INFO, logger="cloud_dast.runtime.consultation"):
        promoted = workflow._replanning._consultation._ground_latency_work_item(
            _request(), work_item, deficits, accumulator
        )

    expected = int(state in {"existing", "updated"})
    assert promoted == deficits.closed_count == expected
    assert deficits.pending_count == 1 - expected
    assert deficits.saturated_count == 0
    assert deficits.dispatchable is False
    assert any("latency_baseline_deferred" in msg for msg in caplog.messages) == (
        not expected
    )
    if state == "missing":
        oracle.has_baseline.assert_not_called()
    else:
        oracle.has_baseline.assert_called_once_with(action)
    if state in {"missing", "existing"}:
        oracle.update_baseline_from_observations.assert_not_called()
    else:
        observations = accumulator.observations
        matching = () if state == "empty" else (observations[0], observations[2])
        oracle.update_baseline_from_observations.assert_called_once_with(
            action, matching
        )


def test_promotion_closes_every_deficit_requiring_the_promoted_fact() -> None:
    """Closure propagates beyond the work item that produced the fact."""

    grounding = ExposureReactiveGrounding()
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding,
        source=SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
        options=LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    )
    deficits = DeficitQueue(max_tasks=None)
    exposure = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, Atom(value="email")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="svc.Get",
        context=(("field", "email"),),
    )
    response = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, _ANY_FIELD),
            ),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="svc.Get",
        context=(("fields", "email"), ("observation_id", "obs-1")),
    )
    deficits.add((exposure, response))

    promoted = workflow._replanning.drain_reactive(
        _request(),
        deficits,
        CampaignAccumulator.empty(),
        graph=QdlGraph(),
    )

    assert promoted == 1
    assert grounding.reactive_calls == [("exposures", ("svc.Get",))]
    assert deficits.closed_count == 2
    assert deficits.pending_count == 0


def test_promotion_removes_stale_path_deficits() -> None:
    """A deficit for a removed path leaves the queue without a consultation."""

    grounding = ExposureReactiveGrounding()
    workflow = assemble_workflow(
        None,
        Mock(spec_set=assemble_runner(Mock(), Mock(), Mock())),
        None,
        grounding=grounding,
        source=SimpleNamespace(load=lambda *args, **kwargs: QdlGraph()),
        options=LiveWorkflowOptions(grounding_runner=ThreadedGroundingRunner()),
    )
    deficits = DeficitQueue(max_tasks=1)
    exposure = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (
                Atom(value="svc.Get"),
                field(_ANY_RESOURCE, Atom(value="email")),
            ),
        ),
        predicate_class="exposes",
        axis="exposures",
        action="svc.Get",
        context=(("field", "email"),),
    )
    stale = _blocked_deficit("path-old")
    deficits.add((exposure, exposure, stale))

    promoted = workflow._replanning.drain_reactive(
        _request(),
        deficits,
        CampaignAccumulator.empty(),
        graph=QdlGraph(),
        active_path_ids=frozenset({"path-new"}),
    )

    assert promoted == 1
    assert grounding.reactive_calls == [("exposures", ("svc.Get",))]
    assert deficits.closed_count == 1
    assert deficits.stale_count == 1
    assert deficits.pending_count == 0


@pytest.mark.parametrize("wave", [False, True])
def test_propagation_preserves_reentrant_dispatch(wave, monkeypatch):
    from cloud_dast.runtime.deficits import propagation

    deficit = _blocked_deficit("path")
    queue = DeficitQueue(max_tasks=4, max_attempts=1)
    queue.add((deficit,))
    item = single_deficit_work_item(deficit)
    graph = _closing_graph()

    def closes(*args, **kwargs):
        assert len(queue.pop_wave()) == 1
        return True

    monkeypatch.setattr(propagation, "grounding_result_closes_deficit", closes)
    if wave:
        queue.propagate_wave_results(
            {item.work_item_id: WorkItemGrounding(item.work_item_id, graph)}
        )
    else:
        queue.propagate_work_item_result(item, graph)
    assert queue.closed_count == 1
    # Closure does not cancel the work selected by the reentrant callback.
    # Its later failure still charges the dispatched work-item attempt.
    queue.record_failure(deficit)
    assert queue.saturated_count == 1


@pytest.mark.parametrize("wave", [False, True])
@pytest.mark.parametrize(
    "exception", [RuntimeError("probe failed"), StopIteration("probe stopped")]
)
def test_propagation_keeps_partial_closure_on_error(wave, exception, monkeypatch):
    from cloud_dast.runtime.deficits import propagation

    first = _blocked_deficit("first", action="svc.A")
    second = _blocked_deficit("second", action="svc.B", effect=_OTHER_EFFECT)
    queue = DeficitQueue(max_tasks=None)
    queue.add((first, second))
    item = single_deficit_work_item(first)
    graph = _closing_graph()

    def closes(deficit, *args, **kwargs):
        if deficit == second:
            raise exception
        return True

    monkeypatch.setattr(propagation, "grounding_result_closes_deficit", closes)
    with pytest.raises(type(exception)) as caught:
        if wave:
            queue.propagate_wave_results(
                {item.work_item_id: WorkItemGrounding(item.work_item_id, graph)}
            )
        else:
            queue.propagate_work_item_result(item, graph)
    assert caught.value is exception
    assert queue.closed_count == 1
    assert queue.pending_count == 1
    queue.close_key(second.key)
    assert queue.closed_count == 2
