from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import Context
from cloud_dast.qdl.state_machine_spec import (
    StateMachineForbiddenState,
    StateMachineSpecification,
    StateMachineTransition,
)
from cloud_dast.runtime.ingestion import StateMachineImporter


class FakeRepository:
    def __init__(self) -> None:
        self.saved: list[dict[str, object]] = []
        self.graphs: dict[str, object] = {}

    def save(self, source_id, graph, *, provenance, adapter_version, mapping_report):
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )
        self.graphs[source_id] = graph

    def load(self, source_id):
        return self.graphs.get(source_id)

    def load_merged(self, source_prefix):
        merged = QdlGraph()
        for source_id, graph in self.graphs.items():
            if source_id.startswith(source_prefix):
                merged = merge_graphs(merged, graph)
        return merged


from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs


def specification() -> StateMachineSpecification:
    return StateMachineSpecification(
        states=("created", "approved", "shipped"),
        actions=("approve", "ship"),
        norms=("no_ship_without_approval",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="approve", from_state="created", to_state="approved"
            ),
            StateMachineTransition(
                action="ship", from_state="approved", to_state="shipped"
            ),
        ),
        forbidden_states=(
            StateMachineForbiddenState(
                norm="no_ship_without_approval",
                state="shipped",
            ),
        ),
    )


def test_state_machine_ingestion_saves_qdl_graph() -> None:
    repository = FakeRepository()
    service = StateMachineImporter(repository)

    result = service.ingest("orders", specification())

    assert result.source_id == "state-machine:orders"
    assert result.graph_hash
    assert repository.saved[0]["adapter_version"] == "state-machine-v1"
    assert (
        repository.saved[0]["provenance"]["source_kind"] == "declarative-state-machine"
    )
    assert repository.saved[0]["mapping_report"]["mapped"] > 0
    assert repository.load("state-machine:orders") == repository.saved[0]["graph"]


def test_state_machine_ingestion_rejects_empty_service() -> None:
    service = StateMachineImporter(FakeRepository())

    with pytest.raises(ValueError, match="service must not be empty"):
        service.ingest("   ", specification())


def test_state_machine_specification_requires_initial_state() -> None:
    with pytest.raises(ValueError, match="at least one initial state"):
        StateMachineSpecification(
            states=("created",),
            actions=("approve",),
            transitions=(
                StateMachineTransition(
                    action="approve",
                    from_state="created",
                    to_state="approved",
                ),
            ),
        )


def test_state_machine_specification_requires_transition() -> None:
    with pytest.raises(ValueError, match="at least one transition"):
        StateMachineSpecification(
            states=("created",),
            initial_states=("created",),
        )


def test_state_machine_specification_compiles_runtime_observations() -> None:
    spec = StateMachineSpecification(
        states=("created", "shipped"),
        actions=("ship",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="ship", from_state="created", to_state="shipped"
            ),
        ),
        observed_transitions=(
            StateMachineTransition(
                action="ship", from_state="created", to_state="shipped"
            ),
        ),
    )

    graph = spec.to_qdl_graph()

    assert any(
        fact.context is Context.RUNTIME and fact.predicate.name == "transition"
        for fact in graph.facts
    )


def test_unprefixed_action_ids_are_canonicalized_once() -> None:
    spec = StateMachineSpecification(
        states=("created", "approved"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="approve", from_state="created", to_state="approved"
            ),
        ),
        observed_transitions=(
            StateMachineTransition(
                action="approve", from_state="created", to_state="approved"
            ),
        ),
    )

    graph = spec.to_qdl_graph()

    assert spec.actions == ("action:approve",)
    assert _declared_actions(graph) == {"action:approve"}
    assert _transition_actions(graph) == {"action:approve"}
    assert _transition_actions(graph, Context.RUNTIME) == {"action:approve"}


def test_prefixed_action_ids_compile_to_the_same_graph() -> None:
    unprefixed = StateMachineSpecification(
        states=("created", "shipped"),
        actions=("ship",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="ship", from_state="created", to_state="shipped"
            ),
        ),
    )
    prefixed = StateMachineSpecification(
        states=("created", "shipped"),
        actions=("action:ship",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="action:ship", from_state="created", to_state="shipped"
            ),
        ),
    )

    assert unprefixed.to_qdl_graph() == prefixed.to_qdl_graph()


def test_alias_duplicate_actions_and_transitions_collapse() -> None:
    spec = StateMachineSpecification(
        states=("created", "approved"),
        actions=("approve", "action:approve"),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="approve", from_state="created", to_state="approved"
            ),
            StateMachineTransition(
                action="action:approve", from_state="created", to_state="approved"
            ),
        ),
    )
    repository = FakeRepository()

    result = StateMachineImporter(repository).ingest("orders", spec)

    assert result.action_count == 1
    assert result.transition_count == 1
    assert _declared_actions(repository.graphs["state-machine:orders"]) == {
        "action:approve"
    }
    assert _transition_actions(repository.graphs["state-machine:orders"]) == {
        "action:approve"
    }


def _declared_actions(graph: QdlGraph) -> set[str]:
    return {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and fact.args[1].value == "Action"
    }


def _transition_actions(graph: QdlGraph, context: Context | None = None) -> set[str]:
    return {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "transition"
        and (context is None or fact.context is context)
    }
