from __future__ import annotations

from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
    resource_state_machine_graph,
)


def test_resource_path_preserves_effect_and_precondition_pairs() -> None:
    graph = resource_state_machine_graph(
        resource_states={"order": "new"},
        resource_transitions=(
            ("Create", "order", "new", "created"),
            ("Pay", "order", "created", "paid"),
        ),
    )
    paths = StateMachineEngine().find_resource_paths(graph, "order", "paid")
    assert len(paths) == 1
    path = paths[0]
    assert path.resource == "order"
    assert path.final_state == "paid"
    assert path.actions == ("Create", "Pay")
    assert list(zip(path.states[:-1], path.states[1:], strict=True)) == [
        ("new", "created"),
        ("created", "paid"),
    ]
