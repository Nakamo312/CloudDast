"""Persist declarative state-machine specifications as canonical QDL."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.ports import FormalRepository
from cloud_dast.qdl.state_machine_spec import (
    StateMachineSpecification,
)


@dataclass(frozen=True, slots=True)
class StateMachineIngestionResult:
    """Summary of one state-machine ingestion."""

    service: str
    source_id: str
    graph_hash: str
    state_count: int
    action_count: int
    transition_count: int
    forbidden_state_count: int


class StateMachineIngestionService:
    """Persist a state-machine graph through the repository port."""

    def __init__(
        self,
        repository: FormalRepository,
        *,
        adapter_version: str = "state-machine-v1",
    ) -> None:
        self._repository = repository
        self._adapter_version = adapter_version

    def ingest(
        self,
        service: str,
        specification: StateMachineSpecification,
        *,
        source_id: str | None = None,
    ) -> StateMachineIngestionResult:
        normalized_service = service.strip()
        if not normalized_service:
            raise ValueError("service must not be empty")

        graph = specification.to_qdl_graph()
        logical_source_id = source_id or f"state-machine:{normalized_service}"
        self._repository.save(
            logical_source_id,
            graph,
            provenance={
                "service": normalized_service,
                "source_kind": "declarative-state-machine",
                "state_count": len(specification.states),
                "action_count": len(specification.actions),
                "transition_count": len(specification.transitions),
                "forbidden_state_count": len(specification.forbidden_states),
            },
            adapter_version=self._adapter_version,
            mapping_report={
                "mapped": len(graph.facts),
                "unmapped": (),
                "ambiguous": (),
                "conflict": (),
            },
        )

        return StateMachineIngestionResult(
            service=normalized_service,
            source_id=logical_source_id,
            graph_hash=graph.content_hash,
            state_count=len(specification.states),
            action_count=len(specification.actions),
            transition_count=len(specification.transitions),
            forbidden_state_count=len(specification.forbidden_states),
        )


__all__ = ["StateMachineIngestionResult", "StateMachineIngestionService"]
