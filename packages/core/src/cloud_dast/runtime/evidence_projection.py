"""Project executed observations into the campaign's evidence graph.

This module is deliberately narrower than the execution runner: it owns the
read/write boundary for runtime evidence, while path execution decides when
an observation is produced and how it is classified.
"""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.binding import scenario_scope
from cloud_dast.model import Check, Observation
from cloud_dast.model.events import CheckCompleted, DomainEvent
from cloud_dast.ports import FormalRepository
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.execution.contracts import QdlExecutionPath, QdlExecutionStep
from cloud_dast.verification.projection import ObservationProjector


class Projection:
    """Read and persist the normalized evidence visible to a path runner."""

    def __init__(
        self,
        *,
        events: Callable[[], tuple[DomainEvent, ...]],
        path_lookup: Callable[[str], QdlExecutionPath | None],
        checks: Callable[[], tuple[Check, ...]],
        formal_repository: FormalRepository | None,
        observation_projector: ObservationProjector,
    ) -> None:
        self._events = events
        self._path_lookup = path_lookup
        self._checks = checks
        self._formal_repository = formal_repository
        self._observation_projector = observation_projector

    def observed_graph(self, path: QdlExecutionPath) -> QdlGraph:
        """Read canonical evidence or project the runner's journal calls."""

        graph = merge_graphs(
            *(
                step.evidence_graph
                for step in path.steps
                if step.evidence_graph is not None
            )
        )
        if self._formal_repository is not None:
            return merge_graphs(
                graph, self._formal_repository.load_merged("observation:")
            )

        checks = {check.check_id: check for check in self._checks()}
        for event in self._events():
            if not isinstance(event, CheckCompleted):
                continue
            check = checks.get(event.observation.check_id) or event.check
            if check is None:
                continue
            previous = self._path_lookup(event.path_id)
            step = (
                next(
                    (
                        candidate
                        for candidate in previous.steps
                        if candidate.step_id == event.step_id
                        and candidate.method.method_id == check.method_id
                        and candidate.scenario.scenario_id == check.scenario_id
                    ),
                    None,
                )
                if previous is not None
                else None
            )
            if step is None:
                continue
            graph = merge_graphs(
                graph,
                self._observation_projector.project(
                    event.observation,
                    check.method_id,
                    graph=graph,
                    identities=check.identities,
                    scope=scenario_scope(step.scenario),
                    observed_at=event.occurred_at.timestamp(),
                    check=check,
                ),
            )
        return graph

    def persist_observation(
        self,
        step: QdlExecutionStep,
        observation: Observation,
        service: str,
        *,
        graph: QdlGraph,
        identities: tuple[str, ...],
    ) -> None:
        """Persist one normalized observation projection when storage exists."""

        observed_at = next(
            (
                event.occurred_at.timestamp()
                for event in self._events()
                if isinstance(event, CheckCompleted)
                and event.observation.observation_id == observation.observation_id
            ),
            None,
        )
        check = next(
            (
                check
                for check in self._checks()
                if check.check_id == observation.check_id
            ),
            None,
        )
        graph = self._observation_projector.project(
            observation,
            step.method.method_id,
            graph=graph,
            identities=identities,
            scope=scenario_scope(step.scenario),
            observed_at=observed_at,
            check=check,
        )
        if self._formal_repository is None:
            return
        self._formal_repository.save(
            f"observation:{observation.observation_id}",
            graph,
            provenance={
                "service": service,
                "source_kind": "runtime-observation",
                "method_id": step.method.method_id,
                "scenario_id": observation.scenario_id,
                "check_id": observation.check_id,
            },
            adapter_version="observation-projection-v3",
            mapping_report={
                "mapped": len(graph.facts),
                "unmapped": (),
                "ambiguous": (),
                "conflict": (),
            },
        )


__all__ = ["Projection"]
