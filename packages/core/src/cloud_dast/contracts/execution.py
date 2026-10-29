"""Runtime-neutral campaign inputs, bound runs and execution results."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import NamedTuple

from cloud_dast.contracts.assessment import (
    ActionRuntimeLedger,
    BindingDeficit,
    CoverageMatrix,
    NormCoverageRow,
)
from cloud_dast.contracts.plan import InvariantProjection, QdlExecutionView
from cloud_dast.model import (
    Check,
    Finding,
    MethodSpec,
    Observation,
    PolicyVerdict,
    ScenarioPosition,
)
from cloud_dast.ports import GroundingEnrichmentStatus
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.reasoning import QdlPlan


class ObservationProvenance(NamedTuple):
    """Path identity and bound norm used to interpret an observation."""

    goal_id: str | None
    path_id: str
    step_id: str
    invariant_id: str
    identities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Physical history and norm-indexed evaluations produced by one run."""

    observations: tuple[Observation, ...]
    checks: tuple[Check, ...]
    provenance: Mapping[tuple[str, str], ObservationProvenance]
    policy_verdicts: Mapping[tuple[str, str], PolicyVerdict]
    minimal_checks: Mapping[tuple[str, str], Check] = dataclass_field(
        default_factory=dict
    )


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Findings and replayable event projections produced by evaluation."""

    findings: tuple[Finding, ...]
    replayed_observations: tuple[Observation, ...]
    replayed_findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class LiveRequest:
    """Inputs for one QDL-backed service run."""

    service: str
    principal_id: str
    resource_id: str
    method_id: str | None = None
    max_checks: int | None = None


@dataclass(frozen=True, slots=True)
class LiveResult:
    scenario: ScenarioPosition
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    replayed_observations: tuple[Observation, ...]
    replayed_findings: tuple[Finding, ...]
    qdl_graph: QdlGraph | None = None
    qdl_plan: QdlPlan | None = None
    coverage: CoverageMatrix | None = None
    action_runtime: ActionRuntimeLedger | None = None
    norm_coverage: tuple[NormCoverageRow, ...] = ()
    grounding_enrichment_status: GroundingEnrichmentStatus = "not_started"


@dataclass(frozen=True, slots=True)
class ScenarioBinding:
    """A live run bound to a method, scenario, QDL graph, and QDL plan."""

    scenario: ScenarioPosition
    graph: QdlGraph
    plan: QdlPlan
    execution: QdlExecutionView
    invariants: Mapping[str, InvariantProjection]
    methods: tuple[MethodSpec, ...]
    deficits: tuple[BindingDeficit, ...] = ()
    action_runtime: ActionRuntimeLedger | None = None


__all__ = [
    "EvaluationResult",
    "ExecutionResult",
    "ObservationProvenance",
    "LiveRequest",
    "LiveResult",
    "ScenarioBinding",
]
