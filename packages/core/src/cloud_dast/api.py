"""Public request and result contracts for a QDL-backed campaign."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cloud_dast.contracts.execution import (
    EvaluationResult,
    ExecutionResult,
    ObservationProvenance,
)
from cloud_dast.model import (
    Finding,
    MethodSpec,
    Observation,
    ScenarioPosition,
)
from cloud_dast.ports import GroundingEnrichmentStatus
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
)
from cloud_dast.runtime.planning import QdlPlan
from cloud_dast.verification.action_runtime import (
    ActionRuntimeLedger,
    BindingDeficit,
)
from cloud_dast.verification.coverage_models import CoverageMatrix
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norm_coverage import NormCoverageRow


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
    "QdlExecutionPath",
    "QdlExecutionStep",
    "QdlExecutionView",
    "LiveRequest",
    "LiveResult",
    "ObservationProvenance",
    "ScenarioBinding",
]
