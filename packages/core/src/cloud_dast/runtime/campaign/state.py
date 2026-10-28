"""Campaign state owned by the lifecycle of one QDL run.

Per-round execution state lives in :mod:`cloud_dast.runtime.execution.state`;
per-step adaptive state stays in :mod:`cloud_dast_fuzzing.session`.  This
module contains only campaign-wide coordination state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_dast.api import LiveRequest, ScenarioBinding
from cloud_dast.model.events import EventScope
from cloud_dast.ports import GroundingHandle
from cloud_dast.runtime.budget import CallLimits
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.differential import results
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.recovery import Coordinator
from cloud_dast.runtime.scheduler import CoverageDrivenScheduler


@dataclass(slots=True)
class ExecutionState:
    """Scheduler and result state that advances through campaign rounds."""

    scheduler: CoverageDrivenScheduler
    accumulator: CampaignAccumulator
    budget: CallLimits
    rounds: int = 0
    branch_backlog: tuple[QdlExecutionPath, ...] = ()
    blocked_reasons: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DifferentialState:
    """Measurements and one-time reserve state for differential execution."""

    diff_budget_reserve: int
    variance_records: dict[tuple[str, ...], results.VarianceRecord]
    paired_steps: set[tuple[str, ...]]
    differential_swept: bool
    differential_evidence: Store[MeasurementKey]


@dataclass(slots=True)
class GroundingState:
    """Grounding, deficit, and branch-recovery state for one campaign."""

    deficits: DeficitQueue
    recovery: Coordinator
    handle: GroundingHandle | None = None
    classified_paths: set[str] = field(default_factory=set)
    classified_observations: int = 0
    grounding_finished: bool = False
    reactive_active: bool = False


@dataclass(slots=True)
class RuntimeState:
    """Stable request context plus explicitly owned mutable state slices."""

    request: LiveRequest
    binding: ScenarioBinding
    scope: EventScope
    execution: ExecutionState
    differential: DifferentialState
    grounding: GroundingState
