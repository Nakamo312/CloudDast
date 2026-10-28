"""Mutable state accumulated while executing one campaign round.

The campaign lifecycle owns :class:`RuntimeState`; this module owns only
the state that is rebuilt for, and consumed by, one execution round.  Keeping
the two lifecycles separate prevents path execution from depending on the
campaign's replanning and grounding state container.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_dast.contracts.execution import (
    ExecutionResult,
    ObservationProvenance,
)
from cloud_dast.model import Check, Observation
from cloud_dast.runtime.campaign.replay import RoundReplay
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.runtime.differential.results import PartialExecutionResult
from cloud_dast.verification.oracles.policy_verdict import PolicyVerdict


@dataclass(slots=True)
class CampaignRoundState:
    """Mutable state shared by every path in one scheduler round."""

    observations: list[Observation]
    traces: dict[str, tuple[Observation, ...]]
    provenance: dict[tuple[str, str], ObservationProvenance]
    policy_verdicts: dict[tuple[str, str], object]
    path_reasons: dict[str, str]
    path_history: dict[str, list[Observation]]
    minimal_checks: dict[tuple[str, str], Check]
    differential_evidence: Store[MeasurementKey]
    replay: RoundReplay = field(default_factory=lambda: RoundReplay(set(), {}, {}))
    deficit_sink: object | None = None
    blocked_reasons: dict[str, str] | None = None


@dataclass(slots=True)
class CampaignAccumulator:
    """Merge execution results across campaign rounds."""

    observations: list[Observation]
    checks: list[Check]
    traces: dict[str, tuple[Observation, ...]]
    provenance: dict[tuple[str, str], ObservationProvenance]
    policy_verdicts: dict[tuple[str, str], PolicyVerdict]
    minimal_checks: dict[tuple[str, str], Check]

    @classmethod
    def empty(cls) -> CampaignAccumulator:
        return cls([], [], {}, {}, {}, {})

    def add(self, result: ExecutionResult) -> None:
        self.observations.extend(result.observations)
        self.checks.extend(result.checks)
        self.traces.update(result.traces)
        self.provenance.update(result.provenance)
        self.policy_verdicts.update(result.policy_verdicts)
        self.minimal_checks.update(result.minimal_checks)

    def add_partial(self, result: PartialExecutionResult) -> None:
        self.observations.extend(result.observations)
        self.checks.extend(result.checks)

    def as_result(self) -> ExecutionResult:
        return ExecutionResult(
            observations=tuple(self.observations),
            checks=tuple(self.checks),
            traces=dict(self.traces),
            provenance=dict(self.provenance),
            policy_verdicts=dict(self.policy_verdicts),
            minimal_checks=dict(self.minimal_checks),
        )


__all__ = ["CampaignAccumulator", "CampaignRoundState"]
