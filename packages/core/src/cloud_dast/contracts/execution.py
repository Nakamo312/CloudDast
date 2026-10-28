"""Runtime-neutral physical execution and evaluation result contracts."""

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import NamedTuple

from cloud_dast.model import Check, Finding, Observation


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
    traces: Mapping[str, tuple[Observation, ...]]
    provenance: Mapping[tuple[str, str], ObservationProvenance]
    policy_verdicts: Mapping[tuple[str, str], object]
    minimal_checks: Mapping[tuple[str, str], Check] = dataclass_field(
        default_factory=dict
    )


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Findings and replayable event projections produced by evaluation."""

    findings: tuple[Finding, ...]
    replayed_observations: tuple[Observation, ...]
    replayed_findings: tuple[Finding, ...]


__all__ = [
    "EvaluationResult",
    "ExecutionResult",
    "ObservationProvenance",
]
