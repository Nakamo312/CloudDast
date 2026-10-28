"""Per-norm execution coverage for QDL live campaigns (S24R).

Every norm maps to its requirement term — the effect its ``prevents`` fact
must produce — and is classified through the same term coverage algebra as
the graph projection:
``coverage(term) = semantic × setup × oracle × runtime``.  The pipeline
witnesses each factor differently (scheduler paths, latency baselines,
oracle verdicts), but the deficit is always typed by the first missing
factor, never by a pipeline stage or action.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from cloud_dast.model import (
    Check,
    Finding,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import (
    CoverageUpdated,
    DomainEvent,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.qdl.graph import Struct, canonical_json
from cloud_dast.verification.coverage_models import (
    BlindDeficitType,
    CoverageFactor,
    TermCoverageEvaluation,
    TermFactors,
    evaluate_term_coverage,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.norms import EFFECT_PRIMITIVES

_GENERIC_STEP_REASONS = frozenset({"QDL step evaluated", "QDL chain step evaluated"})
_GENERIC_PATH_REASONS = frozenset(
    {
        "QDL effect chain was not verified",
        "QDL effect chain verified",
    }
)


@dataclass(frozen=True, slots=True)
class NormCoverageRow:
    """Where one executable norm stopped in the live pipeline."""

    norm_id: str
    effect: str
    path_count: int
    scheduled: bool
    selected: bool
    executed: bool
    oracle_called: bool
    verdict: str
    blocked_reason: str
    action_ids: tuple[str, ...]
    path_ids: tuple[str, ...]
    check_count: int
    finding_count: int
    effect_id: str = ""
    deficit: BlindDeficitType | None = None
    missing_factor: CoverageFactor | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class _ProvenanceView(Protocol):
    invariant_id: str
    path_id: str


class _ExecutionView(Protocol):
    observations: tuple[Observation, ...]
    checks: tuple[Check, ...]
    provenance: Mapping[tuple[str, str], _ProvenanceView]
    policy_verdicts: Mapping[tuple[str, str], object]


class _BindingView(Protocol):
    execution: Any


class _SchedulerStateView(Protocol):
    selections: list[str]


class _SchedulerView(Protocol):
    paths: tuple[Any, ...]
    state: _SchedulerStateView

    def is_prewarmed(self, path_id: str) -> bool: ...


def build_norm_coverage(
    binding: _BindingView,
    execution: _ExecutionView,
    scheduler: _SchedulerView,
    findings: Iterable[Finding] = (),
    events: Iterable[DomainEvent] = (),
    *,
    budget_exhausted: bool = False,
) -> tuple[NormCoverageRow, ...]:
    """Explain every bound norm without importing benchmark ground truth."""

    events = tuple(events)
    scheduler_path_ids = {path.path_id for path in scheduler.paths}
    selected_ids = set(scheduler.state.selections)
    checks_by_id = {check.check_id: check for check in execution.checks}
    invariant_ids_by_check = _invariant_ids_by_check(events)
    observations_by_invariant = _observations_by_invariant(
        execution,
        checks_by_id,
        invariant_ids_by_check,
    )
    path_events = {
        event.path_id: event for event in events if isinstance(event, QdlPathEvaluated)
    }
    step_reasons = _step_reasons_by_path(events)
    findings_by_norm = _findings_by_norm(findings)

    rows: list[NormCoverageRow] = []
    for invariant_id, invariant in binding.execution.invariants.items():
        paths = _paths_for_invariant(binding.execution.paths, invariant_id)
        observations = observations_by_invariant.get(invariant_id, ())
        historical_path_ids = _path_ids_for_observations(
            execution, observations, invariant_id
        )
        path_ids = tuple(
            sorted({*(path.path_id for path in paths), *historical_path_ids})
        )
        verdicts = tuple(
            execution.policy_verdicts[(observation.observation_id, invariant_id)]
            for observation in observations
            if (observation.observation_id, invariant_id) in execution.policy_verdicts
        )
        oracle_verdicts = tuple(
            verdict for verdict in verdicts if getattr(verdict, "oracle_called", True)
        )
        oracle_called = bool(oracle_verdicts)
        # A selected/probed path is only logical execution planning evidence.
        # Runtime execution requires an actual observation produced by the
        # transport boundary; a path event with ``probe_count`` alone must not
        # close a norm or hide a terminal action deficit.
        executed = bool(observations)
        finding_count = len(findings_by_norm.get(invariant_id, ()))
        verdict = _verdict(oracle_verdicts, executed, oracle_called, finding_count)
        selected = any(path_id in selected_ids for path_id in path_ids)
        waiting_for_latency_baseline = any(
            scheduler.is_prewarmed(path_id) for path_id in path_ids
        )
        blocked_reason = _blocked_reason(
            path_ids,
            path_events,
            step_reasons,
            scheduler_path_ids=scheduler_path_ids,
            selected=selected,
            executed=executed,
            oracle_called=oracle_called,
            verdict=verdict,
            policy_reason=_policy_reason(oracle_verdicts),
            budget_exhausted=budget_exhausted,
            waiting_for_latency_baseline=waiting_for_latency_baseline,
        )
        evaluation = _term_evaluation(
            invariant,
            path_ids=path_ids,
            scheduler_path_ids=scheduler_path_ids,
            executed=executed,
            oracle_called=oracle_called,
            waiting_for_latency_baseline=waiting_for_latency_baseline,
        )

        rows.append(
            NormCoverageRow(
                norm_id=invariant.norm_id,
                effect=_effect(invariant),
                path_count=len(path_ids),
                scheduled=any(path_id in scheduler_path_ids for path_id in path_ids),
                selected=any(path_id in selected_ids for path_id in path_ids),
                executed=executed,
                oracle_called=oracle_called,
                verdict=verdict,
                blocked_reason=blocked_reason,
                action_ids=tuple(
                    sorted(
                        {
                            *(
                                step.method.method_id
                                for path in paths
                                for step in path.steps
                            ),
                            *(
                                check.method_id
                                for check in checks_by_id.values()
                                if check.invariant_id == invariant_id
                            ),
                        }
                    )
                ),
                path_ids=path_ids,
                check_count=len(observations),
                finding_count=finding_count,
                effect_id=_effect_id(invariant),
                deficit=evaluation.deficit,
                missing_factor=evaluation.missing_factor,
            )
        )
    return tuple(sorted(rows, key=lambda row: (row.norm_id, row.effect)))


def _paths_for_invariant(
    paths: Iterable[Any],
    invariant_id: str,
) -> tuple[Any, ...]:
    return tuple(
        dict.fromkeys(
            path
            for path in paths
            if any(step.invariant.invariant_id == invariant_id for step in path.steps)
        )
    )


def _invariant_ids_by_check(events: Iterable[DomainEvent]) -> dict[str, str]:
    result: dict[str, str] = {}
    for event in events:
        if isinstance(event, CoverageUpdated):
            result[event.check_id] = event.invariant_id
    return result


def _observations_by_invariant(
    execution: _ExecutionView,
    checks_by_id: Mapping[str, Check],
    invariant_ids_by_check: Mapping[str, str],
) -> dict[str, tuple[Observation, ...]]:
    result: dict[str, list[Observation]] = {}
    for observation in execution.observations:
        invariant_ids = {
            provenance.invariant_id
            for (observation_id, _), provenance in execution.provenance.items()
            if observation_id == observation.observation_id
        }
        if not invariant_ids:
            invariant_id = invariant_ids_by_check.get(observation.check_id)
            if invariant_id is None:
                check = checks_by_id.get(observation.check_id)
                invariant_id = check.invariant_id if check is not None else None
            if invariant_id is not None:
                invariant_ids.add(invariant_id)
        for invariant_id in sorted(invariant_ids):
            result.setdefault(invariant_id, []).append(observation)
    return {
        invariant_id: tuple(observations)
        for invariant_id, observations in result.items()
    }


def _path_ids_for_observations(
    execution: _ExecutionView,
    observations: Iterable[Observation],
    invariant_id: str,
) -> set[str]:
    observation_ids = {observation.observation_id for observation in observations}
    return {
        provenance.path_id
        for (observation_id, norm_id), provenance in execution.provenance.items()
        if observation_id in observation_ids and norm_id == invariant_id
    }


def _step_reasons_by_path(events: Iterable[DomainEvent]) -> dict[str, str]:
    result: dict[str, str] = {}
    for event in events:
        if not isinstance(event, QdlStepEvaluated):
            continue
        if event.reason in _GENERIC_STEP_REASONS:
            continue
        result[event.path_id] = event.reason
    return result


def _findings_by_norm(findings: Iterable[Finding]) -> dict[str, tuple[Finding, ...]]:
    result: dict[str, list[Finding]] = {}
    for finding in findings:
        result.setdefault(finding.invariant_id, []).append(finding)
    return {key: tuple(values) for key, values in result.items()}


def _effect(invariant: InvariantProjection) -> str:
    fact = invariant.norm_fact
    if fact is None or len(fact.args) != 2:
        return "none"
    effect = fact.args[1]
    return getattr(effect, "name", "unknown")


def _effect_id(invariant: InvariantProjection) -> str:
    """Return the canonical effect identity of one norm requirement."""

    fact = invariant.norm_fact
    if fact is None or len(fact.args) != 2:
        return ""
    effect = fact.args[1]
    if not hasattr(effect, "name"):
        return ""
    return canonical_json(effect)


def _term_evaluation(
    invariant: InvariantProjection,
    *,
    path_ids: tuple[str, ...],
    scheduler_path_ids: set[str],
    executed: bool,
    oracle_called: bool,
    waiting_for_latency_baseline: bool,
) -> TermCoverageEvaluation:
    """Classify one norm row through the S24R term coverage algebra.

    The norm's requirement term is the effect its ``prevents`` fact must
    produce.  The pipeline witnesses the four factors as:

    - ``semantic`` — the norm compiles to a structural requirement term;
    - ``setup`` — the runtime fixture is calibrated (latency baseline);
    - ``oracle_channel`` — an executable derivation (a bound, scheduled
      path) reaches the requirement;
    - ``oracle_primitive`` — the requirement's constructor has a
      deterministic oracle primitive;
    - ``runtime`` — the requirement was executed *and* the deterministic
      oracle produced a verdict.

    Path selection is pipeline provenance, not a factor: a norm whose path
    was never selected simply lacks runtime evidence, exactly like a
    selected path that produced no observation.
    """

    requirement = _requirement_term(invariant)
    factors = TermFactors(
        semantic=requirement is not None,
        setup=not waiting_for_latency_baseline,
        oracle_channel=bool(path_ids)
        and any(path_id in scheduler_path_ids for path_id in path_ids),
        oracle_primitive=(
            requirement is not None
            and EFFECT_PRIMITIVES.get(requirement.name, "unknown") != "unknown"
        ),
        runtime=executed and oracle_called,
    )
    return evaluate_term_coverage(factors)


def _requirement_term(invariant: InvariantProjection) -> Struct | None:
    """Return the structural effect term one norm requirement addresses."""

    fact = invariant.norm_fact
    if fact is None or len(fact.args) != 2:
        return None
    effect = fact.args[1]
    return effect if isinstance(effect, Struct) else None


def _verdict(
    verdicts: tuple[object, ...],
    executed: bool,
    oracle_called: bool,
    finding_count: int,
) -> str:
    if finding_count:
        return VerdictStatus.FAIL.value
    statuses = {
        getattr(verdict, "status", None)
        for verdict in verdicts
        if getattr(verdict, "status", None) is not None
    }
    if VerdictStatus.FAIL in statuses:
        return VerdictStatus.FAIL.value
    if VerdictStatus.UNSCOREABLE in statuses:
        return VerdictStatus.UNSCOREABLE.value
    if VerdictStatus.PASS in statuses:
        return VerdictStatus.PASS.value
    if executed:
        return "no_oracle"
    return "not_executed"


def _blocked_reason(
    path_ids: tuple[str, ...],
    path_events: dict[str, QdlPathEvaluated],
    step_reasons: Mapping[str, str],
    *,
    scheduler_path_ids: set[str],
    selected: bool,
    executed: bool,
    oracle_called: bool,
    verdict: str,
    policy_reason: str,
    budget_exhausted: bool,
    waiting_for_latency_baseline: bool,
) -> str:
    if not path_ids:
        return "no executable path bound to norm"

    if not any(path_id in scheduler_path_ids for path_id in path_ids):
        return f"{len(path_ids)} paths were not added to the scheduler"

    if waiting_for_latency_baseline:
        return (
            "campaign check budget exhausted while path waited for a runtime "
            "latency baseline"
            if budget_exhausted
            else "path is waiting for a runtime latency baseline"
        )
    if not selected:
        return (
            "campaign check budget exhausted before path selection"
            if budget_exhausted
            else "path was not selected before campaign stopped"
        )
    if not executed:
        return (
            "campaign check budget exhausted before path execution"
            if budget_exhausted
            else "path was selected but not evaluated"
        )
    if not oracle_called:
        return "no deterministic oracle produced a verdict"

    step_reason = next(
        (
            step_reasons[path_id]
            for path_id in reversed(path_ids)
            if path_id in step_reasons
        ),
        "",
    )
    if step_reason:
        return step_reason

    reasons = [
        path_events[path_id].reason
        for path_id in path_ids
        if path_id in path_events and path_events[path_id].outcome == "blocked"
    ]
    specific_reasons = [
        reason for reason in reasons if reason not in _GENERIC_PATH_REASONS
    ]
    if specific_reasons:
        return specific_reasons[-1]
    if verdict == "unscoreable":
        return policy_reason or "deterministic oracle could not score observations"
    if verdict == "not_executed":
        return "path produced no observations"
    return ""


def _policy_reason(verdicts: tuple[object, ...]) -> str:
    for verdict in reversed(verdicts):
        reason = getattr(verdict, "rationale", "")
        if isinstance(reason, str) and reason:
            return reason
    return ""
