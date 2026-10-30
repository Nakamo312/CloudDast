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

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Protocol

from cloud_dast.contracts.assessment import (
    NormCoverageRow,
    TermCoverageEvaluation,
    TermFactors,
)
from cloud_dast.contracts.execution import ExecutionResult, ObservationProvenance
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionView,
)
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
from cloud_dast.verification.norms import EFFECT_PRIMITIVES
from cloud_dast.verification.term_coverage import evaluate_term_coverage

_GENERIC_STEP_REASONS = frozenset({"QDL step evaluated", "QDL chain step evaluated"})
_GENERIC_PATH_REASONS = frozenset(
    {
        "QDL effect chain was not verified",
        "QDL effect chain verified",
    }
)


class _SchedulerStateView(Protocol):
    selections: list[str]


class _SchedulerView(Protocol):
    paths: tuple[QdlExecutionPath, ...]
    state: _SchedulerStateView

    def is_prewarmed(self, path_id: str) -> bool: ...


def build_norm_coverage(
    plan: QdlExecutionView,
    execution: ExecutionResult,
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
    invariant_ids_by_check = {
        event.check_id: event.invariant_id
        for event in events
        if isinstance(event, CoverageUpdated)
    }
    observations_by_invariant = _observations_by_invariant(
        execution,
        checks_by_id,
        invariant_ids_by_check,
    )
    path_events = {
        event.path_id: event for event in events if isinstance(event, QdlPathEvaluated)
    }
    step_reasons = {
        event.path_id: event.reason
        for event in events
        if isinstance(event, QdlStepEvaluated)
        and event.reason not in _GENERIC_STEP_REASONS
    }
    finding_counts = Counter(finding.invariant_id for finding in findings)
    paths_by_invariant: dict[str, list[QdlExecutionPath]] = defaultdict(list)
    for path in plan.paths:
        for invariant_id in {step.invariant.invariant_id for step in path.steps}:
            paths_by_invariant[invariant_id].append(path)
    check_actions: dict[str, set[str]] = defaultdict(set)
    for check in checks_by_id.values():
        check_actions[check.invariant_id].add(check.method_id)

    rows: list[NormCoverageRow] = []
    for invariant_id, invariant in plan.invariants.items():
        paths = tuple(dict.fromkeys(paths_by_invariant.get(invariant_id, ())))
        observations = observations_by_invariant.get(invariant_id, ())
        historical_path_ids = {
            execution.provenance[(observation.observation_id, invariant_id)].path_id
            for observation in observations
            if (observation.observation_id, invariant_id) in execution.provenance
        }
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
        finding_count = finding_counts.get(invariant_id, 0)
        verdict = _verdict(oracle_verdicts, executed, finding_count)
        selected = any(path_id in selected_ids for path_id in path_ids)
        scheduled = any(path_id in scheduler_path_ids for path_id in path_ids)
        waiting_for_latency_baseline = any(
            scheduler.is_prewarmed(path_id) for path_id in path_ids
        )
        blocked_reason = _blocked_reason(
            path_ids,
            path_events,
            step_reasons,
            scheduled=scheduled,
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
            scheduled=scheduled,
            executed=executed,
            oracle_called=oracle_called,
            waiting_for_latency_baseline=waiting_for_latency_baseline,
        )

        rows.append(
            NormCoverageRow(
                norm_id=invariant.norm_id,
                effect=_effect(invariant),
                path_count=len(path_ids),
                scheduled=scheduled,
                selected=selected,
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
                            *check_actions.get(invariant_id, ()),
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


def _observations_by_invariant(
    execution: ExecutionResult,
    checks_by_id: Mapping[str, Check],
    invariant_ids_by_check: Mapping[str, str],
) -> dict[str, list[Observation]]:
    if not execution.observations:
        return {}
    provenance_by_observation: dict[str, list[ObservationProvenance]] = defaultdict(
        list
    )
    for (observation_id, _), provenance in execution.provenance.items():
        provenance_by_observation[observation_id].append(provenance)
    result: dict[str, list[Observation]] = {}
    for observation in execution.observations:
        invariant_ids = {
            provenance.invariant_id
            for provenance in provenance_by_observation.get(
                observation.observation_id, ()
            )
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
    return result


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
    scheduled: bool,
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
        oracle_channel=scheduled,
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
    scheduled: bool,
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

    if not scheduled:
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
