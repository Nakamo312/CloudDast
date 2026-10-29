"""Typed semantic deficits and reactive grounding constructors.

Deficit construction and semantic closure are pure projections over QDL and
execution evidence. Queue state, work-item grouping, wave planning, and
dispatch budgets live in :mod:`cloud_dast.runtime.deficits.queue` and
:mod:`cloud_dast.runtime.deficits.work_items`.

S21R (remediation plan 6.11) keeps the deficit algebraic and makes the
consultation routing total.  A deficit is one unprovable QDL subgoal —
``deficit(R, G) :- requirement(R, G), not derivable(R, G)`` — never an
action/reason string, and its axis is
``f(predicate_class, evidence_context)`` over the declarative consultation
algebra in :mod:`cloud_dast.consultation`.
A predicate class without an image — for example ``may``, which no
consultation may author — materializes as
``consultation_deficit(predicate_class)``: a typed engineering gap that is
never dispatched to a model.  Path/step/reason provenance lives in
``context`` without ever splitting the subgoal identity, so one subgoal
naturally covers every path deficit that requires it.

S26R turns queue selection into a generic constrained optimization:
maximize the deterministic information-gain score subject to max-min
fairness over QDL predicate classes.  No axis name, vulnerability class, or
manual reserve participates in the decision.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from cloud_dast.contracts.execution import ScenarioBinding
from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model import (
    AccessOutcome,
    Observation,
    VerdictStatus,
)
from cloud_dast.model.events import QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Struct,
    Term,
    canonical_json,
    differs,
    duration,
    input_field,
)
from cloud_dast.qdl.graph import (
    field as field_term,
)
from cloud_dast.qdl.reasoning import QdlSubgoal, term_from_canonical_json
from cloud_dast.qdl.semantic_norm_compiler import norm_requirement
from cloud_dast.runtime.deficits.closure import (
    action_aliases,
    grounded_output_paths,
    interpreted_signal_kinds,
    is_transport_sentinel,
    observation_action,
)
from cloud_dast.runtime.deficits.model import Deficit
from cloud_dast.runtime.deficits.routing import (
    _ANY_ACTION,
    _ANY_DIMENSION,
    _ANY_EFFECT,
    _ANY_FIELD,
    _ANY_FROM,
    _ANY_MS,
    _ANY_NORM,
    _ANY_RESOURCE,
    _ANY_ROLE,
    _ANY_TARGET,
    build_deficit,
    deduplicate,
)
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.witness import WitnessSignal

logger = logging.getLogger("cloud_dast.runtime.deficits")

__all__ = [
    "Deficit",
    "EVIDENCE_DEFICIT_KIND",
    "LATENCY_BASELINE_PREFIX",
    "blocked_step_deficit",
    "evidence_deficit",
    "missing_irreversibility_deficit",
    "missing_role_deficit",
    "witness_deficit",
    "witness_deficits",
    "classify_step_event",
    "response_semantics_deficits",
    "signal_deficits",
    "variance_deficit",
]


# Availability is repaired deterministically from observations; semantic
# reference and causal gaps use the ordinary consultation algebra.
_VARIANCE_AXIS: str = "variance"
_AVAILABILITY_AXIS: str = "availability"

_BLOCKED_PATH_REASON = "QDL effect chain was not verified"
LATENCY_BASELINE_PREFIX = "no runtime latency baseline for method "
_STATE_SEMANTICS_REASONS = frozenset({"missing_state_semantics"})
_EXACT_ACTION_REASONS = frozenset({"missing_irreversibility_fact"})
_TRANSPORT_SENTINEL_ROOTS = frozenset({"__truncated__", "__response__", "__unknown__"})
_VARIANCE_FIELD_CLOSURE_PREDICATES = frozenset(
    {"causes", "exposes", "has", "prevents", "reaches", "requires"}
)
_VARIANCE_EFFECT_CLOSURE_PREDICATES = frozenset({"causes", "prevents", "reaches"})
_SIGNAL_VARIANCE_KINDS = frozenset({"latency_delta", "content_delta"})
_SIGNAL_GROUNDING_PREDICATE = "signal_grounds"
_SINK_INTERPRETATION_PREDICATE = "sink_interprets"


def witness_deficit(
    path: QdlExecutionPath,
    step: QdlExecutionStep,
) -> Deficit:
    """Name the graph prerequisite of a marker/OOB execution channel.

    The binder supplies the query from the norm's oracle primitive.  A
    consultation proposes its premises; only derivation from the executable
    graph closes the obligation.
    """

    if step.witness_requirement is None:
        raise ValueError("step has no witness requirement")
    return build_deficit(
        step.witness_requirement,
        action=step.method.method_id,
        context=(
            ("origin", "witness_requirement"),
            ("path_id", path.path_id),
            ("step_id", step.step_id),
            ("invariant_id", step.invariant.invariant_id),
        ),
    )


def witness_deficits(paths: Iterable[QdlExecutionPath]) -> tuple[Deficit, ...]:
    """Collect missing channel obligations from the bound graph projection.

    The binder already solved the carrier relation for this graph snapshot
    and restricted it to each method's schema.  Re-solving the same graph
    per path would multiply solver work by path fan-out and could disagree
    with that schema restriction.
    """

    return deduplicate(
        witness_deficit(path, step)
        for path in paths
        for step in path.steps
        if step.witness_requirement is not None and not step.plan.probe_fields
    )


def blocked_step_deficit(
    path: QdlExecutionPath,
    step: QdlExecutionStep,
    *,
    reason: str = _BLOCKED_PATH_REASON,
    recovery_action: str | None = None,
    clue_observation_id: str | None = None,
    effect: Struct | None = None,
) -> Deficit:
    """Describe the QDL obligation that blocks one ordinary action step.

    Causal prerequisites retain their explicit effect. Missing references,
    state semantics and mutation declarations keep their own predicate sort.
    Path, step and recovery details remain provenance for the shared queue.
    """

    reason = reason or _BLOCKED_PATH_REASON
    action = step.method.method_id
    effect = effect or _step_effect(step)
    field = None
    if reason == "missing_refers_to":
        typed = dict(step.plan.resource_types)
        field = next(
            (name for name in step.plan.resource_params if name not in typed), None
        )
        subgoal = QdlSubgoal(
            predicate="refers_to",
            args=(
                input_field(Atom(value=action), Atom(value=field))
                if field is not None
                else input_field(Atom(value=action), _ANY_FIELD),
                _ANY_TARGET,
            ),
        )
    elif reason in _STATE_SEMANTICS_REASONS:
        state = step.scenario.profile.resource_state
        subgoal = QdlSubgoal(
            predicate="transition",
            args=(_ANY_ACTION, _ANY_FROM, Atom(value=state) if state else _ANY_TARGET),
        )
    else:
        exact_action = reason in _EXACT_ACTION_REASONS or effect is None
        subgoal = QdlSubgoal(
            predicate="causes",
            args=(
                Atom(value=action) if exact_action else _ANY_ACTION,
                effect or _ANY_EFFECT,
            ),
        )

    context = [
        ("origin", "blocked_step"),
        ("path_id", path.path_id),
        ("step_id", step.step_id),
        ("reason", reason),
        ("effect", canonical_json(effect) if effect is not None else ""),
        ("field", field or ""),
        ("required_state", step.scenario.profile.resource_state),
    ]
    if recovery_action is not None:
        context.append(("recovery_action", recovery_action))
    if clue_observation_id is not None:
        context.append(("clue_observation_id", clue_observation_id))
    return build_deficit(subgoal, action=action, context=tuple(context))


def _step_effect(step: QdlExecutionStep) -> Struct | None:
    """Return the explicit causal obligation, falling back to the step norm."""

    if step.required_effects:
        return step.required_effects[0]
    norm_fact = step.invariant.norm_fact
    if norm_fact is None or len(norm_fact.args) != 2:
        return None
    return norm_requirement(norm_fact)


def classify_step_event(event: QdlStepEvaluated) -> Deficit | None:
    """Classify one unscoreable step rationale into a reactive deficit."""

    if event.verdict is not VerdictStatus.UNSCOREABLE:
        return None
    if not event.reason.startswith(LATENCY_BASELINE_PREFIX):
        return None

    action = event.reason[len(LATENCY_BASELINE_PREFIX) :]
    if not action:
        return None
    action_term = Atom(value=action)
    return build_deficit(
        QdlSubgoal(
            predicate="causes",
            args=(action_term, duration(action_term, _ANY_MS)),
        ),
        action=action,
        # The availability strategy grounds causes(Action, duration(Action,
        # ms)), which the latency oracle needs as its runtime baseline.
        context=(
            ("path_id", event.path_id),
            ("reason", event.reason),
        ),
    )


def missing_irreversibility_deficit(
    path: QdlExecutionPath,
    step: QdlExecutionStep,
    *,
    effect: str = "",
) -> Deficit:
    """Build the causal deficit for one action without a mutation declaration.

    The action itself must cause the mutation effect:
    the subgoal is ``causes(Action, Effect)`` with both
    positions fixed.
    """

    action = step.method.method_id
    effect_term = term_from_canonical_json(effect) if effect else _step_effect(step)
    args: tuple[Term, ...] = (
        (Atom(value=action), effect_term)
        if effect_term is not None
        else (Atom(value=action), _ANY_EFFECT)
    )
    return build_deficit(
        QdlSubgoal(predicate="causes", args=args),
        action=action,
        context=(
            ("origin", "missing_irreversibility"),
            ("path_id", path.path_id),
            ("step_id", step.step_id),
            ("reason", "missing_irreversibility_fact"),
            ("effect", canonical_json(effect_term) if effect_term is not None else ""),
        ),
    )


def variance_deficit(report: DiffReport) -> Deficit:
    """Build the grounding deficit for one unexplained behavior variance.

    The measured difference is not a finding — it is a question.  The
    subgoal anchors the requirement to the action's measured divergence
    (``prevents(AnyNorm, differs(Action, AnyDimension))``); the report
    signature stays as the requirement discriminator because it is part
    of the requirement itself, and both observation ids ride along so the
    dispatcher can recover the paired legs.
    """

    variance_fields = ",".join(
        dict.fromkeys(
            (
                *report.fields_only_control,
                *report.fields_only_treatment,
                *report.value_differs,
            )
        )
    )
    return build_deficit(
        QdlSubgoal(
            predicate="prevents",
            args=(
                _ANY_NORM,
                differs(Atom(value=report.action_id), _ANY_DIMENSION),
            ),
        ),
        action=report.action_id,
        context=(
            ("diff", report.signature),
            ("control", report.control_observation_id),
            ("treatment", report.treatment_observation_id),
            ("variance_fields", variance_fields),
        ),
    )


def signal_deficits(
    signals: Iterable[WitnessSignal],
    graph: object | None = None,
) -> tuple[Deficit, ...]:
    """Return reactive deficits for signals without a complete QDL mapping.

    A signal is a question, not a finding.  Paired numeric/content differences
    extend the variance axis; marker, OOB, and known-content observations extend
    response semantics until QDL supplies the signal/sink/norm interpretation.
    """

    deficits: list[Deficit] = []
    for signal in signals:
        if signal.action_id is None:
            continue
        if signal.kind in interpreted_signal_kinds(graph, signal.action_id):
            continue
        if signal.kind in _SIGNAL_VARIANCE_KINDS:
            deficits.append(
                build_deficit(
                    QdlSubgoal(
                        predicate="prevents",
                        args=(
                            _ANY_NORM,
                            differs(
                                Atom(value=signal.action_id),
                                _ANY_DIMENSION,
                            ),
                        ),
                    ),
                    action=signal.action_id,
                    context=(
                        ("signal", signal.kind),
                        ("diff", signal.signature),
                        ("control", signal.evidence_refs[0]),
                        ("treatment", signal.evidence_refs[-1]),
                        ("variance_fields", ",".join(signal.paths)),
                    ),
                )
            )
            continue
        deficits.append(
            build_deficit(
                QdlSubgoal(
                    predicate="exposes",
                    args=(
                        Atom(value=signal.action_id),
                        field_term(_ANY_RESOURCE, _ANY_FIELD),
                    ),
                ),
                action=signal.action_id,
                context=(
                    ("signal", signal.kind),
                    ("fields", ",".join(signal.paths) or signal.kind),
                    ("observation_id", signal.evidence_refs[0]),
                ),
                live_response=True,
            )
        )
    return deduplicate(deficits)


def response_semantics_deficits(
    binding: ScenarioBinding,
    observations: Iterable[Observation],
) -> tuple[Deficit, ...]:
    """Return one response-semantics gap per action with ungrounded paths.

    A structured response is evidence that the action has response fields, but
    another grounded field must not hide a sibling.  Every response leaf keeps
    its full output path as the field identity — ``items.0.foo.bar`` and
    ``metadata.bar`` are different fields and never collapse — and is checked
    verbatim against the bound ``(action, output_path)`` witnesses: ``exposes``
    facts and accepted output-field roles.  Every ungrounded path of one
    action is then grouped into a single reactive task carrying the sorted
    path set and the latest successful observation id, so one reactive call
    can ground all remaining paths of the action.
    """

    grounded_paths = grounded_output_paths(binding.graph)
    ungrounded_paths: dict[str, set[str]] = {}
    latest_observation_ids: dict[str, str] = {}
    for observation in observations:
        if observation.observed_outcome is not AccessOutcome.ALLOWED:
            continue
        if not observation.response_tree:
            continue
        action = observation_action(observation)
        if action is None:
            continue
        aliases = action_aliases(action)
        for path, _value in observation.response_tree:
            if is_transport_sentinel(path):
                continue
            if any((alias, path) in grounded_paths for alias in aliases):
                continue
            ungrounded_paths.setdefault(action, set()).add(path)
            latest_observation_ids[action] = observation.observation_id
    deficits = [
        build_deficit(
            QdlSubgoal(
                predicate="exposes",
                args=(
                    Atom(value=action),
                    field_term(_ANY_RESOURCE, _ANY_FIELD),
                ),
            ),
            action=action,
            context=(
                ("fields", ",".join(sorted(paths))),
                ("observation_id", latest_observation_ids[action]),
            ),
            live_response=True,
        )
        for action, paths in ungrounded_paths.items()
    ]
    return deduplicate(deficits)


EVIDENCE_DEFICIT_KIND = "evidence_deficit"


def missing_role_deficit(
    action: str,
    context: tuple[tuple[str, str], ...] = (),
    *,
    field: str | None = None,
) -> Deficit:
    """Build the has-class deficit for one action without grounded roles."""

    witness: Term = (
        input_field(Atom(value=action), Atom(value=field))
        if field is not None
        else input_field(Atom(value=action), _ANY_FIELD)
    )
    return build_deficit(
        QdlSubgoal(predicate="has", args=(witness, _ANY_ROLE)),
        action=action,
        context=context,
    )


def evidence_deficit(deficit: Deficit) -> Deficit:
    """Park one evidence-less deficit as an observation requirement.

    The subgoal is preserved verbatim and only the consultation axis is
    withdrawn, so the parked record can never reach a model and a later
    evidence-backed drain reuses the same subgoal identity.
    """

    return Deficit(
        subgoal=deficit.subgoal,
        predicate_class=deficit.predicate_class,
        axis=None,
        action=deficit.action,
        context=(
            *deficit.context,
            ("evidence_kind", EVIDENCE_DEFICIT_KIND),
            ("source_class", deficit.predicate_class),
            ("source_consultation_id", deficit.consultation_id),
            ("evidence_reason", "missing_live_observation"),
        ),
    )
