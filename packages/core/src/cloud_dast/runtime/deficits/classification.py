"""Deficits for unresolved security finding classification facts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from cloud_dast.contracts.execution import ScenarioBinding
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import Check, Observation, PolicyVerdict, VerdictStatus
from cloud_dast.qdl.graph import Atom, Term, canonical_json, input_field
from cloud_dast.qdl.graph import field as field_term
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.deficits.model import Deficit
from cloud_dast.runtime.deficits.routing import (
    _ANY_ROLE,
    _ANY_TYPE,
    build_deficit,
    deduplicate,
)
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.taxonomy import DEFAULT_CATALOG, ClassificationFacts

CLASSIFICATION_DEFICIT_KIND = "classification_deficit"


def gap_for_invariant(
    invariant: InvariantProjection,
    facts: ClassificationFacts,
    *,
    action_id: str,
    context: tuple[tuple[str, str], ...] = (),
) -> Deficit | None:
    """Turn one presentation-classification gap into a QDL work item."""

    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        facts=facts,
        action_id=action_id,
    )
    if classification.entry is not None or not classification.deficit_reasons:
        return None

    try:
        norm = NormView.from_invariant(invariant)
    except ValueError:
        return None
    if norm is None:
        return None
    candidates = DEFAULT_CATALOG.candidates_for(invariant)
    if not candidates:
        return None

    action = norm.action_id or action_id
    for reason in classification.deficit_reasons:
        projection = _missing_fact(reason, norm, candidates, action)
        if projection is None:
            continue
        term, allowed, subgoal = projection

        if not allowed:
            continue
        return build_deficit(
            subgoal,
            action=action,
            context=(
                ("deficit_kind", CLASSIFICATION_DEFICIT_KIND),
                ("classification_reason", reason),
                ("classification_term", canonical_json(term)),
                ("allowed_values", ",".join(allowed)),
                ("invariant_id", invariant.invariant_id),
                *context,
            ),
            classification=True,
        )
    return None


def _missing_fact(
    reason: str,
    norm: NormView,
    candidates: Iterable[object],
    action: str,
) -> tuple[Term, list[str], QdlSubgoal] | None:
    if reason == "missing_input_role":
        field_name = norm.forbidden_field
        if field_name is None:
            return None
        term = input_field(Atom(value=action), Atom(value=field_name))
        values = sorted({role for entry in candidates for role in entry.input_roles})
        return term, values, QdlSubgoal("has", (term, _ANY_ROLE))
    if reason == "missing_witness_role":
        field_name = norm.forbidden_field
        resource_id = norm.resource_id
        if field_name is None or resource_id is None:
            return None
        term = field_term(Atom(value=resource_id), Atom(value=field_name))
        values = sorted({role for entry in candidates for role in entry.witness_roles})
        return term, values, QdlSubgoal("has", (term, _ANY_ROLE))
    if reason == "missing_sink_type":
        sink_id = norm.marker
        if sink_id is None:
            return None
        term = Atom(value=sink_id)
        values = sorted(
            {sink_type for entry in candidates for sink_type in entry.sink_types}
        )
        return term, values, QdlSubgoal("is", (term, _ANY_TYPE))
    return None


def gaps_for_observations(
    binding: ScenarioBinding,
    *,
    checks: Mapping[str, Check],
    observations: Iterable[Observation],
    policy_verdicts: Mapping[tuple[str, str], object],
) -> tuple[Deficit, ...]:
    """Project deterministic failed observations into classification work."""

    facts = ClassificationFacts.from_graph(binding.graph)
    deficits: list[Deficit] = []
    observations_by_id = {o.observation_id: o for o in observations}
    for (observation_id, invariant_id), verdict in policy_verdicts.items():
        observation = observations_by_id.get(observation_id)
        if observation is None:
            continue
        if not isinstance(verdict, PolicyVerdict):
            continue
        if (
            verdict.status is not VerdictStatus.FAIL
            or not verdict.deterministic
            or not verdict.grounded
        ):
            continue
        check = checks.get(observation.check_id)
        if check is None:
            continue
        invariant = binding.invariants.get(invariant_id)
        if invariant is None:
            continue
        deficit = gap_for_invariant(
            invariant,
            facts,
            action_id=check.method_id,
            context=(("observation_id", observation.observation_id),),
        )
        if deficit is not None:
            deficits.append(deficit)
    return deduplicate(deficits)


__all__ = [
    "CLASSIFICATION_DEFICIT_KIND",
    "gap_for_invariant",
    "gaps_for_observations",
]
