"""Deterministic identity projections from the executable QDL graph."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

from cloud_dast.contracts.plan import QdlExecutionPath, QdlExecutionStep
from cloud_dast.model import ANONYMOUS_PRINCIPAL_ID, PrincipalRef
from cloud_dast.model.events import normalize_action, normalize_principal
from cloud_dast.qdl.graph import Context, Fact, QdlGraph, Term
from cloud_dast.qdl.graph_ops import atom_value

_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})


@dataclasses.dataclass(frozen=True, slots=True)
class IdentityView:
    """Materialized ``valid_identity(action, subject)`` over one QDL graph."""

    attackers: tuple[str, ...] = ()
    by_action: Mapping[str, tuple[str, ...]] = dataclasses.field(
        default_factory=dict,
    )

    def subjects_for(self, action: str) -> tuple[str, ...]:
        """Return valid subjects for one action, attackers first."""

        subjects = dict.fromkeys(self.attackers)
        subjects.update(
            dict.fromkeys(self.by_action.get(normalize_action(action) or "", ()))
        )
        return tuple(subjects)


def _read_identity(fact: Fact) -> tuple[Term | None, Term | None] | None:
    """Select subject/action terms from supported identity fact forms."""

    match fact.predicate.name, fact.args:
        case "is", (subject, kind) if atom_value(kind) == "Subject":
            return subject, None
        case "attacker", (subject,):
            return subject, None
        case "owner", (_, subject):
            return subject, None
        case "may", (subject, action, _) | (_, subject, action, _):
            return subject, action
        case "targets", (action, _):
            return None, action
    return None


def derive_identities(graph: QdlGraph) -> IdentityView:
    """Materialize the canonical ``valid_identity(action, subject)`` view.

    The view introduces no QDL primitive. It is derived from declared
    subjects, attacker hypotheses, policy ``may`` facts, owners, and targets.
    """

    declared_subjects: set[str] = set()
    attackers: set[str] = set()
    may_pairs: set[tuple[str, str]] = set()
    owners: set[str] = set()
    targeted_actions: set[str] = set()
    subjects = {"is": declared_subjects, "attacker": attackers, "owner": owners}
    for fact in graph.facts:
        if fact.context not in _EXECUTABLE_CONTEXTS:
            continue
        terms = _read_identity(fact)
        if terms is None:
            continue
        subject = normalize_principal(atom_value(terms[0]))
        action = normalize_action(atom_value(terms[1])) or ""
        name = fact.predicate.name
        if name == "may":
            if subject and action:
                may_pairs.add((subject, action))
        elif name == "targets":
            if action:
                targeted_actions.add(action)
        elif subject:
            subjects[name].add(subject)

    by_action: dict[str, set[str]] = {}
    for subject, action in may_pairs:
        if subject in declared_subjects:
            by_action.setdefault(action, set()).add(subject)
    declared_owners = owners & declared_subjects
    for action in targeted_actions:
        by_action.setdefault(action, set()).update(declared_owners)
    return IdentityView(
        attackers=tuple(sorted(attackers & declared_subjects)),
        by_action={
            action: tuple(sorted(subjects)) for action, subjects in by_action.items()
        },
    )


def apply_identity_terms(
    paths: list[QdlExecutionPath],
    identities: IdentityView,
) -> list[QdlExecutionPath]:
    """Attach grounded typed identities to norm-bearing execution steps."""

    applied: list[QdlExecutionPath] = []
    for path in paths:
        if path.kind == "smoke":
            # Smoke paths exercise transport reachability, not a norm witness.
            applied.append(path)
            continue
        steps = tuple(
            dataclasses.replace(
                step,
                plan=step.plan.model_copy(
                    update={"identity_terms": identity_terms_for_step(step, identities)}
                ),
            )
            for step in path.steps
        )
        applied.append(dataclasses.replace(path, steps=steps))
    return applied


def identity_terms_for_step(
    step: QdlExecutionStep,
    identities: IdentityView,
) -> tuple[PrincipalRef, ...]:
    """Project valid QDL subjects into typed principal terms."""

    action = normalize_action(step.method.method_id) or ""
    stand = {
        principal.principal_id: principal
        for principal in step.scenario.stand.principals
    }
    return tuple(
        stand.get(subject)
        or PrincipalRef(
            principal_id=subject,
            principal_type=(
                "anonymous" if subject == ANONYMOUS_PRINCIPAL_ID else "user"
            ),
        )
        for subject in identities.subjects_for(action)
    )


__all__ = [
    "IdentityView",
    "apply_identity_terms",
    "derive_identities",
    "identity_terms_for_step",
]
