"""Canonical QDL field-role semantics projected into execution decisions.

Redaction and replay never guess a field's meaning from its name.  A value is
retained only when the graph carries a contract or accepted ``has(field,
role)`` fact whose role is explicitly replay-safe (``object_ref`` or
``replay_safe``).  ``credential`` and ``sensitive`` roles always force
redaction, and a field without any role fact is redacted by default and
reported as a typed deficit for grounding.

The same policy is the single role-resolution point for executable binding:
``object_ref``, ``subject_ref`` and ``role_ref`` fields are substituted from
the live stand only together with a grounded ``refers_to`` target.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

import clingo

from cloud_dast.couplings import normalise_action
from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.asp import decode_term
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import Atom, Context, QdlGraph, Struct, canonical_json
from cloud_dast.qdl.graph_ops import atom_value

type FieldDirection = Literal["input", "output"]

OBJECT_REF_ROLE = "object_ref"
SUBJECT_REF_ROLE = "subject_ref"
ROLE_REF_ROLE = "role_ref"
CREDENTIAL_ROLE = "credential"
SENSITIVE_ROLE = "sensitive"
REPLAY_SAFE_ROLE = "replay_safe"

REPLAY_SAFE_ROLES = frozenset({OBJECT_REF_ROLE, REPLAY_SAFE_ROLE})
FORCED_REDACTION_ROLES = frozenset({CREDENTIAL_ROLE, SENSITIVE_ROLE})

FIELD_ROLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})
_DIRECTION_BY_HOLDER = {"input_field": "input", "output_field": "output"}


@dataclass(frozen=True, order=True, slots=True)
class FieldRoleDeficit:
    """One typed gap: a field with no accepted role fact."""

    action: str | None
    direction: FieldDirection
    field: str


@dataclass(frozen=True, slots=True)
class FieldRolePolicy:
    """Per-action field roles resolved from contract or accepted QDL facts."""

    roles_by_field: Mapping[tuple[FieldDirection, str, str], frozenset[str]] = field(
        default_factory=dict
    )

    def roles(
        self,
        action: str | None,
        field_name: str,
        *,
        direction: FieldDirection,
    ) -> frozenset[str]:
        """Return every accepted role for one action field, if any."""

        if action is None:
            return frozenset()
        return self.roles_by_field.get((direction, action, field_name), frozenset())

    def retains(
        self,
        action: str | None,
        field_name: str,
        *,
        direction: FieldDirection,
    ) -> bool:
        """Whether accepted facts permit retaining one field value."""

        roles = self.roles(action, field_name, direction=direction)
        if not roles:
            return False
        return bool(roles & REPLAY_SAFE_ROLES) and not roles & FORCED_REDACTION_ROLES

    def retained_fields(
        self,
        action: str | None,
        *,
        direction: FieldDirection = "input",
    ) -> frozenset[str]:
        """Return field names whose values may be retained for one action."""

        if action is None:
            return frozenset()
        return frozenset(
            field_name
            for field_direction, field_action, field_name in self.roles_by_field
            if field_direction == direction
            and field_action == action
            and self.retains(action, field_name, direction=direction)
        )

    def deficits(
        self,
        action: str | None,
        field_names: Iterable[str],
        *,
        direction: FieldDirection,
    ) -> tuple[FieldRoleDeficit, ...]:
        """Return typed deficits for fields without any accepted role fact."""

        return tuple(
            FieldRoleDeficit(
                action=action,
                direction=direction,
                field=field_name,
            )
            for field_name in sorted(set(field_names))
            if not self.roles(action, field_name, direction=direction)
        )


def resolve_field_roles(graph: QdlGraph) -> FieldRolePolicy:
    """Project accepted ``has(field, role)`` facts into a redaction policy.

    Both ``action:get`` and ``get`` spellings of one action resolve to the
    same field roles, matching the executable graph conventions elsewhere.
    Proposal-context facts are deliberately ignored: an unvalidated LLM
    hypothesis must never decide what survives redaction.
    """

    superseded_replacements = {
        canonical_json(fact.args[1])
        for fact in graph.facts
        if fact.context in FIELD_ROLE_CONTEXTS
        and fact.predicate.name == "supersedes"
        and len(fact.args) == 2
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "replacement"
    }
    roles: dict[tuple[FieldDirection, str, str], set[str]] = {}
    for fact in graph.facts:
        if fact.context not in FIELD_ROLE_CONTEXTS:
            continue
        if fact.predicate.name != "has" or len(fact.args) != 2:
            continue
        holder, role_term = fact.args
        if not isinstance(holder, Struct) or len(holder.args) != 2:
            continue
        direction = _DIRECTION_BY_HOLDER.get(holder.name)
        if direction is None:
            continue
        action = atom_value(holder.args[0])
        field_name = atom_value(holder.args[1])
        role = atom_value(role_term)
        if action is None or field_name is None or role is None:
            continue
        replacement = Struct(name="replacement", args=(holder, role_term))
        if canonical_json(replacement) in superseded_replacements:
            continue
        for alias in action_aliases(action):
            roles.setdefault((direction, alias, field_name), set()).add(role)
    return FieldRolePolicy(
        roles_by_field={key: frozenset(values) for key, values in sorted(roles.items())}
    )


def declared_output_refs(graph: QdlGraph, method_id: str) -> set[Struct] | None:
    """Classify declared object_refs without deciding their current validity."""

    holders = [
        fact.args[0]
        for fact in graph.facts
        if fact.context in {Context.CONTRACT, Context.ACCEPTED}
        and fact.predicate.name == "has"
        and fact.args[1] == Atom(value="object_ref")
    ]
    if graph.rules:
        try:
            declarations = graph.select_contexts({Context.CONTRACT, Context.ACCEPTED})
            solutions = ClingoEngine().solve(declarations)
        except (ValueError, RuntimeError):
            return None
        for solution in solutions:
            for atom in solution.atoms:
                if not atom.startswith("has("):
                    continue
                context, holder, role = map(
                    decode_term, clingo.parse_term(atom).arguments
                )
                if atom_value(context) in {
                    Context.CONTRACT,
                    Context.ACCEPTED,
                } and role == Atom(value="object_ref"):
                    holders.append(holder)
    return {
        holder
        for holder in holders
        if isinstance(holder, Struct)
        and holder.name == "output_field"
        and (action := atom_value(holder.args[0])) is not None
        and normalise_action(action) == normalise_action(method_id)
    }
