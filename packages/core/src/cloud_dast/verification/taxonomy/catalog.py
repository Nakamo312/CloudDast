"""Presentation catalog of vulnerability classes and QDL detection strategies.

The catalog is declarative data in ``classes.yaml``.  Each entry links a
vulnerability class to the QDL effect constructors it can observe and the
deterministic oracle primitives that can score those effects.  Classification
is presentation-only: it joins the violated norm effect to QDL role and sink
facts, never request-field or benchmark names, and never controls execution
or verdicts.  Missing classification facts produce an explicit classification
deficit instead of a name-based guess.

For reached effects, the presentation relation is::

    classify(norm) :- effect(norm, reached), is(sink, type), class_rule(type, class).

The sink identifier is only a join key to its QDL type; it never selects a
class by itself.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Context,
    QdlGraph,
    Struct,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.roles import (
    SEMANTIC_ROLE_NAMES,
    semantic_role_taxonomy,
)
from cloud_dast.verification.norm_view import NormView
from cloud_dast.verification.norms import Primitive

if TYPE_CHECKING:
    from cloud_dast.verification.invariant_projection import (
        InvariantProjection,
    )

CLASSIFICATION_DEFICIT = "classification_deficit"


@dataclass(frozen=True, slots=True)
class ClassificationFacts:
    """QDL role and sink facts used by deterministic finding classification."""

    input_roles: frozenset[tuple[str, str, str]] = frozenset()
    witness_roles: frozenset[tuple[str, str, str]] = frozenset()
    sink_types: frozenset[tuple[str, str]] = frozenset()

    @classmethod
    def from_graph(cls, graph: QdlGraph | None) -> ClassificationFacts:
        """Project only the facts needed to classify a violated QDL norm."""

        if graph is None:
            return cls()

        input_roles: set[tuple[str, str, str]] = set()
        witness_roles: set[tuple[str, str, str]] = set()
        sink_types: set[tuple[str, str]] = set()

        for fact in graph.facts:
            if fact.context not in {Context.CONTRACT, Context.ACCEPTED}:
                continue
            if fact.predicate.name == "has" and len(fact.args) == 2:
                holder, role = fact.args
                role_name = atom_value(role)
                if role_name not in SEMANTIC_ROLE_NAMES or not isinstance(
                    holder, Struct
                ):
                    continue
                if holder.name == "input_field" and len(holder.args) == 2:
                    action = atom_value(holder.args[0])
                    field_name = atom_value(holder.args[1])
                    if action is not None and field_name is not None:
                        for alias in action_aliases(action):
                            input_roles.add((alias, field_name, role_name))
                elif holder.name == "output_field" and len(holder.args) == 2:
                    action = atom_value(holder.args[0])
                    field_name = atom_value(holder.args[1])
                    if action is not None and field_name is not None:
                        for alias in action_aliases(action):
                            witness_roles.add((alias, field_name, role_name))
                elif holder.name == "field" and len(holder.args) == 2:
                    resource = atom_value(holder.args[0])
                    field_name = atom_value(holder.args[1])
                    if resource is not None and field_name is not None:
                        witness_roles.add((resource, field_name, role_name))
            elif fact.predicate.name == "is" and len(fact.args) == 2:
                identifier, kind = fact.args
                identifier_value = atom_value(identifier)
                kind_value = atom_value(kind)
                if identifier_value is None or kind_value is None:
                    continue
                sink_types.add((identifier_value, kind_value))

        return cls(
            input_roles=frozenset(input_roles),
            witness_roles=frozenset(witness_roles),
            sink_types=frozenset(sink_types),
        )

    def input_roles_for(self, action_id: str | None, field_name: str) -> frozenset[str]:
        actions = action_aliases(action_id) if action_id is not None else frozenset()
        return frozenset(
            role
            for action, field, role in self.input_roles
            if action in actions and field == field_name
        )

    def input_roles_for_action(self, action_id: str | None) -> frozenset[str]:
        actions = action_aliases(action_id) if action_id is not None else frozenset()
        return frozenset(
            role for action, _field, role in self.input_roles if action in actions
        )

    def witness_roles_for(
        self,
        action_id: str | None,
        resource_id: str,
        field_name: str,
    ) -> frozenset[str]:
        direct = frozenset(
            role
            for resource, field, role in self.witness_roles
            if resource == resource_id and field == field_name
        )
        action_roles = frozenset(
            role
            for action, field, role in self.witness_roles
            if action in action_aliases(action_id or "") and field == field_name
        )
        return direct | action_roles

    def sink_types_for(self, sink_id: str) -> frozenset[str]:
        return frozenset(kind for sink, kind in self.sink_types if sink == sink_id)


class ClassEntry(BaseModel):
    """One detection strategy for one vulnerability class."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    class_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    owasp_api: str = Field(min_length=1)
    effect_constructors: tuple[str, ...] = Field(min_length=1)
    primitives: tuple[Primitive, ...] = Field(min_length=1)
    norm_source: str
    cwe: tuple[str, ...] = Field(min_length=1)
    stride: tuple[str, ...] = Field(min_length=1)
    default_effects: tuple[str, ...] = ()
    input_roles: tuple[str, ...] = ()
    witness_roles: tuple[str, ...] = ()
    sink_types: tuple[str, ...] = ()
    status: Literal["active", "planned"] = "active"
    requires_primitive: str | None = None
    note: str = ""

    @model_validator(mode="after")
    def validate_entry(self) -> ClassEntry:
        if self.status == "planned" and not self.requires_primitive:
            raise ValueError("planned entries must name the missing primitive")
        if self.status == "active" and self.requires_primitive:
            raise ValueError("active entries cannot require a missing primitive")
        unknown_effects = set(self.effect_constructors) - set(
            CAUSAL_EFFECT_CONSTRUCTORS
        )
        if unknown_effects:
            raise ValueError(
                "unknown QDL effect constructors: " + ", ".join(sorted(unknown_effects))
            )
        if len(self.effect_constructors) != len(set(self.effect_constructors)):
            raise ValueError("effect constructors must be unique")
        if len(self.primitives) != len(set(self.primitives)):
            raise ValueError("primitives must be unique")
        unknown_defaults = set(self.default_effects) - set(self.effect_constructors)
        if unknown_defaults:
            raise ValueError(
                "unknown default QDL effects: " + ", ".join(sorted(unknown_defaults))
            )
        if len(self.default_effects) != len(set(self.default_effects)):
            raise ValueError("default effects must be unique")
        for values, field_name in (
            (self.input_roles, "input roles"),
            (self.witness_roles, "witness roles"),
            (self.sink_types, "sink types"),
            (self.stride, "STRIDE categories"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
        for values, field_name in (
            (self.input_roles, "input roles"),
            (self.witness_roles, "witness roles"),
        ):
            unknown_roles = set(values) - SEMANTIC_ROLE_NAMES
            if unknown_roles:
                raise ValueError(
                    f"unknown semantic {field_name}: "
                    + ", ".join(sorted(unknown_roles))
                )
        if any(
            len(category) != 1 or category not in "STRIDE" for category in self.stride
        ):
            raise ValueError("STRIDE categories must be single letters")
        return self


@dataclass(frozen=True, slots=True)
class FindingClassification:
    """Classification projection for one QDL-grounded finding."""

    entry: ClassEntry | None
    deficit_reasons: tuple[str, ...]
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    stride: tuple[str, ...]

    @property
    def vulnerability_class(self) -> str:
        """Return the selected class or the explicit deficit class."""

        return self.entry.class_id if self.entry is not None else CLASSIFICATION_DEFICIT


def is_classification_deficit(vulnerability_class: str) -> bool:
    """Return whether a vulnerability class names the classification deficit."""

    return vulnerability_class == CLASSIFICATION_DEFICIT


def load_entries(path: Path | str | None = None) -> tuple[ClassEntry, ...]:
    """Load and validate the declarative class catalog."""

    catalog_path = (
        Path(path) if path is not None else Path(__file__).with_name("classes.yaml")
    )
    raw: Any = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError(f"invalid class-catalog schema: {catalog_path}")
    rows = raw.get("entries")
    if not isinstance(rows, list):
        raise ValueError(f"class catalog has no entries list: {catalog_path}")
    entries = tuple(ClassEntry.model_validate(row) for row in rows)
    if not entries:
        raise ValueError("class catalog must contain at least one entry")
    return entries


class ClassCatalog:
    """Present vulnerability classes for QDL-grounded findings."""

    def __init__(self, entries: tuple[ClassEntry, ...] = ()) -> None:
        values = entries or load_entries()
        self._by_id = {entry.class_id: entry for entry in values}
        if len(self._by_id) != len(values):
            raise ValueError("catalog entries must have unique class ids")
        self._entries = values

    @property
    def entries(self) -> tuple[ClassEntry, ...]:
        return self._entries

    @property
    def active_entries(self) -> tuple[ClassEntry, ...]:
        return tuple(entry for entry in self._entries if entry.status == "active")

    def get(self, class_id: str) -> ClassEntry | None:
        return self._by_id.get(class_id)

    def candidates_for(self, invariant: InvariantProjection) -> tuple[ClassEntry, ...]:
        """Return active catalog entries that could classify one norm.

        The candidate set is the presentation algebra's pre-image:
        ``(effect constructor, primitive)`` selects entries before QDL role
        and sink facts refine the choice.  Classification-deficit routing uses
        this pre-image to derive a closed value alphabet without naming any
        action, field, sink, or vulnerability in code.
        """

        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            return ()
        if norm is None:
            return ()
        return tuple(
            entry
            for entry in self.active_entries
            if norm.effect_name in entry.effect_constructors
            and norm.primitive in entry.primitives
        )

    def classify(
        self,
        invariant: InvariantProjection,
        facts: ClassificationFacts | None = None,
        action_id: str | None = None,
    ) -> ClassEntry | None:
        """Return the active class entry for a QDL-grounded failed check."""

        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            return None
        if norm is None:
            return None

        candidates = tuple(
            entry
            for entry in self.active_entries
            if norm.effect_name in entry.effect_constructors
            and norm.primitive in entry.primitives
        )
        if not candidates:
            return None
        return self._select_entry(
            candidates,
            norm,
            facts or ClassificationFacts(),
            action_id,
        )

    def classify_finding(
        self,
        invariant: InvariantProjection,
        facts: ClassificationFacts | None = None,
        action_id: str | None = None,
    ) -> FindingClassification:
        """Classify a finding and expose a deficit when QDL facts are absent."""

        projected_facts = facts or ClassificationFacts()
        try:
            norm = NormView.from_invariant(invariant)
        except ValueError:
            return self._build_deficit_classification(
                ("invalid_norm_fact",),
                projected_facts,
            )
        if norm is None:
            return self._build_deficit_classification(
                ("missing_norm_fact",),
                projected_facts,
            )

        candidates = tuple(
            entry
            for entry in self.active_entries
            if norm.effect_name in entry.effect_constructors
            and norm.primitive in entry.primitives
        )
        if not candidates:
            return self._build_deficit_classification(
                ("missing_catalog_entry",),
                projected_facts,
                effect_name=norm.effect_name,
            )

        entry = self._select_entry(candidates, norm, projected_facts, action_id)
        if entry is None:
            return self._build_deficit_classification(
                _collect_classification_deficits(
                    candidates, norm, projected_facts, action_id
                ),
                projected_facts,
                entries=candidates,
            )
        return FindingClassification(
            entry=entry,
            deficit_reasons=(),
            cwe=entry.cwe,
            owasp=(entry.owasp_api,),
            stride=entry.stride,
        )

    @staticmethod
    def _build_deficit_classification(
        deficit_reasons: tuple[str, ...],
        facts: ClassificationFacts,
        *,
        effect_name: str | None = None,
        entries: tuple[ClassEntry, ...] = (),
    ) -> FindingClassification:
        if entries:
            cwe, owasp, stride = _project_entry_taxonomy(entries)
        elif effect_name is not None:
            cwe, owasp, stride = _project_effect_taxonomy(effect_name)
        else:
            cwe, owasp, stride = _project_facts_taxonomy(facts)
        return FindingClassification(
            entry=None,
            deficit_reasons=deficit_reasons,
            cwe=cwe,
            owasp=owasp,
            stride=stride,
        )

    @staticmethod
    def _select_entry(
        candidates: tuple[ClassEntry, ...],
        norm: NormView,
        facts: ClassificationFacts,
        action_id: str | None,
    ) -> ClassEntry | None:
        """Select one entry from QDL effect, role, and sink facts."""

        evidence_action = _effect_action(norm, action_id)
        defaulted = tuple(
            entry for entry in candidates if norm.effect_name in entry.default_effects
        )
        if defaulted:
            candidates = tuple(
                entry
                for entry in candidates
                if entry in defaulted or _has_fact_constraint(entry, norm.effect_name)
            )
        matching: list[ClassEntry] = []
        for entry in candidates:
            if _entry_matches(entry, norm, facts, evidence_action):
                matching.append(entry)
        if not matching:
            return None
        constrained = [
            entry for entry in matching if _has_fact_constraint(entry, norm.effect_name)
        ]
        return sorted(
            constrained or matching,
            key=lambda entry: (-len(_constraint_count(entry)), entry.class_id),
        )[0]


def _entry_matches(
    entry: ClassEntry,
    norm: NormView,
    facts: ClassificationFacts,
    action_id: str | None,
) -> bool:
    if (
        entry.default_effects
        and norm.effect_name not in entry.default_effects
        and not _has_fact_constraint(entry, norm.effect_name)
    ):
        return False
    return not _collect_entry_residuals(entry, norm, facts, action_id)


def _collect_entry_residuals(
    entry: ClassEntry,
    norm: NormView,
    facts: ClassificationFacts,
    action_id: str | None,
) -> tuple[str, ...]:
    """Return unsatisfied fact constraints for one exact catalog candidate.

    Each constraint requires an intersection with its declared alternatives;
    unrelated actual values neither satisfy it nor contradict those alternatives.
    Matching and deficit diagnostics use the same residual algebra.
    """

    residuals: list[str] = []
    if entry.input_roles and norm.effect_name == "changed":
        field_name = norm.forbidden_field
        roles = (
            facts.input_roles_for(action_id, field_name)
            if field_name is not None
            else frozenset()
        )
        if not roles.intersection(entry.input_roles):
            residuals.append("missing_input_role")
    if entry.input_roles and norm.effect_name == "allowed":
        roles = facts.input_roles_for_action(action_id)
        if not roles.intersection(entry.input_roles):
            residuals.append("missing_input_role")
    if entry.witness_roles and norm.effect_name == "has":
        field_name = norm.forbidden_field
        resource_id = norm.resource_id
        roles = (
            facts.witness_roles_for(action_id, resource_id, field_name)
            if field_name is not None and resource_id is not None
            else frozenset()
        )
        if not roles.intersection(entry.witness_roles):
            residuals.append("missing_witness_role")
    if entry.sink_types and norm.effect_name == "reached":
        sink_id = norm.marker
        # The class rule joins the norm effect to the QDL sink type.  The
        # sink identifier itself is never part of the classification key.
        if sink_id is None or not facts.sink_types_for(sink_id).intersection(
            entry.sink_types
        ):
            residuals.append("missing_sink_type")
    return tuple(residuals)


def _collect_classification_deficits(
    candidates: tuple[ClassEntry, ...],
    norm: NormView,
    facts: ClassificationFacts,
    action_id: str | None,
) -> tuple[str, ...]:
    effect_action = _effect_action(norm, action_id)
    residuals = _unique_values(
        reason
        for entry in candidates
        for reason in _collect_entry_residuals(entry, norm, facts, effect_action)
    )
    return residuals or ("unsatisfied_catalog_constraints",)


def _project_entry_taxonomy(
    entries: tuple[ClassEntry, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    cwe = _unique_values(value for entry in entries for value in entry.cwe)
    owasp = _unique_values(entry.owasp_api for entry in entries)
    stride = _unique_values(value for entry in entries for value in entry.stride)
    return cwe, owasp, stride


def _project_effect_taxonomy(
    effect_name: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    taxonomy: dict[
        str,
        tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]],
    ] = {
        "allowed": (("CWE-285",), ("A01",), ("E",)),
        "changed": (("CWE-693",), ("A08",), ("T",)),
        "completed": (("CWE-840",), ("A04",), ("E",)),
        "create": (("CWE-284",), ("A08",), ("T",)),
        "denied": (("CWE-285",), ("A01",), ("E",)),
        "duration": (("CWE-400",), ("API4",), ("D",)),
        "external_call": (("CWE-918",), ("A10",), ("E",)),
        "has": (("CWE-200",), ("A02",), ("I",)),
        "identity": (("CWE-287",), ("A07",), ("S", "E")),
        "reached": (("CWE-94",), ("A03",), ("T",)),
        "remove": (("CWE-284",), ("A08",), ("T",)),
        "transition": (("CWE-840",), ("A04",), ("T",)),
    }
    return taxonomy.get(effect_name, ((), (), ()))


def _project_facts_taxonomy(
    facts: ClassificationFacts,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    roles = sorted(
        {role for _action, _field, role in facts.input_roles}
        | {role for _resource, _field, role in facts.witness_roles}
    )
    entries = tuple(semantic_role_taxonomy(role) for role in roles)
    cwe = _unique_values(value for cwe, _owasp, _stride in entries for value in cwe)
    owasp = _unique_values(value for _cwe, owasp, _stride in entries for value in owasp)
    stride = _unique_values(
        value for _cwe, _owasp, stride in entries for value in stride
    )
    return cwe, owasp, stride


def _unique_values(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _effect_action(norm: NormView, action_id: str | None) -> str | None:
    if norm.action_id is not None:
        return norm.action_id
    return action_id


def _has_fact_constraint(entry: ClassEntry, effect_name: str) -> bool:
    if effect_name in {"allowed", "changed"} and entry.input_roles:
        return True
    if effect_name == "has" and entry.witness_roles:
        return True
    return effect_name == "reached" and bool(entry.sink_types)


def _constraint_count(entry: ClassEntry) -> tuple[int, ...]:
    return (
        len(entry.input_roles),
        len(entry.witness_roles),
        len(entry.sink_types),
    )


DEFAULT_CATALOG = ClassCatalog()
