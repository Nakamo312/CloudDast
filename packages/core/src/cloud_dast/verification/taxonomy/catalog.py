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
from cloud_dast.verification.norms import NormView, Primitive

if TYPE_CHECKING:
    from cloud_dast.contracts.plan import InvariantProjection

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
            match fact.predicate.name, fact.args:
                case "has", (
                    Struct(
                        name=("input_field" | "output_field" | "field") as kind,
                        args=(entity, path),
                    ),
                    role,
                ):
                    role_name = atom_value(role)
                    identifier = atom_value(entity)
                    field_name = atom_value(path)
                    if (
                        role_name not in SEMANTIC_ROLE_NAMES
                        or identifier is None
                        or field_name is None
                    ):
                        continue
                    roles = input_roles if kind == "input_field" else witness_roles
                    aliases = (
                        (identifier,) if kind == "field" else action_aliases(identifier)
                    )
                    roles.update((alias, field_name, role_name) for alias in aliases)
                case "is", (identifier, type_term):
                    identifier_value = atom_value(identifier)
                    kind_value = atom_value(type_term)
                    if identifier_value is not None and kind_value is not None:
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

    def _candidates(self, norm: NormView) -> tuple[ClassEntry, ...]:
        return tuple(
            entry
            for entry in self.active_entries
            if norm.effect_name in entry.effect_constructors
            and norm.primitive in entry.primitives
        )

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
        return self._candidates(norm)

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

        candidates = self._candidates(norm)
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

        candidates = self._candidates(norm)
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
                if entry in defaulted or _select_constraints(entry, norm.effect_name)
            )
        matching: list[ClassEntry] = []
        for entry in candidates:
            if _entry_matches(entry, norm, facts, evidence_action):
                matching.append(entry)
        if not matching:
            return None
        constrained = [
            entry for entry in matching if _select_constraints(entry, norm.effect_name)
        ]
        # Fact-constrained matches win; class ID breaks ties deterministically.
        return min(constrained or matching, key=lambda entry: entry.class_id)


def _entry_matches(
    entry: ClassEntry,
    norm: NormView,
    facts: ClassificationFacts,
    action_id: str | None,
) -> bool:
    if (
        entry.default_effects
        and norm.effect_name not in entry.default_effects
        and not _select_constraints(entry, norm.effect_name)
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

    constraints = _select_constraints(entry, norm.effect_name)
    if not constraints:
        return ()
    roles = frozenset()
    if norm.effect_name == "changed" and norm.forbidden_field is not None:
        roles = facts.input_roles_for(action_id, norm.forbidden_field)
    elif norm.effect_name == "allowed":
        roles = facts.input_roles_for_action(action_id)
    elif (
        norm.effect_name == "has"
        and norm.forbidden_field is not None
        and norm.resource_id is not None
    ):
        roles = facts.witness_roles_for(
            action_id, norm.resource_id, norm.forbidden_field
        )
    elif norm.effect_name == "reached" and norm.marker is not None:
        # The class rule joins the norm effect to the QDL sink type.  The
        # sink identifier itself is never part of the classification key.
        roles = facts.sink_types_for(norm.marker)
    if roles.intersection(constraints):
        return ()
    return (_FACT_CONSTRAINTS[norm.effect_name][1],)


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


_FACT_CONSTRAINTS = {
    "changed": ("input_roles", "missing_input_role"),
    "allowed": ("input_roles", "missing_input_role"),
    "has": ("witness_roles", "missing_witness_role"),
    "reached": ("sink_types", "missing_sink_type"),
}


def _select_constraints(entry: ClassEntry, effect_name: str) -> tuple[str, ...]:
    policy = _FACT_CONSTRAINTS.get(effect_name)
    return getattr(entry, policy[0]) if policy is not None else ()


DEFAULT_CATALOG = ClassCatalog()
