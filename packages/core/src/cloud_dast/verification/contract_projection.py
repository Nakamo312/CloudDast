"""Deterministic projection of contract graph slices into QDL."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cloud_dast.model import MethodSpec
from cloud_dast.ports import (
    GraphEdge,
    GraphNode,
    ServiceGraphSlice,
)
from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    input_field,
)
from cloud_dast.qdl.roles import SEMANTIC_ROLE_NAMES

type IssueCategory = Literal["unmapped", "ambiguous", "conflict"]
type ElementKind = Literal["node", "edge", "field", "annotation"]
type NodeStatus = Literal["mapped", "unmapped", "ambiguous", "conflict"]

CLASSIFICATION_SINK_TYPES = frozenset({"interpreter", "filesystem", "external_net"})
_CLASSIFICATION_PROPERTY = "data_classification"
_ANNOTATION_ACTION_KEYS = ("action", "method_id")
_ANNOTATION_FIELD_KEYS = ("field", "field_path")
_CLASSIFICATION_LABEL_KEYS = ("classification", "classifications", "labels")
_SINK_LABEL_KEYS = ("sink", "sinks", "sink_type", "sink_types")


_EXTENSION_PREDICATES = {
    schema.name: Predicate.from_schema(schema) for schema in EXTENSION_PREDICATE_SCHEMAS
}
_IS = Predicate.from_name("is")
_GRANTS = Predicate.from_name("grants")
_HAS = Predicate.from_name("has")
_APPLIES_TO = Predicate.from_name("applies_to")
_PART = Predicate.from_name("part")
_REACHES = Predicate.from_name("reaches")
_TARGETS = Predicate.from_name("targets")
_REQUIRES = Predicate.from_name("requires")

_NODE_SPECS: dict[str, tuple[tuple[str, ...], tuple[str, ...], str | None]] = {
    "Service": (("canonical_id", "service_id"), ("name",), "service"),
    "ApiSurface": (("canonical_id", "package", "api"), ("name",), "api"),
    "Method": (("method_id", "canonical_id"), ("name",), "action"),
    "Permission": (("permission_id", "canonical_id"), ("name",), "permission"),
    "ResourceType": (("resource_type", "canonical_id"), ("name",), "resource"),
    "Param": (("path", "field_path", "key"), ("name", "param_id"), None),
    "Endpoint": (("endpoint_id", "canonical_id"), ("name",), "endpoint"),
    "Alias": (("alias", "canonical_id"), ("name",), "alias"),
    "DocPage": (("page_id", "canonical_id"), ("url",), "doc_page"),
    "Source": (("source_id",), ("path", "file"), "source"),
    "Role": (("role_id", "canonical_id"), ("name",), "role"),
}

_NODE_TYPES = {
    "Service": "Service",
    "ApiSurface": "ApiSurface",
    "Method": "Action",
    "Permission": "Permission",
    "ResourceType": "ResourceType",
    "Param": "InputField",
    "Endpoint": "Endpoint",
    "Alias": "Alias",
    "DocPage": "DocPage",
    "Source": "Source",
    "Role": "Role",
}

_EDGE_SPECS = {
    "EXPOSES": ("ApiSurface", "Service", _PART, False),
    "EXPOSES_METHOD": ("Service", "Method", _PART, True),
    "HAS_METHOD": ("Method", "ApiSurface", _PART, False),
    "HAS_PARAM": ("Method", "Param", _PART, False),
    "PARENT_OF": ("ResourceType", "ResourceType", _PART, True),
    "OWNS": ("Service", "ResourceType", _PART, True),
    "DEFINED_IN": ("Method", "Source", _PART, False),
    "APPLIES_TO": ("Permission", "ResourceType", _APPLIES_TO, False),
    "SERVES": ("Endpoint", "ApiSurface", _EXTENSION_PREDICATES["serves"], False),
    "KNOWN_AS": ("Service", "Alias", _EXTENSION_PREDICATES["known_as"], False),
    "DESCRIBES": ("DocPage", "Service", _EXTENSION_PREDICATES["describes"], False),
    "REQUIRES": ("Method", "Permission", _REQUIRES, False),
    "TARGETS": ("Method", "ResourceType", _TARGETS, False),
    "REFERS_TO": ("Param", "ResourceType", _EXTENSION_PREDICATES["refers_to"], False),
    "GRANTS": ("Role", "Permission", _GRANTS, False),
}


class MappedElement(BaseModel):
    """One source element with a stable logical projection."""

    model_config = ConfigDict(frozen=True)

    kind: ElementKind
    logical_id: str
    predicates: tuple[str, ...] = ()


class ProjectionIssue(BaseModel):
    """An explicit projection gap or contradiction."""

    model_config = ConfigDict(frozen=True)

    category: IssueCategory
    element: Literal["node", "edge", "field", "annotation"]
    identifier: str
    detail: str
    choices: tuple[str, ...] = ()


class ProjectionReport(BaseModel):
    """Deterministic mapping and issue report for one projection."""

    model_config = ConfigDict(frozen=True)

    mapped: tuple[MappedElement, ...] = ()
    unmapped: tuple[ProjectionIssue, ...] = ()
    ambiguous: tuple[ProjectionIssue, ...] = ()
    conflict: tuple[ProjectionIssue, ...] = ()


class Result(BaseModel):
    """The QDL graph and mapping report produced from a contract slice."""

    model_config = ConfigDict(frozen=True)

    graph: QdlGraph
    report: ProjectionReport

    @property
    def canonical_hash(self) -> str:
        return self.graph.content_hash


class ClassificationProfile(BaseModel):
    """Curated mapping from source data labels to QDL semantics.

    The profile is source metadata, not a vulnerability catalogue: labels map
    only into the closed semantic-role and executable sink-type alphabets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    roles: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    sink_types: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_targets(self) -> ClassificationProfile:
        for field_name, mappings in (
            ("roles", self.roles),
            ("sink types", self.sink_types),
        ):
            for label, targets in mappings.items():
                if not label.strip():
                    raise ValueError(f"{field_name} labels must not be empty")
                if label != label.strip():
                    raise ValueError(
                        f"{field_name} label {label!r} has surrounding whitespace"
                    )
                if not targets:
                    raise ValueError(f"{field_name} label {label!r} has no targets")
                if any(not target.strip() for target in targets):
                    raise ValueError(
                        f"{field_name} label {label!r} has an empty target"
                    )
                if any(target != target.strip() for target in targets):
                    raise ValueError(
                        f"{field_name} label {label!r} has a target with whitespace"
                    )
                if len(targets) != len(set(targets)):
                    raise ValueError(
                        f"{field_name} label {label!r} has duplicate targets"
                    )

        unknown_roles = {
            role for targets in self.roles.values() for role in targets
        } - SEMANTIC_ROLE_NAMES
        if unknown_roles:
            raise ValueError(
                "unknown semantic roles: " + ", ".join(sorted(unknown_roles))
            )
        unknown_sink_types = {
            sink_type for targets in self.sink_types.values() for sink_type in targets
        } - CLASSIFICATION_SINK_TYPES
        if unknown_sink_types:
            raise ValueError(
                "unknown sink types: " + ", ".join(sorted(unknown_sink_types))
            )
        return self


@dataclass(slots=True)
class _NodeState:
    node: GraphNode
    status: NodeStatus
    kind: str | None = None
    identity: str | None = None
    atom: Atom | None = None
    field_path: str | None = None
    usable: bool = True
    choices: tuple[str, ...] = ()


@dataclass(slots=True)
class _FieldRecord:
    action: Atom
    path: str
    types: set[str] = field(default_factory=set)
    required: set[bool] = field(default_factory=set)
    repeated: set[bool] = field(default_factory=set)
    oneofs: set[str] = field(default_factory=set)
    enum_values: set[str] = field(default_factory=set)
    minimums: set[Atom] = field(default_factory=set)
    maximums: set[Atom] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class _SourceAnnotation:
    action: str
    field: str
    classifications: tuple[str, ...]
    sinks: tuple[str, ...]


class ContractProjector:
    """Project a service contract slice into extension-safe QDL facts.

    The adapter never uses storage element IDs. Logical identities come from
    contract properties and are prefixed by their QDL entity kind. Param nodes
    become path-qualified ``input_field`` terms owned by their method.
    DocPage annotations are trusted only when the page describes the selected
    service; they are compiled into contract-context facts through the curated
    classification profile.
    """

    def __init__(
        self,
        classification_profile: ClassificationProfile | None = None,
    ) -> None:
        self._classification_profile = classification_profile or ClassificationProfile()

    def project(self, graph_slice: ServiceGraphSlice) -> Result:
        self._validate_slice(graph_slice)

        states = {node.node_id: self._map_node(node) for node in graph_slice.nodes}
        conflicts = self._mark_identity_conflicts(states)

        mapped: list[MappedElement] = []
        unmapped: list[ProjectionIssue] = []
        ambiguous: list[ProjectionIssue] = []
        conflict: list[ProjectionIssue] = [*conflicts]
        facts_by_key: dict[str, Fact] = {}

        node_unmapped, node_ambiguous = self._collect_node_issues(states)
        unmapped.extend(node_unmapped)
        ambiguous.extend(node_ambiguous)

        self._declare_nodes(states, mapped, facts_by_key)

        owners = self._collect_param_owners(graph_slice, states)
        param_terms = self._project_fields(
            states,
            owners,
            mapped,
            unmapped,
            conflict,
            facts_by_key,
        )
        self._project_edges(
            graph_slice,
            states,
            param_terms,
            mapped,
            unmapped,
            ambiguous,
            conflict,
            facts_by_key,
        )
        self._project_classifications(
            graph_slice,
            states,
            mapped,
            unmapped,
            ambiguous,
            facts_by_key,
        )

        graph = QdlGraph(facts=tuple(facts_by_key.values()))
        report = ProjectionReport(
            mapped=_sorted_mapped(mapped),
            unmapped=_sorted_issues(unmapped),
            ambiguous=_sorted_issues(ambiguous),
            conflict=_sorted_issues(conflict),
        )
        return Result(graph=graph, report=report)

    def project_methods(
        self,
        service: str,
        methods: tuple[MethodSpec, ...],
    ) -> Result:
        """Project method-only sources through the same contract pipeline.

        Binary input specifications and protocol message descriptions use this
        entry point so they cannot grow a second projection semantics.
        """

        return self.project(ServiceGraphSlice.from_methods(service, methods))

    @staticmethod
    def _validate_slice(graph_slice: ServiceGraphSlice) -> None:
        if not graph_slice.service.strip():
            raise ValueError("service graph slice requires a service name")

        node_ids = [node.node_id for node in graph_slice.nodes]
        if any(not node_id.strip() for node_id in node_ids):
            raise ValueError("service graph slice contains an empty node ID")
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("service graph slice contains duplicate node IDs")

        edge_ids = [edge.edge_id for edge in graph_slice.edges]
        if any(not edge_id.strip() for edge_id in edge_ids):
            raise ValueError("service graph slice contains an empty edge ID")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("service graph slice contains duplicate edge IDs")

    @staticmethod
    def _map_node(node: GraphNode) -> _NodeState:
        kinds = tuple(
            dict.fromkeys(label for label in node.labels if label in _NODE_SPECS)
        )
        if not kinds:
            return _NodeState(node=node, status="unmapped")
        if len(kinds) > 1:
            return _NodeState(
                node=node,
                status="ambiguous",
                kind="/".join(kinds),
                choices=kinds,
            )

        kind = kinds[0]
        primary_names, fallback_names, prefix = _NODE_SPECS[kind]
        values = _identity_values(node, primary_names)
        if not values:
            values = _identity_values(node, fallback_names)
        if not values:
            return _NodeState(node=node, status="unmapped", kind=kind)
        if len(values) > 1:
            return _NodeState(
                node=node,
                status="ambiguous",
                kind=kind,
                identity=values[0],
                choices=values,
            )

        identity = values[0]
        if kind == "Param":
            return _NodeState(
                node=node,
                status="mapped",
                kind=kind,
                identity=identity,
                field_path=identity,
            )
        return _NodeState(
            node=node,
            status="mapped",
            kind=kind,
            identity=identity,
            atom=Atom(value=f"{prefix}:{identity}"),
        )

    @staticmethod
    def _mark_identity_conflicts(
        states: dict[str, _NodeState],
    ) -> tuple[ProjectionIssue, ...]:
        groups: dict[str, list[_NodeState]] = {}
        for state in states.values():
            if state.status == "mapped" and state.atom is not None:
                groups.setdefault(state.atom.value, []).append(state)

        issues: list[ProjectionIssue] = []
        for logical_id, group in groups.items():
            kinds = {state.kind for state in group}
            if len(group) == 1 and len(kinds) == 1:
                continue
            for state in group:
                state.status = "conflict"
                state.usable = False
            issues.append(
                ProjectionIssue(
                    category="conflict",
                    element="node",
                    identifier=logical_id,
                    detail="logical identity is assigned to multiple nodes or kinds",
                    choices=tuple(sorted(str(kind) for kind in kinds)),
                )
            )
        return tuple(issues)

    @staticmethod
    def _collect_node_issues(
        states: dict[str, _NodeState],
    ) -> tuple[tuple[ProjectionIssue, ...], tuple[ProjectionIssue, ...]]:
        unmapped: list[ProjectionIssue] = []
        ambiguous: list[ProjectionIssue] = []
        for state in states.values():
            identifier = _node_fingerprint(state.node)
            if state.status == "unmapped":
                detail = (
                    "node has no recognized contract label"
                    if state.kind is None
                    else f"{state.kind} node has no logical identity property"
                )
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="node",
                        identifier=identifier,
                        detail=detail,
                    )
                )
            elif state.status == "ambiguous":
                ambiguous.append(
                    ProjectionIssue(
                        category="ambiguous",
                        element="node",
                        identifier=identifier,
                        detail="node has ambiguous labels or logical identity",
                        choices=state.choices or tuple(state.node.labels),
                    )
                )
        return tuple(unmapped), tuple(ambiguous)

    @staticmethod
    def _declare_nodes(
        states: dict[str, _NodeState],
        mapped: list[MappedElement],
        facts_by_key: dict[str, Fact],
    ) -> None:
        declared: set[str] = set()
        for state in states.values():
            if state.status != "mapped" or state.atom is None:
                continue
            key = state.atom.value
            if key in declared:
                continue
            declared.add(key)
            fact = _fact(_IS, state.atom, Atom(value=_NODE_TYPES[state.kind]))
            _add_fact(fact, facts_by_key)
            mapped.append(
                MappedElement(kind="node", logical_id=key, predicates=("is",))
            )

    @staticmethod
    def _collect_param_owners(
        graph_slice: ServiceGraphSlice,
        states: dict[str, _NodeState],
    ) -> dict[str, tuple[Atom, ...]]:
        owners: dict[str, dict[str, Atom]] = {}
        for edge in graph_slice.edges:
            if edge.kind != "HAS_PARAM":
                continue
            source = states.get(edge.source_id)
            target = states.get(edge.target_id)
            if (
                source is None
                or target is None
                or source.status != "mapped"
                or target.status != "mapped"
                or source.kind != "Method"
                or target.kind != "Param"
                or source.atom is None
                or target.field_path is None
            ):
                continue
            owners.setdefault(edge.target_id, {})[canonical_json(source.atom)] = (
                source.atom
            )
        return {
            target_id: tuple(owner for _, owner in sorted(owner_map.items()))
            for target_id, owner_map in owners.items()
        }

    @staticmethod
    def _project_fields(
        states: dict[str, _NodeState],
        owners: dict[str, tuple[Atom, ...]],
        mapped: list[MappedElement],
        unmapped: list[ProjectionIssue],
        conflict: list[ProjectionIssue],
        facts_by_key: dict[str, Fact],
    ) -> dict[str, tuple[Struct, ...]]:
        records: dict[tuple[str, str], _FieldRecord] = {}

        for state in states.values():
            if state.status != "mapped" or state.kind != "Method":
                continue
            if state.atom is None or "input_fields" not in state.node.properties:
                continue
            entries = _parse_entries(state.node.properties["input_fields"])
            if entries is None:
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="field",
                        identifier=state.atom.value,
                        detail="method input_fields is not a list of field objects",
                    )
                )
            else:
                ContractProjector._collect_fields(
                    state.atom, entries, "", records, unmapped
                )

        param_terms: dict[str, tuple[Struct, ...]] = {}
        for raw_id, state in states.items():
            if state.status != "mapped" or state.kind != "Param":
                continue
            if state.field_path is None:
                continue
            actions = owners.get(raw_id, ())
            if not actions:
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="field",
                        identifier=f"param:{state.field_path}",
                        detail="Param has no owning Method",
                    )
                )
                continue

            entry = dict(state.node.properties)
            entry["name"] = state.field_path
            terms = []
            for action in actions:
                ContractProjector._collect_fields(
                    action, (entry,), "", records, unmapped
                )
                terms.append(input_field(action, Atom(value=state.field_path)))
            param_terms[raw_id] = tuple(terms)

        for record in records.values():
            ContractProjector._emit_field(record, mapped, conflict, facts_by_key)
        return param_terms

    @staticmethod
    def _collect_fields(
        action: Atom,
        entries: tuple[dict[str, Any], ...],
        prefix: str,
        records: dict[tuple[str, str], _FieldRecord],
        unmapped: list[ProjectionIssue],
    ) -> None:
        for entry in entries:
            if not isinstance(entry, dict):
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="field",
                        identifier=action.value,
                        detail="input field entry is not an object",
                    )
                )
                continue

            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="field",
                        identifier=action.value,
                        detail="input field has no non-empty string name",
                    )
                )
                continue

            path = f"{prefix}{name.strip()}"
            field_id = _field_id(action, path)
            record = records.setdefault(
                (canonical_json(action), path),
                _FieldRecord(action=action, path=path),
            )
            _merge_field_attributes(record, entry, field_id, unmapped)

            if "fields" in entry:
                nested = _parse_entries(entry["fields"])
                if nested is None:
                    unmapped.append(
                        ProjectionIssue(
                            category="unmapped",
                            element="field",
                            identifier=field_id,
                            detail="nested fields is not a list of field objects",
                        )
                    )
                else:
                    ContractProjector._collect_fields(
                        action,
                        nested,
                        f"{path}.",
                        records,
                        unmapped,
                    )

    @staticmethod
    def _emit_field(
        record: _FieldRecord,
        mapped: list[MappedElement],
        conflict: list[ProjectionIssue],
        facts_by_key: dict[str, Fact],
    ) -> None:
        term = input_field(record.action, Atom(value=record.path))
        field_id = canonical_json(term)
        predicates = {"is", "part"}
        _add_fact(_fact(_IS, term, Atom(value="InputField")), facts_by_key)
        _add_fact(_fact(_PART, term, record.action), facts_by_key)

        for attribute, values, predicate_name in (
            ("type", record.types, "field_type"),
            ("required", record.required, "field_required"),
            ("repeated", record.repeated, "field_repeated"),
            ("oneof", record.oneofs, "field_oneof"),
        ):
            _emit_scalar(
                attribute,
                values,
                predicate_name,
                field_id,
                term,
                facts_by_key,
                predicates,
                conflict,
            )

        for value in record.enum_values:
            _add_fact(
                _fact(
                    _EXTENSION_PREDICATES["field_enum_value"],
                    term,
                    Atom(value=value),
                ),
                facts_by_key,
            )
            predicates.add("field_enum_value")

        for attribute, values, predicate_name in (
            ("minimum", record.minimums, "field_minimum"),
            ("maximum", record.maximums, "field_maximum"),
        ):
            _emit_scalar(
                attribute,
                values,
                predicate_name,
                field_id,
                term,
                facts_by_key,
                predicates,
                conflict,
            )

        mapped.append(
            MappedElement(
                kind="field",
                logical_id=field_id,
                predicates=tuple(sorted(predicates)),
            )
        )

    @staticmethod
    def _project_edges(
        graph_slice: ServiceGraphSlice,
        states: dict[str, _NodeState],
        param_terms: dict[str, tuple[Struct, ...]],
        mapped: list[MappedElement],
        unmapped: list[ProjectionIssue],
        ambiguous: list[ProjectionIssue],
        conflict: list[ProjectionIssue],
        facts_by_key: dict[str, Fact],
    ) -> None:
        for edge in graph_slice.edges:
            source = states.get(edge.source_id)
            target = states.get(edge.target_id)
            identifier = _edge_identifier(edge, source, target)

            if source is None or target is None:
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="edge",
                        identifier=identifier,
                        detail="edge endpoint node is missing",
                    )
                )
                continue
            if source.status == "ambiguous" or target.status == "ambiguous":
                ambiguous.append(
                    ProjectionIssue(
                        category="ambiguous",
                        element="edge",
                        identifier=identifier,
                        detail="edge endpoint has an ambiguous logical identity",
                    )
                )
                continue
            if not source.usable or not target.usable:
                conflict.append(
                    ProjectionIssue(
                        category="conflict",
                        element="edge",
                        identifier=identifier,
                        detail="edge endpoint has a conflicting logical identity",
                    )
                )
                continue

            facts = _edge_facts(edge, source, target, param_terms)
            if facts is None:
                expected = _EDGE_SPECS.get(edge.kind)
                if expected is None:
                    unmapped.append(
                        ProjectionIssue(
                            category="unmapped",
                            element="edge",
                            identifier=identifier,
                            detail="edge kind has no QDL mapping",
                        )
                    )
                else:
                    ambiguous.append(
                        ProjectionIssue(
                            category="ambiguous",
                            element="edge",
                            identifier=identifier,
                            detail="edge endpoint labels do not match the mapping",
                            choices=(
                                f"{expected[0]}->{expected[1]}",
                                f"{source.kind or 'unknown'}->{target.kind or 'unknown'}",
                            ),
                        )
                    )
                continue

            for fact in facts:
                _add_fact(fact, facts_by_key)
            mapped.append(
                MappedElement(
                    kind="edge",
                    logical_id=identifier,
                    predicates=tuple(sorted({fact.predicate.name for fact in facts})),
                )
            )

    def _project_classifications(
        self,
        graph_slice: ServiceGraphSlice,
        states: dict[str, _NodeState],
        mapped: list[MappedElement],
        unmapped: list[ProjectionIssue],
        ambiguous: list[ProjectionIssue],
        facts_by_key: dict[str, Fact],
    ) -> None:
        """Project trusted DocPage annotations into contract-context semantics."""

        actions = _declared_atoms(facts_by_key, "Action")
        input_fields = frozenset(
            canonical_json(term) for term in _declared_input_fields(facts_by_key)
        )
        mapped_predicates: dict[str, set[str]] = {}

        for origin, raw in _classification_sources(graph_slice, states):
            entries = _classification_entries(raw)
            if entries is None:
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="annotation",
                        identifier=origin,
                        detail="data_classification is not a list of field annotations",
                    )
                )
                continue

            for entry in entries:
                annotation = _parse_annotation(entry, origin, unmapped, ambiguous)
                if annotation is None:
                    continue
                self._emit_annotation(
                    annotation,
                    actions,
                    input_fields,
                    mapped_predicates,
                    unmapped,
                    facts_by_key,
                )

        for field_id, predicates in mapped_predicates.items():
            mapped.append(
                MappedElement(
                    kind="annotation",
                    logical_id=field_id,
                    predicates=tuple(sorted(predicates)),
                )
            )

    def _emit_annotation(
        self,
        annotation: _SourceAnnotation,
        actions: frozenset[str],
        input_fields: frozenset[str],
        mapped_predicates: dict[str, set[str]],
        unmapped: list[ProjectionIssue],
        facts_by_key: dict[str, Fact],
    ) -> None:
        action_id = _canonical_action(annotation.action, actions)
        identifier = f"annotation:{annotation.action}:{annotation.field}"
        if action_id is None:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="annotation",
                    identifier=identifier,
                    detail="annotation action is not declared by the contract graph",
                )
            )
            return

        term = input_field(Atom(value=action_id), Atom(value=annotation.field))
        field_id = canonical_json(term)
        if field_id not in input_fields:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="annotation",
                    identifier=identifier,
                    detail="annotation field is not declared by the contract graph",
                )
            )
            return

        unknown_labels = False
        for labels, mapping, kind in (
            (
                annotation.classifications,
                self._classification_profile.roles,
                "classification",
            ),
            (annotation.sinks, self._classification_profile.sink_types, "sink"),
        ):
            unknown = [label for label in labels if label not in mapping]
            if unknown:
                unknown_labels = True
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="annotation",
                        identifier=identifier,
                        detail=f"source {kind} labels are not mapped",
                        choices=tuple(sorted(set(unknown))),
                    )
                )

        roles = sorted(
            {
                role
                for label in annotation.classifications
                for role in self._classification_profile.roles.get(label, ())
            }
        )
        sink_types = sorted(
            {
                sink_type
                for label in annotation.sinks
                for sink_type in self._classification_profile.sink_types.get(label, ())
            }
        )
        if not roles and not sink_types and not unknown_labels:
            if annotation.classifications or annotation.sinks:
                detail = "annotation has no mapped classification or sink labels"
            else:
                detail = "annotation has no classification or sink labels"
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="annotation",
                    identifier=identifier,
                    detail=detail,
                )
            )
            return

        predicates = mapped_predicates.setdefault(field_id, set())
        for role in roles:
            _add_fact(_fact(_HAS, term, Atom(value=role)), facts_by_key)
            predicates.add("has")

        for sink_type in sink_types:
            sink = Atom(value=f"sink:{action_id}:{annotation.field}:{sink_type}")
            _add_fact(_fact(_IS, sink, Atom(value=sink_type)), facts_by_key)
            _add_fact(_fact(_REACHES, term, sink), facts_by_key)
            predicates.update({"is", "reaches"})


def _logical_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _identity_values(node: GraphNode, names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            identity
            for name in names
            if (identity := _logical_value(node.properties.get(name))) is not None
        )
    )


def _fact(predicate: Predicate, *args: Atom | Struct) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=predicate,
        args=tuple(args),
    )


def _add_fact(fact: Fact, facts_by_key: dict[str, Fact]) -> None:
    facts_by_key[canonical_json(fact)] = fact


def _parse_entries(raw: object) -> tuple[dict[str, Any], ...] | None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, list | tuple):
        return None
    return tuple(raw)


def _field_id(action: Atom, path: str) -> str:
    return canonical_json(input_field(action, Atom(value=path)))


def _merge_field_attributes(
    record: _FieldRecord,
    entry: dict[str, Any],
    field_id: str,
    unmapped: list[ProjectionIssue],
) -> None:
    raw_type = entry.get("type", entry.get("field_type"))
    if isinstance(raw_type, str) and raw_type.strip():
        record.types.add(raw_type.strip())
    else:
        unmapped.append(
            ProjectionIssue(
                category="unmapped",
                element="field",
                identifier=field_id,
                detail="field type is missing or is not a non-empty string",
            )
        )

    for name, values in (
        ("required", record.required),
        ("repeated", record.repeated),
    ):
        raw = entry.get(name, False)
        if isinstance(raw, bool):
            values.add(raw)
        else:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="field",
                    identifier=field_id,
                    detail=f"field {name} is not a boolean",
                )
            )

    raw_oneof = entry.get("oneof")
    if raw_oneof is not None:
        if isinstance(raw_oneof, str) and raw_oneof.strip():
            record.oneofs.add(raw_oneof.strip())
        else:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="field",
                    identifier=field_id,
                    detail="field oneof is not a non-empty string",
                )
            )

    raw_enum_values = entry.get("enum_values", ())
    if isinstance(raw_enum_values, list | tuple):
        for value in raw_enum_values:
            if isinstance(value, str):
                record.enum_values.add(value)
            else:
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="field",
                        identifier=field_id,
                        detail="enum value is not a string",
                    )
                )
    else:
        unmapped.append(
            ProjectionIssue(
                category="unmapped",
                element="field",
                identifier=field_id,
                detail="field enum_values is not a list",
            )
        )

    for name, values in (
        ("minimum", record.minimums),
        ("maximum", record.maximums),
    ):
        raw = entry.get(name)
        if raw is None:
            continue
        bound = _bound_atom(raw)
        if bound is None:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="field",
                    identifier=field_id,
                    detail=f"field {name} is not a finite number",
                )
            )
        else:
            values.add(bound)


def _bound_atom(value: object) -> Atom | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Atom(value=value)
    if isinstance(value, float) and math.isfinite(value):
        return Atom(value=repr(value))
    return None


def _emit_scalar(
    attribute: str,
    values: set[Any],
    predicate_name: str,
    field_id: str,
    term: Struct,
    facts_by_key: dict[str, Fact],
    predicates: set[str],
    conflict: list[ProjectionIssue],
) -> None:
    if len(values) > 1:
        conflict.append(
            ProjectionIssue(
                category="conflict",
                element="field",
                identifier=field_id,
                detail=f"field {attribute} has conflicting values",
                choices=tuple(
                    sorted(
                        canonical_json(
                            value if isinstance(value, Atom) else Atom(value=value)
                        )
                        for value in values
                    )
                ),
            )
        )
        return
    if not values:
        return
    value = next(iter(values))
    atom = value if isinstance(value, Atom) else Atom(value=value)
    _add_fact(
        _fact(_EXTENSION_PREDICATES[predicate_name], term, atom),
        facts_by_key,
    )
    predicates.add(predicate_name)


def _edge_facts(
    edge: GraphEdge,
    source: _NodeState,
    target: _NodeState,
    param_terms: dict[str, tuple[Struct, ...]],
) -> tuple[Fact, ...] | None:
    expected = _EDGE_SPECS.get(edge.kind)
    if expected is None:
        return None
    if source.kind != expected[0] or target.kind != expected[1]:
        return None
    if (source.kind != "Param" and source.atom is None) or (
        target.kind != "Param" and target.atom is None
    ):
        return None

    if edge.kind == "HAS_PARAM":
        term = input_field(source.atom, Atom(value=target.field_path))
        return (_fact(expected[2], term, source.atom),)
    if edge.kind == "REFERS_TO":
        terms = param_terms.get(edge.source_id, ())
        if not terms:
            return None
        return tuple(_fact(expected[2], term, target.atom) for term in terms)
    predicate, reverse = expected[2:]
    left, right = (target.atom, source.atom) if reverse else (source.atom, target.atom)
    return (_fact(predicate, left, right),)


def _edge_identifier(
    edge: GraphEdge,
    source: _NodeState | None,
    target: _NodeState | None,
) -> str:
    return f"{edge.kind}:{_node_key(source)}->{_node_key(target)}"


def _node_key(state: _NodeState | None) -> str:
    if state is None:
        return "missing-node"
    if state.atom is not None:
        return state.atom.value
    if state.field_path is not None:
        return f"param:{state.field_path}"
    return _node_fingerprint(state.node)


def _node_fingerprint(node: GraphNode) -> str:
    payload = {
        "labels": list(node.labels),
        "properties": _plain_value(node.properties),
    }
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:16]
    labels = "|".join(node.labels) if node.labels else "unknown"
    return f"node:{labels}:{digest}"


def _plain_value(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain_value(item) for item in value]
    if value is None or isinstance(value, str | int | bool):
        return value
    return f"{type(value).__name__}:{value!r}"


def _classification_sources(
    graph_slice: ServiceGraphSlice,
    states: dict[str, _NodeState],
) -> tuple[tuple[str, object], ...]:
    sources: list[tuple[str, object]] = []
    described_doc_ids: set[str] = set()

    for edge in graph_slice.edges:
        if edge.kind != "DESCRIBES":
            continue
        source = states.get(edge.source_id)
        target = states.get(edge.target_id)
        if (
            source is None
            or target is None
            or source.status != "mapped"
            or target.status != "mapped"
            or not source.usable
            or not target.usable
            or source.kind != "DocPage"
            or target.kind != "Service"
            or target.atom is None
            or target.atom.value != f"service:{graph_slice.service}"
        ):
            continue
        described_doc_ids.add(edge.source_id)
        raw = edge.properties.get(_CLASSIFICATION_PROPERTY)
        if raw is not None:
            sources.append((_edge_identifier(edge, source, target), raw))

    for node in graph_slice.nodes:
        state = states.get(node.node_id)
        if (
            state is None
            or state.status != "mapped"
            or state.kind != "DocPage"
            or state.atom is None
            or node.node_id not in described_doc_ids
        ):
            continue
        raw = node.properties.get(_CLASSIFICATION_PROPERTY)
        if raw is not None:
            sources.append((f"doc_page:{state.atom.value}", raw))
    return tuple(sources)


def _classification_entries(raw: object) -> tuple[object, ...] | None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if isinstance(raw, list | tuple):
        return tuple(raw)
    if not isinstance(raw, dict):
        return None

    selected = tuple(name for name in ("fields", "classifications") if name in raw)
    if len(selected) != 1:
        return None
    entries = raw[selected[0]]
    if not isinstance(entries, list | tuple):
        return None
    return tuple(entries)


def _parse_annotation(
    entry: object,
    origin: str,
    unmapped: list[ProjectionIssue],
    ambiguous: list[ProjectionIssue],
) -> _SourceAnnotation | None:
    if not isinstance(entry, dict):
        unmapped.append(
            ProjectionIssue(
                category="unmapped",
                element="annotation",
                identifier=origin,
                detail="source annotation is not an object",
            )
        )
        return None

    action = _annotation_scalar(
        entry, _ANNOTATION_ACTION_KEYS, "action", origin, unmapped, ambiguous
    )
    field = _annotation_scalar(
        entry, _ANNOTATION_FIELD_KEYS, "field", origin, unmapped, ambiguous
    )
    classifications = _annotation_labels(
        entry,
        _CLASSIFICATION_LABEL_KEYS,
        "classification",
        origin,
        unmapped,
        ambiguous,
    )
    sinks = _annotation_labels(
        entry,
        _SINK_LABEL_KEYS,
        "sink",
        origin,
        unmapped,
        ambiguous,
    )
    if action is None or field is None or classifications is None or sinks is None:
        return None
    return _SourceAnnotation(
        action=action,
        field=field,
        classifications=classifications,
        sinks=sinks,
    )


def _annotation_scalar(
    entry: dict[str, object],
    keys: tuple[str, ...],
    name: str,
    origin: str,
    unmapped: list[ProjectionIssue],
    ambiguous: list[ProjectionIssue],
) -> str | None:
    values: list[str] = []
    for key in keys:
        if key not in entry:
            continue
        value = entry[key]
        if not isinstance(value, str) or not value.strip():
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="annotation",
                    identifier=origin,
                    detail=f"annotation {name} is not a non-empty string",
                )
            )
            return None
        values.append(value.strip())

    if not values:
        unmapped.append(
            ProjectionIssue(
                category="unmapped",
                element="annotation",
                identifier=origin,
                detail=f"annotation has no {name}",
            )
        )
        return None
    if any(value != values[0] for value in values[1:]):
        ambiguous.append(
            ProjectionIssue(
                category="ambiguous",
                element="annotation",
                identifier=origin,
                detail=f"annotation has conflicting {name} keys",
                choices=tuple(values),
            )
        )
        return None
    return values[0]


def _annotation_labels(
    entry: dict[str, object],
    keys: tuple[str, ...],
    name: str,
    origin: str,
    unmapped: list[ProjectionIssue],
    ambiguous: list[ProjectionIssue],
) -> tuple[str, ...] | None:
    groups: list[tuple[str, ...]] = []
    for key in keys:
        if key not in entry:
            continue
        raw = entry[key]
        if isinstance(raw, str):
            candidates: tuple[object, ...] = (raw,)
        elif isinstance(raw, list | tuple):
            candidates = tuple(raw)
        else:
            candidates = None
        if candidates is None:
            unmapped.append(
                ProjectionIssue(
                    category="unmapped",
                    element="annotation",
                    identifier=origin,
                    detail=f"annotation {name} labels are not a string or list",
                )
            )
            return None

        values: list[str] = []
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate.strip():
                unmapped.append(
                    ProjectionIssue(
                        category="unmapped",
                        element="annotation",
                        identifier=origin,
                        detail=f"annotation {name} label is not a non-empty string",
                    )
                )
                return None
            values.append(candidate.strip())
        groups.append(tuple(dict.fromkeys(values)))

    if not groups:
        return ()
    if any(group != groups[0] for group in groups[1:]):
        ambiguous.append(
            ProjectionIssue(
                category="ambiguous",
                element="annotation",
                identifier=origin,
                detail=f"annotation has conflicting {name} keys",
                choices=tuple(sorted(set().union(*groups))),
            )
        )
        return None
    return groups[0]


def _declared_atoms(facts_by_key: dict[str, Fact], type_name: str) -> frozenset[str]:
    atoms: set[str] = set()
    for fact in facts_by_key.values():
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        identifier, declared_type = fact.args
        if (
            isinstance(identifier, Atom)
            and isinstance(identifier.value, str)
            and isinstance(declared_type, Atom)
            and declared_type.value == type_name
        ):
            atoms.add(identifier.value)
    return frozenset(atoms)


def _declared_input_fields(facts_by_key: dict[str, Fact]) -> tuple[Struct, ...]:
    fields: list[Struct] = []
    for fact in facts_by_key.values():
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        term, declared_type = fact.args
        if (
            isinstance(term, Struct)
            and term.name == "input_field"
            and len(term.args) == 2
            and isinstance(declared_type, Atom)
            and declared_type.value == "InputField"
        ):
            fields.append(term)
    return tuple(fields)


def _canonical_action(action: str, actions: frozenset[str]) -> str | None:
    if action in actions:
        return action
    prefixed = f"action:{action}"
    return prefixed if prefixed in actions else None


def _sorted_mapped(items: list[MappedElement]) -> tuple[MappedElement, ...]:
    return tuple(
        sorted(items, key=lambda item: (item.kind, item.logical_id, item.predicates))
    )


def _sorted_issues(items: list[ProjectionIssue]) -> tuple[ProjectionIssue, ...]:
    unique: dict[tuple[str, str, str, str, tuple[str, ...]], ProjectionIssue] = {}
    for item in items:
        key = (
            item.category,
            item.element,
            item.identifier,
            item.detail,
            item.choices,
        )
        unique[key] = item
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.element,
                item.identifier,
                item.detail,
                item.choices,
            ),
        )
    )


__all__ = [
    "ClassificationProfile",
    "Result",
    "ContractProjector",
    "EXTENSION_PREDICATE_SCHEMAS",
    "MappedElement",
    "ProjectionIssue",
    "ProjectionReport",
]
