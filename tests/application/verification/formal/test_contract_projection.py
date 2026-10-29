from __future__ import annotations

import pytest
from pydantic import ValidationError

from cloud_dast.ports import (
    GraphEdge,
    GraphNode,
    ServiceGraphSlice,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    input_field,
)
from cloud_dast.runtime.payload_hints import (
    compile_payload_hints,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
    ClassificationProfile,
    ContractProjector,
)

_EXTENSION_PREDICATES = {
    schema.name: Predicate.from_schema(schema) for schema in EXTENSION_PREDICATE_SCHEMAS
}
_BUILTIN_PREDICATES = {
    name: Predicate.from_name(name)
    for name in (
        "is",
        "part",
        "requires",
        "targets",
        "grants",
        "applies_to",
        "has",
        "reaches",
    )
}


def qfact(name: str, *args: object) -> Fact:
    predicate = _BUILTIN_PREDICATES.get(name) or _EXTENSION_PREDICATES[name]
    return Fact(
        context=Context.CONTRACT,
        predicate=predicate,
        args=tuple(args),  # type: ignore[arg-type]
    )


def graph_edge(
    edge_id: str,
    source_id: str,
    target_id: str,
    kind: str,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        source_id=source_id,
        target_id=target_id,
        kind=kind,
    )


def make_graph_slice() -> ServiceGraphSlice:
    nodes = (
        GraphNode(
            node_id="4:service:0",
            labels=("Service",),
            properties={"canonical_id": "catalog"},
        ),
        GraphNode(
            node_id="4:api:1",
            labels=("ApiSurface",),
            properties={"package": "catalog.v1"},
        ),
        GraphNode(
            node_id="4:method:2",
            labels=("Method",),
            properties={
                "method_id": "grpc:catalog.v1.Catalog.Get",
                "input_fields": (
                    {
                        "name": "limit",
                        "type": "int32",
                        "required": True,
                        "repeated": True,
                        "minimum": 1,
                        "maximum": 100,
                    },
                    {
                        "name": "mode",
                        "type": "string",
                        "required": False,
                        "oneof": "selector",
                        "enum_values": ("auto", "manual"),
                    },
                ),
            },
        ),
        GraphNode(
            node_id="4:param:3",
            labels=("Param",),
            properties={
                "key": "resource_id",
                "type": "string",
                "required": True,
            },
        ),
        GraphNode(
            node_id="4:permission:4",
            labels=("Permission",),
            properties={"permission_id": "catalog.read"},
        ),
        GraphNode(
            node_id="4:resource:5",
            labels=("ResourceType",),
            properties={"resource_type": "catalog.item"},
        ),
        GraphNode(
            node_id="4:resource:6",
            labels=("ResourceType",),
            properties={"resource_type": "catalog.folder"},
        ),
        GraphNode(
            node_id="4:role:7",
            labels=("Role",),
            properties={"role_id": "viewer"},
        ),
        GraphNode(
            node_id="4:endpoint:8",
            labels=("Endpoint",),
            properties={"endpoint_id": "gateway"},
        ),
        GraphNode(
            node_id="4:alias:9",
            labels=("Alias",),
            properties={"alias": "catalog-api"},
        ),
        GraphNode(
            node_id="4:doc:10",
            labels=("DocPage",),
            properties={"page_id": "catalog-docs"},
        ),
        GraphNode(
            node_id="4:source:11",
            labels=("Source",),
            properties={"path": "catalog.proto"},
        ),
    )
    edges = (
        graph_edge("5:exposes:0", "4:api:1", "4:service:0", "EXPOSES"),
        graph_edge("5:method:1", "4:method:2", "4:api:1", "HAS_METHOD"),
        graph_edge("5:param:2", "4:method:2", "4:param:3", "HAS_PARAM"),
        graph_edge("5:requires:3", "4:method:2", "4:permission:4", "REQUIRES"),
        graph_edge("5:targets:4", "4:method:2", "4:resource:5", "TARGETS"),
        graph_edge("5:parent:5", "4:resource:6", "4:resource:5", "PARENT_OF"),
        graph_edge("5:owns:6", "4:service:0", "4:resource:5", "OWNS"),
        graph_edge("5:applies:7", "4:permission:4", "4:resource:5", "APPLIES_TO"),
        graph_edge("5:serves:8", "4:endpoint:8", "4:api:1", "SERVES"),
        graph_edge("5:known:9", "4:service:0", "4:alias:9", "KNOWN_AS"),
        graph_edge("5:describes:10", "4:doc:10", "4:service:0", "DESCRIBES"),
        graph_edge("5:defined:11", "4:method:2", "4:source:11", "DEFINED_IN"),
        graph_edge("5:refers:12", "4:param:3", "4:resource:5", "REFERS_TO"),
        graph_edge("5:grants:13", "4:role:7", "4:permission:4", "GRANTS"),
    )
    return ServiceGraphSlice(
        service="catalog",
        nodes=nodes,
        edges=edges,
    )


def test_golden_projection() -> None:
    projection = ContractProjector().project(make_graph_slice())

    service = Atom(value="service:catalog")
    api = Atom(value="api:catalog.v1")
    action = Atom(value="action:grpc:catalog.v1.Catalog.Get")
    permission = Atom(value="permission:catalog.read")
    item = Atom(value="resource:catalog.item")
    folder = Atom(value="resource:catalog.folder")
    role = Atom(value="role:viewer")
    endpoint = Atom(value="endpoint:gateway")
    alias = Atom(value="alias:catalog-api")
    doc_page = Atom(value="doc_page:catalog-docs")
    source = Atom(value="source:catalog.proto")

    resource_id = input_field(action, Atom(value="resource_id"))
    limit = input_field(action, Atom(value="limit"))
    mode = input_field(action, Atom(value="mode"))

    expected = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", api, Atom(value="ApiSurface")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", permission, Atom(value="Permission")),
            qfact("is", item, Atom(value="ResourceType")),
            qfact("is", folder, Atom(value="ResourceType")),
            qfact("is", role, Atom(value="Role")),
            qfact("is", endpoint, Atom(value="Endpoint")),
            qfact("is", alias, Atom(value="Alias")),
            qfact("is", doc_page, Atom(value="DocPage")),
            qfact("is", source, Atom(value="Source")),
            qfact("is", resource_id, Atom(value="InputField")),
            qfact("is", limit, Atom(value="InputField")),
            qfact("is", mode, Atom(value="InputField")),
            qfact("part", api, service),
            qfact("part", action, api),
            qfact("part", resource_id, action),
            qfact("part", limit, action),
            qfact("part", mode, action),
            qfact("part", item, folder),
            qfact("part", item, service),
            qfact("part", action, source),
            qfact("requires", action, permission),
            qfact("targets", action, item),
            qfact("applies_to", permission, item),
            qfact("serves", endpoint, api),
            qfact("known_as", service, alias),
            qfact("describes", doc_page, service),
            qfact("refers_to", resource_id, item),
            qfact("grants", role, permission),
            qfact("field_type", resource_id, Atom(value="string")),
            qfact("field_type", limit, Atom(value="int32")),
            qfact("field_type", mode, Atom(value="string")),
            qfact("field_required", resource_id, Atom(value=True)),
            qfact("field_required", limit, Atom(value=True)),
            qfact("field_required", mode, Atom(value=False)),
            qfact("field_repeated", resource_id, Atom(value=False)),
            qfact("field_repeated", limit, Atom(value=True)),
            qfact("field_repeated", mode, Atom(value=False)),
            qfact("field_oneof", mode, Atom(value="selector")),
            qfact("field_enum_value", mode, Atom(value="auto")),
            qfact("field_enum_value", mode, Atom(value="manual")),
            qfact("field_minimum", limit, Atom(value=1)),
            qfact("field_maximum", limit, Atom(value=100)),
        )
    )

    assert projection.graph == expected
    assert projection.canonical_hash == expected.content_hash
    assert not projection.report.unmapped
    assert not projection.report.ambiguous
    assert not projection.report.conflict
    field_predicates = {
        predicate
        for element in projection.report.mapped
        if element.kind == "field"
        for predicate in element.predicates
    }
    assert field_predicates == {
        "field_enum_value",
        "field_maximum",
        "field_minimum",
        "field_oneof",
        "field_repeated",
        "field_required",
        "field_type",
        "is",
        "part",
    }
    assert {element.predicates for element in projection.report.mapped} >= {
        ("is",),
        ("part",),
        ("requires",),
        ("targets",),
    }
    rendered = projection.model_dump_json()
    assert "4:service:0" not in rendered
    assert "5:exposes:0" not in rendered


def test_projection_is_independent_of_node_and_edge_order() -> None:
    slice_ = make_graph_slice()
    reordered = slice_.model_copy(
        update={
            "nodes": tuple(reversed(slice_.nodes)),
            "edges": tuple(reversed(slice_.edges)),
        }
    )

    first = ContractProjector().project(slice_)
    second = ContractProjector().project(reordered)

    assert first == second
    assert first.canonical_hash == second.canonical_hash


def test_unmapped_node_and_edge_are_reported() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="4:service:0",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="4:unknown:1",
                labels=("Queue",),
                properties={"queue_id": "unknown"},
            ),
        ),
        edges=(
            GraphEdge(
                edge_id="5:unknown:0",
                source_id="4:service:0",
                target_id="4:unknown:1",
                kind="UNKNOWN_RELATION",
            ),
        ),
    )

    projection = ContractProjector().project(slice_)

    assert {issue.element for issue in projection.report.unmapped} == {"node", "edge"}
    assert any(
        issue.detail == "edge kind has no QDL mapping"
        for issue in projection.report.unmapped
    )
    assert "4:unknown:1" not in projection.report.model_dump_json()
    assert "5:unknown:0" not in projection.report.model_dump_json()


def test_ambiguous_node_is_reported() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="4:ambiguous:0",
                labels=("Service", "Method"),
                properties={
                    "canonical_id": "catalog",
                    "method_id": "grpc:catalog.Get",
                },
            ),
        ),
    )

    projection = ContractProjector().project(slice_)

    assert len(projection.report.ambiguous) == 1
    assert projection.report.ambiguous[0].element == "node"
    assert projection.report.ambiguous[0].choices == ("Service", "Method")
    assert projection.graph.facts == ()


def test_conflicting_field_metadata_is_reported() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="4:method:0",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {"name": "limit", "type": "int32", "required": True},
                    ),
                },
            ),
            GraphNode(
                node_id="4:param:1",
                labels=("Param",),
                properties={
                    "key": "limit",
                    "type": "string",
                    "required": True,
                },
            ),
        ),
        edges=(
            GraphEdge(
                edge_id="5:param:0",
                source_id="4:method:0",
                target_id="4:param:1",
                kind="HAS_PARAM",
            ),
        ),
    )

    projection = ContractProjector().project(slice_)

    assert len(projection.report.conflict) == 1
    issue = projection.report.conflict[0]
    assert issue.element == "field"
    assert issue.detail == "field type has conflicting values"
    field_types = [
        fact for fact in projection.graph.facts if fact.predicate.name == "field_type"
    ]
    assert field_types == []


def test_nested_input_fields_do_not_collapse() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="4:method:0",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {
                            "name": "request",
                            "type": "message",
                            "required": True,
                            "fields": (
                                {
                                    "name": "user",
                                    "type": "message",
                                    "required": True,
                                    "fields": ({"name": "role", "type": "string"},),
                                },
                            ),
                        },
                        {"name": "role", "type": "string"},
                    ),
                },
            ),
        ),
    )

    projection = ContractProjector().project(slice_)

    action = Atom(value="action:grpc:catalog.Get")
    nested = input_field(action, Atom(value="request.user.role"))
    flat = input_field(action, Atom(value="role"))
    nested_ids = {
        canonical_json(fact.args[0])
        for fact in projection.graph.facts
        if fact.predicate.name == "field_type"
    }

    assert canonical_json(nested) in nested_ids
    assert canonical_json(flat) in nested_ids
    assert canonical_json(nested) != canonical_json(flat)


def test_doc_page_classification_projects_source_semantics() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="service:catalog",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="method:get",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {"name": "secret_id", "type": "string", "required": True},
                    ),
                },
            ),
            GraphNode(
                node_id="doc:catalog",
                labels=("DocPage",),
                properties={
                    "page_id": "catalog-docs",
                    "data_classification": {
                        "fields": (
                            {
                                "action": "grpc:catalog.Get",
                                "field": "secret_id",
                                "classification": "secret",
                                "sink": "sql",
                            },
                        ),
                    },
                },
            ),
        ),
        edges=(
            graph_edge(
                "edge:method",
                "service:catalog",
                "method:get",
                "EXPOSES_METHOD",
            ),
            graph_edge(
                "edge:describes",
                "doc:catalog",
                "service:catalog",
                "DESCRIBES",
            ),
        ),
    )
    profile = ClassificationProfile(
        roles={"secret": ("sensitive",)},
        sink_types={"sql": ("interpreter",)},
    )

    projection = ContractProjector(profile).project(slice_)

    action = Atom(value="action:grpc:catalog.Get")
    field = input_field(action, Atom(value="secret_id"))
    sink = Atom(value="sink:action:grpc:catalog.Get:secret_id:interpreter")
    expected = {
        qfact("has", field, Atom(value="sensitive")),
        qfact("is", sink, Atom(value="interpreter")),
        qfact("reaches", field, sink),
    }
    assert expected.issubset(set(projection.graph.facts))
    assert all(fact.context is Context.CONTRACT for fact in expected)
    assert not projection.report.unmapped
    assert not projection.report.ambiguous
    assert not projection.report.conflict
    annotation = next(
        element for element in projection.report.mapped if element.kind == "annotation"
    )
    assert annotation.logical_id == canonical_json(field)
    assert annotation.predicates == ("has", "is", "reaches")
    assert compile_payload_hints(projection.graph) == {
        "action:grpc:catalog.Get": ("secret_id",)
    }


def test_describes_edge_classification_projects_source_semantics() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="service:catalog",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="method:get",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {"name": "path", "type": "string", "required": True},
                    ),
                },
            ),
            GraphNode(
                node_id="doc:catalog",
                labels=("DocPage",),
                properties={"page_id": "catalog-docs"},
            ),
        ),
        edges=(
            graph_edge(
                "edge:method",
                "service:catalog",
                "method:get",
                "EXPOSES_METHOD",
            ),
            GraphEdge(
                edge_id="edge:describes",
                source_id="doc:catalog",
                target_id="service:catalog",
                kind="DESCRIBES",
                properties={
                    "data_classification": (
                        {
                            "action": "action:grpc:catalog.Get",
                            "field": "path",
                            "sink_type": "file",
                        },
                    ),
                },
            ),
        ),
    )
    profile = ClassificationProfile(sink_types={"file": ("filesystem",)})

    projection = ContractProjector(profile).project(slice_)

    action = Atom(value="action:grpc:catalog.Get")
    field = input_field(action, Atom(value="path"))
    sink = Atom(value="sink:action:grpc:catalog.Get:path:filesystem")
    assert qfact("is", sink, Atom(value="filesystem")) in projection.graph.facts
    assert qfact("reaches", field, sink) in projection.graph.facts
    assert not projection.report.unmapped


def test_unmapped_source_labels_are_reported_without_facts() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="service:catalog",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="method:get",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {"name": "value", "type": "string", "required": True},
                    ),
                },
            ),
            GraphNode(
                node_id="doc:catalog",
                labels=("DocPage",),
                properties={
                    "page_id": "catalog-docs",
                    "data_classification": (
                        {
                            "action": "grpc:catalog.Get",
                            "field": "value",
                            "classification": "unknown-classification",
                            "sink": "unknown-sink",
                        },
                    ),
                },
            ),
        ),
        edges=(
            graph_edge(
                "edge:method",
                "service:catalog",
                "method:get",
                "EXPOSES_METHOD",
            ),
            graph_edge(
                "edge:describes",
                "doc:catalog",
                "service:catalog",
                "DESCRIBES",
            ),
        ),
    )

    projection = ContractProjector(ClassificationProfile()).project(slice_)

    issues = [
        issue for issue in projection.report.unmapped if issue.element == "annotation"
    ]
    assert {issue.detail for issue in issues} == {
        "source classification labels are not mapped",
        "source sink labels are not mapped",
    }
    assert {issue.choices for issue in issues} == {
        ("unknown-classification",),
        ("unknown-sink",),
    }
    assert not [fact for fact in projection.graph.facts if fact.predicate.name == "has"]
    assert not [
        fact for fact in projection.graph.facts if fact.predicate.name == "reaches"
    ]


def test_classification_action_and_field_must_be_declared() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="service:catalog",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="method:get",
                labels=("Method",),
                properties={
                    "method_id": "grpc:catalog.Get",
                    "input_fields": (
                        {"name": "value", "type": "string", "required": True},
                    ),
                },
            ),
            GraphNode(
                node_id="doc:catalog",
                labels=("DocPage",),
                properties={
                    "page_id": "catalog-docs",
                    "data_classification": (
                        {
                            "action": "grpc:catalog.Unknown",
                            "field": "value",
                            "classification": "secret",
                        },
                        {
                            "action": "grpc:catalog.Get",
                            "field": "missing",
                            "classification": "secret",
                        },
                    ),
                },
            ),
        ),
        edges=(
            graph_edge(
                "edge:method",
                "service:catalog",
                "method:get",
                "EXPOSES_METHOD",
            ),
            graph_edge(
                "edge:describes",
                "doc:catalog",
                "service:catalog",
                "DESCRIBES",
            ),
        ),
    )
    profile = ClassificationProfile(roles={"secret": ("sensitive",)})

    projection = ContractProjector(profile).project(slice_)

    details = {
        issue.detail
        for issue in projection.report.unmapped
        if issue.element == "annotation"
    }
    assert details == {
        "annotation action is not declared by the contract graph",
        "annotation field is not declared by the contract graph",
    }
    assert not [fact for fact in projection.graph.facts if fact.predicate.name == "has"]


def test_doc_page_without_describes_is_not_a_classification_source() -> None:
    slice_ = ServiceGraphSlice(
        service="catalog",
        nodes=(
            GraphNode(
                node_id="service:catalog",
                labels=("Service",),
                properties={"canonical_id": "catalog"},
            ),
            GraphNode(
                node_id="doc:unrelated",
                labels=("DocPage",),
                properties={
                    "page_id": "unrelated-docs",
                    "data_classification": (
                        {
                            "action": "grpc:catalog.Get",
                            "field": "value",
                            "classification": "secret",
                        },
                    ),
                },
            ),
        ),
    )

    projection = ContractProjector(
        ClassificationProfile(roles={"secret": ("sensitive",)})
    ).project(slice_)

    assert not [fact for fact in projection.graph.facts if fact.predicate.name == "has"]
    assert not [
        issue for issue in projection.report.unmapped if issue.element == "annotation"
    ]


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (
            {"roles": {"secret": ["unknown-role"]}},
            "unknown semantic roles: unknown-role",
        ),
        (
            {"sink_types": {"sql": ["database"]}},
            "unknown sink types: database",
        ),
        (
            {"roles": {"secret": ["sensitive", "sensitive"]}},
            "roles label 'secret' has duplicate targets",
        ),
    ),
)
def test_classification_profile_rejects_invalid_targets(
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ClassificationProfile.model_validate(payload)
