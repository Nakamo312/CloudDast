from __future__ import annotations

import hashlib

import pytest

protobuf = pytest.importorskip("google.protobuf")

from google.protobuf import descriptor_pb2
from google.protobuf.message_factory import GetMessageClass

from cloud_dast.config import (
    RESPONSE_TREE_MAX_DEPTH,
    RESPONSE_TREE_MAX_LEAVES,
)
from cloud_dast.infrastructure.runtime import DescriptorRegistry, ProtobufPayloadCodec


def descriptor_set() -> bytes:
    file = descriptor_pb2.FileDescriptorProto(
        name="sample.proto",
        package="sample",
        syntax="proto3",
    )
    request = file.message_type.add(name="Request")
    field = request.field.add(name="resource_id", number=1)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    response = file.message_type.add(name="Response")
    field = response.field.add(name="resource_id", number=1)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    field = response.field.add(name="secret", number=2)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
    status_enum = file.enum_type.add(name="Status")
    status_enum.value.add(name="STATUS_UNKNOWN", number=0)
    status_enum.value.add(name="STATUS_ACTIVE", number=1)
    field = response.field.add(name="status", number=3)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_ENUM
    field.type_name = ".sample.Status"
    field = response.field.add(name="ratio", number=4)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT
    field = response.field.add(name="tags", number=5)
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    nested = file.message_type.add(name="Nested")
    field = nested.field.add(name="resource_id", number=1)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    wrapper = file.message_type.add(name="Wrapper")
    field = wrapper.field.add(name="payload", number=1)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field.type_name = ".sample.Nested"
    field = wrapper.field.add(name="deltas", number=2)
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field.type_name = ".sample.Nested"
    tree = file.message_type.add(name="Tree")
    field = tree.field.add(name="name", number=1)
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    field = tree.field.add(name="children", number=2)
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
    field.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field.type_name = ".sample.Tree"
    files = descriptor_pb2.FileDescriptorSet()
    files.file.append(file)
    return files.SerializeToString()


def varint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def field_key(field_number: int, wire_type: int) -> bytes:
    return varint((field_number << 3) | wire_type)


def test_descriptor_registry_resolves_full_and_short_names() -> None:
    registry = DescriptorRegistry(descriptor_set())
    assert registry.descriptor("sample.Request").full_name == "sample.Request"
    assert registry.descriptor("Request").full_name == "sample.Request"


def test_descriptor_registry_projects_canonical_request_schema() -> None:
    registry = DescriptorRegistry(descriptor_set())

    schema = registry.request_schema("sample.Response")

    assert schema.type_name == "sample.Response"
    assert tuple(field.name for field in schema.fields) == (
        "ratio",
        "resource_id",
        "secret",
        "status",
        "tags",
    )
    assert schema.fields[0].type == "float"
    assert schema.fields[0].minimum == pytest.approx(-3.4028234663852886e38)
    assert schema.fields[0].maximum == pytest.approx(3.4028234663852886e38)
    assert schema.fields[3].enum_values == ("STATUS_UNKNOWN", "STATUS_ACTIVE")
    assert schema.fields[4].repeated is True


def test_descriptor_registry_projects_nested_response_schema() -> None:
    registry = DescriptorRegistry(descriptor_set())

    schema = registry.response_schema("sample.Wrapper")

    assert schema.type_name == "sample.Wrapper"
    assert tuple(field.name for field in schema.fields) == (
        "deltas",
        "deltas.resource_id",
        "payload",
        "payload.resource_id",
    )
    assert schema.fields[0].type == "sample.Nested"
    assert schema.fields[0].repeated is True
    assert schema.fields[1].type == "string"


def test_codec_round_trips_and_filters_unsafe_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry, safe_fields=("resource_id", "secret"))
    encoded = codec.encode("sample.Request", {"resource_id": "secret-1"})
    request = GetMessageClass(registry.descriptor("sample.Request"))()
    request.ParseFromString(encoded)
    assert request.resource_id == "secret-1"

    response = GetMessageClass(registry.descriptor("sample.Response"))(
        resource_id="secret-1",
        secret=b"sensitive",
    )
    output = codec.decode("sample.Response", response.SerializeToString())
    assert output.fields == (("resource_id", "secret-1"),)


def test_codec_expands_dotted_repeated_paths() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)

    encoded = codec.encode(
        "sample.Wrapper",
        {
            "deltas": (None,),
            "deltas.resource_id": "secret-1",
        },
    )

    wrapper = GetMessageClass(registry.descriptor("sample.Wrapper"))()
    wrapper.ParseFromString(encoded)
    assert len(wrapper.deltas) == 1
    assert wrapper.deltas[0].resource_id == "secret-1"


def test_codec_rejects_unknown_request_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)

    with pytest.raises(ValueError, match="private_call"):
        codec.encode("sample.Wrapper", {"private_call": True})


def test_codec_rejects_unknown_nested_request_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)

    with pytest.raises(ValueError, match="payload.extra_field"):
        codec.encode("sample.Wrapper", {"payload": {"extra_field": True}})


def test_codec_allows_explicit_nested_scalar_paths() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry, safe_fields=("payload.resource_id",))
    response = GetMessageClass(registry.descriptor("sample.Wrapper"))(
        payload={"resource_id": "secret-1"}
    )
    output = codec.decode("sample.Wrapper", response.SerializeToString())
    assert output.fields == (("payload.resource_id", "secret-1"),)


def test_decode_collects_nested_and_repeated_field_names() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry, safe_fields=("payload.resource_id",))
    response = GetMessageClass(registry.descriptor("sample.Wrapper"))(
        payload={"resource_id": "secret-1"},
        deltas=[{"resource_id": "secret-2"}],
    )

    output = codec.decode("sample.Wrapper", response.SerializeToString())

    assert output.fields == (("payload.resource_id", "secret-1"),)
    assert output.field_names == (
        "deltas",
        "deltas.resource_id",
        "payload",
        "payload.resource_id",
    )


def test_codec_rejects_safe_paths_absent_from_every_descriptor() -> None:
    registry = DescriptorRegistry(descriptor_set())

    with pytest.raises(
        ValueError, match="safe response field paths.*any protobuf.*missing"
    ):
        ProtobufPayloadCodec(registry, safe_fields=("resource_id", "missing"))


def test_decode_projects_subset_of_global_safe_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(
        registry,
        safe_fields=("resource_id", "payload.resource_id", "status", "ratio"),
    )
    response = GetMessageClass(registry.descriptor("sample.Response"))(
        resource_id="secret-1",
        status=1,
        ratio=1.5,
    )

    output = codec.decode("sample.Response", response.SerializeToString())

    assert output.fields == (
        ("ratio", 1.5),
        ("resource_id", "secret-1"),
        ("status", 1),
    )


def test_decode_skips_safe_field_valid_only_in_another_response() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(
        registry,
        safe_fields=("payload.resource_id",),
    )
    response = GetMessageClass(registry.descriptor("sample.Response"))(
        resource_id="secret-1"
    )

    output = codec.decode("sample.Response", response.SerializeToString())

    assert output.fields == ()


def test_decode_field_names_cut_recursive_message_cycles() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response = GetMessageClass(registry.descriptor("sample.Tree"))(
        name="root",
        children=[{"name": "leaf"}],
    )

    output = codec.decode("sample.Tree", response.SerializeToString())

    assert output.field_names == (
        "children",
        "children.children",
        "children.name",
        "name",
    )


def test_codec_keeps_explicit_proto3_scalar_defaults() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry, safe_fields=("resource_id",))
    response = GetMessageClass(registry.descriptor("sample.Response"))()

    output = codec.decode("sample.Response", response.SerializeToString())

    assert output.fields == (("resource_id", ""),)


def test_decode_full_returns_nested_repeated_and_default_leaves() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response = GetMessageClass(registry.descriptor("sample.Wrapper"))(
        payload={"resource_id": "secret-1"},
        deltas=[{"resource_id": "delta-a"}, {"resource_id": "delta-b"}],
    )

    tree = codec.decode_full("sample.Wrapper", response.SerializeToString())

    assert tree == (
        ("deltas.0.resource_id", "delta-a"),
        ("deltas.1.resource_id", "delta-b"),
        ("payload.resource_id", "secret-1"),
    )


def test_decode_full_ignores_safe_field_allowlist() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(
        registry,
        safe_fields=("resource_id", "payload.resource_id"),
    )
    full_codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    response = response_class(
        resource_id="resource-1",
        secret=b"sensitive",
        status=1,
        ratio=1.5,
        tags=["safe", "secret"],
    )
    response.ParseFromString(
        response.SerializeToString() + field_key(99, 0) + varint(7)
    )

    tree = codec.decode_full("sample.Response", response.SerializeToString())

    assert tree == full_codec.decode_full(
        "sample.Response", response.SerializeToString()
    )
    assert ("secret", "sensitive") in tree
    assert ("status", "STATUS_ACTIVE") in tree
    assert ("tags.0", "safe") in tree
    assert ("tags.1", "secret") in tree
    assert ("__unknown__.99.0", 7) in tree


def test_decode_full_retains_unknown_response_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    varint_unknown = field_key(99, 0) + varint(7)
    string_unknown = (
        field_key(98, 2) + varint(len(b"drifted-schema")) + b"drifted-schema"
    )
    response = response_class()
    response.ParseFromString(varint_unknown + string_unknown)

    tree = codec.decode_full("sample.Response", response.SerializeToString())

    assert ("__unknown__.98.0", "drifted-schema") in tree
    assert ("__unknown__.99.0", 7) in tree


def test_decode_full_retains_unknown_nested_response_fields() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    nested_class = GetMessageClass(registry.descriptor("sample.Nested"))
    wrapper_class = GetMessageClass(registry.descriptor("sample.Wrapper"))
    nested = nested_class()
    nested.ParseFromString(field_key(99, 0) + varint(7))
    wrapper = wrapper_class(payload=nested)

    tree = codec.decode_full("sample.Wrapper", wrapper.SerializeToString())

    assert ("payload.__unknown__.99.0", 7) in tree


def test_decode_full_keeps_utf8_bytes_and_hashes_binary_bytes() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    utf8 = response_class(resource_id="r", secret=b"sensitive")
    binary = response_class(secret=b"\xff\x00\xfe")

    utf8_tree = codec.decode_full("sample.Response", utf8.SerializeToString())
    binary_tree = codec.decode_full("sample.Response", binary.SerializeToString())

    assert ("secret", "sensitive") in utf8_tree
    assert ("secret", f"sha256:{hashlib.sha256(b'\xff\x00\xfe').hexdigest()}") in (
        binary_tree
    )


def test_decode_full_uses_enum_names_and_unknown_numbers() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    named = response_class(status=1)
    unknown = response_class(status=99)

    named_tree = codec.decode_full("sample.Response", named.SerializeToString())
    unknown_tree = codec.decode_full("sample.Response", unknown.SerializeToString())

    assert ("status", "STATUS_ACTIVE") in named_tree
    assert ("status", 99) in unknown_tree


def test_decode_full_normalizes_non_finite_floats() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    response = response_class(ratio=float("inf"))

    tree = codec.decode_full("sample.Response", response.SerializeToString())

    assert ("ratio", "Infinity") in tree


def test_decode_full_caps_exponential_leaf_cardinality() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    response_class = GetMessageClass(registry.descriptor("sample.Response"))
    response = response_class(
        tags=[f"tag-{index}" for index in range(RESPONSE_TREE_MAX_LEAVES + 1)]
    )

    tree = codec.decode_full("sample.Response", response.SerializeToString())

    assert len(tree) == RESPONSE_TREE_MAX_LEAVES + 1
    assert ("tags.0", "tag-0") in tree
    schema_leaf_count = sum(
        path != "__truncated__" and not path.startswith("tags.") for path, _ in tree
    )
    last_leaf = RESPONSE_TREE_MAX_LEAVES - schema_leaf_count - 1
    assert (f"tags.{last_leaf}", f"tag-{last_leaf}") in tree
    assert (f"tags.{last_leaf + 1}", f"tag-{last_leaf + 1}") not in tree
    assert tree[-1] == ("__truncated__", True)


def test_decode_full_caps_recursive_message_depth() -> None:
    registry = DescriptorRegistry(descriptor_set())
    codec = ProtobufPayloadCodec(registry)
    tree_class = GetMessageClass(registry.descriptor("sample.Tree"))
    root = tree_class(name="level-0")
    current = root
    for level in range(1, RESPONSE_TREE_MAX_DEPTH + 6):
        current = current.children.add()
        current.name = f"level-{level}"

    tree = codec.decode_full("sample.Tree", root.SerializeToString())

    deepest_level = RESPONSE_TREE_MAX_DEPTH - 1
    deepest = ".".join(["children.0"] * deepest_level + ["name"])
    assert (deepest, f"level-{deepest_level}") in tree
    assert tree[-1] == ("__truncated__", True)
    assert len(tree) == RESPONSE_TREE_MAX_DEPTH + 1
