"""Descriptor-set backed protobuf codec for live gRPC execution."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from cloud_dast.config import RESPONSE_TREE_MAX_DEPTH, RESPONSE_TREE_MAX_LEAVES
from cloud_dast.model import (
    FieldSpec,
    JsonValue,
    RequestSchema,
    ResponseData,
    ResponseSchema,
)
from cloud_dast.model.schemas import float_range, integer_range

_RESPONSE_TREE_TRUNCATED = "__truncated__"
"""Synthetic leaf path emitted when the response tree budget is exhausted."""

_UNKNOWN_FIELD_PREFIX = "__unknown__"
_WIRE_TYPE_VARINT = 0
_WIRE_TYPE_FIXED64 = 1
_WIRE_TYPE_LENGTH_DELIMITED = 2
_WIRE_TYPE_START_GROUP = 3
_WIRE_TYPE_END_GROUP = 4
_WIRE_TYPE_FIXED32 = 5


class CodecError(ValueError):
    """A descriptor mismatch whose reason is safe to retain as evidence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.safe_reason = reason


class DescriptorRegistry:
    """Resolve protobuf message names from a serialized descriptor set."""

    def __init__(
        self,
        source: str | Path | bytes | None = None,
        *,
        environment_variable: str = "CLOUD_DAST_DESCRIPTOR_SET",
    ) -> None:
        descriptor_pb2, descriptor_pool = _load_modules()
        if source is None:
            import os

            source = os.environ.get(environment_variable, "").strip()
            if not source:
                raise RuntimeError(
                    f"descriptor set is not configured; set {environment_variable}"
                )
        if isinstance(source, (str, Path)):
            data = Path(source).read_bytes()
        else:
            data = source
        files = descriptor_pb2.FileDescriptorSet()
        files.ParseFromString(data)
        self._pool = descriptor_pool.DescriptorPool()
        self._message_names: tuple[str, ...] = ()
        self._load_files(files.file)
        names: list[str] = []
        for file in files.file:
            prefix = f"{file.package}." if file.package else ""
            names.extend(_message_names(file.message_type, prefix))
        self._message_names = tuple(names)

    @classmethod
    def from_environment(
        cls, variable: str = "CLOUD_DAST_DESCRIPTOR_SET"
    ) -> DescriptorRegistry:
        return cls(environment_variable=variable)

    def descriptor(self, name: str) -> Any:
        normalized = name.lstrip(".")
        try:
            return self._pool.FindMessageTypeByName(normalized)
        except KeyError:
            if "." in normalized:
                raise ValueError(f"protobuf message is not in descriptor set: {name}")
            matches = [
                self._pool.FindMessageTypeByName(name)
                for name in self._message_names
                if name.rsplit(".", 1)[-1] == normalized
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"protobuf message name is ambiguous or missing: {name}"
                )
            return matches[0]

    def message_class(self, name: str) -> type[Any]:
        from google.protobuf.message_factory import GetMessageClass

        return GetMessageClass(self.descriptor(name))

    def descriptors(self) -> Iterable[Any]:
        for name in self._message_names:
            yield self.descriptor(name)

    def request_schema(self, name: str) -> RequestSchema:
        """Project one protobuf message into the canonical request schema."""

        descriptor = self.descriptor(name)
        return RequestSchema(
            type_name=descriptor.full_name,
            fields=_descriptor_schema_fields(descriptor),
        )

    def response_schema(self, name: str) -> ResponseSchema:
        """Project one protobuf message into the canonical response schema."""

        descriptor = self.descriptor(name)
        return ResponseSchema(
            type_name=descriptor.full_name,
            fields=_descriptor_schema_fields(descriptor),
        )

    def _load_files(self, files: Iterable[Any]) -> None:
        pending = [item.SerializeToString() for item in files]
        while pending:
            remaining: list[bytes] = []
            loaded = False
            for serialized in pending:
                try:
                    self._pool.AddSerializedFile(serialized)
                except (KeyError, TypeError) as exc:
                    # Some Yandex descriptor snapshots contain a duplicate
                    # extension file.  The first copy is already in the pool;
                    # it is safe to skip this redundant file.
                    if "duplicate extension entry" in str(exc):
                        continue
                    remaining.append(serialized)
                else:
                    loaded = True
            if not loaded:
                raise ValueError("descriptor set has unresolved file dependencies")
            pending = remaining


class ProtobufPayloadCodec:
    """Encode requests and decode responses into safe and full views.

    ``decode`` projects only explicitly safe scalar response fields for
    workflow dataflow forwarding.  ``decode_full`` retains the complete
    decoded response tree as evidence: the engine runs against isolated
    application copies, so full response retention is the default.

    ``safe_fields`` is a registry-wide allowlist.  It is validated once at
    construction, while each decoded message projects only the entries that
    its own descriptor declares.
    """

    def __init__(
        self,
        registry: DescriptorRegistry,
        *,
        safe_fields: Iterable[str] = (),
    ) -> None:
        self._registry = registry
        self._safe_fields = frozenset(safe_fields)
        unresolved_fields = set(self._safe_fields)
        for descriptor in registry.descriptors():
            unresolved_fields = {
                path
                for path in unresolved_fields
                if _field_at_path(descriptor, path) is None
            }
            if not unresolved_fields:
                break
        if unresolved_fields:
            raise CodecError(
                "safe response field paths are not declared by any protobuf "
                f"descriptor: {', '.join(sorted(unresolved_fields))}"
            )

    def encode(self, input_type: str, request: Mapping[str, Any]) -> bytes:
        from google.protobuf import json_format

        message = self._registry.message_class(input_type)()
        descriptor = message.DESCRIPTOR
        repeated_roots = {
            name
            for name, field in descriptor.fields_by_name.items()
            if field.is_repeated
        }
        payload = _normalize_request(request, repeated_roots)
        payload = _filter_known_fields(payload, descriptor)
        json_format.ParseDict(payload, message)
        return message.SerializeToString()

    def decode(self, output_type: str, response: bytes) -> ResponseData:
        from google.protobuf import json_format

        message = self._registry.message_class(output_type)()
        message.ParseFromString(response)
        values = json_format.MessageToDict(
            message,
            preserving_proto_field_name=True,
            use_integers_for_enums=True,
        )
        fields: list[tuple[str, Any]] = []
        for path in self._safe_fields:
            field = _field_at_path(message.DESCRIPTOR, path)
            value = _value_at_path(values, path)
            if field is None:
                continue
            if field.type in {
                field.TYPE_MESSAGE,
                field.TYPE_GROUP,
                field.TYPE_BYTES,
            }:
                continue
            if value is None and not getattr(field, "has_presence", False):
                value = _default_value_at_path(message, path)
            if value is None:
                continue
            if _is_repeated(field):
                if not isinstance(value, list) or not all(
                    _scalar(item) for item in value
                ):
                    continue
                value = tuple(value)
            if _scalar(value):
                fields.append((path, value))
        fields.sort()
        return ResponseData(
            fields=tuple(fields),
            field_names=_descriptor_field_names(message.DESCRIPTOR),
        )

    def decode_full(
        self, output_type: str, response: bytes
    ) -> tuple[tuple[str, JsonValue], ...]:
        """Decode a complete response into its full-fidelity leaf tree.

        Nested messages contribute nested dotted paths, repeated fields
        contribute index segments (``items.0.name``), UTF-8-decodable bytes
        are retained as text while any other bytes become a ``sha256:``
        reference, enums use their symbolic names, and unknown wire fields
        are retained as descriptor-drift evidence.  Depth and leaf cardinality
        are capped so an exponential response cannot exhaust the host.
        """
        message = self._registry.message_class(output_type)()
        message.ParseFromString(response)
        return _response_tree(message)


class _TreeBudget:
    """Bounded accumulator for full-fidelity response leaves."""

    __slots__ = ("leaves", "truncated")

    def __init__(self) -> None:
        self.leaves: list[tuple[str, JsonValue]] = []
        self.truncated = False

    def exhausted(self) -> bool:
        if len(self.leaves) < RESPONSE_TREE_MAX_LEAVES:
            return False
        self.truncated = True
        return True

    def add(self, path: str, value: JsonValue) -> None:
        self.leaves.append((path, value))


def _response_tree(message: Any) -> tuple[tuple[str, JsonValue], ...]:
    """Walk one decoded protobuf message into flat scalar leaves."""

    budget = _TreeBudget()
    _walk_unknown_fields(
        message.SerializeToString(deterministic=True),
        message.DESCRIPTOR,
        "",
        budget,
    )
    _walk_message(message, "", 0, budget)
    if budget.truncated:
        budget.add(_RESPONSE_TREE_TRUNCATED, True)
    return tuple(budget.leaves)


def _walk_message(
    message: Any,
    prefix: str,
    depth: int,
    budget: _TreeBudget,
) -> None:
    if depth >= RESPONSE_TREE_MAX_DEPTH:
        budget.truncated = True
        return
    descriptor = message.DESCRIPTOR
    for name in sorted(descriptor.fields_by_name):
        field = descriptor.fields_by_name[name]
        path = f"{prefix}{name}"
        if _is_repeated(field):
            for index, item in enumerate(getattr(message, name)):
                if budget.exhausted():
                    return
                if _is_message_field(field):
                    _walk_message(item, f"{path}.{index}.", depth + 1, budget)
                else:
                    budget.add(f"{path}.{index}", _leaf_value(item, field))
        elif _is_message_field(field):
            if _field_present(message, name):
                _walk_message(getattr(message, name), f"{path}.", depth + 1, budget)
        elif _field_present(message, name):
            if budget.exhausted():
                return
            budget.add(path, _leaf_value(getattr(message, name), field))


def _is_message_field(field: Any) -> bool:
    return field.type in {field.TYPE_MESSAGE, field.TYPE_GROUP}


def _field_present(message: Any, name: str) -> bool:
    """Return whether a singular field carries explicit presence.

    Proto3 implicit scalars have no presence tracking: their decoded value
    is the type default and is retained as-is.
    """
    try:
        return bool(message.HasField(name))
    except ValueError:
        return True


def _leaf_value(value: Any, field: Any) -> JsonValue:
    """Normalize one decoded protobuf scalar into a JSON leaf value."""

    if field.type == field.TYPE_BYTES:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"sha256:{hashlib.sha256(value).hexdigest()}"
    if field.type == field.TYPE_ENUM:
        enum_value = field.enum_type.values_by_number.get(value)
        return enum_value.name if enum_value is not None else int(value)
    if field.type in {field.TYPE_FLOAT, field.TYPE_DOUBLE}:
        number = float(value)
        if math.isnan(number):
            return "NaN"
        if math.isinf(number):
            return "Infinity" if number > 0 else "-Infinity"
        return number
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int(value)
    return str(value)


def _walk_unknown_fields(
    data: bytes,
    descriptor: Any,
    prefix: str,
    budget: _TreeBudget,
) -> None:
    """Retain wire fields that are absent from the supplied descriptor.

    Unknown fields are evidence of descriptor drift or a newer server schema.
    Their field number, occurrence index, and a safe scalar representation are
    emitted before known fields so a large known response cannot silently
    crowd them out of the bounded tree.
    """

    offset = 0
    occurrences: dict[int, int] = {}
    while offset < len(data):
        field_number, wire_type, value, offset = _read_wire_field(data, offset)
        index = occurrences.get(field_number, 0)
        occurrences[field_number] = index + 1
        field = descriptor.fields_by_number.get(field_number)

        if field is None:
            if budget.exhausted():
                return
            budget.add(
                f"{prefix}{_UNKNOWN_FIELD_PREFIX}.{field_number}.{index}",
                _unknown_value(wire_type, value),
            )
            continue

        if wire_type == _WIRE_TYPE_LENGTH_DELIMITED and _is_message_field(field):
            nested_prefix = f"{prefix}{field.name}."
            if _is_repeated(field):
                nested_prefix = f"{prefix}{field.name}.{index}."
            _walk_unknown_fields(value, field.message_type, nested_prefix, budget)
        elif wire_type == _WIRE_TYPE_START_GROUP and field.type == field.TYPE_GROUP:
            nested_prefix = f"{prefix}{field.name}."
            if _is_repeated(field):
                nested_prefix = f"{prefix}{field.name}.{index}."
            _walk_unknown_fields(value, field.message_type, nested_prefix, budget)


def _read_wire_field(data: bytes, offset: int) -> tuple[int, int, Any, int]:
    """Read one protobuf wire field and return its safe payload."""

    tag, offset = _read_varint(data, offset)
    field_number = tag >> 3
    wire_type = tag & 0b111
    if field_number == 0:
        raise ValueError("protobuf wire field number is zero")

    if wire_type == _WIRE_TYPE_VARINT:
        value, offset = _read_varint(data, offset)
        return field_number, wire_type, value, offset
    if wire_type == _WIRE_TYPE_FIXED64:
        end = offset + 8
        if end > len(data):
            raise ValueError("truncated fixed64 protobuf field")
        return field_number, wire_type, data[offset:end], end
    if wire_type == _WIRE_TYPE_LENGTH_DELIMITED:
        length, offset = _read_varint(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("truncated length-delimited protobuf field")
        return field_number, wire_type, data[offset:end], end
    if wire_type == _WIRE_TYPE_START_GROUP:
        body, offset = _read_group(data, offset, field_number)
        return field_number, wire_type, body, offset
    if wire_type == _WIRE_TYPE_FIXED32:
        end = offset + 4
        if end > len(data):
            raise ValueError("truncated fixed32 protobuf field")
        return field_number, wire_type, data[offset:end], end
    raise ValueError(f"unsupported protobuf wire type: {wire_type}")


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint is too long")


def _read_group(data: bytes, offset: int, field_number: int) -> tuple[bytes, int]:
    body_start = offset
    while offset < len(data):
        tag_position = offset
        tag, offset = _read_varint(data, offset)
        end_field_number = tag >> 3
        wire_type = tag & 0b111
        if wire_type == _WIRE_TYPE_END_GROUP:
            if end_field_number != field_number:
                raise ValueError("mismatched protobuf group end tag")
            return data[body_start:tag_position], offset
        _, _, _, offset = _read_wire_field(data, offset)
    raise ValueError("unterminated protobuf group")


def _unknown_value(wire_type: int, value: Any) -> JsonValue:
    if wire_type == _WIRE_TYPE_VARINT:
        return int(value)
    if wire_type == _WIRE_TYPE_FIXED64:
        return f"fixed64:{value.hex()}"
    if wire_type == _WIRE_TYPE_LENGTH_DELIMITED:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"sha256:{hashlib.sha256(value).hexdigest()}"
    if wire_type == _WIRE_TYPE_FIXED32:
        return f"fixed32:{value.hex()}"
    if wire_type == _WIRE_TYPE_START_GROUP:
        return "group"
    return f"wire_type:{wire_type}"


def _load_modules() -> tuple[Any, Any]:
    try:
        from google.protobuf import descriptor_pb2, descriptor_pool
    except ImportError as exc:  # pragma: no cover - dependency environment
        raise RuntimeError(
            "protobuf is required for descriptor-backed live execution; "
            "install protobuf"
        ) from exc
    return descriptor_pb2, descriptor_pool


def _message_names(messages: Iterable[Any], prefix: str) -> Iterable[str]:
    for message in messages:
        name = f"{prefix}{message.name}"
        yield name
        yield from _message_names(message.nested_type, f"{name}.")


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def _descriptor_field_names(descriptor: Any) -> tuple[str, ...]:
    """Return every dotted field path declared by a message descriptor.

    The traversal is shape-only: every declared field contributes its path,
    nested messages contribute ``outer.inner`` paths, and repeated fields use
    the path suffix without element indices.  A recursive message type may
    appear at most twice on one path, so direct nested names stay visible
    while the traversal remains finite.
    """

    max_recursive_depth = 2
    names: list[str] = []

    def visit(current: Any, prefix: str, ancestors: tuple[str, ...]) -> None:
        if ancestors.count(current.full_name) >= max_recursive_depth:
            return
        descendants = (*ancestors, current.full_name)
        for name in sorted(current.fields_by_name):
            field = current.fields_by_name[name]
            path = f"{prefix}{name}"
            names.append(path)
            if field.type in {field.TYPE_MESSAGE, field.TYPE_GROUP}:
                visit(field.message_type, f"{path}.", descendants)

    visit(descriptor, "", ())
    return tuple(sorted(names))


def _descriptor_schema_fields(descriptor: Any) -> tuple[FieldSpec, ...]:
    """Return a bounded, transport-neutral schema for a protobuf message.

    Nested scalar leaves use dotted paths, matching the request projection and
    response evidence formats.  Composite fields are retained as well: they
    describe the shape boundary and let a transport-specific adapter decide
    whether to materialize the object or one of its leaves.  Recursive message
    types are bounded in the same way as ``_descriptor_field_names``.
    """

    max_recursive_depth = 2
    fields: list[FieldSpec] = []

    def visit(current: Any, prefix: str, ancestors: tuple[str, ...]) -> None:
        if ancestors.count(current.full_name) >= max_recursive_depth:
            return
        descendants = (*ancestors, current.full_name)
        for name in sorted(current.fields_by_name):
            field = current.fields_by_name[name]
            path = f"{prefix}{name}"
            fields.append(_field_spec(field, path))
            if field.type in {field.TYPE_MESSAGE, field.TYPE_GROUP}:
                # Map entries are implementation messages, not user-facing
                # request/response fields; the map field itself is sufficient.
                if not _is_map_entry(field.message_type):
                    visit(field.message_type, f"{path}.", descendants)

    visit(descriptor, "", ())
    return tuple(sorted(fields, key=lambda item: item.name))


def _field_spec(field: Any, name: str) -> FieldSpec:
    field_type = _field_type_name(field)
    bounds = integer_range(field_type) or float_range(field_type)
    oneof = getattr(field, "containing_oneof", None)
    if oneof is not None and getattr(oneof, "is_synthetic", False):
        oneof = None
    return FieldSpec(
        name=name,
        type=field_type,
        required=bool(getattr(field, "is_required", False)),
        repeated=_is_repeated(field),
        oneof=None if oneof is None else oneof.name,
        enum_values=(
            tuple(value.name for value in field.enum_type.values)
            if field.type == field.TYPE_ENUM
            else ()
        ),
        minimum=None if bounds is None else bounds[0],
        maximum=None if bounds is None else bounds[1],
    )


def _field_type_name(field: Any) -> str:
    if field.type in {field.TYPE_MESSAGE, field.TYPE_GROUP}:
        return field.message_type.full_name
    if field.type == field.TYPE_ENUM:
        return "enum"
    return {
        field.TYPE_DOUBLE: "double",
        field.TYPE_FLOAT: "float",
        field.TYPE_INT64: "int64",
        field.TYPE_UINT64: "uint64",
        field.TYPE_INT32: "int32",
        field.TYPE_FIXED64: "fixed64",
        field.TYPE_FIXED32: "fixed32",
        field.TYPE_BOOL: "bool",
        field.TYPE_STRING: "string",
        field.TYPE_BYTES: "bytes",
        field.TYPE_UINT32: "uint32",
        field.TYPE_SFIXED32: "sfixed32",
        field.TYPE_SFIXED64: "sfixed64",
        field.TYPE_SINT32: "sint32",
        field.TYPE_SINT64: "sint64",
    }.get(field.type, "unknown")


def _is_map_entry(descriptor: Any) -> bool:
    return bool(descriptor.GetOptions().map_entry)


def _is_repeated(field: Any) -> bool:
    """Support modern upb descriptors and legacy protobuf runtimes."""
    repeated = getattr(field, "is_repeated", None)
    if repeated is not None:
        return bool(repeated)
    return field.label == field.LABEL_REPEATED


def _field_at_path(descriptor: Any, path: str) -> Any | None:
    current = descriptor
    parts = path.split(".")
    for index, part in enumerate(parts):
        field = current.fields_by_name.get(part)
        if field is None:
            return None
        if index == len(parts) - 1:
            return field
        if field.type not in {field.TYPE_MESSAGE, field.TYPE_GROUP}:
            return None
        if _is_repeated(field):
            return None
        current = field.message_type
    return None


def _normalize_request(
    request: Mapping[str, Any], repeated_roots: set[str]
) -> dict[str, Any]:
    """Convert flat dotted request fields into protobuf JSON structure.

    ``Check.request`` intentionally stores scalar leaves with dotted names.
    Protobuf expects nested objects, so the codec owns this deterministic
    projection. Null and empty repeated placeholders are dropped; unknown
    fields are rejected later against the descriptor.
    """

    result: dict[str, Any] = {}
    for name, raw_value in request.items():
        value = _normalize_value(raw_value)
        if value is None or value == []:
            continue
        _set_dotted_value(result, name, value, repeated_roots)
    return result


def _normalize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(name): normalized
            for name, item in value.items()
            if (normalized := _normalize_value(item)) is not None
        }
    if isinstance(value, (list, tuple)):
        return [item for item in map(_normalize_value, value) if item is not None]
    return value


def _set_dotted_value(
    target: dict[str, Any],
    name: str,
    value: Any,
    repeated_roots: set[str],
) -> None:
    parts = name.split(".")
    if len(parts) == 1:
        target[name] = value
        return

    current: dict[str, Any]
    root = parts[0]
    if root in repeated_roots:
        items = target.setdefault(root, [])
        if not isinstance(items, list):
            return
        if not items or not isinstance(items[0], dict):
            items.insert(0, {})
        current = items[0]
        parts = parts[1:]
    else:
        current = target

    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def _filter_known_fields(
    value: Mapping[str, Any],
    descriptor: Any,
    path: str = "",
) -> dict[str, Any]:
    fields = descriptor.fields_by_name
    unknown: list[str] = []
    filtered: dict[str, Any] = {}
    for name, item in value.items():
        if name not in fields:
            unknown.append(f"{path}{name}")
            continue
        filtered[name] = _filter_known_value(item, fields[name], f"{path}{name}.")
    if unknown:
        raise CodecError(
            "request fields are not declared by protobuf descriptor: "
            + ", ".join(sorted(unknown))
        )
    return filtered


def _filter_known_value(value: Any, field: Any, path: str) -> Any:
    if isinstance(value, list):
        if not field.is_repeated:
            return []
        if field.message_type is None:
            return value
        return [
            _filter_known_fields(item, field.message_type, f"{path}{index}.")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping) and field.message_type is not None:
        return _filter_known_fields(value, field.message_type, path)
    return value


def _value_at_path(values: Mapping[str, Any], path: str) -> Any:
    value: Any = values
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _default_value_at_path(message: Any, path: str) -> Any:
    """Read a proto3 scalar default omitted by ``MessageToDict``."""
    current = message
    parts = path.split(".")
    for index, part in enumerate(parts):
        descriptor = current.DESCRIPTOR.fields_by_name.get(part)
        if descriptor is None:
            return None
        if index < len(parts) - 1:
            if descriptor.type not in {
                descriptor.TYPE_MESSAGE,
                descriptor.TYPE_GROUP,
            } or _is_repeated(descriptor):
                return None
            if getattr(descriptor, "has_presence", False):
                try:
                    if not current.HasField(part):
                        return None
                except ValueError:
                    return None
            current = getattr(current, part)
            continue
        value = getattr(current, part)
        if _is_repeated(descriptor):
            value = tuple(value)
        return value
    return None
