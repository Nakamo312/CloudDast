"""Deterministic parse-then-mutate generation for textual carriers.

Real seed values are parsed into format trees, mutated, and rendered back.
The module contains no vulnerability catalogue and never evaluates a verdict:
runtime placeholders are the only externally supplied values.
"""

from __future__ import annotations

import hashlib
import json
import pickletools
import re
import struct
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal
from xml.parsers import expat
from xml.sax.saxutils import escape, quoteattr

from cloud_dast.candidates import validate_binding
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.contracts.request_fields import (
    Absent,
    Present,
    field_value,
    with_field_value,
)
from cloud_dast.extensions import (
    OOB_URL_PLACEHOLDER,
    TestCaseGenerator,
    runtime_placeholder,
)
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)

TextualFormat = Literal["xml", "template", "deserialization"]

_DEFAULT_CANDIDATES = 4
_MAX_TEXTUAL_LENGTH = 4096
_XML_ENTITY_NAME = "dast"
_XML_ENTITY_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")

_XML_FORMATS = frozenset({"xml", "xxe", "application/xml", "text/xml"})
_XML_SINK_TYPES = frozenset({"xml_parser", "xml", "xxe"})
_TEMPLATE_FORMATS = frozenset({"template", "ssti", "template_engine"})
_TEMPLATE_SINK_TYPES = frozenset({"template_engine", "template", "ssti"})
_TEMPLATE_DIALECTS = frozenset(
    {
        "django",
        "erb",
        "freemarker",
        "go",
        "handlebars",
        "jinja",
        "liquid",
        "mustache",
        "smarty",
        "thymeleaf",
        "twig",
        "velocity",
    }
)
_DESERIALIZATION_FORMATS = frozenset(
    {
        "deserialization",
        "java",
        "javascript",
        "js",
        "json",
        "pickle",
        "serialization",
    }
)
_DESERIALIZATION_SINK_TYPES = frozenset(
    {"deserializer", "deserialization", "java", "javascript", "pickle"}
)
_DESERIALIZATION_DIALECTS = frozenset(
    {"java", "javascript", "js", "json", "pickle", "serialization"}
)

_TEMPLATE_DELIMITERS: dict[str, tuple[tuple[str, str], ...]] = {
    "django": (("{{", "}}"),),
    "erb": (("<%=", "%>"),),
    "freemarker": (("${", "}"),),
    "go": (("{{", "}}"),),
    "handlebars": ((("{{{", "}}}"), ("{{", "}}"))),
    "jinja": (("{{", "}}"),),
    "liquid": (("{{", "}}"),),
    "mustache": ((("{{{", "}}}"), ("{{", "}}"))),
    "smarty": (("{$", "}"),),
    "thymeleaf": (("${", "}"),),
    "twig": (("{{", "}}"),),
    "velocity": (("${", "}"), ("$!{", "}")),
}
_LITERAL_TEMPLATE_DIALECTS = frozenset({"handlebars", "mustache"})

_PICKLE_STRING_PREFIXES = {
    "SHORT_BINUNICODE": 1,
    "BINUNICODE": 4,
    "BINUNICODE8": 8,
}
_PICKLE_STRING_CODES = {
    "SHORT_BINUNICODE": b"\x8c",
    "BINUNICODE": b"X",
    "BINUNICODE8": b"\x8d",
}

_JAVA_MAGIC = b"\xac\xed\x00\x05"
_JAVA_TC_NULL = 0x70
_JAVA_TC_REFERENCE = 0x71
_JAVA_TC_CLASSDESC = 0x72
_JAVA_TC_OBJECT = 0x73
_JAVA_TC_STRING = 0x74
_JAVA_TC_ARRAY = 0x75
_JAVA_TC_BLOCKDATA = 0x77
_JAVA_TC_ENDBLOCKDATA = 0x78
_JAVA_TC_RESET = 0x79
_JAVA_TC_BLOCKDATALONG = 0x7A
_JAVA_TC_LONGSTRING = 0x7C
_JAVA_TC_ENUM = 0x7E
_JAVA_SC_WRITE_METHOD = 0x01
_JAVA_SC_BLOCK_DATA = 0x08
_JAVA_PRIMITIVE_SIZES = {
    "B": 1,
    "C": 2,
    "D": 8,
    "F": 4,
    "I": 4,
    "J": 8,
    "S": 2,
    "Z": 1,
}


@dataclass(frozen=True, slots=True)
class _TextualTarget:
    field: str
    format: TextualFormat
    dialect: str = ""


@dataclass(slots=True)
class _XmlText:
    value: str


@dataclass(slots=True)
class _XmlEntityReference:
    name: str


@dataclass(slots=True)
class _XmlElement:
    tag: str
    attributes: dict[str, str]
    children: list[_XmlText | _XmlEntityReference | _XmlElement]


@dataclass(frozen=True, slots=True)
class _XmlEntity:
    name: str
    value: str | None = None
    system_id: str | None = None
    public_id: str | None = None


@dataclass(slots=True)
class _XmlDocument:
    root: _XmlElement
    entities: dict[str, _XmlEntity]
    public_id: str | None
    system_id: str | None


@dataclass(frozen=True, slots=True)
class _TemplateExpression:
    opener: str
    body: str
    closer: str


@dataclass(frozen=True, slots=True)
class _TemplateDocument:
    segments: tuple[str | _TemplateExpression, ...]


@dataclass(frozen=True, slots=True)
class _PickleStringSlot:
    position: int
    next_position: int
    opcode: str
    value: str


@dataclass(frozen=True, slots=True)
class _JavaStringSlot:
    position: int
    prefix_size: int
    value_bytes: bytes


@dataclass(frozen=True, slots=True)
class _JavaClassDescriptor:
    name: str
    flags: int
    fields: tuple[tuple[str, str], ...]


class TextualGenerator:
    """Generate structurally valid textual candidates from real seed values."""

    def __init__(
        self,
        seed_generator: TestCaseGenerator,
        *,
        max_candidates: int = _DEFAULT_CANDIDATES,
    ) -> None:
        self._seed_generator = seed_generator
        self._max_candidates = max_candidates

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        validate_binding(plan, method, invariant, scenario)
        seeds = self._seed_generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )
        targets = _select_targets(plan, method)
        if not targets:
            return seeds

        placeholder = runtime_placeholder(plan, invariant)
        fields = {field.name: field for field in method.request_schema.fields}
        checks: list[Check] = []
        seen: set[tuple[tuple[tuple[str, JsonValue], ...], tuple[str, ...]]] = set()
        for seed in seeds:
            seed = _with_seed_id(seed)
            for index, request in enumerate(
                _mutate_requests(
                    seed.request,
                    fields,
                    targets,
                    placeholder=placeholder,
                    probe_fields=plan.probe_fields,
                    max_candidates=self._max_candidates,
                )
            ):
                key = (request, seed.identities)
                if key in seen:
                    continue
                seen.add(key)
                checks.append(_copy_check(seed, request=request, index=index))
        return tuple(checks) or seeds


def mutate_textual_seed(
    seed: str,
    *,
    carrier_format: TextualFormat,
    dialect: str = "",
    placeholder: str = "",
) -> tuple[str, ...]:
    """Parse, mutate, and render one textual seed deterministically."""

    if not seed or len(seed) > _MAX_TEXTUAL_LENGTH:
        return ()
    if placeholder and seed.count(placeholder) > 1:
        return ()

    if carrier_format == "xml":
        candidates = _mutate_xml(seed, placeholder=placeholder)
    elif carrier_format == "template":
        candidates = _mutate_template(seed, dialect=dialect, placeholder=placeholder)
    else:
        candidates = _mutate_serialization(
            seed,
            dialect=dialect,
            placeholder=placeholder,
        )

    return tuple(
        candidate
        for candidate in candidates
        if len(candidate) <= _MAX_TEXTUAL_LENGTH
        and (not placeholder or candidate.count(placeholder) == 1)
    )


def _select_targets(
    plan: VerificationPlan,
    method: MethodSpec,
) -> tuple[_TextualTarget, ...]:
    fields = {
        field.name: field
        for field in method.request_schema.fields
        if _is_text_field(field)
        and not field.enum_values
        and field.name not in plan.resource_params
    }
    if not fields:
        return ()

    explicit: dict[str, TextualFormat | None] = {}
    explicit_names: dict[str, str] = {}
    inferred: dict[str, set[TextualFormat]] = {}
    for field, format_name in plan.grammar_formats:
        if field not in fields:
            continue
        format_value = _format_from_name(format_name)
        if format_value is not None:
            explicit[field] = format_value
            explicit_names[field] = format_name.strip().lower()

    for field, dialect in plan.grammar_dialects:
        if field not in fields:
            continue
        normalized = dialect.strip().lower()
        if normalized in _TEMPLATE_DIALECTS:
            inferred.setdefault(field, set()).add("template")
        if normalized in _DESERIALIZATION_DIALECTS:
            inferred.setdefault(field, set()).add("deserialization")

    for field, sink_type in plan.sink_types:
        if field not in fields:
            continue
        normalized = sink_type.strip().lower()
        if normalized in _XML_SINK_TYPES:
            inferred.setdefault(field, set()).add("xml")
        if normalized in _TEMPLATE_SINK_TYPES:
            inferred.setdefault(field, set()).add("template")
        if normalized in _DESERIALIZATION_SINK_TYPES:
            inferred.setdefault(field, set()).add("deserialization")

    dialects = {
        field: dialect for field, dialect in plan.grammar_dialects if field in fields
    }
    targets: list[_TextualTarget] = []
    for field in sorted(fields):
        format_value = explicit.get(field)
        if format_value is None:
            available = inferred.get(field, set())
            if len(available) != 1:
                continue
            format_value = next(iter(available))
        dialect = dialects.get(field, "")
        if not dialect and format_value == "deserialization":
            # The declared format may itself name the serialization family
            # (for example ``format(Field, pickle)``); that is still a QDL
            # fact, unlike sniffing magic bytes or defaulting to JSON.
            name = explicit_names.get(field, "")
            dialect = name if name in _DESERIALIZATION_DIALECTS else ""
        targets.append(
            _TextualTarget(
                field=field,
                format=format_value,
                dialect=dialect,
            )
        )
    return tuple(targets)


def _format_from_name(value: str) -> TextualFormat | None:
    normalized = value.strip().lower()
    if normalized in _XML_FORMATS:
        return "xml"
    if normalized in _TEMPLATE_FORMATS:
        return "template"
    if normalized in _DESERIALIZATION_FORMATS:
        return "deserialization"
    return None


def _mutate_requests(
    seed_request: tuple[tuple[str, JsonValue], ...],
    fields: Mapping[str, FieldSpec],
    targets: Sequence[_TextualTarget],
    *,
    placeholder: str,
    probe_fields: tuple[str, ...],
    max_candidates: int,
) -> tuple[tuple[tuple[str, JsonValue], ...], ...]:
    request = dict(seed_request)
    allowed_fields = set(probe_fields) if placeholder else set()
    candidates: list[tuple[tuple[str, JsonValue], ...]] = []
    seen: set[tuple[tuple[str, JsonValue], ...]] = {seed_request}

    for target in targets:
        field = fields[target.field]
        if isinstance(field_value(request, field), Absent) or (
            allowed_fields and target.field not in allowed_fields
        ):
            continue
        value = request[target.field]
        values = value if field.repeated and isinstance(value, tuple) else (value,)
        for value_index, item in enumerate(values):
            if not isinstance(item, str):
                continue
            for mutated in mutate_textual_seed(
                item,
                carrier_format=target.format,
                dialect=target.dialect,
                placeholder=placeholder,
            ):
                new_value: JsonValue = mutated
                if field.repeated:
                    if not isinstance(value, tuple):
                        continue
                    new_value = (
                        *values[:value_index],
                        mutated,
                        *values[value_index + 1 :],
                    )
                new_request = with_field_value(
                    tuple(request.items()),
                    field,
                    Present(((field.name, new_value),)),
                )
                if new_request in seen or len(candidates) >= max_candidates:
                    continue
                seen.add(new_request)
                candidates.append(new_request)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break
    return tuple(candidates)


def _mutate_xml(
    seed: str,
    *,
    placeholder: str,
) -> tuple[str, ...]:
    try:
        document = _parse_xml(seed)
    except (ValueError, expat.ExpatError):
        return ()

    elements = list(_walk_xml_elements(document.root))
    if not elements:
        return ()
    text_elements = [
        element
        for element in elements
        if any(
            isinstance(child, _XmlText) and child.value.strip()
            for child in element.children
        )
    ] or elements
    target_elements = _first_and_last(text_elements)
    first_text = _first_xml_text(document.root) or document.root.tag
    external_system = next(
        (
            entity.system_id
            for entity in document.entities.values()
            if entity.system_id is not None
        ),
        None,
    )

    candidates: list[str] = []
    seen: set[str] = set()
    for target_index, target in enumerate(target_elements):
        mutations: tuple[tuple[str, str | None], ...] = (
            (placeholder or first_text, None),
        )
        if placeholder == OOB_URL_PLACEHOLDER:
            mutations += ((placeholder, placeholder),)
        elif external_system is not None:
            mutations += ((external_system, external_system),)

        for mutation_index, (value, system_id) in enumerate(mutations):
            mutated = deepcopy(document)
            mutated_elements = _walk_xml_elements(mutated.root)
            mutated_target = mutated_elements[_xml_element_index(elements, target)]
            name = _unique_xml_entity_name(
                mutated.entities,
                target_index * 2 + mutation_index,
            )
            mutated.entities[name] = _XmlEntity(
                name=name,
                value=value if system_id is None else None,
                system_id=system_id,
            )
            mutated_target.children.append(_XmlEntityReference(name=name))
            rendered = _render_xml(mutated)
            try:
                _parse_xml(rendered)
            except (ValueError, expat.ExpatError):
                continue
            if rendered not in seen:
                seen.add(rendered)
                candidates.append(rendered)
    return tuple(candidates)


def _parse_xml(value: str) -> _XmlDocument:
    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.ExternalEntityRefHandler = lambda *args: True

    entities: dict[str, _XmlEntity] = {}
    public_id: str | None = None
    system_id: str | None = None
    root: _XmlElement | None = None
    stack: list[_XmlElement] = []
    pending_text: list[str] = []

    def append_child(
        child: _XmlText | _XmlEntityReference | _XmlElement,
    ) -> None:
        if not stack:
            return
        stack[-1].children.append(child)

    def flush_text() -> None:
        nonlocal pending_text
        text = "".join(pending_text)
        pending_text = []
        if text and stack:
            append_child(_XmlText(text))

    def start_element(name: str, attributes: dict[str, str]) -> None:
        nonlocal root
        flush_text()
        element = _XmlElement(name, dict(attributes), [])
        if root is None:
            root = element
        else:
            append_child(element)
        stack.append(element)

    def end_element(name: str) -> None:
        del name
        flush_text()
        if stack:
            stack.pop()

    def character_data(data: str) -> None:
        pending_text.append(data)

    def default_handler(data: str) -> None:
        if (
            len(data) > 2
            and data.startswith("&")
            and data.endswith(";")
            and _XML_ENTITY_NAME_PATTERN.fullmatch(data[1:-1]) is not None
        ):
            flush_text()
            append_child(_XmlEntityReference(data[1:-1]))

    def entity_decl(
        name: str,
        is_parameter_entity: bool,
        value: str | None,
        base: str,
        entity_system_id: str | None,
        entity_public_id: str | None,
        notation_name: str,
    ) -> None:
        del base, notation_name
        if is_parameter_entity or not name:
            return
        entities[name] = _XmlEntity(
            name=name,
            value=value,
            system_id=entity_system_id,
            public_id=entity_public_id,
        )

    def start_doctype(
        name: str,
        doctype_system_id: str | None,
        doctype_public_id: str | None,
        has_internal_subset: bool,
    ) -> None:
        nonlocal public_id, system_id
        del name, has_internal_subset
        public_id = doctype_public_id
        system_id = doctype_system_id

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = character_data
    parser.DefaultHandler = default_handler
    parser.EntityDeclHandler = entity_decl
    parser.StartDoctypeDeclHandler = start_doctype
    parser.Parse(value, True)
    if root is None:
        raise ValueError("XML seed has no root element")
    return _XmlDocument(
        root=root,
        entities=entities,
        public_id=public_id,
        system_id=system_id,
    )


def _render_xml(document: _XmlDocument) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        + _render_xml_doctype(document)
        + _render_xml_element(document.root)
    )


def _render_xml_doctype(document: _XmlDocument) -> str:
    external = ""
    if document.public_id is not None and document.system_id is not None:
        external = (
            f" PUBLIC {quoteattr(document.public_id)} {quoteattr(document.system_id)}"
        )
    elif document.system_id is not None:
        external = f" SYSTEM {quoteattr(document.system_id)}"

    declarations = "".join(
        _render_xml_entity(entity) for entity in document.entities.values()
    )
    if not declarations:
        return ""
    return f"<!DOCTYPE {document.root.tag}{external} [{declarations}]>"


def _render_xml_entity(entity: _XmlEntity) -> str:
    if entity.value is not None:
        return f"<!ENTITY {entity.name} {quoteattr(entity.value)}>"
    if entity.public_id is not None and entity.system_id is not None:
        return (
            f"<!ENTITY {entity.name} PUBLIC "
            f"{quoteattr(entity.public_id)} {quoteattr(entity.system_id)}>"
        )
    if entity.system_id is not None:
        return f"<!ENTITY {entity.name} SYSTEM {quoteattr(entity.system_id)}>"
    return ""


def _render_xml_element(element: _XmlElement) -> str:
    attributes = "".join(
        f" {name}={quoteattr(value)}" for name, value in element.attributes.items()
    )
    if not element.children:
        return f"<{element.tag}{attributes}/>"
    children = "".join(_render_xml_child(child) for child in element.children)
    return f"<{element.tag}{attributes}>{children}</{element.tag}>"


def _render_xml_child(
    child: _XmlText | _XmlEntityReference | _XmlElement,
) -> str:
    if isinstance(child, _XmlText):
        return escape(child.value)
    if isinstance(child, _XmlEntityReference):
        return f"&{child.name};"
    return _render_xml_element(child)


def _walk_xml_elements(element: _XmlElement) -> tuple[_XmlElement, ...]:
    result = [element]
    for child in element.children:
        if isinstance(child, _XmlElement):
            result.extend(_walk_xml_elements(child))
    return tuple(result)


def _first_xml_text(element: _XmlElement) -> str | None:
    for child in element.children:
        if isinstance(child, _XmlText) and child.value.strip():
            return child.value.strip()
    for child in element.children:
        if isinstance(child, _XmlElement):
            text = _first_xml_text(child)
            if text is not None:
                return text
    return None


def _xml_element_index(
    elements: Sequence[_XmlElement],
    target: _XmlElement,
) -> int:
    for index, element in enumerate(elements):
        if element is target:
            return index
    raise ValueError("XML target element is not in the document")


def _unique_xml_entity_name(entities: Mapping[str, _XmlEntity], index: int) -> str:
    name = f"{_XML_ENTITY_NAME}{index}"
    suffix = 0
    while name in entities:
        suffix += 1
        name = f"{_XML_ENTITY_NAME}{index}_{suffix}"
    return name


def _mutate_template(
    seed: str,
    *,
    dialect: str,
    placeholder: str,
) -> tuple[str, ...]:
    normalized_dialect = dialect.strip().lower()
    try:
        document = _parse_template(seed, normalized_dialect)
    except ValueError:
        return ()

    expression_indexes = [
        index
        for index, segment in enumerate(document.segments)
        if isinstance(segment, _TemplateExpression)
    ]
    if not expression_indexes:
        return ()

    candidates: list[str] = []
    seen: set[str] = set()
    for index in _first_and_last(expression_indexes):
        expression = document.segments[index]
        if not isinstance(expression, _TemplateExpression):
            continue
        if placeholder:
            if normalized_dialect in _LITERAL_TEMPLATE_DIALECTS:
                segments = _insert_template_literal(
                    document.segments,
                    index,
                    placeholder,
                )
            else:
                segments = _replace_template_expression(
                    document.segments,
                    index,
                    _quote_template_string(placeholder),
                )
        else:
            segments = _replace_template_expression(
                document.segments,
                index,
                _quote_template_string(expression.body.strip() or expression.body),
            )
        rendered = _render_template(segments)
        try:
            reparsed = _parse_template(rendered, normalized_dialect)
        except ValueError:
            continue
        if len(reparsed.segments) != len(segments):
            continue
        if rendered not in seen:
            seen.add(rendered)
            candidates.append(rendered)
    return tuple(candidates)


def _parse_template(
    value: str,
    dialect: str,
) -> _TemplateDocument:
    delimiters = _template_delimiters(dialect)
    segments: list[str | _TemplateExpression] = []
    index = 0
    while index < len(value):
        matches = [
            (position, -len(opener), opener, closer)
            for opener, closer in delimiters
            if (position := value.find(opener, index)) != -1
        ]
        if not matches:
            segments.append(value[index:])
            break
        position, _, opener, closer = min(matches)
        if position > index:
            segments.append(value[index:position])
        end = value.find(closer, position + len(opener))
        if end == -1:
            raise ValueError("template seed has an unterminated expression")
        segments.append(
            _TemplateExpression(
                opener=opener,
                body=value[position + len(opener) : end],
                closer=closer,
            )
        )
        index = end + len(closer)
    return _TemplateDocument(segments=tuple(segments))


def _template_delimiters(dialect: str) -> tuple[tuple[str, str], ...]:
    """Return delimiters only for a declared template dialect.

    An unknown dialect must not fall back to Jinja-style ``{{ }}`` braces:
    that would mutate an unknown template format as if it were Jinja.
    """

    return _TEMPLATE_DELIMITERS.get(dialect, ())


def _render_template(segments: Sequence[str | _TemplateExpression]) -> str:
    return "".join(
        segment
        if isinstance(segment, str)
        else f"{segment.opener}{segment.body}{segment.closer}"
        for segment in segments
    )


def _replace_template_expression(
    segments: Sequence[str | _TemplateExpression],
    index: int,
    body: str,
) -> tuple[str | _TemplateExpression, ...]:
    replaced: list[str | _TemplateExpression] = []
    for current_index, segment in enumerate(segments):
        if current_index == index and isinstance(segment, _TemplateExpression):
            replaced.append(
                _TemplateExpression(
                    opener=segment.opener,
                    body=body,
                    closer=segment.closer,
                )
            )
        else:
            replaced.append(segment)
    return tuple(replaced)


def _insert_template_literal(
    segments: Sequence[str | _TemplateExpression],
    index: int,
    literal: str,
) -> tuple[str | _TemplateExpression, ...]:
    result: list[str | _TemplateExpression] = []
    for current_index, segment in enumerate(segments):
        result.append(segment)
        if current_index == index:
            result.append(literal)
    return tuple(result)


def _quote_template_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _mutate_serialization(
    seed: str,
    *,
    dialect: str,
    placeholder: str,
) -> tuple[str, ...]:
    """Mutate only the serialization family declared by a QDL dialect fact.

    An unknown dialect returns no candidate: sniffing magic bytes or
    defaulting to JSON would guess a serialization the graph never declared.
    """

    normalized = dialect.strip().lower()
    if normalized == "java":
        return _mutate_java(seed, placeholder=placeholder)
    if normalized == "pickle":
        return _mutate_pickle(seed, placeholder=placeholder)
    if normalized in {"javascript", "js", "json"}:
        return _mutate_json(seed, placeholder=placeholder)
    return ()


def _mutate_json(
    seed: str,
    *,
    placeholder: str,
) -> tuple[str, ...]:
    try:
        tree = json.loads(seed)
    except (json.JSONDecodeError, TypeError):
        return ()
    paths = _json_string_paths(tree)
    if not paths:
        return ()

    candidates: list[str] = []
    seen: set[str] = set()
    for path, value in _first_and_last(paths):
        replacement = placeholder if placeholder else value + value
        mutated = _replace_json_path(deepcopy(tree), path, replacement)
        rendered = json.dumps(
            mutated,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            json.loads(rendered)
        except (json.JSONDecodeError, TypeError):
            continue
        if rendered not in seen:
            seen.add(rendered)
            candidates.append(rendered)
    return tuple(candidates)


def _json_string_paths(
    value: object,
    path: tuple[object, ...] = (),
) -> tuple[tuple[tuple[object, ...], str], ...]:
    if isinstance(value, str):
        return ((path, value),)
    if isinstance(value, list):
        return tuple(
            item
            for index, item in enumerate(value)
            for item in _json_string_paths(item, (*path, index))
        )
    if isinstance(value, dict):
        return tuple(
            item
            for key, item_value in value.items()
            for item in _json_string_paths(item_value, (*path, key))
        )
    return ()


def _replace_json_path(
    value: object,
    path: Sequence[object],
    replacement: str,
) -> object:
    if not path:
        return replacement
    key = path[0]
    if isinstance(value, list) and isinstance(key, int):
        return [
            _replace_json_path(item, path[1:], replacement)
            if item_index == key
            else item
            for item_index, item in enumerate(value)
        ]
    if isinstance(value, dict) and isinstance(key, str):
        return {
            item_key: _replace_json_path(item, path[1:], replacement)
            if item_key == key
            else item
            for item_key, item in value.items()
        }
    return value


def _mutate_pickle(
    seed: str,
    *,
    placeholder: str,
) -> tuple[str, ...]:
    data = _decode_binary_text(seed)
    if data is None:
        return ()
    try:
        operations = list(pickletools.genops(data))
        slots = _pickle_string_slots(operations)
    except ValueError:
        return ()
    if not slots:
        return ()

    candidates: list[str] = []
    seen: set[str] = set()
    for slot in _first_and_last(slots):
        replacement = placeholder if placeholder else slot.value + slot.value
        encoded = _encode_pickle_string(slot.opcode, replacement)
        if encoded is None:
            continue
        candidate = data[: slot.position] + encoded + data[slot.next_position :]
        try:
            reparsed = list(pickletools.genops(candidate))
        except ValueError:
            continue
        if not reparsed or reparsed[-1][0].name != "STOP":
            continue
        rendered = candidate.decode("latin-1")
        if rendered not in seen:
            seen.add(rendered)
            candidates.append(rendered)
    return tuple(candidates)


def _pickle_string_slots(
    operations: Sequence[object],
) -> tuple[_PickleStringSlot, ...]:
    slots: list[_PickleStringSlot] = []
    for index, operation in enumerate(operations):
        opcode, argument, position = operation  # type: ignore[misc]
        if opcode.name not in _PICKLE_STRING_PREFIXES or not isinstance(argument, str):
            continue
        if index + 1 >= len(operations):
            continue
        next_operation = operations[index + 1]
        next_position = next_operation[2]  # type: ignore[misc]
        slots.append(
            _PickleStringSlot(
                position=position,
                next_position=next_position,
                opcode=opcode.name,
                value=argument,
            )
        )
    return tuple(slots)


def _encode_pickle_string(opcode: str, value: str) -> bytes | None:
    encoded = value.encode("utf-8")
    if opcode == "SHORT_BINUNICODE":
        if len(encoded) <= 0xFF:
            return (
                _PICKLE_STRING_CODES[opcode] + struct.pack("<B", len(encoded)) + encoded
            )
        opcode = "BINUNICODE"
    if opcode == "BINUNICODE":
        return _PICKLE_STRING_CODES[opcode] + struct.pack("<I", len(encoded)) + encoded
    if opcode == "BINUNICODE8":
        return _PICKLE_STRING_CODES[opcode] + struct.pack("<Q", len(encoded)) + encoded
    return None


def _mutate_java(
    seed: str,
    *,
    placeholder: str,
) -> tuple[str, ...]:
    data = _decode_binary_text(seed)
    if data is None:
        return ()
    try:
        slots = _parse_java_slots(data)
    except ValueError:
        return ()
    if not slots:
        return ()

    candidates: list[str] = []
    seen: set[str] = set()
    for slot in _first_and_last(slots):
        replacement = (
            placeholder.encode("utf-8")
            if placeholder
            else slot.value_bytes + slot.value_bytes
        )
        if slot.prefix_size == 2 and len(replacement) > 0xFFFF:
            continue
        length = len(replacement).to_bytes(slot.prefix_size, "big")
        candidate = (
            data[: slot.position]
            + length
            + replacement
            + data[slot.position + slot.prefix_size + len(slot.value_bytes) :]
        )
        try:
            _parse_java_slots(candidate)
        except ValueError:
            continue
        rendered = candidate.decode("latin-1")
        if rendered not in seen:
            seen.add(rendered)
            candidates.append(rendered)
    return tuple(candidates)


def _parse_java_slots(data: bytes) -> tuple[_JavaStringSlot, ...]:
    reader = _JavaReader(data)
    if reader.read(4) != _JAVA_MAGIC:
        raise ValueError("Java serialization seed has an invalid stream header")
    reader.read_content()
    if reader.position != len(data):
        raise ValueError("Java serialization seed has trailing content")
    return tuple(reader.strings)


class _JavaReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0
        self.strings: list[_JavaStringSlot] = []

    @property
    def position(self) -> int:
        return self._position

    def read(self, size: int) -> bytes:
        end = self._position + size
        if end > len(self._data):
            raise ValueError("truncated Java serialization stream")
        chunk = self._data[self._position : end]
        self._position = end
        return chunk

    def peek(self) -> int:
        if self._position >= len(self._data):
            raise ValueError("truncated Java serialization stream")
        return self._data[self._position]

    def read_u1(self) -> int:
        return self.read(1)[0]

    def read_u2(self) -> int:
        return int.from_bytes(self.read(2), "big")

    def read_u4(self) -> int:
        return int.from_bytes(self.read(4), "big")

    def read_raw_utf(self) -> bytes:
        return self.read(self.read_u2())

    def read_content(self) -> None:
        token = self.read_u1()
        if token == _JAVA_TC_NULL:
            return
        if token == _JAVA_TC_REFERENCE:
            self.read(4)
            return
        if token in {_JAVA_TC_STRING, _JAVA_TC_LONGSTRING}:
            self.read_string_payload(token, mutable=True)
            return
        if token == _JAVA_TC_OBJECT:
            self.read_object()
            return
        if token == _JAVA_TC_ARRAY:
            self.read_array()
            return
        if token == _JAVA_TC_BLOCKDATA:
            self.read(self.read_u1())
            return
        if token == _JAVA_TC_BLOCKDATALONG:
            self.read(self.read_u4())
            return
        if token == _JAVA_TC_RESET:
            return
        if token == _JAVA_TC_ENUM:
            self.read_class_descriptor()
            self.read_content()
            return
        raise ValueError(f"unsupported Java serialization token: {token:#x}")

    def read_string_payload(self, token: int, *, mutable: bool) -> bytes:
        prefix_size = 2 if token == _JAVA_TC_STRING else 8
        position = self._position
        length = int.from_bytes(self.read(prefix_size), "big")
        value = self.read(length)
        if mutable:
            self.strings.append(
                _JavaStringSlot(
                    position=position,
                    prefix_size=prefix_size,
                    value_bytes=value,
                )
            )
        return value

    def read_class_name(self) -> None:
        token = self.read_u1()
        if token in {_JAVA_TC_STRING, _JAVA_TC_LONGSTRING}:
            self.read_string_payload(token, mutable=False)
            return
        if token == _JAVA_TC_REFERENCE:
            self.read(4)
            return
        raise ValueError(f"invalid Java class-name token: {token:#x}")

    def read_class_descriptor(self) -> _JavaClassDescriptor | None:
        token = self.read_u1()
        if token == _JAVA_TC_NULL:
            return None
        if token == _JAVA_TC_REFERENCE:
            self.read(4)
            return None
        if token != _JAVA_TC_CLASSDESC:
            raise ValueError(f"invalid Java class descriptor token: {token:#x}")

        name = self.read_raw_utf().decode("utf-8")
        self.read(8)
        flags = self.read_u1()
        field_count = self.read_u2()
        fields: list[tuple[str, str]] = []
        for _ in range(field_count):
            type_code = self.read(1).decode("ascii")
            field_name = self.read_raw_utf().decode("utf-8")
            if type_code in {"L", "["}:
                self.read_class_name()
            fields.append((type_code, field_name))

        while self.peek() != _JAVA_TC_ENDBLOCKDATA:
            self.read_content()
        self.read(1)
        self.read_class_descriptor()
        return _JavaClassDescriptor(
            name=name,
            flags=flags,
            fields=tuple(fields),
        )

    def read_object(self) -> None:
        descriptor = self.read_class_descriptor()
        if descriptor is None:
            raise ValueError("Java object has no class descriptor")
        for type_code, _field_name in descriptor.fields:
            size = _JAVA_PRIMITIVE_SIZES.get(type_code)
            if size is not None:
                self.read(size)
            else:
                self.read_content()
        if descriptor.flags & (_JAVA_SC_WRITE_METHOD | _JAVA_SC_BLOCK_DATA):
            while self.peek() != _JAVA_TC_ENDBLOCKDATA:
                self.read_content()
            self.read(1)

    def read_array(self) -> None:
        descriptor = self.read_class_descriptor()
        if descriptor is None:
            raise ValueError("Java array has no class descriptor")
        component = _java_array_component(descriptor.name)
        length = self.read_u4()
        size = _JAVA_PRIMITIVE_SIZES.get(component)
        for _ in range(length):
            if size is not None:
                self.read(size)
            else:
                self.read_content()


def _java_array_component(class_name: str) -> str:
    if len(class_name) < 2 or class_name[0] != "[":
        raise ValueError("Java array class name must start with '['")
    component = class_name[1]
    if component in _JAVA_PRIMITIVE_SIZES or component in {"L", "["}:
        return component
    raise ValueError(f"unsupported Java array component: {component!r}")


def _decode_binary_text(value: str) -> bytes | None:
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return None


def _first_and_last(value: Sequence[object]) -> tuple[object, ...]:
    if not value:
        return ()
    if len(value) == 1:
        return (value[0],)
    return (value[0], value[-1])


def _is_text_field(field: FieldSpec) -> bool:
    return field.type.lower() in {"string", "bytes", "url", "uri"}


def _with_seed_id(seed: Check) -> Check:
    if seed.seed_id is not None:
        return seed
    return seed.model_copy(
        update={
            "seed_id": hashlib.sha256(
                seed.model_dump_json(exclude={"check_id"}).encode("utf-8")
            ).hexdigest(),
        }
    )


def _copy_check(
    seed: Check,
    *,
    request: tuple[tuple[str, JsonValue], ...],
    index: int,
) -> Check:
    identity = f"{seed.seed_id or seed.check_id}:textual:{index}"
    return seed.model_copy(
        update={
            "check_id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "request": request,
            "generator": "textual",
        }
    )


__all__ = [
    "TextualFormat",
    "TextualGenerator",
    "mutate_textual_seed",
]
