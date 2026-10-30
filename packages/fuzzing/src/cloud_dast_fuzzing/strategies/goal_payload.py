from __future__ import annotations

import re
from uuid import uuid4

from cloud_dast.candidates import (
    apply_seed_hints,
    resolve_resource_ref,
    validate_binding,
)
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.payloads import PayloadCorpus
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.contracts.request_fields import Absent, field_value
from cloud_dast.extensions import (
    OOB_URL_PLACEHOLDER,
    PROBE_MARKER_PLACEHOLDER,
    PayloadCorpusSource,
    TestCaseGenerator,
)
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.ports import OobUrlFactory
from cloud_dast.verification.norms import NormView

RUNTIME_PLACEHOLDERS = (PROBE_MARKER_PLACEHOLDER, OOB_URL_PLACEHOLDER)
_STRUCTURED_GENERATORS = frozenset({"grammar", "textual"})


class GoalPayloadGenerator:
    """Apply QDL norm payload hints after a base generator runs."""

    def __init__(
        self,
        generator: TestCaseGenerator,
        *,
        oob_urls: OobUrlFactory | None = None,
        payload_corpus: PayloadCorpus | PayloadCorpusSource | None = None,
    ) -> None:
        self._generator = generator
        self._oob_urls = oob_urls
        self._payload_corpus = payload_corpus

    @property
    def uses_feedback(self) -> bool:
        """Expose whether this source uses the shared feedback hook."""

        return getattr(self._generator, "uses_feedback", False)

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
        checks = self._generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )
        if plan.seed_hints:
            checks = tuple(
                apply_seed_hints(
                    check,
                    method,
                    plan.seed_hints,
                    scenario=scenario,
                )
                for check in checks
            )
        norm = NormView.from_invariant(invariant)
        return tuple(
            decorated
            for check in checks
            if (
                decorated := self._decorate(
                    check,
                    method,
                    norm,
                    scenario,
                    probe_fields=plan.probe_fields,
                    resource_fields=plan.resource_params,
                    resource_types=plan.resource_types,
                    sink_types=plan.sink_types,
                    grammar_formats=plan.grammar_formats,
                    grammar_dialects=plan.grammar_dialects,
                )
            )
            is not None
        )

    def _decorate(
        self,
        check: Check,
        method: MethodSpec,
        norm: NormView | None,
        scenario: ScenarioPosition,
        *,
        probe_fields: tuple[str, ...] = (),
        resource_fields: tuple[str, ...] = (),
        resource_types: tuple[tuple[str, str], ...] = (),
        sink_types: tuple[tuple[str, str], ...] = (),
        grammar_formats: tuple[tuple[str, str], ...] = (),
        grammar_dialects: tuple[tuple[str, str], ...] = (),
    ) -> Check | None:
        request = dict(check.request)
        self._apply_resource_refs(
            request,
            method,
            scenario,
            resource_fields,
            resource_types,
        )
        probe_marker: str | None = None

        if norm is not None and norm.primitive in {"marker", "oob_event"}:
            marker = norm.marker
            if marker:
                placeholder = (
                    OOB_URL_PLACEHOLDER
                    if norm.primitive == "oob_event"
                    else PROBE_MARKER_PLACEHOLDER
                )
                placeholder_present = _has_placeholder(request, placeholder)
                if norm.primitive == "marker" and not probe_fields:
                    if placeholder_present or check.generator in _STRUCTURED_GENERATORS:
                        return None
                    return self._finalize(check, request, None)
                probe_marker = f"{_marker_safe(marker)}_{uuid4().hex}"
                value = (
                    self._oob_urls.url_for(probe_marker)
                    if norm.primitive == "oob_event" and self._oob_urls is not None
                    else probe_marker
                )
                if placeholder_present:
                    # The model-derived grammar already positions and quotes
                    # the carrier; replacing only the runtime token preserves
                    # that grammar instead of collapsing it to a raw canary.
                    if norm.primitive == "oob_event" and self._oob_urls is None:
                        return None
                    if _replace_placeholder(
                        request,
                        placeholder,
                        value,
                        allowed_fields=probe_fields,
                        fields=method.request_schema.fields,
                        primitive=norm.primitive,
                        resource_fields=resource_fields,
                    ):
                        return self._finalize(check, request, probe_marker)
                    return None
                if check.generator in _STRUCTURED_GENERATORS:
                    # A structured candidate without a runtime carrier is not
                    # a structural mutation.  Drop it instead of silently
                    # turning it back into the quoted-canary heuristic.
                    return None
                if norm.primitive == "marker":
                    carrier = self._carrier_field(
                        method.request_schema.fields,
                        primitive=norm.primitive,
                        probe_fields=probe_fields,
                        resource_fields=resource_fields,
                    )
                    if carrier is None:
                        return self._finalize(check, request, None)
                    value = self._render_canary(
                        probe_marker,
                        norm,
                        field_name=carrier.name,
                        sink_types=sink_types,
                        grammar_formats=grammar_formats,
                        grammar_dialects=grammar_dialects,
                    )
                if norm.primitive == "oob_event" and self._oob_urls is None:
                    # A bare marker is not a URL.  Keep the base check without
                    # claiming OOB evidence rather than poisoning a path-like
                    # field with an unusable token.
                    return self._finalize(check, request, None)
                if not self._inject(
                    request,
                    method.request_schema.fields,
                    value,
                    primitive=norm.primitive,
                    probe_fields=probe_fields,
                    resource_fields=resource_fields,
                ):
                    # A read-back/control leg may use another method that does
                    # not contain the probe field.  Keep the base check: the
                    # oracle will honestly report the missing marker evidence.
                    return self._finalize(check, request, None)
            else:
                return None

        return self._finalize(check, request, probe_marker)

    @staticmethod
    def _finalize(
        check: Check,
        request: dict[str, JsonValue],
        probe_marker: str | None,
    ) -> Check | None:
        """Reject candidates whose runtime placeholders were not decorated."""

        if _has_unresolved_placeholder(request):
            return None
        return check.model_copy(
            update={
                "request": tuple(request.items()),
                "probe_marker": probe_marker,
            }
        )

    def _render_canary(
        self,
        canary: str,
        norm: NormView,
        *,
        field_name: str,
        sink_types: tuple[tuple[str, str], ...],
        grammar_formats: tuple[tuple[str, str], ...],
        grammar_dialects: tuple[tuple[str, str], ...],
    ) -> str:
        """Compile a marker with the versioned grammar of its sink class."""

        if norm.primitive != "marker":
            return canary
        sink_classes = (
            *(kind for field, kind in sink_types if field == field_name),
            *(kind for field, kind in grammar_formats if field == field_name),
        )
        dialects = tuple(
            kind for field, kind in grammar_dialects if field == field_name
        )
        if self._payload_corpus is None:
            return canary
        corpus = (
            self._payload_corpus
            if isinstance(self._payload_corpus, PayloadCorpus)
            else self._payload_corpus.corpus
        )
        rendered = corpus.render_marker(
            sink_classes,
            dialects,
            canary,
        )
        if rendered is not None:
            return rendered
        # Without a grounded sink/format/dialect fact the bare marker is the
        # generic structural probe.  Decorating it would guess a grammar the
        # QDL graph never declared; the missing fact is reported as a deficit
        # by the grounding axes instead.
        return canary

    @staticmethod
    def _carrier_field(
        fields: tuple[FieldSpec, ...],
        *,
        primitive: str,
        probe_fields: tuple[str, ...],
        resource_fields: tuple[str, ...],
    ) -> FieldSpec | None:
        """Select the same carrier field that runtime injection would use."""

        fields_by_name = {field.name: field for field in fields}
        for name in probe_fields:
            field = fields_by_name.get(name)
            if field is not None and _accepts_probe(
                field,
                primitive=primitive,
                resource_fields=resource_fields,
                explicitly_grounded=True,
            ):
                return field
        if primitive == "marker":
            return None
        for field in fields:
            if _is_schema_fallback(
                field,
                primitive=primitive,
                resource_fields=resource_fields,
            ):
                return field
        return None

    def _inject(
        self,
        request: dict[str, JsonValue],
        fields: tuple[FieldSpec, ...],
        value: str,
        *,
        primitive: str,
        probe_fields: tuple[str, ...] = (),
        resource_fields: tuple[str, ...] = (),
    ) -> bool:
        """Select a carrier for a runtime probe.

        A marker is written only to a field grounded by the verification plan.
        An OOB URL first uses explicit grounding and then falls back only to a
        field whose schema type explicitly declares a URL; without either
        signal it is never written to an arbitrary ID field.
        """

        field = self._carrier_field(
            fields,
            primitive=primitive,
            probe_fields=probe_fields,
            resource_fields=resource_fields,
        )
        if field is None:
            return False
        request[field.name] = _fit_value(value, field)
        return True

    @staticmethod
    def _apply_resource_refs(
        request: dict[str, JsonValue],
        method: MethodSpec,
        scenario: ScenarioPosition,
        resource_fields: tuple[str, ...],
        resource_types: tuple[tuple[str, str], ...],
    ) -> None:
        fields_by_name = {field.name: field for field in method.request_schema.fields}
        types_by_field = dict(resource_types)
        for name in resource_fields:
            field = fields_by_name.get(name)
            if field is None:
                continue
            if not field.required and isinstance(field_value(request, field), Absent):
                continue
            value = resolve_resource_ref(
                field,
                scenario=scenario,
                resource_type=types_by_field.get(name),
            )
            if value is not None:
                request[field.name] = value


def _replace_placeholder(
    request: dict[str, JsonValue],
    placeholder: str,
    value: str,
    *,
    allowed_fields: tuple[str, ...] = (),
    fields: tuple[FieldSpec, ...] = (),
    primitive: str,
    resource_fields: tuple[str, ...] = (),
) -> bool:
    """Replace a model-provided carrier placeholder in-place.

    The base generator decides the carrier grammar.  This function only
    substitutes the unique runtime token, including inside repeated values.
    """

    allowed = set(allowed_fields)
    fields_by_name = {field.name: field for field in fields}
    occurrences = 0
    for name, item in request.items():
        count = _placeholder_count(item, placeholder)
        if not count:
            continue
        if allowed and name not in allowed:
            return False
        field = fields_by_name.get(name)
        explicitly_grounded = bool(allowed) and name in allowed
        if field is None or not _accepts_probe(
            field,
            primitive=primitive,
            resource_fields=resource_fields,
            explicitly_grounded=explicitly_grounded,
        ):
            return False
        occurrences += count
    if occurrences != 1:
        return False

    for name, item in request.items():
        replaced, item_changed = _replace_value_placeholder(item, placeholder, value)
        if item_changed:
            request[name] = replaced
    return True


def _has_placeholder(request: dict[str, JsonValue], placeholder: str) -> bool:
    return any(
        _placeholder_count(name, placeholder) > 0
        or _placeholder_count(item, placeholder) > 0
        for name, item in request.items()
    )


def _has_unresolved_placeholder(request: dict[str, JsonValue]) -> bool:
    return any(_has_placeholder(request, item) for item in RUNTIME_PLACEHOLDERS)


def _placeholder_count(value: JsonValue, placeholder: str) -> int:
    if isinstance(value, str):
        return value.count(placeholder)
    if isinstance(value, tuple):
        return sum(_placeholder_count(item, placeholder) for item in value)
    return 0


def _replace_value_placeholder(
    value: JsonValue,
    placeholder: str,
    replacement: str,
) -> tuple[JsonValue, bool]:
    if isinstance(value, str):
        if placeholder not in value:
            return value, False
        return value.replace(placeholder, replacement), True
    if isinstance(value, tuple):
        replaced: list[JsonValue] = []
        changed = False
        for item in value:
            new_item, item_changed = _replace_value_placeholder(
                item,
                placeholder,
                replacement,
            )
            replaced.append(new_item)
            changed = changed or item_changed
        return tuple(replaced), changed
    return value, False


def _fit_value(value: JsonValue, field: FieldSpec) -> JsonValue:
    if field.repeated and not isinstance(value, tuple):
        return (value,)
    return value


def _marker_safe(marker: str) -> str:
    """Make a QDL marker survive parser/error-message tokenization."""

    return re.sub(r"[^A-Za-z0-9_]+", "_", marker).strip("_") or "marker"


def _is_text_field(field: FieldSpec) -> bool:
    return field.type.lower() in {"string", "bytes", "url", "uri"}


def _accepts_probe(
    field: FieldSpec,
    *,
    primitive: str,
    resource_fields: tuple[str, ...] = (),
    explicitly_grounded: bool = False,
) -> bool:
    """Decide whether a field can carry the runtime probe.

    Explicit plan grounding may promote a semantically selected string field
    to an OOB URL carrier even when the transport schema calls it only a
    string.  Schema fallback remains stricter: without that grounding an OOB
    URL is written only to a field whose declared type is URL or URI.
    """

    if field.name in resource_fields or not _is_text_field(field):
        return False
    if field.enum_values:
        return False
    if primitive == "oob_event":
        return explicitly_grounded or field.type.lower() in {"url", "uri"}
    return field.type.lower() in {"string", "bytes"}


def _is_schema_fallback(
    field: FieldSpec,
    *,
    primitive: str,
    resource_fields: tuple[str, ...] = (),
) -> bool:
    if field.required or not _accepts_probe(
        field,
        primitive=primitive,
        resource_fields=resource_fields,
    ):
        return False
    return True
