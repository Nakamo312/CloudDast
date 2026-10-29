"""Deterministic QDL-to-Hypothesis grammar compilation.

The compiler is the only place where grammar facts become strategies.  Source
graphs and models emit facts; this module never evaluates model prose and never
creates findings.
"""

from __future__ import annotations

import hashlib
import json
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from hypothesis import HealthCheck, find, settings, target
from hypothesis import strategies as st
from hypothesis.errors import NoSuchExample
from hypothesis_jsonschema import from_schema

from cloud_dast.binding import validate_binding
from cloud_dast.contracts.grammar import (
    GrammarConstraint,
    GrammarFacts,
    GrammarFieldRule,
    GrammarSolution,
)
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.couplings import (
    FieldCoupling,
)
from cloud_dast.extensions import (
    ExecutionFeedback,
    PayloadStrategyCompiler,
    RequestSolver,
    TestCaseGenerator,
    VerificationPlan,
    runtime_placeholder,
)
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.schemas import (
    float_range,
    integer_range,
    is_float_type,
    is_integer_type,
)

_MAX_STRING_LENGTH = 256
_MAX_REPEATED_ITEMS = 4
_MAX_PARENT_DEPTH = 4
_DEFAULT_CANDIDATES = 4
_IDENTIFIER_ALPHABET = string.ascii_letters + string.digits + "_"

_FIND_SETTINGS = settings(
    derandomize=True,
    database=None,
    deadline=None,
    max_examples=100,
    suppress_health_check=[
        HealthCheck.data_too_large,
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
    ],
)


@dataclass(frozen=True, slots=True)
class CompiledGrammar:
    """The three composed strategy layers for one method."""

    schema: dict[str, object]
    rules: tuple[GrammarFieldRule, ...]
    structural: st.SearchStrategy[dict[str, JsonValue]]
    payload: st.SearchStrategy[dict[str, JsonValue]] | None
    strategy: st.SearchStrategy[dict[str, JsonValue]]

    def examples(
        self,
        count: int = _DEFAULT_CANDIDATES,
        *,
        minimum_complexity: int = -1,
    ) -> tuple[dict[str, JsonValue], ...]:
        """Return deterministic, increasingly complex shrunk examples."""

        if count <= 0:
            return ()
        examples: list[dict[str, JsonValue]] = []
        threshold = minimum_complexity
        for _ in range(count):
            try:
                example = find(
                    self.strategy,
                    lambda value: _complexity(value) > threshold,
                    settings=_FIND_SETTINGS,
                )
            except NoSuchExample:
                break
            examples.append(example)
            threshold = _complexity(example)
        return tuple(examples)

    def simpler_example(
        self,
        *,
        max_complexity: int,
        exclude: set[str] = frozenset(),
    ) -> dict[str, JsonValue] | None:
        """Return one schema-valid Hypothesis example below a complexity bound.

        Hypothesis performs the actual shrinking: strings move toward simple
        terminals, repeated values lose items, and optional structure becomes
        smaller.  ``exclude`` prevents a rejected candidate from being offered
        again at the same bound.
        """

        if max_complexity < 0:
            return None
        try:
            return find(
                self.strategy,
                lambda value: (
                    _complexity(value) <= max_complexity
                    and _example_key(value) not in exclude
                ),
                settings=_FIND_SETTINGS,
            )
        except NoSuchExample:
            return None


class _EmptyPayloadCompiler:
    """Structural-only fallback when the optional payload extension is absent."""

    @staticmethod
    def compile(
        sink_types: Sequence[str],
        dialects: Sequence[str],
        *,
        marker_placeholder: str = "",
    ) -> None:
        del sink_types, dialects, marker_placeholder
        return None


class GrammarCompiler:
    """Compile schema, payload grammars, and couplings into one strategy.

    Recursive schema-v2 payload grammars are compiled by
    ``PayloadCorpusCompiler`` and composed with the structural strategy here.
    """

    def __init__(
        self,
        payload_compiler: PayloadStrategyCompiler | None = None,
        request_solver: RequestSolver | None = None,
    ) -> None:
        self._payload_compiler = payload_compiler or _EmptyPayloadCompiler()
        self._request_solver = request_solver

    def compile(
        self,
        method: MethodSpec,
        facts: GrammarFacts | None = None,
        *,
        couplings: Sequence[FieldCoupling] = (),
        carrier_fields: Sequence[str] = (),
        placeholder: str = "",
    ) -> CompiledGrammar:
        fields = {field.name: field for field in method.request_schema.fields}
        rules = tuple(
            rule for rule in (facts or GrammarFacts()).fields if rule.field in fields
        )
        schema = _schema(method)
        structural = from_schema(schema).filter(
            lambda value: _oneof_is_valid(value, method)
        )
        payload = _payload_strategy(
            method,
            rules,
            carrier_fields=carrier_fields,
            placeholder=placeholder,
            payload_compiler=self._payload_compiler,
        )
        constraints = tuple(
            GrammarConstraint(
                field=constraint.field,
                operator=constraint.operator,
                value=constraint.value,
            )
            for rule in rules
            for constraint in rule.constraints
        )
        strategy = _combined_strategy(
            method,
            structural,
            payload,
            couplings=couplings,
            constraints=constraints,
            rules=rules,
            request_solver=self._request_solver,
        )
        return CompiledGrammar(
            schema=schema,
            rules=rules,
            structural=structural,
            payload=payload,
            strategy=strategy,
        )


def compile_plan_grammar(
    plan: VerificationPlan,
    method: MethodSpec,
    invariant: InvariantProjection,
    *,
    payload_compiler: PayloadStrategyCompiler | None = None,
    request_solver: RequestSolver | None = None,
) -> CompiledGrammar:
    """Compile exactly the Hypothesis strategy used by plan generation."""

    return GrammarCompiler(payload_compiler, request_solver).compile(
        method,
        GrammarFacts.from_plan(plan),
        couplings=_method_couplings(plan, method),
        carrier_fields=plan.probe_fields,
        placeholder=runtime_placeholder(plan, invariant),
    )


class GrammarGenerator:
    """Generate sink-aware candidates from deterministic grammar facts."""

    uses_feedback = True

    def __init__(
        self,
        seed_generator: TestCaseGenerator,
        *,
        max_candidates: int = _DEFAULT_CANDIDATES,
        payload_compiler: PayloadStrategyCompiler | None = None,
        request_solver: RequestSolver | None = None,
    ) -> None:
        self._seed_generator = seed_generator
        self._max_candidates = max_candidates
        self._payload_compiler = payload_compiler
        self._request_solver = request_solver

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
        seed = self._seed_generator.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )[0]
        compiled = GrammarCompiler(
            self._payload_compiler,
            self._request_solver,
        ).compile(
            method,
            GrammarFacts.from_plan(plan),
            couplings=_method_couplings(plan, method),
            carrier_fields=plan.probe_fields,
            placeholder=runtime_placeholder(plan, invariant),
        )
        return build_checks_from_grammar(
            seed,
            method,
            compiled,
            generator="grammar",
            count=self._max_candidates,
            include_identity=False,
        )


def build_checks_from_grammar(
    seed: Check,
    method: MethodSpec,
    compiled: CompiledGrammar,
    *,
    generator: str,
    count: int = _DEFAULT_CANDIDATES,
    include_identity: bool = True,
    identity_variants: tuple[tuple[str, ...], ...] = (),
) -> tuple[Check, ...]:
    """Turn shrunk grammar examples into canonical checks.

    ``identity_variants`` carries QDL-grounded ``valid_identity`` terms from
    the caller; the compiler never invents an identity, and the historical
    magic ``anonymous`` downgrade is gone.  Without grounded variants no
    identity candidate is produced.
    """

    if seed.seed_id is None:
        seed = seed.model_copy(
            update={
                "seed_id": hashlib.sha256(
                    seed.model_dump_json(exclude={"check_id"}).encode("utf-8")
                ).hexdigest(),
            }
        )
    fields = {field.name: field for field in method.request_schema.fields}
    checks: list[Check] = []
    seen = {(seed.request, seed.identities)}
    for index, values in enumerate(
        compiled.examples(
            count,
            minimum_complexity=_complexity(dict(seed.request)),
        )
    ):
        request = _merge_request(seed.request, values, fields)
        key = (request, seed.identities)
        if key in seen:
            continue
        seen.add(key)
        checks.append(
            _copy_check(
                seed,
                request=request,
                generator=generator,
                index=index,
            )
        )

    if include_identity:
        request = seed.request
        for index, identities in enumerate(identity_variants):
            if not identities or identities == seed.identities:
                continue
            key = (request, identities)
            if key in seen:
                continue
            seen.add(key)
            checks.append(
                _copy_check(
                    seed,
                    request=request,
                    generator=generator,
                    index=f"identity:{index}",
                    identities=identities,
                )
            )
    return tuple(checks)


def build_simpler_check(
    seed: Check,
    compiled: CompiledGrammar,
    *,
    method: MethodSpec,
    max_complexity: int,
    exclude: set[str] = frozenset(),
) -> Check | None:
    """Build one canonical check from a simpler Hypothesis example."""

    fields = {field.name: field for field in method.request_schema.fields}

    def is_acceptable(value: dict[str, JsonValue]) -> bool:
        request = _shrunk_request(seed.request, value, fields)
        return (
            _complexity(value) <= max_complexity
            and _example_key(value) not in exclude
            and _example_key(request) not in exclude
        )

    try:
        values = find(
            compiled.strategy,
            is_acceptable,
            settings=_FIND_SETTINGS,
        )
    except NoSuchExample:
        return None
    request = _shrunk_request(seed.request, values, fields)
    index = hashlib.sha256(_example_key(request).encode("utf-8")).hexdigest()
    return _copy_check(
        seed,
        request=request,
        generator="fuzzing",
        index=f"shrink:{index}",
    )


def _shrunk_request(
    seed_request: tuple[tuple[str, JsonValue], ...],
    values: Mapping[str, JsonValue],
    fields: Mapping[str, FieldSpec],
) -> tuple[tuple[str, JsonValue], ...]:
    """Merge a simpler example while retaining only required seed terminals."""

    request = {
        name: _normalise_json(value) for name, value in values.items() if name in fields
    }
    for name, value in seed_request:
        field = fields.get(name)
        if field is not None and field.required and name not in request:
            request[name] = value
    return tuple(request.items())


def _combined_strategy(
    method: MethodSpec,
    structural: st.SearchStrategy[dict[str, JsonValue]],
    payload: st.SearchStrategy[dict[str, JsonValue]] | None,
    *,
    couplings: Sequence[FieldCoupling],
    constraints: Sequence[GrammarConstraint],
    rules: Sequence[GrammarFieldRule],
    request_solver: RequestSolver | None,
) -> st.SearchStrategy[dict[str, JsonValue]]:
    @st.composite
    def compose(draw: st.DrawFn) -> dict[str, JsonValue]:
        request = draw(structural)
        if payload is not None:
            request = {**request, **draw(payload)}
        solution = _solve_request(
            request,
            method,
            couplings,
            constraints,
            request_solver,
        )
        if solution.status not in {"sat", "no-constraints"}:
            from hypothesis import assume

            assume(False)
        target(
            _goal_proximity(request, rules),
            label=f"grammar:{method.method_id}",
        )
        return solution.request

    return compose()


def _solve_request(
    request: dict[str, JsonValue],
    method: MethodSpec,
    couplings: Sequence[FieldCoupling],
    constraints: Sequence[GrammarConstraint],
    request_solver: RequestSolver | None,
) -> GrammarSolution:
    if request_solver is None:
        if couplings or constraints:
            raise RuntimeError(
                "grammar compilation with QDL constraints requires a request solver"
            )
        return GrammarSolution(dict(request), "no-constraints")
    return request_solver(request, method, couplings, constraints)


def _schema(method: MethodSpec) -> dict[str, object]:
    properties = {
        field.name: _field_schema(field) for field in method.request_schema.fields
    }
    required = [field.name for field in method.request_schema.fields if field.required]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _field_schema(field: FieldSpec) -> dict[str, object]:
    schema = _scalar_schema(field)
    if field.repeated:
        return {
            "type": "array",
            "items": schema,
            "minItems": 1 if field.required else 0,
            "maxItems": _MAX_REPEATED_ITEMS,
        }
    return schema


def _scalar_schema(field: FieldSpec) -> dict[str, object]:
    if field.enum_values:
        schema: dict[str, object] = {
            "type": _json_type(field),
            "enum": list(field.enum_values),
        }
    else:
        schema = {"type": _json_type(field)}

    if "bool" in field.type.lower():
        return schema
    if is_integer_type(field.type):
        bounds = integer_range(field.type)
        if bounds is not None:
            _bound_schema(schema, field, bounds)
        return schema
    if is_float_type(field.type):
        bounds = float_range(field.type)
        if bounds is not None:
            _bound_schema(schema, field, bounds)
        return schema
    if _is_text_field(field):
        schema["maxLength"] = _MAX_STRING_LENGTH
    return schema


def _bound_schema(
    schema: dict[str, object],
    field: FieldSpec,
    bounds: tuple[int, int] | tuple[float, float],
) -> None:
    low, high = bounds
    if field.minimum is not None:
        low = max(low, field.minimum)
    if field.maximum is not None:
        high = min(high, field.maximum)
    schema["minimum"] = low
    schema["maximum"] = high


def _json_type(field: FieldSpec) -> str | list[str]:
    if "bool" in field.type.lower():
        return "boolean"
    if is_integer_type(field.type):
        return "integer"
    if is_float_type(field.type):
        return "number"
    if _is_text_field(field):
        return "string"
    return ["null", "string"]


def _payload_strategy(
    method: MethodSpec,
    rules: Sequence[GrammarFieldRule],
    *,
    carrier_fields: Sequence[str],
    placeholder: str,
    payload_compiler: PayloadStrategyCompiler,
) -> st.SearchStrategy[dict[str, JsonValue]] | None:
    fields = {field.name: field for field in method.request_schema.fields}
    carriers = set(carrier_fields)
    strategies: dict[str, st.SearchStrategy[JsonValue]] = {}
    for rule in rules:
        field = fields.get(rule.field)
        if field is None or field.enum_values or not _is_text_field(field):
            continue
        scalar = (
            _carrier_strategy(placeholder, rule, payload_compiler)
            if placeholder and rule.field in carriers
            else _sink_strategy(rule, payload_compiler)
        )
        if field.repeated:
            scalar = st.lists(
                scalar,
                min_size=1,
                max_size=_MAX_REPEATED_ITEMS,
            ).map(tuple)
        strategies[rule.field] = scalar
    if not strategies:
        return None
    return st.fixed_dictionaries(strategies)


def _sink_strategy(
    rule: GrammarFieldRule,
    payload_compiler: PayloadStrategyCompiler,
) -> st.SearchStrategy[str]:
    filesystem = "filesystem" in rule.sink_types or "path" in rule.formats
    payload = payload_compiler.compile(
        (*rule.sink_types, *rule.formats),
        rule.dialects,
    )
    if filesystem:
        if payload is not None:
            return payload
    if "external_net" in rule.sink_types or "url" in rule.formats:
        return _url_strategy()
    if payload is not None:
        return payload
    if "identifier" in rule.formats:
        return st.text(
            alphabet=_IDENTIFIER_ALPHABET,
            min_size=1,
            max_size=32,
        )
    return _text_strategy(rule.dialects)


def _carrier_strategy(
    placeholder: str,
    rule: GrammarFieldRule,
    payload_compiler: PayloadStrategyCompiler,
) -> st.SearchStrategy[str]:
    filesystem = "filesystem" in rule.sink_types or "path" in rule.formats
    payload = payload_compiler.compile(
        (*rule.sink_types, *rule.formats),
        rule.dialects,
        marker_placeholder=placeholder,
    )
    if filesystem:
        if payload is not None:
            return payload
    if "external_net" in rule.sink_types or "url" in rule.formats:
        return _carrier_url_strategy(placeholder)
    if payload is not None:
        return payload
    # No grounded sink grammar: position the bare runtime token.  Wrapping it
    # in quotes would guess a quoted-literal carrier the facts never declared.
    return st.just(placeholder)


def _carrier_url_strategy(placeholder: str) -> st.SearchStrategy[str]:
    return st.builds(
        lambda scheme, host: f"{scheme}://{host}/{placeholder}",
        st.sampled_from(("http", "https")),
        st.sampled_from(("example.test", "host.test")),
    )


def _text_strategy(dialects: Sequence[str]) -> st.SearchStrategy[str]:
    tokens = ["a", "value", "😀Ω", "'", '"', "\\", ",", ";", "=", ":"]
    tokens.extend(_quote_tokens(dialects))
    return st.builds(
        lambda prefix, body, repetition, suffix: f"{prefix}{body * repetition}{suffix}"[
            :_MAX_STRING_LENGTH
        ],
        st.sampled_from(("", *_quote_tokens(dialects))),
        st.sampled_from(tokens),
        st.integers(min_value=1, max_value=8),
        st.sampled_from(("", *_quote_tokens(dialects))),
    )


def _path_strategy(dialects: Sequence[str]) -> st.SearchStrategy[str]:
    separators = _path_separators(dialects)
    return st.builds(
        lambda anchor, separator, depth, name, extension: (
            f"{anchor}{separator.join((('..',) * depth))}"
            f"{separator if depth else ''}{name}.{extension}"
        )[:_MAX_STRING_LENGTH],
        st.sampled_from(("/", "./")),
        st.sampled_from(separators),
        st.integers(min_value=0, max_value=_MAX_PARENT_DEPTH),
        st.sampled_from(("file", "document", "resource")),
        st.sampled_from(("txt", "pdf", "json")),
    )


def _url_strategy() -> st.SearchStrategy[str]:
    return st.builds(
        lambda scheme, host, path: f"{scheme}://{host}/{path}",
        st.sampled_from(("http", "https")),
        st.sampled_from(("example.test", "host.test")),
        _path_strategy(("posix",)),
    )


def _quote_tokens(dialects: Sequence[str]) -> tuple[str, ...]:
    quotes = {
        "ansi": "'",
        "single": "'",
        "double": '"',
        "backtick": "`",
        "none": "",
    }
    selected = tuple(
        dict.fromkeys(quotes[dialect] for dialect in dialects if dialect in quotes)
    )
    return selected or ("'", '"')


def _path_separators(dialects: Sequence[str]) -> tuple[str, ...]:
    separators = {
        "posix": "/",
        "unix": "/",
        "windows": "\\",
    }
    selected = tuple(
        dict.fromkeys(
            separators[dialect] for dialect in dialects if dialect in separators
        )
    )
    return selected or ("/", "\\")


def _method_couplings(
    plan: VerificationPlan,
    method: MethodSpec,
) -> tuple[FieldCoupling, ...]:
    from cloud_dast.couplings import (
        couplings_for_method,
    )

    return couplings_for_method(plan.couplings, method.method_id)


def _merge_request(
    seed_request: tuple[tuple[str, JsonValue], ...],
    values: Mapping[str, JsonValue],
    fields: Mapping[str, FieldSpec],
) -> tuple[tuple[str, JsonValue], ...]:
    request = dict(seed_request)
    for name, value in values.items():
        field = fields.get(name)
        if field is None:
            continue
        if field.oneof is not None:
            for other_name in tuple(request):
                other = fields.get(other_name)
                if other is not None and other.oneof == field.oneof:
                    del request[other_name]
        request[name] = _normalise_json(value)
    return tuple(request.items())


def _normalise_json(value: object) -> JsonValue:
    if isinstance(value, list):
        return tuple(_normalise_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_normalise_json(item) for item in value)
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _copy_check(
    seed: Check,
    *,
    request: tuple[tuple[str, JsonValue], ...],
    generator: str,
    index: int | str,
    identities: tuple[str, ...] | None = None,
) -> Check:
    payload = f"{seed.seed_id or seed.check_id}:{generator}:{index}"
    return seed.model_copy(
        update={
            "check_id": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "request": request,
            "identities": seed.identities if identities is None else identities,
            "generator": generator,
        }
    )


def _oneof_is_valid(value: Mapping[str, object], method: MethodSpec) -> bool:
    groups: dict[str, int] = {}
    for field in method.request_schema.fields:
        if field.oneof is None or value.get(field.name) is None:
            continue
        groups[field.oneof] = groups.get(field.oneof, 0) + 1
    return all(count == 1 for count in groups.values())


def _is_text_field(field: FieldSpec) -> bool:
    return field.type.lower() in {"string", "bytes", "url", "uri"}


def _complexity(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, int):
        return abs(value)
    if isinstance(value, float):
        return int(abs(value))
    if isinstance(value, str):
        return len(value)
    if isinstance(value, Mapping):
        return sum(_complexity(item) for item in value.values())
    if isinstance(value, list | tuple):
        return sum(_complexity(item) for item in value)
    return 0


def _example_key(value: Mapping[str, object]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _goal_proximity(
    request: Mapping[str, object],
    rules: Sequence[GrammarFieldRule],
) -> float:
    score = 0.0
    for rule in rules:
        value = request.get(rule.field)
        if value is None:
            continue
        score += bool(rule.sink_types) + bool(rule.formats)
        if isinstance(value, str):
            score += min(len(value) / _MAX_STRING_LENGTH, 1.0)
            score += any(dialect in value for dialect in rule.dialects)
    return score


__all__ = [
    "CompiledGrammar",
    "GrammarCompiler",
    "GrammarConstraint",
    "GrammarFacts",
    "GrammarFieldRule",
    "GrammarGenerator",
    "build_checks_from_grammar",
    "build_simpler_check",
    "compile_plan_grammar",
]
