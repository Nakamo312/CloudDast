"""Model-backed request generator for norm-directed exploration.

The strategy contains no vulnerability catalogue and no fixed payload list.
It gives the model the request schema, the target QDL norm, and the seed
request, then validates returned values against that schema.  The model
proposes hypotheses; deterministic execution and oracles decide the result.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from cloud_dast.api import (
    DEFAULT_SLICE_BUDGET,
    NormView,
    SliceBudget,
    build_execution_feedback_view,
    build_slice,
    estimate_tokens,
)
from cloud_dast.binding import validate_binding
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.couplings import (
    couplings_for_method,
)
from cloud_dast.extensions import (
    OOB_URL_PLACEHOLDER,
    PROBE_MARKER_PLACEHOLDER,
    ExecutionFeedback,
    TestCaseGenerator,
    VerificationPlan,
)
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.schemas import is_float_type, is_integer_type
from cloud_dast.ports import ModelClient, ModelRequest
from cloud_dast.qdl.graph import (
    STRUCT_SCHEMAS,
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
)

logger = logging.getLogger("cloud_dast.generators.llm")


class LlmGenerator:
    """Generate schema-valid request candidates with a constrained model call."""

    uses_feedback = True

    def __init__(
        self,
        model_client: ModelClient | None,
        seed_generator: TestCaseGenerator | None = None,
        *,
        task: str = "generate_test_case",
        instruction: str | None = None,
        generator: str = "llm",
        slice_budget: SliceBudget = DEFAULT_SLICE_BUDGET,
    ) -> None:
        self._model_client = model_client
        if seed_generator is None:
            raise ValueError("LLM generator requires an explicit seed generator")
        self._seed_generator = seed_generator
        self._task = task
        self._instruction = instruction
        self._generator = generator
        self._slice_budget = slice_budget
        self._model_failure_warning_emitted = False

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
        seed = self._generate_seed(plan, method, invariant, scenario)
        if self._model_client is None:
            return (seed,)

        method_couplings = tuple(
            (
                coupling.left.args[1].value,
                coupling.right.args[1].value,
                coupling.operator,
            )
            for coupling in couplings_for_method(plan.couplings, method.method_id)
        )
        placeholders = _payload_placeholders(NormView.from_invariant(invariant))
        instruction = self._instruction or _instruction(
            placeholders,
        )
        if feedback is not None and feedback:
            instruction = _with_execution_feedback_instruction(instruction)
        feedback_view = (
            build_execution_feedback_view(feedback)
            if feedback is not None and feedback
            else None
        )
        slice_ = build_slice(
            _norm_graph(invariant),
            actions=(method.method_id,),
            evidence=feedback_view,
            budget=self._slice_budget,
        )
        schema = _schema_slice(
            method,
            max_tokens=max(
                0,
                self._slice_budget.max_tokens - slice_.token_estimate,
            ),
            bytes_per_token=self._slice_budget.bytes_per_token,
        )
        plan_context = {
            "probe_fields": list(plan.probe_fields),
            "seed_hints": [list(item) for item in plan.seed_hints],
            "couplings": [list(item) for item in method_couplings],
        }
        if self._generator == "grammar":
            plan_context["sink_types"] = [list(item) for item in plan.sink_types]
        context = {
            **slice_.context(),
            "schema": schema,
            "invariant": {
                "invariant_id": invariant.invariant_id,
                "norm_id": invariant.norm_id,
                "statement": invariant.statement,
            },
            "scenario": {
                "scenario_id": scenario.scenario_id,
                "profile": scenario.profile.model_dump(mode="json"),
                "stand": scenario.stand.model_dump(mode="json"),
            },
            "plan": plan_context,
            "seed_request": dict(seed.request),
        }
        # Keep the generator's established prompt key: the slice still bounds
        # and hashes this evidence, only the context name stays stable.
        feedback_payload = context.pop("evidence", None)
        if feedback_payload is not None:
            context["execution_feedback"] = feedback_payload
        if placeholders:
            context["payload_placeholders"] = placeholders
        logger.debug(
            "llm_generator_slice task=%s slice_hash=%s truncated=%s tokens=%d",
            self._task,
            slice_.slice_hash,
            slice_.truncated,
            slice_.token_estimate,
        )

        model_request = ModelRequest(
            task=self._task,
            instruction=instruction,
            context=context,
        )
        from cloud_dast_llm.proposals import LlmGeneratedChecks

        try:
            response = self._model_client.complete(
                model_request,
                response_type=LlmGeneratedChecks,
            )
        except Exception as error:
            self._warn_model_failure(error, model_request.request_id)
            return (seed,)
        generated = _validate_checks(response.structured)
        if generated is None or not generated.checks:
            return (seed,)

        fields = {field.name: field for field in method.request_schema.fields}
        checks: list[Check] = []
        for candidate in generated.checks:
            request = _merge_request(
                seed.request,
                candidate.request,
                fields,
                couplings=method_couplings,
                resource_fields=plan.resource_params,
            )
            if request is None or request == seed.request:
                continue
            checks.append(
                seed.model_copy(
                    update={
                        "check_id": uuid4().hex,
                        "request": request,
                        "generator": self._generator,
                    }
                )
            )
        return tuple(checks) or (seed,)

    def _warn_model_failure(self, error: Exception, request_id: str) -> None:
        if self._model_failure_warning_emitted:
            return
        logger.warning(
            "llm_generator_model_failed task=%s request_id=%s error_type=%s "
            "fallback=template",
            self._task,
            request_id,
            type(error).__name__,
        )
        self._model_failure_warning_emitted = True

    def _generate_seed(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
    ) -> Check:
        return self._seed_generator.generate(
            plan,
            method,
            invariant,
            scenario,
        )[0]


_INSTRUCTION_BASE = (
    "Generate diverse candidate request values for the supplied API method so "
    "the target QDL norm can be tested. Use only fields from the supplied "
    "schema and values that fit each field's declared type, enum, and "
    "repetition. Do not invent field names. Do not rely on a predefined "
    "vulnerability catalogue; reason from the norm, field semantics, scenario, "
    "and the seed request."
)


def _payload_placeholders(norm: NormView | None) -> dict[str, str]:
    if norm is None or norm.marker is None:
        return {}
    if norm.primitive == "marker":
        return {"probe_marker": PROBE_MARKER_PLACEHOLDER}
    if norm.primitive == "oob_event":
        return {"oob_url": OOB_URL_PLACEHOLDER}
    return {}


_DECLARATION_TYPES = {
    "action": "Action",
    "attacker": "Subject",
    "flow": "Flow",
    "norm": "Norm",
    "object": "Resource",
    "principal": "Principal",
    "resource": "Resource",
    "resource_type": "ResourceType",
    "sink": "Sink",
    "subject": "Subject",
    "victim": "Subject",
    "witness": "Witness",
}
_STRUCT_SCHEMAS_BY_NAME = {schema.name: schema for schema in STRUCT_SCHEMAS}


def _norm_graph(invariant: InvariantProjection) -> QdlGraph:
    """Wrap the invariant's QDL norm for transport in a bounded slice.

    This is a transport projection, not a second formal model: the norm fact
    travels unchanged and only receives the ``is`` declarations its own
    references need to stay self-contained outside the source graph.
    """

    if invariant.norm_fact is None:
        return QdlGraph()
    declarations: dict[str, Fact] = {}
    _declare_references(
        invariant.norm_fact.args,
        invariant.norm_fact.predicate.definition.arguments,
        context=invariant.norm_fact.context,
        declarations=declarations,
    )
    facts = (invariant.norm_fact, *(declarations[key] for key in sorted(declarations)))
    return QdlGraph(
        facts=facts,
    )


def _declare_references(
    terms: object,
    schemas: tuple[ArgumentSchema, ...],
    *,
    context: Context,
    declarations: dict[str, Fact],
) -> None:
    if not isinstance(terms, tuple):
        return
    for term, schema in zip(terms, schemas, strict=True):
        type_name = _DECLARATION_TYPES.get(schema.name, "Term")
        if isinstance(term, Struct):
            struct_schema = _STRUCT_SCHEMAS_BY_NAME[term.name]
            if schema.reference:
                _declare(
                    term,
                    type_name=type_name,
                    context=context,
                    declarations=declarations,
                )
            _declare_references(
                term.args,
                struct_schema.all_arguments[: len(term.args)],
                context=context,
                declarations=declarations,
            )
        elif isinstance(term, Atom) and schema.reference:
            _declare(
                term,
                type_name=type_name,
                context=context,
                declarations=declarations,
            )


def _declare(
    term: Atom | Struct,
    *,
    type_name: str,
    context: Context,
    declarations: dict[str, Fact],
) -> None:
    key = canonical_json(term)
    if key in declarations:
        return
    declarations[key] = Fact(
        context=context,
        predicate=Predicate.from_name("is"),
        args=(term, Atom(value=type_name)),
    )


def _schema_slice(
    method: MethodSpec,
    *,
    max_tokens: int,
    bytes_per_token: int,
) -> dict[str, Any]:
    """Render a token-bounded schema slice of the service contract."""

    fields: list[dict[str, Any]] = []
    truncated = False
    for field in method.request_schema.fields:
        candidate = [*fields, field.model_dump(mode="json")]
        payload = {"method_id": method.method_id, "fields": candidate}
        if estimate_tokens(payload, bytes_per_token=bytes_per_token) > max_tokens:
            truncated = True
            break
        fields = candidate
    payload: dict[str, Any] = {
        "method_id": method.method_id,
        "fields": fields,
    }
    if truncated:
        payload["truncated"] = True
    return payload


def _instruction(placeholders: dict[str, str]) -> str:
    instruction = _INSTRUCTION_BASE
    if "probe_marker" in placeholders:
        instruction += (
            " This norm needs a unique runtime canary: embed "
            f"{PROBE_MARKER_PLACEHOLDER} exactly at the carrier position."
        )
    if "oob_url" in placeholders:
        instruction += (
            f" This norm needs an outbound URL carrier: use {OOB_URL_PLACEHOLDER}."
        )
    return instruction + " Return only JSON matching the schema."


def _with_execution_feedback_instruction(instruction: str) -> str:
    return instruction + (
        " Use execution_feedback as bounded evidence from earlier executions: "
        "compare prior requests, responses, traces, and resource states, then "
        "propose the next candidate that tests a materially different "
        "schema-valid hypothesis. Recorded verdicts and proximity are guidance "
        "from deterministic oracles, not model-authored conclusions."
    )


def _validate_checks(structured: object) -> object | None:
    from cloud_dast_llm.proposals import LlmGeneratedChecks

    if isinstance(structured, LlmGeneratedChecks):
        return structured
    if isinstance(structured, dict):
        try:
            return LlmGeneratedChecks.model_validate(structured)
        except ValidationError:
            return None
    return None


def _merge_request(
    seed: tuple[tuple[str, JsonValue], ...],
    values: dict[str, JsonValue],
    fields: dict[str, FieldSpec],
    *,
    couplings: tuple[tuple[str, str, str], ...] = (),
    resource_fields: tuple[str, ...] = (),
) -> tuple[tuple[str, JsonValue], ...] | None:
    """Merge model values only when the complete request remains schema-valid."""

    merged = dict(seed)
    protected_fields = set(resource_fields)
    for name, value in values.items():
        if name in protected_fields:
            continue
        field = fields.get(name)
        if field is None or value is None:
            continue
        fitted = _fit_value(value, field)
        if fitted is _INVALID:
            return None
        merged[name] = fitted
    if not _oneof_valid(merged, fields):
        return None
    if not _couplings_hold(merged, couplings):
        return None
    return tuple(merged.items())


def _fit_value(value: JsonValue, field: FieldSpec) -> JsonValue | object:
    if field.repeated and not isinstance(value, tuple):
        value = (value,)
    if not isinstance(value, tuple):
        return _fit_scalar(value, field)
    if len(value) > _MAX_REPEATED_LENGTH:
        return _INVALID
    fitted: list[JsonValue] = []
    for item in value:
        item_value = _fit_scalar(item, field)
        if item_value is _INVALID:
            return _INVALID
        fitted.append(item_value)
    return tuple(fitted)


def _fit_scalar(value: JsonValue, field: FieldSpec) -> JsonValue | object:
    if field.enum_values:
        return value if value in field.enum_values else _INVALID

    field_type = field.type.lower()
    if "bool" in field_type:
        return value if type(value) is bool else _INVALID
    if is_integer_type(field_type):
        if type(value) is not int or not _within_bounds(value, field):
            return _INVALID
        return value
    if is_float_type(field_type):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return _INVALID
        if not _within_bounds(value, field):
            return _INVALID
        return value
    if "string" in field_type or "bytes" in field_type:
        if not isinstance(value, str) or len(value) > _MAX_STRING_LENGTH:
            return _INVALID
        return value
    return _INVALID


def _within_bounds(value: int | float, field: FieldSpec) -> bool:
    if field.minimum is not None and value < field.minimum:
        return False
    if field.maximum is not None and value > field.maximum:
        return False
    return True


def _oneof_valid(
    request: dict[str, JsonValue],
    fields: dict[str, FieldSpec],
) -> bool:
    selected: dict[str, str] = {}
    for name, value in request.items():
        field = fields.get(name)
        if field is None or field.oneof is None or value is None:
            continue
        current = selected.setdefault(field.oneof, name)
        if current != name:
            return False
    return True


def _couplings_hold(
    request: dict[str, JsonValue],
    couplings: tuple[tuple[str, str, str], ...],
) -> bool:
    for left, right, operator in couplings:
        if left not in request or right not in request:
            continue
        left_value = request[left]
        right_value = request[right]
        if left_value is None or right_value is None:
            continue
        try:
            holds = {
                "eq": left_value == right_value,
                "ne": left_value != right_value,
                "lt": left_value < right_value,
                "le": left_value <= right_value,
                "gt": left_value > right_value,
                "ge": left_value >= right_value,
            }[operator]
        except (KeyError, TypeError):
            return False
        if not holds:
            return False
    return True


_INVALID = object()
_MAX_STRING_LENGTH = 4096
_MAX_REPEATED_LENGTH = 32
