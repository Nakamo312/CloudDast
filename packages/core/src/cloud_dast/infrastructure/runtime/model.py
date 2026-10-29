"""LangChain adapter for the structured model capability."""

from __future__ import annotations

import json
import logging
import re
from time import monotonic
from typing import Any

from pydantic import BaseModel

from cloud_dast.ports import MAX_MODEL_PROMPT_BYTES, ModelRequest, ModelResponse

logger = logging.getLogger("cloud_dast.model")

_SINGLE_QUOTED_STRING = re.compile(r"(?<!\\)'((?:\\.|[^'\\])*)'")
_UNQUOTED_KEY = re.compile(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*:)")


class LangChainModelClient:
    """Adapt an injected LangChain chat model to the DAST model capability.

    When a Pydantic ``response_type`` is supplied, the adapter asks the provider
    for native structured output through ``response_format``.  A deterministic
    JSON repair parser remains as a compatibility layer for providers and test
    models that return prose-wrapped or slightly malformed JSON.
    """

    def __init__(
        self,
        model: Any,
        *,
        max_prompt_bytes: int = MAX_MODEL_PROMPT_BYTES,
    ) -> None:
        if max_prompt_bytes <= 0:
            raise ValueError("max_prompt_bytes must be positive")
        self._model = model
        self._max_prompt_bytes = max_prompt_bytes

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type: type[BaseModel] | None = None,
    ) -> ModelResponse:
        started = monotonic()
        logger.info(
            "model_request_started request_id=%s structured=%s",
            request.request_id,
            response_type is not None,
        )
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
        except ImportError as error:
            raise RuntimeError(
                "install langchain-core for model-backed runs"
            ) from error
        model = self._model
        native_response_format = False
        schema = (
            response_type.model_json_schema() if response_type is not None else None
        )
        if response_type is not None:
            bind = getattr(model, "bind", None)
            if callable(bind):
                response_format = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": response_type.__name__,
                        "schema": schema,
                    },
                }
                try:
                    model = bind(response_format=response_format)
                    native_response_format = True
                except (TypeError, ValueError):
                    logger.warning(
                        "model_structured_output_unavailable request_id=%s",
                        request.request_id,
                    )

        prompt_payload: dict[str, Any] = {
            "task": request.task,
            "instruction": request.instruction,
        }
        # The schema stays in the prompt even when the provider claims native
        # structured output: not every backend (e.g. OpenAI-compatible
        # endpoints) enforces response_format strictly, and a model that
        # cannot see the schema invents its own response shapes.  The prefix
        # (task, instruction, schema) is stable per strategy, so provider
        # prefix caching is unaffected.
        if response_type is not None:
            prompt_payload["response_schema"] = schema
        prompt_payload["context"] = request.context
        prompt = json.dumps(
            prompt_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        prompt_bytes = len(prompt.encode("utf-8"))
        if prompt_bytes > self._max_prompt_bytes:
            raise ValueError(
                "model prompt exceeds the byte cap: "
                f"{prompt_bytes} > {self._max_prompt_bytes}"
            )
        messages = [
            SystemMessage(
                content="Return only a JSON object matching the requested schema."
            ),
            HumanMessage(content=prompt),
        ]

        if request.budget is not None:
            model = model.bind(max_tokens=request.budget.max_output_tokens)

        try:
            response = model.invoke(messages)
        except Exception:
            logger.exception(
                "model_request_failed request_id=%s duration_ms=%.1f native_schema=%s",
                request.request_id,
                (monotonic() - started) * 1000,
                native_response_format,
            )
            raise

        parsed = _native_parsed(response, response_type)
        content = _message_content(response)
        if parsed is None:
            parsed = _parse_json(content)

        # Extract token usage from the provider response.
        usage = _extract_token_usage(response)
        if usage is None:
            raise RuntimeError("model token usage unavailable; accounting is unknown")
        input_tokens, cached_input_tokens, output_tokens = usage

        result = ModelResponse(
            structured=parsed,
            content=content,
            model_id=str(getattr(self._model, "model_name", "unknown")),
            request_id=request.request_id,
            finish_reason=str(
                getattr(response, "response_metadata", {}).get("finish_reason", "")
            )
            or None,
            input_tokens=input_tokens,
            cached_input_tokens=cached_input_tokens,
            output_tokens=output_tokens,
        )
        if request.budget is not None and (
            result.input_tokens > request.budget.max_input_tokens
            or result.output_tokens > request.budget.max_output_tokens
        ):
            result = result.model_copy(
                update={"structured": None, "finish_reason": "token_budget_exceeded"}
            )
        if result.structured is None:
            logger.warning(
                "model_request_unstructured request_id=%s duration_ms=%.1f native_schema=%s",
                request.request_id,
                (monotonic() - started) * 1000,
                native_response_format,
            )
        logger.info(
            "model_request_completed request_id=%s structured=%s "
            "duration_ms=%.1f native_schema=%s cached_input_tokens=%d",
            request.request_id,
            result.structured is not None,
            (monotonic() - started) * 1000,
            native_response_format,
            cached_input_tokens,
        )
        return result


def _extract_token_usage(response: Any) -> tuple[int, int, int] | None:
    """Use complete provider usage before SDK defaults can invent zero counts."""

    metadata = getattr(response, "response_metadata", None)
    if isinstance(metadata, dict) and (
        "usage" in metadata or "token_usage" in metadata
    ):
        usage = metadata["usage"] if "usage" in metadata else metadata["token_usage"]
        if not isinstance(usage, dict):
            return None
        input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
        output_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
        details = usage.get("prompt_tokens_details", usage.get("input_token_details"))
    else:
        usage = getattr(response, "usage_metadata", None)
        if not isinstance(usage, dict):
            return None
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        details = usage.get("input_token_details")
    if not all(
        type(value) is int and value >= 0 for value in (input_tokens, output_tokens)
    ):
        return None
    return input_tokens, _cached_tokens(details), output_tokens


def _cached_tokens(details: Any) -> int:
    """Read cached input tokens from provider-specific usage details."""

    if not isinstance(details, dict):
        return 0
    for key in ("cached_tokens", "cache_read", "cached_input_tokens"):
        value = details.get(key)
        if isinstance(value, int):
            return value
    return 0


def _native_parsed(
    response: Any, response_type: type[BaseModel] | None
) -> dict[str, Any] | None:
    if response_type is None:
        return None
    additional = getattr(response, "additional_kwargs", {})
    parsed = additional.get("parsed") if isinstance(additional, dict) else None
    if isinstance(parsed, response_type):
        return parsed.model_dump(mode="json")
    if isinstance(parsed, dict):
        return parsed
    return None


def _message_content(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return str(content)


def _parse_json(content: str) -> Any:
    text = _extract_json(content)
    for candidate in (text, _repair_json(text)):
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


def _extract_json(content: str) -> str:
    text = content.strip().lstrip("﻿")
    if text.startswith("```"):
        for prefix in ("```json", "```JSON", "```"):
            if text.startswith(prefix):
                text = text[len(prefix) :].lstrip()
                break
        if text.endswith("```"):
            text = text[:-3].rstrip()
        return text

    span = _balanced_json_span(text)
    return text[span[0] : span[1]] if span is not None else text


def _balanced_json_span(text: str) -> tuple[int, int] | None:
    start = next(
        (index for index, character in enumerate(text) if character in "{["),
        None,
    )
    if start is None:
        return None
    opening = text[start]
    closing = "}" if opening == "{" else "]"
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
        elif character in "}]":
            depth -= 1
            if depth == 0 and character == closing:
                return start, index + 1
    return None


def _repair_json(text: str) -> str:
    text = (
        text.replace("“", '"')
        .replace("”", '"')
        .replace("‘", "'")
        .replace("’", "'")
        .replace("﻿", "")
    )
    text = _remove_json_comments(text)
    text = _replace_non_json_constants(text)
    text = _single_quotations_to_double(text)
    text = _quote_unquoted_keys(text)
    text = _remove_trailing_commas(text)
    text = _escape_control_characters_in_strings(text)
    return text


def _remove_json_comments(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if in_string:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            result.append(character)
            index += 1
            continue
        if character == "/" and index + 1 < len(text):
            if text[index + 1] == "/":
                index += 2
                while index < len(text) and text[index] not in "\r\n":
                    index += 1
                continue
            if text[index + 1] == "*":
                index += 2
                while index + 1 < len(text):
                    if text[index] == "*" and text[index + 1] == "/":
                        index += 2
                        break
                    index += 1
                else:
                    index = len(text)
                continue
        result.append(character)
        index += 1
    return "".join(result)


def _replace_non_json_constants(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    replacements = {
        "None": "null",
        "True": "true",
        "False": "false",
        "NaN": "null",
        "Infinity": "null",
        "-Infinity": "null",
    }
    while index < len(text):
        character = text[index]
        if in_string:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            result.append(character)
            index += 1
            continue
        for source, target in replacements.items():
            if text.startswith(source, index):
                result.append(target)
                index += len(source)
                break
        else:
            result.append(character)
            index += 1
    return "".join(result)


def _single_quotations_to_double(text: str) -> str:
    return _SINGLE_QUOTED_STRING.sub(lambda match: f'"{match.group(1)}"', text)


def _quote_unquoted_keys(text: str) -> str:
    return _UNQUOTED_KEY.sub(
        lambda match: f'{match.group(1)}"{match.group(2)}"{match.group(3)}', text
    )


def _remove_trailing_commas(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if in_string:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        result.append(character)
        index += 1
    return "".join(result)


def _escape_control_characters_in_strings(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                result.append(character)
                escaped = False
                continue
            if character == "\\":
                result.append(character)
                escaped = True
                continue
            if character == '"':
                result.append(character)
                in_string = False
                continue
            if character == "\n":
                result.append("\\n")
            elif character == "\r":
                result.append("\\r")
            elif character == "\t":
                result.append("\\t")
            elif ord(character) < 0x20:
                result.append(f"\\u{ord(character):04x}")
            else:
                result.append(character)
            continue
        result.append(character)
        if character == '"':
            in_string = True
    return "".join(result)
