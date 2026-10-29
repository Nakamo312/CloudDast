"""Composition factories for LangChain model runtimes."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from cloud_dast.infrastructure.runtime import LangChainModelClient
from cloud_dast.infrastructure.secrets import secret_value


def unwrap_openai_response(response: httpx.Response) -> None:
    """Normalize a nested chat-completion response envelope for the SDK."""

    try:
        response.read()
        payload: Any = response.json()
    except (ValueError, httpx.ResponseNotRead):
        return
    if not isinstance(payload, dict):
        return
    nested = payload.get("response")
    if not isinstance(nested, dict) or not isinstance(nested.get("choices"), list):
        return
    if payload.get("choices") is not None:
        return

    normalized = json.dumps(nested, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    response._content = normalized  # noqa: SLF001 - httpx response hook contract
    response.headers["content-length"] = str(len(normalized))


def make_model_client(*, required: bool = False) -> LangChainModelClient | None:
    """Build a LangChain-backed model capability from deployment settings."""

    endpoint = os.environ.get("CLOUD_DAST_MODEL_URL", "").strip()
    if not endpoint:
        if required:
            raise RuntimeError(
                "CLOUD_DAST_MODEL_URL is required for model-backed live runs"
            )
        return None
    model_id = os.environ.get("CLOUD_DAST_MODEL_ID", "").strip()
    if not model_id:
        raise RuntimeError("CLOUD_DAST_MODEL_ID is required for model-backed runs")
    token = model_token()
    if required and not token:
        raise RuntimeError(
            "CLOUD_DAST_MODEL_TOKEN_FILE or CLOUD_DAST_MODEL_TOKEN is required "
            "for model-backed live runs"
        )
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as error:
        raise RuntimeError(
            "install langchain-openai for model-backed live runs"
        ) from error
    api_mode = (
        os.environ.get(
            "CLOUD_DAST_MODEL_API",
            os.environ.get("CLOUD_DAST_MODEL_WIRE_API", "chat"),
        )
        .strip()
        .lower()
    )
    if api_mode not in {"", "chat", "responses"}:
        raise RuntimeError("CLOUD_DAST_MODEL_API must be one of: chat, responses")
    reasoning_effort = os.environ.get("CLOUD_DAST_MODEL_REASONING_EFFORT", "").strip()
    http_client = httpx.Client(
        event_hooks={"response": [unwrap_openai_response]},
    )
    model = ChatOpenAI(
        model=model_id,
        base_url=endpoint,
        api_key=token or "unused",
        timeout=float(os.environ.get("CLOUD_DAST_MODEL_TIMEOUT", "60")),
        max_retries=int(os.environ.get("CLOUD_DAST_MODEL_RETRIES", "2")),
        use_responses_api=api_mode == "responses",
        reasoning_effort=reasoning_effort or None,
        http_client=http_client,
    )
    return LangChainModelClient(model)


def model_token() -> str:
    """Read a model credential from a mounted secret or local env fallback."""

    return secret_value("CLOUD_DAST_MODEL_TOKEN")
