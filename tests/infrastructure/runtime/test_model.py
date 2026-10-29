from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel

from cloud_dast.composition import make_model_client
from cloud_dast.composition.model import unwrap_openai_response


def test_model_client_is_optional_for_offline_composition(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_MODEL_URL", raising=False)

    assert make_model_client() is None


def test_model_client_required_mode_reports_configuration_gap(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_MODEL_URL", raising=False)

    with pytest.raises(RuntimeError, match="CLOUD_DAST_MODEL_URL"):
        make_model_client(required=True)


class SimpleResponse(BaseModel):
    value: str


def test_nested_response_envelope_is_normalized_for_openai_sdk() -> None:
    response = httpx.Response(
        200,
        json={
            "key": "DO_NOT_NEED_KEY",
            "choices": None,
            "response": {
                "id": "completion-1",
                "object": "chat.completion",
                "model": "glm-5-3",
                "choices": [{"index": 0, "message": {"content": "OK"}}],
            },
        },
        request=httpx.Request("POST", "https://example.test/v1/chat/completions"),
    )

    unwrap_openai_response(response)

    assert response.json() == {
        "id": "completion-1",
        "object": "chat.completion",
        "model": "glm-5-3",
        "choices": [{"index": 0, "message": {"content": "OK"}}],
    }


def test_envelope_normalizer_preserves_ordinary_openai_payload() -> None:
    response = httpx.Response(
        200,
        json={
            "id": "completion-1",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"content": "OK"}}],
        },
        request=httpx.Request("POST", "https://example.test/v1/chat/completions"),
    )
    original = response.content

    unwrap_openai_response(response)

    assert response.content == original


def test_json_parser_extracts_and_repairs_model_output() -> None:
    from cloud_dast.infrastructure.runtime.model import _parse_json

    cases = {
        "plain": '{"value": "ok"}',
        "fenced": '```json\n{"value": "ok"}\n```',
        "prose_wrapped": 'Here is JSON:\n{"value": "ok"}\nDone.',
        "trailing_comma": '{"value": "ok",}',
        "smart_quotes": "{'value': ‘ok’}",
        "raw_newline": '{"value": "first\nsecond"}',
        "python_constants": '{"value": null, "enabled": True, "disabled": False}',
        "comment": '{\n  // comment\n  "value": "ok"\n}',
        "unquoted_key": '{value: "ok"}',
    }

    expected_values = {
        "raw_newline": "first\nsecond",
        "python_constants": None,
    }
    for name, content in cases.items():
        assert _parse_json(content) is not None, name
        assert _parse_json(content).get("value") == expected_values.get(name, "ok"), (
            name
        )


def test_model_client_uses_native_structured_output() -> None:
    from cloud_dast.infrastructure.runtime.model import LangChainModelClient
    from cloud_dast.ports import ModelRequest

    class BoundModel:
        def __init__(self) -> None:
            self.response_format = None

        def bind(self, **kwargs):
            self.response_format = kwargs.get("response_format")
            return self

        def invoke(self, messages):
            return type(
                "Response",
                (),
                {
                    "content": "not json",
                    "additional_kwargs": {"parsed": SimpleResponse(value="native")},
                    "response_metadata": {
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                    },
                },
            )()

    model = BoundModel()
    response = LangChainModelClient(model).complete(
        ModelRequest(task="test"),
        response_type=SimpleResponse,
    )

    assert model.response_format == {
        "type": "json_schema",
        "json_schema": {
            "name": "SimpleResponse",
            "schema": SimpleResponse.model_json_schema(),
        },
    }
    assert response.structured == {"value": "native"}


def test_model_client_puts_stable_prompt_prefix_before_context() -> None:
    from cloud_dast.infrastructure.runtime.model import LangChainModelClient
    from cloud_dast.ports import ModelRequest

    class BoundModel:
        def bind(self, **kwargs):
            return self

        def invoke(self, messages):
            self.messages = messages
            return SimpleNamespace(
                content="not json",
                additional_kwargs={"parsed": SimpleResponse(value="native")},
                response_metadata={
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                },
            )

    model = BoundModel()
    LangChainModelClient(model).complete(
        ModelRequest(
            task="formal_grounding",
            instruction="stable instruction",
            context={"graph": {"facts": []}},
        ),
        response_type=SimpleResponse,
    )

    prompt = model.messages[1].content
    payload = json.loads(prompt)

    assert list(payload) == ["task", "instruction", "response_schema", "context"]
    assert payload["response_schema"] == SimpleResponse.model_json_schema()


def test_model_client_rejects_prompt_byte_overflow_before_invoke() -> None:
    from cloud_dast.infrastructure.runtime.model import LangChainModelClient
    from cloud_dast.ports import ModelRequest

    class ModelMustNotRun:
        def invoke(self, messages):
            raise AssertionError("an oversized prompt must not reach the model")

    with pytest.raises(ValueError, match="model prompt exceeds the byte cap"):
        LangChainModelClient(ModelMustNotRun(), max_prompt_bytes=8).complete(
            ModelRequest(task="test", context={"value": "0123456789"})
        )


def test_model_client_extracts_cached_input_tokens() -> None:
    from cloud_dast.infrastructure.runtime.model import _extract_token_usage

    langchain_response = SimpleNamespace(
        usage_metadata={
            "input_tokens": 100,
            "output_tokens": 20,
            "input_token_details": {"cache_read": 80},
        },
        response_metadata={},
    )
    openai_response = SimpleNamespace(
        usage_metadata=None,
        response_metadata={
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 30,
                "prompt_tokens_details": {"cached_tokens": 150},
            }
        },
    )

    assert _extract_token_usage(langchain_response) == (100, 80, 20)
    assert _extract_token_usage(openai_response) == (200, 150, 30)


def test_model_client_repairs_invalid_json_content() -> None:
    from cloud_dast.infrastructure.runtime.model import LangChainModelClient
    from cloud_dast.ports import ModelRequest

    class PlainModel:
        def invoke(self, messages):
            return type(
                "Response",
                (),
                {
                    "content": 'Result: {"value": "repaired",}',
                    "additional_kwargs": {},
                    "response_metadata": {
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                    },
                },
            )()

    response = LangChainModelClient(PlainModel()).complete(
        ModelRequest(task="test"),
        response_type=SimpleResponse,
    )

    assert response.structured == {"value": "repaired"}


@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
        {},
        {"prompt_tokens": 10},
        {"completion_tokens": 3},
        {"total_tokens": 13},
        {"prompt_tokens": None, "completion_tokens": 3},
    ],
)
@pytest.mark.parametrize("model_id", ["glm-5.2", "glm-5.3", "another-provider/model"])
def test_sdk_adapter_uses_one_schema_and_budget_without_vendor_tokenizer(
    model_id, usage
):
    import httpx
    from langchain_openai import ChatOpenAI

    from cloud_dast.infrastructure.runtime.model import LangChainModelClient
    from cloud_dast.ports import ModelBudget, ModelRequest

    received = []

    def respond(request):
        received.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "offline-call",
                "object": "chat.completion",
                "model": model_id,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": '{"value":"ok"}'},
                    }
                ],
                "usage": usage,
            },
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as transport:
        sdk = ChatOpenAI(
            model=model_id,
            api_key="unused",
            base_url="https://offline.invalid/v1",
            max_retries=0,
            http_client=transport,
        )
        request = ModelRequest(
            task="offline-test",
            budget=ModelBudget(max_input_tokens=100, max_output_tokens=17),
        )
        adapter = LangChainModelClient(sdk)
        if (
            type(usage.get("prompt_tokens")) is int
            and type(usage.get("completion_tokens")) is int
        ):
            result = adapter.complete(request, response_type=SimpleResponse)
            assert result.structured == {"value": "ok"}
            assert (result.input_tokens, result.output_tokens) == (10, 3)
        else:
            with pytest.raises(RuntimeError, match="usage unavailable"):
                adapter.complete(request, response_type=SimpleResponse)
    assert len(received) == 1
    wire = received[0]
    assert wire["max_completion_tokens"] == 17
    prompt = json.loads(wire["messages"][1]["content"])
    assert prompt["response_schema"] == wire["response_format"]["json_schema"]["schema"]
