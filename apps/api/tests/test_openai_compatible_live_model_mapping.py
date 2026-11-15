"""Regression tests for `/v1/models` mapping across OpenAI-compatible servers.

The point of these tests is the truthfulness rule: OpenAI's own listing carries
no limits or capabilities, so the mapper must return `None` for all of them, and
it may only fill in what a richer server (OpenRouter, vLLM, ...) actually states.
"""

import pytest

from app.models.project_model import ModelType
from app.services.provider_service import infer_openai_compatible_model

# Verbatim shape of https://api.openai.com/v1/models (see
# sandbox/out/openai_live_models_*.json): nothing but identity fields.
OPENAI_ENTRY = {
    "id": "gpt-5-nano",
    "object": "model",
    "created": 1754426384,
    "owned_by": "system",
    "shutdown_date": "2026-12-11",
}


def test_openai_entry_reports_only_identity_fields():
    """OpenAI states no limits/capabilities -> every one of them stays NULL."""
    model = infer_openai_compatible_model(OPENAI_ENTRY)

    assert model.model_id == "gpt-5-nano"
    assert model.display_name == "gpt-5-nano"
    assert model.owned_by == "system"
    assert model.created_at_upstream == 1754426384

    assert model.max_input_tokens is None
    assert model.max_output_tokens is None
    assert model.default_temperature is None
    assert model.max_temperature is None
    assert model.supports_streaming is None
    assert model.supports_tools is None
    assert model.supports_vision is None
    assert model.supports_json_mode is None
    assert model.supports_reasoning is None
    # No "embed"/"rerank" hint, and OpenAI never states a type: catalog storage
    # applies the chat_completion default, not the mapper.
    assert model.model_type is None


def test_openai_embedding_is_classified_by_id_only():
    model = infer_openai_compatible_model(
        {"id": "text-embedding-3-small", "object": "model", "created": 1705948997, "owned_by": "openai"}
    )

    assert model.model_type is ModelType.EMBEDDING
    assert model.max_input_tokens is None
    assert model.supports_streaming is None


def test_openrouter_entry_supplies_real_limits_and_capabilities():
    """OpenRouter does publish context length, completion cap, modalities and params."""
    model = infer_openai_compatible_model(
        {
            "id": "anthropic/claude-3.5-sonnet",
            "name": "Anthropic: Claude 3.5 Sonnet",
            "description": "Claude 3.5 Sonnet",
            "created": 1718841600,
            "context_length": 200000,
            "top_provider": {"context_length": 200000, "max_completion_tokens": 8192},
            "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]},
            "supported_parameters": ["tools", "tool_choice", "response_format", "temperature"],
        }
    )

    assert model.max_input_tokens == 200000
    assert model.max_output_tokens == 8192
    assert model.supports_vision is True
    assert model.supports_tools is True
    assert model.supports_json_mode is True
    # Listed parameters exist, but no reasoning knob among them.
    assert model.supports_reasoning is False
    assert model.default_temperature is None


def test_openrouter_text_only_model_reports_no_vision():
    model = infer_openai_compatible_model(
        {
            "id": "meta-llama/llama-3-8b-instruct",
            "context_length": 8192,
            "architecture": {"input_modalities": ["text"]},
            "supported_parameters": ["max_tokens", "temperature"],
        }
    )

    assert model.supports_vision is False
    assert model.supports_tools is False
    assert model.supports_json_mode is False
    assert model.supports_reasoning is False


def test_vllm_entry_uses_max_model_len():
    model = infer_openai_compatible_model(
        {"id": "Qwen/Qwen2.5-7B-Instruct", "object": "model", "max_model_len": 32768}
    )

    assert model.max_input_tokens == 32768
    # vLLM does not state a separate completion cap or any capability flags.
    assert model.max_output_tokens is None
    assert model.supports_tools is None
    assert model.supports_vision is None


def test_anthropic_iso_created_at_becomes_unix_seconds():
    model = infer_openai_compatible_model(
        {"id": "claude-sonnet-4-5", "display_name": "Claude Sonnet 4.5", "created_at": "2025-09-29T00:00:00Z"}
    )

    assert model.created_at_upstream == 1759104000
    assert model.display_name == "Claude Sonnet 4.5"
    assert model.max_input_tokens is None


def test_explicit_limit_keys_win_over_vendor_specific_ones():
    model = infer_openai_compatible_model(
        {
            "id": "meta/llama-4",
            "max_input_tokens": 128000,
            "context_length": 4096,
            "max_output_tokens": 4096,
            "max_completion_tokens": 1024,
        }
    )

    assert model.max_input_tokens == 128000
    assert model.max_output_tokens == 4096


@pytest.mark.parametrize(
    "entry",
    [
        {"id": "x", "context_length": "200000"},
        {"id": "x", "context_length": True},
        {"id": "x", "max_output_tokens": "8192"},
        {"id": "x", "created": "not-a-date"},
    ],
)
def test_unusable_values_are_not_coerced(entry):
    """Strings/booleans/!dates are not limits; they must not become numbers."""
    model = infer_openai_compatible_model(entry)

    assert model.max_input_tokens is None
    assert model.max_output_tokens is None
    assert model.created_at_upstream is None


def test_strips_google_style_name_prefix_for_compatible_servers():
    model = infer_openai_compatible_model({"name": "models/gemma-3-27b-it", "max_model_len": 8192})

    assert model.model_id == "gemma-3-27b-it"
