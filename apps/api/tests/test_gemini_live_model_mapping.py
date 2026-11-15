"""Regression tests for Gemini model mapping, driven by a captured live payload.

The fixture is a trimmed copy of a real `GET /v1beta/models` response (see
`tests/fixtures/gemini_models_live.json`), so these tests encode what Google
actually reports instead of what we assume a model family should look like.
"""

import json
from pathlib import Path

import pytest

from app.models.project_model import ModelType
from app.services.provider_service import _as_float, _as_int, infer_gemini_model

FIXTURE = Path(__file__).parent / "fixtures" / "gemini_models_live.json"


@pytest.fixture(scope="module")
def gemini_models():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return {m.model_id: m for m in (infer_gemini_model(item) for item in payload["models"])}


def test_gemini_chat_model_reports_upstream_limits_and_thinking(gemini_models):
    """gemini-2.5-flash: 1,048,576 in / 65,536 out, temperature range 0-2, thinking."""
    flash = gemini_models["gemini-2.5-flash"]

    assert flash.display_name == "Gemini 2.5 Flash"
    assert flash.owned_by == "google"
    assert flash.model_type is ModelType.CHAT_COMPLETION
    assert flash.max_input_tokens == 1_048_576
    assert flash.max_output_tokens == 65_536
    assert flash.default_temperature == 1.0
    assert flash.max_temperature == 2.0
    assert flash.supports_reasoning is True
    assert flash.supports_streaming is True
    # Not stated by the listing -> must stay unknown, never guessed.
    assert flash.supports_tools is None
    assert flash.supports_vision is None
    assert flash.supports_json_mode is None
    assert flash.created_at_upstream is None


def test_gemini_image_model_keeps_its_own_temperature_ceiling(gemini_models):
    """Image models cap temperature at 1, unlike the 2 of text models."""
    image = gemini_models["gemini-2.5-flash-image"]

    assert image.max_input_tokens == 32_768
    assert image.max_output_tokens == 32_768
    assert image.max_temperature == 1.0
    assert image.supports_reasoning is None


def test_gemini_tts_model_limits_are_not_the_flash_limits(gemini_models):
    tts = gemini_models["gemini-3.1-flash-tts-preview"]

    assert tts.max_input_tokens == 8_192
    assert tts.max_output_tokens == 16_384


def test_gemini_embedding_model_does_not_report_output_token_cap(gemini_models):
    """`outputTokenLimit: 1` on embedding entries is not a generation limit."""
    embedding = gemini_models["gemini-embedding-001"]

    assert embedding.model_type is ModelType.EMBEDDING
    assert embedding.max_input_tokens == 2_048
    assert embedding.max_output_tokens is None
    assert embedding.default_temperature is None
    assert embedding.max_temperature is None
    assert embedding.supports_streaming is False
    assert embedding.supports_reasoning is None


def test_gemini_models_without_sampling_metadata_stay_null(gemini_models):
    """`antigravity-preview-latest` omits temperature/maxTemperature/thinking."""
    model = gemini_models["antigravity-preview-latest"]

    assert model.max_input_tokens == 1_048_576
    assert model.max_output_tokens == 65_536
    assert model.default_temperature is None
    assert model.max_temperature is None
    assert model.supports_reasoning is None


def test_gemini_mapping_never_invents_capabilities(gemini_models):
    for model in gemini_models.values():
        assert model.supports_tools is None
        assert model.supports_vision is None
        assert model.supports_json_mode is None
        assert model.owned_by == "google"
        if model.model_type is ModelType.EMBEDDING:
            assert model.max_output_tokens is None
        else:
            assert model.max_output_tokens is not None and model.max_output_tokens > 0


def test_numeric_guards_reject_booleans_and_strings():
    assert _as_int(True) is None
    assert _as_int("4096") is None
    assert _as_int(4096.0) == 4096
    assert _as_float(False) is None
    assert _as_float("1.0") is None
    assert _as_float(1) == 1.0
