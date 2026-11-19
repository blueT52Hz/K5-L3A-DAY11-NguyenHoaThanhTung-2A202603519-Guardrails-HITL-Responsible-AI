"""
Chạy toàn bộ bộ mẫu có nhãn của input guardrail (injection, topic, hội thoại).

Bắt lỗi regex (vd. ngoặc lệch làm crash plugin) và hồi quy chặn nhầm / bỏ sót.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))

from guardrails.conversation_flow_samples import CONVERSATION_SAMPLES  # noqa: E402
from guardrails.injection_detection_samples import INJECTION_SAMPLES  # noqa: E402
from guardrails.input_guardrails import (  # noqa: E402
    InputGuardrailPlugin,
    detect_injection,
    topic_filter,
)
from guardrails.topic_filter_samples import TOPIC_SAMPLES  # noqa: E402


@pytest.mark.parametrize("text,expected", INJECTION_SAMPLES)
def test_injection_samples(text, expected):
    assert detect_injection(text) == expected


@pytest.mark.parametrize("text,expected", TOPIC_SAMPLES)
def test_topic_samples(text, expected):
    assert topic_filter(text) == expected


def _plugin_outcome(text: str) -> str:
    from google.genai import types

    plugin = InputGuardrailPlugin()
    content = types.Content(role="user", parts=[types.Part.from_text(text=text)])
    result = asyncio.run(
        plugin.on_user_message_callback(invocation_context=None, user_message=content)
    )
    if result is None:
        return "ALLOW"
    return "REPLY" if plugin.last_block_reason is None else "BLOCK"


@pytest.mark.parametrize("text,expected", CONVERSATION_SAMPLES)
def test_conversation_samples(text, expected):
    assert _plugin_outcome(text) == expected
