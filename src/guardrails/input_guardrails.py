"""
Checkpoint 2 — Input Guardrails
  - detect_injection (normalization + layered signals)
  - topic_filter
  - InputGuardrailPlugin (ADK)

Status convention (không dùng True/False mơ hồ):
  ``"BLOCK"`` = chặn / không cho qua
  ``"ALLOW"`` = cho qua
"""
from __future__ import annotations

import re
from typing import Literal

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext

from core.config import BLOCKED_TOPICS
from guardrails.banking_topic_lexicon import BANKING_KEYWORDS
from guardrails.injection_detection_rules import find_injection_signals
from guardrails.security_text_normalizer import normalize_text, strip_accents
from guardrails.small_talk_responder import is_conversational_followup, small_talk_reply

# Quyết định rõ ràng — tránh đảo nghĩa True/False
InputStatus = Literal["ALLOW", "BLOCK"]


# ============================================================
# Implement detect_injection()
#
# Canonicalize Unicode/invisible spacing, then detect prompt injection.
# Return ``"BLOCK"`` if injection is detected, else ``"ALLOW"``.
#
# Required cases:
# - "ignore (all )?(previous|above) instructions"
# - "you are now"
# - "system prompt"
# - "reveal your (instructions|prompt)"
# - "pretend you are"
# - "act as (a |an )?unrestricted"
# Also handle an instruction embedded in an untrusted email/RAG document, e.g.
# ``Ignore\u200b all previous instructions``. Do not block a benign request to
# summarize an external bank-transfer email just because it is external data.
# Regex is one signal, not the whole security boundary.
# ============================================================

def detect_injection(user_input: str) -> InputStatus:
    """Detect prompt injection patterns in user input.

    Args:
        user_input: The user's message

    Returns:
        ``"BLOCK"`` if injection detected (chặn), ``"ALLOW"`` otherwise (cho qua).

    Pipeline (xem guardrails/injection_detection_rules.py):
      chuẩn hoá Unicode / ký tự ẩn / homoglyph / leetspeak / chữ cách quãng / bỏ dấu
      + giải mã base64 / hex / URL / ROT13 / đảo ngược
      -> STRONG rules (override, persona, prompt/secret extraction, obfuscation,
         fake delimiter, tiếng Việt) -> squashed keywords -> weak-signal combo.
    """
    return "BLOCK" if find_injection_signals(user_input) else "ALLOW"


def explain_injection(user_input: str) -> list[str]:
    """Lý do bị chặn (để log / audit)."""
    return find_injection_signals(user_input)


# ============================================================
# Implement topic_filter()
#
# Check if user_input belongs to allowed topics.
# The VinBank agent should only answer about: banking, account,
# transaction, loan, interest rate, savings, credit card.
#
# Return ``"BLOCK"`` if input should be blocked (off-topic / blocked topic).
# Return ``"ALLOW"`` if banking-related and OK.
# ============================================================

def topic_filter(user_input: str) -> InputStatus:
    """Decide whether the input is on-topic for VinBank.

    Args:
        user_input: The user's message

    Returns:
        ``"BLOCK"`` = chặn (off-topic hoặc topic cấm).
        ``"ALLOW"`` = cho qua (câu banking hợp lệ).
    """
    # Bỏ dấu để khớp keyword tiếng Việt không dấu trong config ("tài khoản" -> "tai khoan")
    # Thêm space cuối để keyword dạng "tk " / "ck " khớp cả khi đứng cuối câu
    input_lower = strip_accents(normalize_text(user_input)) + " "
    if _has_keyword(input_lower, BLOCKED_TOPICS):
        return "BLOCK"
    # BANKING_KEYWORDS = ALLOWED_TOPICS (config) + từ vựng nghiệp vụ mở rộng
    if not _has_keyword(input_lower, BANKING_KEYWORDS):
        return "BLOCK"
    return "ALLOW"


def _has_keyword(text: str, keywords: list[str]) -> bool:
    """Khớp ở ĐẦU từ: 'kill' không khớp 'skill', nhưng 'account' khớp 'accounts'."""
    return any(re.search(rf"\b{re.escape(k)}", text) for k in keywords)


# ============================================================
# Implement InputGuardrailPlugin
#
# This plugin blocks bad input BEFORE it reaches the LLM.
# Fill in the on_user_message_callback method.
#
# NOTE: The callback uses keyword-only arguments (after *).
#   - user_message is types.Content (not str)
#   - Return types.Content to block, or None to pass through
# ============================================================

class InputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that blocks bad input before it reaches the LLM."""

    def __init__(self):
        super().__init__(name="input_guardrail")
        self.blocked_count = 0
        self.total_count = 0
        self.small_talk_count = 0
        self.last_block_reason: str | None = None

    def _extract_text(self, content: types.Content) -> str:
        """Extract plain text from a Content object."""
        text = ""
        if content and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    def _block_response(self, message: str) -> types.Content:
        """Create a Content object with a block message."""
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check user message before sending to the agent.

        Returns:
            None if message is safe (let it through),
            types.Content if message is blocked (return replacement)
        """
        self.total_count += 1
        text = self._extract_text(user_message)

        reasons = explain_injection(text)
        if reasons:
            self.blocked_count += 1
            self.last_block_reason = "injection:" + ",".join(reasons)
            return self._block_response(
                "Yêu cầu bị chặn: phát hiện dấu hiệu prompt injection / jailbreak. "
                "Tôi chỉ hỗ trợ các câu hỏi về dịch vụ ngân hàng VinBank."
            )
        # Xã giao (chào / cảm ơn / bạn là ai): trả lời mẫu, KHÔNG tính là chặn
        reply = small_talk_reply(text)
        if reply:
            self.small_talk_count += 1
            self.last_block_reason = None
            return self._block_response(reply)
        # Câu hỏi nối tiếp ("tại sao?", "cho ví dụ"): cho qua LLM thay vì coi là lạc đề
        if is_conversational_followup(text):
            self.last_block_reason = None
            return None
        if topic_filter(text) == "BLOCK":
            self.blocked_count += 1
            self.last_block_reason = "off_topic"
            return self._block_response(
                "Xin lỗi, tôi chỉ hỗ trợ chủ đề ngân hàng: tài khoản, giao dịch, "
                "chuyển tiền, tiết kiệm, lãi suất, vay và thẻ tín dụng."
            )
        self.last_block_reason = None
        return None


# ============================================================
# Quick tests
# ============================================================

def test_injection_detection():
    """Test detect_injection with sample inputs."""
    from guardrails.injection_detection_samples import INJECTION_SAMPLES

    print("Testing detect_injection():")
    failed = 0
    for text, expected in INJECTION_SAMPLES:
        result = detect_injection(text)
        ok = result == expected
        failed += not ok
        shown = text.encode("unicode_escape").decode()[:60]
        print(f"  [{'PASS' if ok else 'FAIL'}] '{shown}' -> {result} (expected={expected})")
    print(f"  => {len(INJECTION_SAMPLES) - failed}/{len(INJECTION_SAMPLES)} pass")


def test_topic_filter():
    """Test topic_filter with sample inputs."""
    from guardrails.topic_filter_samples import TOPIC_SAMPLES

    print("Testing topic_filter():")
    failed = 0
    for text, expected in TOPIC_SAMPLES:
        result = topic_filter(text)
        ok = result == expected
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] '{text[:50]}' -> {result} (expected={expected})")
    print(f"  => {len(TOPIC_SAMPLES) - failed}/{len(TOPIC_SAMPLES)} pass")


async def test_input_plugin():
    """Test InputGuardrailPlugin with sample messages."""
    from guardrails.conversation_flow_samples import CONVERSATION_SAMPLES

    plugin = InputGuardrailPlugin()
    print("Testing InputGuardrailPlugin:")
    failed = 0
    for msg, expected in CONVERSATION_SAMPLES:
        user_content = types.Content(
            role="user", parts=[types.Part.from_text(text=msg)]
        )
        result = await plugin.on_user_message_callback(
            invocation_context=None, user_message=user_content
        )
        if result and plugin.last_block_reason is None:
            status = "REPLY"  # xã giao: trả lời mẫu, không chặn
        else:
            status = "BLOCK" if result else "ALLOW"
        ok = status == expected
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {status:<5} '{msg[:55]}' (expected={expected})")
        if result and result.parts:
            print(f"           -> {result.parts[0].text[:80]}")
    print(f"  => {len(CONVERSATION_SAMPLES) - failed}/{len(CONVERSATION_SAMPLES)} pass")
    print(f"\nStats: {plugin.blocked_count} blocked / {plugin.small_talk_count} small talk "
          f"/ {plugin.total_count} total")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_injection_detection()
    test_topic_filter()
    import asyncio
    asyncio.run(test_input_plugin())
