"""
Pattern PII / secret cho output guardrail + phát hiện secret bị ngụy trang.

Thứ tự trong dict có ý nghĩa: pattern cụ thể (connection string, key) chạy trước
pattern chung (email, số) để không bị redact lắt nhắt.
"""
from __future__ import annotations

import codecs

from core.config import DEMO_SECRETS
from guardrails.security_text_normalizer import decode_hidden_payloads, normalize_text, squash

SENSITIVE_OUTPUT_PATTERNS: dict[str, str] = {
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    "connection_string": r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@]+@\S+",
    "api_key": r"\bsk-[A-Za-z0-9_-]{8,}",
    "bearer_token": r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    "password": r"(?:password|passwd|pwd|passcode|mật\s*khẩu|mat\s*khau)\s*(?:is|was|là|=|:)\s*"
                r"[\"'`]?[^\s\"'`,;]+",
    "internal_host": r"\b[\w-]+(?:\.[\w-]+)*\.(?:internal|corp|lan|intranet)(?::\d{2,5})?\b",
    "private_ip": r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])"
                  r"(?:\.\d{1,3}){2})(?::\d{2,5})?\b",
    "email": r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
    "card_number": r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
    "phone_vn": r"(?<![\d+])(?:\+?84|0)(?:[\s.-]?\d){9,10}(?!\d)",
    "national_id": r"(?<!\d)(?:\d{12}|\d{9})(?!\d)",
}

# Secret dạng bóp (chỉ a-z0-9) để bắt "a.d.m.i.n.1.2.3", "sk vinbank secret 2024"...
_SQUASHED_SECRETS = tuple(dict.fromkeys(s for s in (squash(x) for x in DEMO_SECRETS) if len(s) >= 6))


def find_obfuscated_secret(text: str) -> bool:
    """True nếu secret còn lộ dưới dạng chèn ký tự / base64 / hex / đảo ngược / ROT13."""
    candidates = [text, normalize_text(text), *decode_hidden_payloads(text)]
    for candidate in candidates:
        squashed = squash(candidate)
        for variant in (squashed, squashed[::-1], codecs.decode(squashed, "rot13")):
            if any(secret in variant for secret in _SQUASHED_SECRETS):
                return True
    return False
