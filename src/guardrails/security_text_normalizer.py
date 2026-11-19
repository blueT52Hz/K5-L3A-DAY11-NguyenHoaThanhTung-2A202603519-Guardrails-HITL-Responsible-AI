"""
Chuẩn hoá văn bản trước khi chạy rule bảo mật (dùng chung cho input + output guardrails).

Kẻ tấn công thường né regex bằng: ký tự vô hình, homoglyph (chữ Cyrillic/Greek
trông giống Latin), leetspeak, chữ cách quãng ("i g n o r e"), dấu tiếng Việt,
hoặc mã hoá payload (base64 / hex / URL / ROT13 / đảo ngược). Module này sinh ra
các "biến thể" đã bóc lớp ngụy trang để rule chỉ cần viết cho dạng chuẩn.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote

# Giới hạn độ dài xử lý để regex không bị khai thác làm chậm (DoS)
MAX_SCAN_CHARS = 20_000

# Zero-width, soft hyphen, bidi override... (không hiển thị nhưng tách từ)
_INVISIBLE_CHARS = (
    "­᠎​‌‍‎‏⁠⁡⁢⁣⁤"
    "‪‫‬‭‮⁦⁧⁨⁩﻿"
)
_INVISIBLE_TABLE = dict.fromkeys(map(ord, _INVISIBLE_CHARS), None)

# Homoglyph phổ biến (Cyrillic / Greek) -> Latin
_HOMOGLYPH_TABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})

# Leetspeak -> chữ
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "i",
})

# >= 4 chữ cái đứng riêng, cách nhau bởi space/dấu: "i g n o r e", "s.y.s.t.e.m"
_SPACED_LETTERS = re.compile(
    r"(?<![a-z])[a-z](?![a-z])(?:[\s._\-*/+]+[a-z](?![a-z])){3,}"
)
# >= 8 ký tự để bắt cả secret ngắn ("YWRtaW4xMjM=" = admin123); rác giải mã bị lọc bằng tỉ lệ printable
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")


def normalize_text(text: str) -> str:
    """NFKC + bỏ ký tự vô hình + homoglyph + lowercase + nối chữ cách quãng."""
    text = unicodedata.normalize("NFKC", (text or "")[:MAX_SCAN_CHARS])
    text = text.translate(_INVISIBLE_TABLE).translate(_HOMOGLYPH_TABLE).lower()
    text = _SPACED_LETTERS.sub(lambda m: re.sub(r"[^a-z]", "", m.group()), text)
    return re.sub(r"\s+", " ", text).strip()


def strip_accents(text: str) -> str:
    """'mật khẩu' -> 'mat khau' (giữ nguyên chữ không dấu)."""
    decomposed = unicodedata.normalize("NFD", text or "")
    no_marks = "".join(c for c in decomposed if unicodedata.category(c) != "Mn")
    return no_marks.replace("đ", "d").replace("Đ", "D")


def squash(text: str) -> str:
    """Chỉ giữ a-z0-9 -> bắt được 'i-g-n-o-r-e' hay 'admin_123'."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isprintable() or c.isspace() for c in text) / len(text)


def decode_hidden_payloads(text: str) -> list[str]:
    """Giải mã các đoạn base64 / hex / URL-encode nằm trong text (nếu đọc được)."""
    decoded: list[str] = []
    raw = (text or "")[:MAX_SCAN_CHARS]

    for token in _BASE64_TOKEN.findall(raw):
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                value = decoder(padded).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if len(value) >= 4 and _printable_ratio(value) > 0.9:
                decoded.append(value)
                break

    for token in _HEX_TOKEN.findall(raw):
        try:
            value = bytes.fromhex(re.sub(r"[\s:]", "", token)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(value) > 0.9:
            decoded.append(value)

    if "%" in raw:
        unquoted = unquote(raw)
        if unquoted != raw:
            decoded.append(unquoted)
    return decoded


def build_scan_variants(text: str) -> list[str]:
    """Các biến thể để chạy regex: chuẩn hoá, bỏ dấu, de-leet, payload đã giải mã."""
    base = normalize_text(text)
    variants = [base, strip_accents(base), base.translate(_LEET_TABLE)]
    for payload in decode_hidden_payloads(text):
        variants.append(normalize_text(payload))
    # Bỏ trùng nhưng giữ thứ tự
    return list(dict.fromkeys(v for v in variants if v))


def build_squashed_variants(text: str) -> list[str]:
    """Biến thể đã bóp chỉ còn a-z0-9, kể cả ROT13 và đảo ngược (cho keyword check)."""
    out = []
    for variant in build_scan_variants(text):
        squashed = squash(variant)
        out.extend([squashed, squashed[::-1], codecs.decode(squashed, "rot13")])
    return list(dict.fromkeys(v for v in out if v))
