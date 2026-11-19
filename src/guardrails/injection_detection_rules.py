"""
Thư viện rule phát hiện prompt injection / jailbreak (đa lớp).

Quyết định:
  1. STRONG rule khớp trên bất kỳ biến thể nào -> chặn ngay.
  2. Keyword "bóp" (squashed, kể cả ROT13 / đảo ngược) -> chặn.
  3. WEAK signal: có nhắc dữ liệu nhạy cảm + ít nhất 1 tín hiệu thao túng
     (giả quyền, cớ audit, khung hư cấu, ép định dạng, ép mở đầu...) -> chặn.

Rule viết cho văn bản ĐÃ chuẩn hoá (lowercase, bỏ ký tự vô hình); rule tiếng Việt
viết dạng không dấu vì luôn có biến thể đã bỏ dấu.
"""
from __future__ import annotations

import re

from guardrails.security_text_normalizer import build_scan_variants, build_squashed_variants

_VERB_LEAK = (
    r"(?:reveal|show|print|display|output|repeat|recite|dump|leak|expose|disclose|share|"
    r"tell|give|write|list|summari[sz]e|paraphrase|translate|encode|spell|copy|echo|return|send)"
)
# Không gồm rules/policies/guidelines: khách hỏi "your rules for transfers" là hợp lệ
_INSTRUCTION_NOUN = (
    r"(?:instructions?|prompts?|directives|configuration|config|system\s+message|guardrails?)"
)
_SECRET_NOUN = r"(?:password|passwd|pwd|credentials?|api\s*key|secret|token|private\s+key|db\s*host)"

STRONG_RULES: dict[str, list[str]] = {
    "instruction_override": [
        # Không có "cancel" ("cancel all previous transfer instructions" là nghiệp vụ thật) và không có "the"
        r"\b(?:ignore|disregard|forget|skip|bypass|override|overrule|abandon|discard|erase|neglect)\b"
        r"[^.\n]{0,40}\b(?:previous|prior|above|earlier|preceding|initial|original|all|any|every|your|"
        r"these|those|system|safety|security)\b[^.\n]{0,30}\b(?:instructions?|prompts?|rules?|"
        r"directives?|guidelines?|guardrails?|polic(?:y|ies)|restrictions?|constraints?|filters?|"
        r"programming|training|commands?)",
        r"\bnew\s+(?:instructions?|rules?|directives?|system\s+prompt)\s*[:\-]",
        r"\b(?:stop|cease|quit)\s+(?:following|obeying)\s+(?:your|the|all|any)\b",
        r"\bdo\s+not\s+(?:follow|obey)\s+(?:your|the|any)\s+(?:rules|instructions|guidelines|polic)",
        r"\b(?:from\s+now\s+on|henceforth|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation)\b"
        r"[^.\n]{0,40}\byou\s+(?:will|must|are|shall|should|can)\b",
    ],
    "persona_jailbreak": [
        r"\byou\s+are\s+(?:now|no\s+longer)\b",
        r"\bpretend\s+(?:that\s+)?(?:you\s+are|you're|to\s+be|you\s+were)\b",
        r"\b(?:role\s*-?\s*play|play\s+the\s+role)\s+(?:as|of)\b",
        r"\b(?:act|behave|respond|operate|function)\s+(?:as|like)\s+(?:an?\s+)?(?:unrestricted|unfiltered|"
        r"uncensored|jailbroken|evil|malicious|rogue|unbound|amoral|unethical|developer|admin|root|system)",
        r"\b(?:developer|dev|god|debug|admin|maintenance|sudo|root|unrestricted|jailbreak|jailbroken|"
        r"evil|opposite|unfiltered|uncensored|dan)\s+mode\b",
        r"\bjail\s*-?\s*break(?:ing|s|ed)?\b",
        r"\bdo\s+anything\s+now\b",
        r"\bstay\s+in\s+character\b",
        r"\b(?:you|assistant|ai|model|bot)\b[^.\n]{0,30}\b(?:have|has|with|are|is)\s+(?:no|zero)\s+"
        r"(?:restrictions|filters|rules|guidelines|limitations|censorship|ethics|morals|boundaries)",
        r"\b(?:respond|answer|reply|talk)\s+(?:without|with\s+no)\s+(?:any\s+)?(?:filters?|restrictions?|"
        r"censorship|warnings?|disclaimers?|safety|refusals?)",
        r"\b(?:two|2|dual|both)\s+(?:responses|answers|outputs|versions)\b[^\n]{0,80}\b(?:jailbroken|"
        r"unfiltered|uncensored|dan|classic)",
    ],
    "prompt_extraction": [
        r"\bsystem\s*(?:prompt|message|instructions?)\b",
        r"\b(?:initial|original|hidden|secret|pre-?)\s*prompt\b",
        rf"\b{_VERB_LEAK}\b[^.\n]{{0,40}}\b(?:your|initial|original|hidden|secret|internal|verbatim|"
        rf"above|previous|preceding)\b[^.\n]{{0,25}}\b{_INSTRUCTION_NOUN}\b",
        r"\b(?:what|which)\s+(?:are|were|is)\s+your\s+(?:instructions|directives|initial\s+prompt|"
        r"configuration|system\s+prompt)",
        r"\b(?:repeat|print|output|echo|copy)\b[^.\n]{0,30}\b(?:everything|all|text|words)\b[^.\n]{0,20}"
        r"\b(?:above|before|prior|preceding|so\s+far)\b",
        r"\b(?:internal|hidden|secret|confidential)\s+(?:notes?|memo|config(?:uration)?|instructions?|data)\b",
    ],
    "secret_extraction": [
        r"\b(?:admin|administrator|root|system|internal|database|db|server|staff|employee|service|"
        r"master|superuser)\s*(?:password|passwd|pwd|credentials?|secret)s?\b",
        r"\b(?:api|secret|access|private|auth|bearer|session)\s*[-_]?\s*(?:key|token)s?\b",
        r"\b(?:connection\s+string|db\s*host|database\s+(?:host|server|url|address|credentials?))\b",
        r"\b[\w-]+\.internal\b|\bsk-[a-z0-9]",
        # Giá trị phải giống credential (có số/ký hiệu) -> "my password is not working" không bị chặn
        r"\b(?:password|passwd|api\s*key|mat\s*khau)\s*(?:is|was|=|:|la)\s*['\"`]?(?=\S*[\d_@#$!%^&*])\S{4,}",
        rf"\b(?:your|its|the\s+bot'?s|the\s+assistant'?s)\s+{_SECRET_NOUN}",
        r"\b(?:confirm|verify|validate)\b[^.\n]{0,40}\b(?:admin|system|internal|your)\s*"
        r"(?:password|credentials?|api\s*key|secret)",
    ],
    "obfuscation_request": [
        rf"\b(?:base\s*64|rot\s*-?\s*13|hex(?:adecimal)?|binary|morse|caesar|leet|reversed?|backwards?|"
        rf"pig\s+latin|unicode\s+escape|url\s*-?\s*encod\w*)\b[^.\n]{{0,40}}(?:{_SECRET_NOUN}|"
        rf"{_INSTRUCTION_NOUN})",
        rf"(?:{_SECRET_NOUN}|{_INSTRUCTION_NOUN})[^.\n]{{0,40}}\b(?:in|as|to|using|into)\s+(?:base\s*64|"
        rf"rot\s*-?\s*13|hex|binary|morse|reverse|backwards|leet)",
        r"\b(?:letter\s+by\s+letter|character\s+by\s+character|one\s+(?:letter|character)\s+at\s+a\s+time|"
        r"with\s+(?:spaces|dashes|dots|hyphens)\s+between)",
        r"\bfill\s+in\s+(?:the\s+)?(?:blanks?|gaps?|missing)|_{3,}|\[\s*blank\s*\]",
        r"\bcomplete\s+(?:the|this)\s+(?:sentence|phrase|line|template)\b[^\n]{0,60}"
        r"(?:password|key|secret|host|credential)",
    ],
    "fake_delimiter": [
        r"<\|?\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>",
        r"(?m)^\s*(?:#{2,}\s*|\[|\{|<)?\s*(?:system|assistant|developer)\s*(?:\]|\}|>|:)",
        r"\[(?:system|admin|developer|override|instructions?|inst)\]",
        r"</?(?:system|instructions?|prompt|admin|sys)>",
        r"\b(?:begin|end)\s+(?:system|admin|developer|hidden)\s+(?:prompt|message|instructions?)\b",
        r"\bend\s+of\s+(?:user\s+)?(?:input|prompt)\b",
    ],
    "vietnamese": [
        r"\b(?:bo\s+qua|phot\s+lo|quen\s+(?:het|di|moi)|lo\s+di|vo\s+hieu\s+hoa|khong\s+(?:can\s+)?tuan\s+theo)"
        r"\b[^.\n]{0,30}\b(?:huong\s+dan|chi\s+dan|quy\s+tac|luat|chi\s+thi|lenh|rang\s+buoc|gioi\s+han)",
        r"\btiet\s+lo\b[^.\n]{0,30}\b(?:mat\s+khau|password|api\s*key|khoa\s+api|prompt|huong\s+dan|"
        r"cau\s+hinh|thong\s+tin\s+noi\s+bo|ghi\s+chu\s+noi\s+bo|bi\s+mat)",
        # Không gồm "mật khẩu" trơn: "cho tôi biết cách đổi mật khẩu" là câu hợp lệ
        r"\b(?:cho\s+(?:toi|minh|tao|em|tui)\s+(?:xem|biet)|in\s+ra|hien\s+thi|liet\s+ke|doc\s+to)\b"
        r"[^.\n]{0,30}\b(?:api\s*key|khoa\s+api|system\s*prompt|prompt\s+he\s+thong|"
        r"huong\s+dan\s+(?:he\s+thong|goc|an)|cau\s+hinh\s+(?:he\s+thong|noi\s+bo)|thong\s+tin\s+noi\s+bo|"
        r"ghi\s+chu\s+noi\s+bo)",
        r"\bmat\s+khau\s+(?:admin|quan\s+tri|he\s+thong|noi\s+bo|database|db|may\s+chu)",
        r"\b(?:ban|may|mi)\s+(?:bay\s+gio\s+|tu\s+gio\s+)?la\s+(?:dan|mot\s+ai\s+khong|ai\s+khong\s+gioi\s+han)",
        r"\b(?:gia\s+vo|gia\s+su\s+ban\s+la|dong\s+vai|nhap\s+vai)\b",
        r"\bche\s+do\s+(?:nha\s+phat\s+trien|developer|khong\s+gioi\s+han|admin|quan\s+tri|bao\s+tri)",
    ],
}

# Keyword sau khi bỏ hết ký tự không phải a-z0-9 (bắt "I-g-n-o-r-e", ROT13, đảo ngược)
SQUASHED_KEYWORDS = (
    "ignoreallpreviousinstructions", "ignorepreviousinstructions", "ignoreallinstructions",
    "ignoreyourinstructions", "disregardpreviousinstructions", "disregardallinstructions",
    "forgetyourinstructions", "systemprompt", "developermode", "jailbreak", "doanythingnow",
    "revealyourinstructions", "adminpassword", "boquamoihuongdan",
)

# Tín hiệu yếu: chỉ chặn khi SENSITIVE + ít nhất 1 MANIPULATION
# Không gồm "internal" (internal transfer) và "token" (OTP token) - thuật ngữ ngân hàng hợp lệ
SENSITIVE_SIGNAL = (
    r"\b(?:password|passwd|credentials?|secret|confidential|config(?:uration)?|"
    r"env(?:ironment)?\s+var(?:iable)?s?|private\s+key|mat\s+khau|bi\s+mat|noi\s+bo)\b"
)
# Không có "urgent": "Urgent, I forgot my password" là câu khách hàng bình thường
MANIPULATION_SIGNALS: dict[str, str] = {
    "authority_claim": r"\b(?:i\s*am|i'm|this\s+is|speaking\s+as)\s+(?:the|your|an?)?\s*(?:developer|creator|"
                       r"admin|administrator|sysadmin|ciso|cto|security\s+(?:team|officer|auditor)|"
                       r"it\s+(?:staff|department|admin)|auditor|system\s+engineer)\b",
    "pretext": r"\b(?:audit|compliance|security\s+review|pen\s*test|penetration\s+test|research|"
               r"educational\s+purposes?|testing\s+purposes?|ticket\s+[a-z]+-?\d+|incident)\b",
    "fiction_frame": r"\b(?:hypothetical(?:ly)?|fictional|imagine|story|poem|novel|screenplay|script|"
                     r"movie|game|role\s*-?\s*play|in\s+theory)\b",
    "format_coercion": r"\b(?:as|in|into)\s+(?:json|yaml|xml|csv|a\s+code\s+block|a\s+table)\b",
    "prefix_forcing": r"\b(?:start|begin)\s+(?:your\s+)?(?:response|answer|reply)\s+with\b|\bsure,?\s+here\s+is\b",
}

_COMPILED_STRONG = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in STRONG_RULES.items()
}
_COMPILED_SENSITIVE = re.compile(SENSITIVE_SIGNAL, re.IGNORECASE)
_COMPILED_MANIPULATION = {k: re.compile(p, re.IGNORECASE) for k, p in MANIPULATION_SIGNALS.items()}
_DAN_EXACT = re.compile(r"\bDAN\b")  # phân biệt hoa/thường để không bắt tên riêng "Dan"


def find_injection_signals(text: str) -> list[str]:
    """Trả về danh sách lý do (rỗng = không phát hiện)."""
    if not text or not text.strip():
        return []
    reasons: list[str] = []
    variants = build_scan_variants(text)

    for category, patterns in _COMPILED_STRONG.items():
        if any(p.search(v) for p in patterns for v in variants):
            reasons.append(category)
    if _DAN_EXACT.search(text):
        reasons.append("persona_jailbreak:dan")

    squashed = build_squashed_variants(text)
    if any(k in s for k in SQUASHED_KEYWORDS for s in squashed):
        reasons.append("squashed_keyword")

    if any(_COMPILED_SENSITIVE.search(v) for v in variants):
        hits = [name for name, p in _COMPILED_MANIPULATION.items() if any(p.search(v) for v in variants)]
        if hits:
            reasons.append("weak_combo:" + "+".join(hits))
    return list(dict.fromkeys(reasons))


def is_injection(text: str) -> bool:
    return bool(find_injection_signals(text))
