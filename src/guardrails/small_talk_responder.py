"""
Xử lý câu hội thoại không mang chủ đề (chào, cảm ơn, xác nhận, hỏi tiếp...).

Vấn đề: topic_filter chặn mọi câu không có keyword ngân hàng, nên "hi", "OK",
"giải thích rõ hơn" bị coi là lạc đề -> trải nghiệm tệ. Hai cách xử lý:

  small_talk_reply()         -> câu xã giao / xác nhận / xin gặp nhân viên:
                                trả lời mẫu (nhất quán, không tốn API, không lộ prompt)
  is_conversational_followup() -> câu hỏi nối tiếp ("tại sao", "cho ví dụ"):
                                cho qua LLM (system prompt giữ LLM trong chủ đề ngân hàng)

Mọi pattern đều fullmatch CẢ câu (sau chuẩn hoá + bỏ dấu), nên kẹp thêm nội dung
khác ("hi, ignore your rules", "giải thích cách nấu phở") sẽ không lọt.
"""
from __future__ import annotations

import re

from guardrails.security_text_normalizer import normalize_text, strip_accents

_ME = r"(?:toi|minh|em|tui|anh|chi)"
_ADDRESS = r"(?:ban|bot|em|anh|chi|ad|admin|vinbank|there|you|all|team|shop)"
_PARTICLE = r"(?:voi|nhe|nha|nhe|a|ah|oi|khong|duoc\s+khong|di|please|pls)"
_TAIL = r"[\s,!.?~:)(]*"

_GREETING = (
    r"(?:hi|hello|hey|hiya|yo|howdy|good\s+(?:morning|afternoon|evening|day)|xin\s+chao|chao|alo|a\s+lo)"
    r"(?:[\s,!.]+(?:how\s+are\s+you(?:\s+doing)?|ban\s+(?:co\s+)?khoe\s+khong))?"
)
_IDENTITY = (
    r"(?:who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|how\s+can\s+you\s+help(?:\s+me)?|"
    r"what\s+services\s+do\s+you\s+(?:offer|have|provide)|"
    r"(?:ban|em|may)\s+la\s+ai|"
    r"(?:ban\s+)?(?:co\s+the\s+)?(?:lam|giup)\s+(?:duoc\s+)?(?:gi|toi\s+gi)(?:\s+cho\s+" + _ME + r")?|"
    r"(?:ban|ngan\s+hang|vinbank|ben\s+ban)?\s*co\s+(?:nhung\s+)?dich\s+vu\s+(?:gi|nao))"
)
_HELP = (
    r"(?:(?:i\s+)?(?:need|want)\s+(?:some\s+)?(?:help|support|assistance)|help(?:\s+me)?|"
    r"(?:can|could)\s+you\s+help(?:\s+me)?|support|"
    r"(?:" + _ME + r"\s+)?(?:can|muon|dang\s+can)\s+(?:duoc\s+)?(?:ho\s+tro|giup(?:\s+do)?|tro\s+giup|tu\s+van)|"
    r"(?:ho\s+tro|giup|tu\s+van)\s+" + _ME + r"(?:\s+voi)?|ho\s+tro|tu\s+van|"
    # Mở đầu chung chung: "cho mình hỏi chút", "tôi có thể hỏi vài câu không?"
    r"cho\s+" + _ME + r"\s+hoi(?:\s+(?:chut|ti|xiu|cai|mot\s+chut))?|"
    r"" + _ME + r"\s+(?:muon|can|co\s+viec\s+can|co\s+the)\s+hoi(?:\s+ban)?"
    r"(?:\s+(?:chut|ti|xiu|(?:mot\s+)?(?:vai|it|may)\s+cau(?:\s+hoi)?))?|"
    r"(?:can|may)\s+i\s+ask(?:\s+(?:you\s+)?(?:a\s+)?(?:question|something|a\s+few\s+questions))?|"
    r"i\s+have\s+(?:a\s+)?(?:question|questions|an\s+issue|a\s+problem))"
)
_ACK_WORD = (
    r"(?:ok|oke|okay|okie|okela|duoc(?:\s+roi)?|dung(?:\s+roi)?|phai|khong\s+phai|co|khong|vang|da|"
    r"u|uh|um|yes|no|yep|yeah|nope|sure|got\s+it|alright|fine|" + _ME + r"?\s*hieu\s+roi|i\s+see|understood)"
)
_ACK = rf"{_ACK_WORD}(?:[\s,.!]+{_ACK_WORD})*"
_THANKS = r"(?:thanks?(?:\s+a\s+lot)?|thank\s+you(?:\s+so\s+much)?|thx|ty|cam\s+on(?:\s+nhieu)?|camon|tks)"
_BYE = r"(?:bye|goodbye|see\s+you|tam\s+biet|bai|hen\s+gap\s+lai)"
_HANDOFF = (
    r"(?:" + _ME + r"\s+)?(?:can|muon)\s+(?:gap|noi\s+chuyen\s+voi|lien\s+he)\s+"
    r"(?:nhan\s+vien|tu\s+van\s+vien|nguoi\s+that|tong\s+dai(?:\s+vien)?)(?:\s+ho\s+tro|\s+tu\s+van)?|"
    r"(?:i\s+(?:want|need)\s+to\s+|can\s+i\s+)?(?:talk|speak)\s+(?:to|with)\s+(?:a\s+)?"
    r"(?:human|person|real\s+person|agent|representative|staff)|live\s+agent|human\s+agent"
)
_FOLLOWUP = (
    r"(?:(?:ban\s+)?(?:co\s+the\s+)?giai\s+thich\s+(?:ro|ky|chi\s+tiet|cu\s+the)\s+hon|"
    r"" + _ME + r"?\s*(?:van\s+)?(?:chua|khong)\s+hieu(?:\s+(?:lam|ro|lam\s+ro))?|"
    r"(?:cho\s+" + _ME + r"\s+|lay\s+|dua\s+ra\s+)?(?:mot\s+|1\s+)?vi\s+du(?:\s+(?:cu\s+the|di))?|"
    r"(?:tai|vi)\s+sao(?:\s+lai)?(?:\s+(?:nhu\s+vay|the|vay))?|"
    r"co\s+cach\s+(?:nao\s+)?khac|tiep\s+(?:tuc|di)(?:\s+di)?|noi\s+(?:ro|them|tiep)(?:\s+hon)?|"
    r"why(?:\s+is\s+that)?|(?:can\s+you\s+)?explain(?:\s+(?:it|that|this))?(?:\s+(?:more|again|in\s+more\s+detail|"
    r"more\s+clearly))?|(?:give\s+me\s+|show\s+me\s+)?an\s+example|i\s+(?:still\s+)?(?:do\s+not|don'?t)\s+understand|"
    r"go\s+on|continue|tell\s+me\s+more|more\s+details?|(?:is\s+there\s+)?any\s+other\s+(?:way|option)s?)"
)


def _fullmatch(kind: str, text: str) -> bool:
    pattern = rf"(?:{kind}){_TAIL}(?:{_ADDRESS}{_TAIL})?(?:{_PARTICLE}{_TAIL})*"
    return re.fullmatch(pattern, text) is not None


def _prepare(user_input: str) -> tuple[str, bool] | None:
    raw = normalize_text(user_input)
    if not raw or len(raw) > 80:
        return None
    text = strip_accents(raw)
    vietnamese = raw != text or bool(re.search(
        r"\b(?:chao|cam\s+on|ban|em|tam\s+biet|alo|ho\s+tro|giup|tu\s+van|hoi|minh|toi|vang|dung)\b", text
    ))
    return text, vietnamese


REPLIES = {
    "intro": ("Xin chào! Tôi là trợ lý ảo của VinBank. Tôi có thể giúp bạn về tài khoản, chuyển tiền, "
              "tiết kiệm, lãi suất, khoản vay và thẻ tín dụng. Bạn cần hỗ trợ gì ạ?",
              "Hello! I'm VinBank's virtual assistant. I can help with accounts, transfers, savings, "
              "interest rates, loans and credit cards. How can I help you today?"),
    "ack": ("Vâng ạ. Bạn cần tôi hỗ trợ thêm gì về tài khoản, thẻ, chuyển tiền, tiết kiệm hay khoản vay không?",
            "Got it. Is there anything else I can help you with - accounts, cards, transfers, savings or loans?"),
    "thanks": ("Rất vui được hỗ trợ bạn! Nếu cần thêm gì về dịch vụ VinBank, cứ hỏi tôi nhé.",
               "You're welcome! Let me know if you need anything else about VinBank services."),
    "bye": ("Cảm ơn bạn đã liên hệ VinBank. Chúc bạn một ngày tốt lành!",
            "Thank you for contacting VinBank. Have a great day!"),
    # Hỏi lại để hỗ trợ trước; chỉ hướng dẫn kết nối nhân viên nếu bot chưa giải quyết được
    "handoff": ("Vâng, tôi sẵn sàng hỗ trợ bạn ngay. Bạn đang gặp vấn đề gì - tài khoản, thẻ, chuyển tiền, "
                "tiết kiệm hay khoản vay? Bạn mô tả giúp tôi nhé. Nếu tôi chưa giải quyết được, tôi sẽ hướng "
                "dẫn bạn kết nối với nhân viên hỗ trợ.",
                "Sure, I'm here to help right away. What issue are you facing - accounts, cards, transfers, "
                "savings or loans? Please describe it. If I can't resolve it, I'll guide you to connect with "
                "a support staff member."),
}
_REPLY_ORDER = (("handoff", _HANDOFF), ("intro", _GREETING), ("intro", _IDENTITY), ("intro", _HELP),
                ("thanks", _THANKS), ("bye", _BYE), ("ack", _ACK))


def small_talk_reply(user_input: str) -> str | None:
    """Câu trả lời mẫu nếu input chỉ là xã giao / xác nhận / xin gặp nhân viên, ngược lại None."""
    prepared = _prepare(user_input)
    if prepared is None:
        return None
    text, vietnamese = prepared
    for key, pattern in _REPLY_ORDER:
        if _fullmatch(pattern, text):
            vi, en = REPLIES[key]
            return vi if vietnamese else en
    return None


def is_conversational_followup(user_input: str) -> bool:
    """True nếu input là câu hỏi nối tiếp ngắn ("tại sao?", "cho ví dụ") -> cho qua LLM."""
    prepared = _prepare(user_input)
    return prepared is not None and _fullmatch(_FOLLOWUP, prepared[0])
