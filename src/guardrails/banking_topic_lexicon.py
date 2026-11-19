"""
Từ vựng chủ đề ngân hàng cho topic_filter (mở rộng ALLOWED_TOPICS trong config).

ALLOWED_TOPICS gốc chỉ ~22 từ -> phần lớn câu mở đầu thật của khách ("thẻ bị khoá",
"không nhận được OTP", "bị trừ tiền 2 lần", "phí thường niên", "login failed"...)
bị chặn nhầm là lạc đề. Danh sách dưới đây gom theo nhóm nghiệp vụ.

Quy ước: chữ thường, tiếng Việt KHÔNG dấu (input luôn được bỏ dấu trước khi so),
so khớp ở đầu từ (\\b prefix) nên "transfer" khớp cả "transferred".
Tránh từ quá chung dễ trùng nghĩa khi bỏ dấu ("lai" = lãi/lại, "the" = thẻ/thế).
"""
from core.config import ALLOWED_TOPICS

_EXTRA_EN = [
    # tài khoản / ngân hàng
    "bank", "acct", "open an account", "close my account", "statement", "branch", "kyc",
    "verify my identity", "beneficiary", "swift", "iban", "routing number",
    # tiền / giao dịch
    "money", "cash", "pay", "bill", "refund", "charge", "charged", "fee", "fees",
    "receipt", "remit", "wire", "send money", "receive money", "top up", "top-up", "withdraw",
    "phone number", "contact details", "frozen", "freeze",
    "exchange rate", "currency", "usd", "vnd", "salary", "wallet", "qr",
    # thẻ
    "card", "debit", "visa", "mastercard", "pin", "cvv", "contactless",
    # truy cập / app
    "otp", "login", "log in", "sign in", "locked out", "unlock", "mobile banking",
    "internet banking", "e-banking", "banking app", "the app", "two-factor", "2fa",
    # sản phẩm
    "mortgage", "installment", "overdraft", "insurance", "invest", "fund", "deposit",
    "term deposit", "credit score", "limit",
    # sự cố / an ninh tài khoản
    "fraud", "scam", "stolen", "lost my", "unauthorized", "dispute", "suspicious",
]

_EXTRA_VI = [
    # tài khoản / ngân hàng
    "ngan hang", "tk ", "mo tk", "so tk", "stk", "mo tai khoan", "dong tai khoan", "sao ke",
    "chi nhanh", "phong giao dich", "ekyc", "xac thuc", "dinh danh", "nguoi thu huong",
    # tiền / giao dịch
    "tien", "thanh toan", "nap tien", "rut tien", "gui tien", "nhan tien", "tru tien",
    "bi tru", "hoan tien", "hoa don", "phi", "bieu phi", "ty gia", "ngoai te", "luong",
    "vi dien tu", "ma qr", "quet qr", "ck ", "chuyen nham", "chuyen khoan", "chuyen tien",
    "mat vi", "vi tien", "so dien thoai", "sdt", "sms banking", "dong bang",
    # thẻ (luôn đi kèm ngữ cảnh vì "the" trùng "thế")
    "the tin dung", "the ghi no", "the atm", "the visa", "the cua toi", "the bi", "mat the",
    "khoa the", "mo khoa the", "lam the", "mo the", "phat hanh the", "gia han the", "ma pin",
    "nuot the",
    # truy cập / app
    "otp", "ma xac thuc", "dang nhap", "mat khau", "ung dung", "app", "smart banking",
    "internet banking", "mobile banking", "bi khoa", "mo khoa", "sinh trac hoc",
    # sản phẩm
    "khoan vay", "vay von", "vay tien", "tra gop", "lai suat", "so tiet kiem", "gui tiet kiem",
    "ky han", "bao hiem", "dau tu", "han muc", "tin dung", "no xau", "dao han",
    # sự cố / an ninh
    "lua dao", "gian lan", "bi hack", "giao dich la", "khieu nai", "tra soat", "mat tien",
]

BANKING_KEYWORDS: list[str] = list(dict.fromkeys([*ALLOWED_TOPICS, *_EXTRA_EN, *_EXTRA_VI]))
