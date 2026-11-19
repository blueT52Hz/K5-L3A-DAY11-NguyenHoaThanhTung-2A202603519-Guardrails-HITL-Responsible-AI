"""
Checkpoint 3 — Defense-in-depth pipeline assembly.

Wire rate limiter + lab guardrails + audit + monitoring + egress.

Thiết kế:
  - Plugin (chạy trong runner, theo thứ tự): RateLimit -> InputGuardrail -> (LLM) -> OutputGuardrail
  - Audit + Monitoring là "side observer": run_assignment_suite gọi quanh mỗi request
    (OpenAIRunner không có hook before/after cho cả vòng request).
  - Egress: is_egress_allowed là rule code thuần, gọi trước mọi sink gửi dữ liệu ra ngoài.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from assignment.assignment_test_queries import (
    ATTACK_QUERIES,
    EDGE_CASES,
    RATE_LIMIT_QUERY,
    SAFE_QUERIES,
)
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.rate_limiter import RateLimitPlugin
from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin, content_filter

# So khớp CHÍNH XÁC hostname (không dùng endswith) -> chặn api.vinbank.example.evil.com
ALLOWED_EGRESS_HOSTS = frozenset({"api.vinbank.example", "cases.vinbank.example"})
_SENSITIVE_PAYLOAD = re.compile(
    r"password|passwd|mật\s*khẩu|api[\s_-]*key|secret|credential|\.internal\b|admin123",
    re.IGNORECASE,
)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_USER_ID = "student"  # OpenAIRunner luôn dùng user_id này


def is_egress_allowed(destination: str, payload: str) -> bool:
    """Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    try:
        url = urlparse(destination or "")
    except ValueError:
        return False
    if url.scheme != "https" or url.hostname not in ALLOWED_EGRESS_HOSTS:
        return False
    if url.username or url.password:  # https://user:pass@host -> lộ credential qua URL
        return False
    payload = payload or ""
    if _SENSITIVE_PAYLOAD.search(payload):
        return False
    # Tái dùng regex PII/secret của CP2 (SĐT, email, CCCD, key, host nội bộ...)
    return content_filter(payload)["safe"]


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = False,
) -> list:
    """Return an ordered list of plugins / layers:

    1. RateLimitPlugin       - chặn spam trước khi tốn regex / LLM
    2. InputGuardrailPlugin  - injection + topic
    3. OutputGuardrailPlugin - redact PII / secret (LLM-as-Judge optional)
    """
    return [
        RateLimitPlugin(max_requests=max_requests, window_seconds=window_seconds),
        InputGuardrailPlugin(),
        OutputGuardrailPlugin(use_llm_judge=use_llm_judge),
    ]


def build_observability():
    """Return (AuditLogPlugin(), MonitoringAlert())."""
    return AuditLogPlugin(), MonitoringAlert()


def _find_plugin(plugins: list, cls):
    return next((p for p in plugins if isinstance(p, cls)), None)


def _counter(plugin, attr: str) -> int:
    return getattr(plugin, attr, 0) if plugin is not None else 0


async def _run_query(agent, runner, plugins, audit, monitor, text: str, request_id: str) -> dict:
    """Chạy 1 câu qua pipeline; suy ra lớp chặn bằng chênh lệch bộ đếm của plugin."""
    from core.utils import chat_with_agent

    rate = _find_plugin(plugins, RateLimitPlugin)
    inp = _find_plugin(plugins, InputGuardrailPlugin)
    out = _find_plugin(plugins, OutputGuardrailPlugin)
    before = (_counter(rate, "blocked_count"), _counter(inp, "blocked_count"),
              _counter(out, "redacted_count"))
    before_small_talk = _counter(inp, "small_talk_count")

    audit.record_input(user_id=_USER_ID, text=text, request_id=request_id)
    error = None
    try:
        response, _ = await chat_with_agent(agent, runner, text)
    except Exception as exc:  # lỗi API (quota, timeout...) không làm sập cả suite
        error = f"{type(exc).__name__}: {exc}"
        response = f"[error] {error}"

    layer = None
    if _counter(rate, "blocked_count") > before[0]:
        layer = "rate_limiter"
    elif _counter(inp, "blocked_count") > before[1]:
        layer = "input_guardrail"
    elif _counter(out, "redacted_count") > before[2]:
        layer = "output_guardrail"
    blocked = layer is not None

    audit.record_output(user_id=_USER_ID, text=response, blocked=blocked,
                        layer=layer, request_id=request_id)
    monitor.record(blocked=blocked, layer=layer)

    row = {"input": text, "blocked": blocked, "layer": layer,
           "response_preview": (response or "")[:200]}
    if layer is None and _counter(inp, "small_talk_count") > before_small_talk:
        row["handled_by"] = "small_talk"  # trả lời mẫu, không gọi LLM, không tính chặn
    if layer == "input_guardrail" and getattr(inp, "last_block_reason", None):
        row["reason"] = inp.last_block_reason
    if layer == "output_guardrail" and getattr(out, "last_issues", None):
        row["issues"] = list(out.last_issues)
    if error:
        row["error"] = error
    return row


async def run_assignment_suite(pipeline) -> dict:
    """Run Tests 1–4 from CHECKPOINTS.md (Checkpoint 3) and
    return a dict matching schemas/results.schema.json.

    Files:
      <repo>/outputs/results.json
      <repo>/outputs/audit_log.json   (via AuditLogPlugin.export_json)
      <repo>/outputs/metrics.json     (via MonitoringAlert.export_json)
    """
    from agents.agent import create_blue_agent  # import muộn tránh vòng import

    plugins, audit, monitor = pipeline["plugins"], pipeline["audit"], pipeline["monitor"]
    agent, runner = create_blue_agent(plugins)
    rate = _find_plugin(plugins, RateLimitPlugin)
    results: dict = {"framework": "google-adk"}
    counter = 0

    # Tests 1-3: user_id luôn là "student" -> reset cửa sổ rate limit giữa các nhóm,
    # để test spam (Test 4) không làm câu safe bị chặn nhầm
    for key, queries in (("safe_queries", SAFE_QUERIES),
                         ("attack_queries", ATTACK_QUERIES),
                         ("edge_cases", EDGE_CASES)):
        if rate is not None:
            rate.reset()
        rows = []
        for query in queries:
            counter += 1
            rows.append(await _run_query(agent, runner, plugins, audit, monitor, query, f"req-{counter}"))
            print(f"  [{key}] blocked={rows[-1]['blocked']!s:<5} layer={rows[-1]['layer']}  {query[:60]!r}")
        results[key] = rows

    # Test 4: rate limit - bộ plugin riêng, max nhỏ để đỡ tốn API
    max_requests, window_seconds, sent = 5, 60, 8
    rl_plugins = build_production_plugins(max_requests=max_requests, window_seconds=window_seconds)
    rl_agent, rl_runner = create_blue_agent(rl_plugins)
    rate_blocked = 0
    for _ in range(sent):
        counter += 1
        row = await _run_query(rl_agent, rl_runner, rl_plugins, audit, monitor,
                               RATE_LIMIT_QUERY, f"req-{counter}")
        rate_blocked += int(row["layer"] == "rate_limiter")
    results["rate_limit"] = {
        "max_requests": max_requests,
        "window_seconds": window_seconds,
        "sent": sent,
        "passed": sent - rate_blocked,
        "blocked": rate_blocked,
    }
    print(f"  [rate_limit] {results['rate_limit']}")

    out_dir = _REPO_ROOT / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    audit.export_json()
    monitor.export_json()
    return results
