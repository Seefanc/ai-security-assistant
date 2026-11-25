"""FastAPI 服务：10 个检测模块的并发调度 + DeepSeek 安全问答。

设计要点
- 每个模块独立超时（10s）与错误隔离：单个模块超时/失败不影响其它模块。
- 模块结果带 status 字段（ok / timeout / error），前端据此区分
  "没发现问题" 与 "根本没检测成功"，避免把失败误读成安全。
- 所有出站请求前先做目标校验（scheme、端口、内网地址），防 SSRF。
- 扫描接口与问答接口都有限流，避免公开服务被刷爆（也保护 API 额度）。
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Callable

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import scanner
from guard import TargetError, assert_public_target, normalize_target
from ratelimit import SlidingWindowLimiter

load_dotenv()

MODULE_TIMEOUT = 10

#: key -> (中文标题, 检测函数, 无发现时的提示语)
MODULES: dict[str, tuple[str, Callable[..., list], str]] = {
    "headers": ("安全响应头", scanner.check_headers, "安全响应头齐全"),
    "exposed": ("敏感文件泄露", scanner.check_exposed_files, "未发现可未授权读取的敏感文件"),
    "xss": ("反射型 XSS", scanner.check_xss, "未发现反射型 XSS"),
    "sqli": ("SQL 注入", scanner.check_sqli, "未发现报错型 SQL 注入"),
    "ports": ("开放端口", scanner.check_open_ports, "常见端口均未开放"),
    "cookie": ("Cookie 安全标记", scanner.check_cookie_flags, "未下发 Cookie 或标记齐全"),
    "redirect": ("开放式重定向", scanner.check_redirect_trap, "未发现开放式重定向"),
    "traversal": ("目录遍历", scanner.check_path_traversal, "未发现目录遍历"),
    "cors": ("CORS 跨域配置", scanner.check_cors_misconfig, "未发现 CORS 配置错误"),
    "option": ("危险 HTTP 方法", scanner.check_option, "未发现 PUT/DELETE 等危险方法"),
}

scan_limiter = SlidingWindowLimiter(limit=6, window_seconds=60)
chat_limiter = SlidingWindowLimiter(limit=20, window_seconds=60)

app = FastAPI(title="AI 安全助手", version="1.1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

_client = None


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    level: str = Field(default="normal", max_length=16)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def get_client():
    """延迟创建 DeepSeek 客户端，缺少 key 时给出明确错误而不是 import 期崩溃。"""
    global _client
    if _client is None:
        api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("服务端未配置 DEEPSEEK_API_KEY")
        from openai import OpenAI  # 延迟导入：没有 openai 包也能跑扫描接口

        _client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    return _client


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate(request: Request, limiter: SlidingWindowLimiter, action: str) -> None:
    ip = _client_ip(request)
    if not limiter.allow(ip):
        wait = max(1, int(limiter.retry_after(ip)) or 1)
        raise HTTPException(
            status_code=429,
            detail=f"{action}请求过于频繁，请 {wait} 秒后重试",
            headers={"Retry-After": str(wait)},
        )


def _status_for_error(exc: Exception) -> str:
    if isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
        return "timeout" if isinstance(exc, requests.exceptions.Timeout) else "error"
    if isinstance(exc, TargetError):
        return "error"
    return "error"


async def _run_module(key: str, title: str, func, target: str) -> dict:
    started = time.perf_counter()
    try:
        items = await asyncio.wait_for(asyncio.to_thread(func, target), timeout=MODULE_TIMEOUT)
        return {
            "key": key,
            "title": title,
            "status": "ok",
            "items": items or [],
            "error": None,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }
    except asyncio.TimeoutError:
        return {
            "key": key,
            "title": title,
            "status": "timeout",
            "items": [],
            "error": f"超过 {MODULE_TIMEOUT} 秒未完成",
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001 - 模块级错误隔离
        status = _status_for_error(exc)
        message = str(exc) or exc.__class__.__name__
        return {
            "key": key,
            "title": title,
            "status": status,
            "items": [],
            "error": message[:300],
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }


@app.get("/", include_in_schema=False)
def index():
    return RedirectResponse(url="/static/index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "deepseek_configured": bool(os.environ.get("DEEPSEEK_API_KEY", "").strip()),
        "modules": len(MODULES),
    }


@app.post("/api/chat")
def chat(req: ChatRequest, request: Request):
    _check_rate(request, chat_limiter, "问答")
    try:
        client = get_client()
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是一个 Web 安全助手。回答要具体、可执行，"
                        "涉及加固建议时给出配置示例，不要编造不存在的漏洞。"
                    ),
                },
                {"role": "user", "content": req.message},
            ],
            max_tokens=1024,
            timeout=60,
        )
        reply = response.choices[0].message.content
        return {"reply": reply}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - 上游 API 异常统一转为 502
        raise HTTPException(status_code=502, detail=f"AI 服务调用失败：{exc}") from exc


@app.post("/api/scan")
async def scan(req: ScanRequest, request: Request):
    _check_rate(request, scan_limiter, "扫描")

    try:
        target = normalize_target(req.url)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        await asyncio.wait_for(asyncio.to_thread(assert_public_target, target), timeout=5)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="目标域名解析超时") from exc

    started = time.perf_counter()
    tasks = [
        asyncio.create_task(_run_module(key, title, func, target))
        for key, (title, func, _empty) in MODULES.items()
    ]
    results = await asyncio.gather(*tasks)
    modules = {result["key"]: result for result in results}

    headers_module = modules["headers"]
    stats = scanner.summarize(headers_module["items"]) if headers_module["status"] == "ok" else {}

    summary = {"ok": 0, "timeout": 0, "error": 0, "findings": 0}
    for result in results:
        summary[result["status"]] = summary.get(result["status"], 0) + 1
        summary["findings"] += len(result["items"])

    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "modules": modules,
        "empty_text": {key: spec[2] for key, spec in MODULES.items()},
        "stats": stats,
        "summary": summary,
    }
