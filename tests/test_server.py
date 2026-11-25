"""接口层测试：目标校验、模块错误隔离、超时语义、限流。"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "assert_public_target", lambda url: None)
    server.scan_limiter.reset()
    server.chat_limiter.reset()
    return TestClient(server.app)


@pytest.fixture
def fake_modules(monkeypatch):
    """把 10 个模块换成可控的假函数。"""

    def install(behaviour):
        modules = {}
        for key, (title, _func, empty) in server.MODULES.items():
            modules[key] = (title, behaviour.get(key, lambda url: []), empty)
        monkeypatch.setattr(server, "MODULES", modules)
        return modules

    return install


def test_root_redirects_to_static(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"].endswith("/static/index.html")


def test_health(client):
    payload = client.get("/api/health").json()
    assert payload["status"] == "ok"
    assert payload["modules"] == 10


def test_scan_rejects_localhost(client, monkeypatch):
    monkeypatch.setattr(server, "assert_public_target", lambda url: (_ for _ in ()).throw(
        server.TargetError("不允许扫描本机或内网地址")
    ))
    response = client.post("/api/scan", json={"url": "http://localhost:8000"})
    assert response.status_code == 400
    assert "内网" in response.json()["detail"]


def test_scan_rejects_bad_scheme(client):
    response = client.post("/api/scan", json={"url": "file:///etc/passwd"})
    assert response.status_code == 400


def test_scan_returns_structured_modules(client, fake_modules):
    fake_modules({})
    payload = client.post("/api/scan", json={"url": "example.com"}).json()

    assert payload["target"] == "https://example.com/"
    assert len(payload["modules"]) == 10
    assert all(module["status"] == "ok" for module in payload["modules"].values())
    assert payload["summary"]["ok"] == 10
    assert payload["summary"]["findings"] == 0
    assert payload["empty_text"]["headers"]


def test_scan_isolates_module_error(client, fake_modules):
    def boom(url):
        raise RuntimeError("连不上目标站点")

    fake_modules({"headers": boom})
    payload = client.post("/api/scan", json={"url": "example.com"}).json()

    headers_module = payload["modules"]["headers"]
    assert headers_module["status"] == "error"
    assert "连不上" in headers_module["error"]
    assert payload["modules"]["xss"]["status"] == "ok"
    assert payload["summary"]["error"] == 1
    assert payload["summary"]["ok"] == 9


def test_scan_marks_timeout(client, fake_modules, monkeypatch):
    def slow(url):
        time.sleep(0.3)
        return []

    monkeypatch.setattr(server, "MODULE_TIMEOUT", 0.05)
    fake_modules({"ports": slow})
    payload = client.post("/api/scan", json={"url": "example.com"}).json()

    assert payload["modules"]["ports"]["status"] == "timeout"
    assert payload["summary"]["timeout"] == 1


def test_scan_counts_findings_and_stats(client, fake_modules):
    def headers(url):
        return [
            {"name": "content-security-policy", "severity": "medium", "desc": "d", "fix": "f"},
            {"name": "x-frame-options", "severity": "low", "desc": "d", "fix": "f"},
        ]

    def xss(url):
        return [{"type": "反射型 XSS", "severity": "high", "payload": "p", "url": "u"}]

    fake_modules({"headers": headers, "xss": xss})
    payload = client.post("/api/scan", json={"url": "example.com"}).json()

    assert payload["stats"] == {"medium": 1, "low": 1}
    assert payload["summary"]["findings"] == 3
    assert payload["elapsed_ms"] >= 0


def test_scan_rate_limited(client, fake_modules):
    fake_modules({})
    for _ in range(6):
        assert client.post("/api/scan", json={"url": "example.com"}).status_code == 200
    response = client.post("/api/scan", json={"url": "example.com"})
    assert response.status_code == 429
    assert response.headers["Retry-After"]


def test_chat_without_key_returns_503(client, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(server, "_client", None)
    response = client.post("/api/chat", json={"message": "hi"})
    assert response.status_code == 503


def test_chat_rejects_empty_message(client):
    assert client.post("/api/chat", json={"message": ""}).status_code == 422


def test_chat_rejects_too_long_message(client):
    assert client.post("/api/chat", json={"message": "a" * 2001}).status_code == 422
