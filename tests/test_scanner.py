"""检测模块的单元测试：全部用假响应，不产生真实网络请求。"""

from __future__ import annotations

import pytest
from conftest import FakeResponse, FakeSession

import scanner


@pytest.fixture
def fake(monkeypatch):
    def install(session):
        monkeypatch.setattr(scanner, "SESSION", session)
        return session

    return install


class TestHeaders:
    def test_reports_missing_headers(self, fake):
        session = fake(FakeSession(default=FakeResponse(headers={"X-Frame-Options": "DENY"})))
        findings = scanner.check_headers("https://example.com/")
        names = {item["name"] for item in findings}
        assert "content-security-policy" in names
        assert "x-frame-options" not in names

    def test_http_site_downgrades_hsts(self, fake):
        fake(FakeSession(default=FakeResponse(headers={})))
        findings = scanner.check_headers("http://example.com/")
        hsts = next(item for item in findings if item["name"] == "strict-transport-security")
        assert hsts["severity"] == "low"

    def test_https_site_keeps_hsts_medium(self, fake):
        fake(FakeSession(default=FakeResponse(headers={})))
        findings = scanner.check_headers("https://example.com/")
        hsts = next(item for item in findings if item["name"] == "strict-transport-security")
        assert hsts["severity"] == "medium"

    def test_all_headers_present_returns_empty(self, fake):
        headers = {name: "x" for name in scanner.SECURITY_HEADERS}
        fake(FakeSession(default=FakeResponse(headers=headers)))
        assert scanner.check_headers("https://example.com/") == []


class TestExposed:
    def test_flags_real_git_head(self, fake):
        session = fake(FakeSession({
            "/.git/HEAD": FakeResponse(text="ref: refs/heads/main\n"),
        }))
        findings = scanner.check_exposed_files("https://example.com/")
        assert any(item["path"] == "/.git/HEAD" for item in findings)
        assert len(session.calls) == len(scanner.EXPOSED_PATHS)

    def test_ignores_spa_fallback_for_git_head(self, fake):
        fake(FakeSession({"/.git/HEAD": FakeResponse(status_code=200, text="<html>spa</html>")}))
        assert scanner.check_exposed_files("https://example.com/") == []

    def test_ignores_404(self, fake):
        fake(FakeSession(default=FakeResponse(status_code=404)))
        assert scanner.check_exposed_files("https://example.com/") == []


class TestXss:
    def test_flags_reflection(self, fake):
        payload = scanner.XSS_PAYLOADS[0]
        fake(FakeSession(default=FakeResponse(
            text=f"<html>{payload}</html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )))
        findings = scanner.check_xss("https://example.com/search?x=1")
        assert len(findings) == 1
        assert findings[0]["payload"] == payload
        # 已有 query 时不能拼出畸形 URL
        assert "x=1" in findings[0]["url"] and "?x=1&q=" in findings[0]["url"]

    def test_ignores_non_html_response(self, fake):
        payload = scanner.XSS_PAYLOADS[0]
        fake(FakeSession(default=FakeResponse(
            text=payload,
            headers={"Content-Type": "application/json"},
        )))
        assert scanner.check_xss("https://example.com/") == []

    def test_uses_all_payloads(self, fake):
        session = fake(FakeSession(default=FakeResponse(
            text="nothing",
            headers={"Content-Type": "text/html"},
        )))
        scanner.check_xss("https://example.com/")
        assert len(session.calls) == len(scanner.XSS_PAYLOADS)


class TestSqli:
    def test_no_false_positive_when_baseline_has_signature(self, fake):
        def session():
            return FakeSession({
                "id=1": FakeResponse(text="Warning: mysql_fetch() expects parameter"),
            }, default=FakeResponse(text="Warning: mysql_fetch() expects parameter"))

        fake(session())
        assert scanner.check_sqli("https://example.com/") == []

    def test_flags_new_error_signature(self, fake):
        fake(FakeSession({
            "id=1": FakeResponse(text="ok"),
        }, default=FakeResponse(text="You have an error in your SQL syntax near '1'")))
        findings = scanner.check_sqli("https://example.com/")
        assert findings and findings[0]["severity"] == "high"


class TestPorts:
    def test_detects_open_port(self, fake, monkeypatch):
        class Conn:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def create_connection(address, timeout=None):
            host, port = address
            if port == 8080:
                return Conn()
            raise OSError("closed")

        monkeypatch.setattr(scanner.socket, "create_connection", create_connection)
        findings = scanner.check_open_ports("https://example.com/")
        assert [item["port"] for item in findings] == [8080]

    def test_skips_target_port(self, fake, monkeypatch):
        def create_connection(address, timeout=None):
            raise OSError("closed")

        monkeypatch.setattr(scanner.socket, "create_connection", create_connection)
        assert scanner.check_open_ports("https://example.com:443/") == []


class TestCookie:
    def test_no_cookie_means_no_findings(self, fake):
        fake(FakeSession(default=FakeResponse(headers={})))
        assert scanner.check_cookie_flags("https://example.com/") == []

    def test_flags_missing_flags(self, fake):
        fake(FakeSession(default=FakeResponse(raw_cookies=["sid=abc; Path=/"])))
        findings = scanner.check_cookie_flags("https://example.com/")
        flags = {item["flag"] for item in findings}
        assert flags == {"HttpOnly", "Secure", "SameSite"}

    def test_secure_cookie_passes(self, fake):
        fake(FakeSession(default=FakeResponse(
            raw_cookies=["sid=abc; HttpOnly; Secure; SameSite=Lax"]
        )))
        assert scanner.check_cookie_flags("https://example.com/") == []


class TestRedirect:
    def test_flags_open_redirect(self, fake):
        fake(FakeSession(default=FakeResponse(
            status_code=302, headers={"Location": "https://evil.example/login"}
        )))
        findings = scanner.check_redirect_trap("https://example.com/")
        assert findings
        assert all(item["severity"] == "high" for item in findings)

    def test_ignores_internal_redirect(self, fake):
        fake(FakeSession(default=FakeResponse(
            status_code=302, headers={"Location": "/login"}
        )))
        assert scanner.check_redirect_trap("https://example.com/") == []


class TestTraversal:
    def test_ignores_plain_localhost_word(self, fake):
        fake(FakeSession(default=FakeResponse(
            text="<html>Server running on localhost, root: ready</html>"
        )))
        assert scanner.check_path_traversal("https://example.com/") == []

    def test_flags_passwd_content(self, fake):
        fake(FakeSession(default=FakeResponse(
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        )))
        findings = scanner.check_path_traversal("https://example.com/")
        assert findings and findings[0]["signature"] == "root:"

    def test_flags_win_ini(self, fake):
        fake(FakeSession(default=FakeResponse(
            text="[extensions]\n[fonts]\n[files]\n"
        )))
        findings = scanner.check_path_traversal("https://example.com/")
        assert findings and findings[0]["signature"] == "[extensions]"


class TestCors:
    def test_wildcard_is_medium(self, fake):
        fake(FakeSession(default=FakeResponse(
            headers={"Access-Control-Allow-Origin": "*"}
        )))
        findings = scanner.check_cors_misconfig("https://example.com/")
        assert findings[0]["severity"] == "medium"

    def test_wildcard_with_credentials_is_high(self, fake):
        fake(FakeSession(default=FakeResponse(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })))
        findings = scanner.check_cors_misconfig("https://example.com/")
        assert findings[0]["severity"] == "high"

    def test_reflected_origin_is_high(self, fake):
        fake(FakeSession(default=FakeResponse(
            headers={"Access-Control-Allow-Origin": "https://evil.example"}
        )))
        findings = scanner.check_cors_misconfig("https://example.com/")
        assert findings and "反射" in findings[0]["type"]

    def test_no_cors_header(self, fake):
        fake(FakeSession(default=FakeResponse(headers={})))
        assert scanner.check_cors_misconfig("https://example.com/") == []


class TestOptions:
    def test_flags_put(self, fake):
        fake(FakeSession(default=FakeResponse(headers={"Allow": "GET, PUT, DELETE"})))
        findings = scanner.check_option("https://example.com/")
        assert findings and set(findings[0]["methods"]) == {"PUT", "DELETE"}

    def test_allows_safe_methods(self, fake):
        fake(FakeSession(default=FakeResponse(headers={"Allow": "GET, HEAD, POST"})))
        assert scanner.check_option("https://example.com/") == []


class TestSummarize:
    def test_counts_by_severity(self):
        items = [{"severity": "high"}, {"severity": "high"}, {"severity": "low"}]
        assert scanner.summarize(items) == {"high": 2, "low": 1}

    def test_tolerates_non_list(self):
        assert scanner.summarize({"error": "boom"}) == {}
