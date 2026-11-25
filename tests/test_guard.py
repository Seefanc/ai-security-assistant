"""目标校验（SSRF 防护）的单元测试。"""

from __future__ import annotations

import pytest

from guard import (
    TargetError,
    assert_public_target,
    normalize_target,
    resolve_host,
)


class TestNormalize:
    def test_adds_https_scheme(self):
        assert normalize_target("example.com") == "https://example.com/"

    def test_keeps_path_and_query(self):
        assert normalize_target("http://example.com/a?b=1#frag") == "http://example.com/a?b=1"

    def test_strips_spaces(self):
        assert normalize_target("  example.com  ") == "https://example.com/"

    def test_rejects_empty(self):
        with pytest.raises(TargetError):
            normalize_target("   ")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(TargetError):
            normalize_target("ftp://example.com")

    def test_rejects_file_scheme(self):
        with pytest.raises(TargetError):
            normalize_target("file:///etc/passwd")

    def test_rejects_credentials(self):
        with pytest.raises(TargetError):
            normalize_target("http://user:pass@example.com")

    def test_rejects_localhost(self):
        with pytest.raises(TargetError):
            normalize_target("http://localhost:8080")

    def test_rejects_loopback_ip(self):
        with pytest.raises(TargetError):
            normalize_target("http://127.0.0.1")

    def test_rejects_private_ip(self):
        with pytest.raises(TargetError):
            normalize_target("http://192.168.1.1")

    def test_rejects_metadata_ip(self):
        with pytest.raises(TargetError):
            normalize_target("http://169.254.169.254/latest/meta-data/")

    def test_rejects_disallowed_port(self):
        with pytest.raises(TargetError):
            normalize_target("http://example.com:22")

    def test_allows_web_port(self):
        assert normalize_target("http://example.com:8080/x") == "http://example.com:8080/x"

    def test_rejects_too_long(self):
        with pytest.raises(TargetError):
            normalize_target("https://example.com/" + "a" * 3000)


class TestResolve:
    def test_returns_ips(self, monkeypatch):
        monkeypatch.setattr(
            "guard.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        assert resolve_host("example.com") == ["93.184.216.34"]

    def test_raises_on_dns_failure(self, monkeypatch):
        import socket as socket_module

        def boom(*args, **kwargs):
            raise socket_module.gaierror("nope")

        monkeypatch.setattr("guard.socket.getaddrinfo", boom)
        with pytest.raises(TargetError):
            resolve_host("nonexistent.invalid")


class TestAssertPublicTarget:
    def test_accepts_public_ip_literal(self):
        assert_public_target("http://93.184.216.34/")

    def test_rejects_private_ip_literal(self):
        with pytest.raises(TargetError):
            assert_public_target("http://10.0.0.5/")

    def test_rejects_hostname_resolving_to_private(self, monkeypatch):
        monkeypatch.setattr(
            "guard.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("192.168.0.10", 0))],
        )
        with pytest.raises(TargetError):
            assert_public_target("http://internal.example.com/")

    def test_accepts_hostname_resolving_to_public(self, monkeypatch):
        monkeypatch.setattr(
            "guard.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        assert_public_target("http://example.com/")
