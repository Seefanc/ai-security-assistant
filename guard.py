"""目标地址归一化与 SSRF（服务端请求伪造）防护。

公开部署的扫描服务会把用户输入的 URL 用自己的服务器去请求，
如果不做限制，攻击者可以让服务端访问内网地址、云厂商元数据接口
（169.254.169.254）或 Redis/数据库等非 HTTP 服务，把扫描器变成内网代理。
所以所有出站探测前，统一走这里做校验。
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

#: 只允许 HTTP(S)，避免 file:// / gopher:// 之类的协议被当成探测入口
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: 只允许常见 Web 端口，避免拿扫描器去敲 22/3306/6379 这类非 HTTP 服务
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443, 8000, 3000, 5000, 9000})

#: 私网、回环、链路本地、保留地址一律拒绝
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
)

#: 常见内网主机名，不需要 DNS 就能判断
BLOCKED_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "metadata"}
)


class TargetError(ValueError):
    """目标地址不合法或不允许访问。"""


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        return True
    if ip.is_multicast or ip.is_unspecified:
        return True
    return any(ip in net for net in BLOCKED_NETWORKS)


def _split_host_port(hostname: str, port: int | None) -> tuple[str, int | None]:
    """处理 `example.com:8080` 这种被 urlparse 当成 netloc 的写法。"""
    if port is not None:
        return hostname, port
    if hostname.startswith("[") and "]" in hostname:  # IPv6 字面量
        inner, _, rest = hostname[1:].partition("]")
        return inner, (int(rest[1:]) if rest.startswith(":") else None)
    if hostname.count(":") == 1:
        host, _, maybe_port = hostname.partition(":")
        if maybe_port.isdigit():
            return host, int(maybe_port)
    return hostname, None


def normalize_target(raw: str) -> str:
    """把用户输入整理成合法的 http(s) URL，同时做基础校验。"""
    target = (raw or "").strip()
    if not target:
        raise TargetError("目标地址不能为空")
    if len(target) > 2048:
        raise TargetError("目标地址过长")
    if "://" not in target:
        target = "https://" + target

    try:
        parts = urlsplit(target)
    except ValueError as exc:  # 非法 IPv6 等
        raise TargetError(f"目标地址格式错误：{exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError(f"只支持 http/https，收到：{scheme or '空'}")
    if parts.username or parts.password:
        raise TargetError("目标地址不允许携带账号密码")
    if not parts.hostname:
        raise TargetError("无法解析目标主机名")

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"端口不合法：{exc}") from exc

    hostname, port = _split_host_port(parts.hostname, port)
    hostname = hostname.rstrip(".").lower()
    if not hostname:
        raise TargetError("无法解析目标主机名")
    if hostname in BLOCKED_HOSTNAMES:
        raise TargetError("不允许扫描本机或内网地址")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and _is_blocked_ip(literal):
        raise TargetError(f"不允许访问该地址：{hostname}")
    if port is not None and port not in ALLOWED_PORTS:
        raise TargetError(f"不允许探测端口 {port}")

    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def resolve_host(hostname: str) -> list[str]:
    """解析域名，返回去重后的 IP 列表。DNS 失败时抛 TargetError。"""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetError(f"域名解析失败：{hostname}") from exc
    seen: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise TargetError(f"域名解析失败：{hostname}")
    return seen


def assert_public_target(url: str) -> None:
    """解析 URL 的主机名，确认它落在公网地址上。

    注意：这里做的是「请求前」检查，严格的实现还应把 IP 固定到连接上，
    否则存在 DNS rebinding 的窗口（解析出公网 IP、实际连接时换成内网 IP）。
    本项目为演示用途，已通过 `allow_redirects=False` 关闭跳转绕过路径。
    """
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    hostname, _ = _split_host_port(hostname, None)
    if not hostname:
        raise TargetError("无法解析目标主机名")
    if hostname in BLOCKED_HOSTNAMES:
        raise TargetError("不允许扫描本机或内网地址")

    # 字面量 IP 直接判断，省一次 DNS
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_ip(literal):
            raise TargetError(f"不允许访问该地址：{hostname}")
        return

    for ip_text in resolve_host(hostname):
        ip = ipaddress.ip_address(ip_text)
        if _is_blocked_ip(ip):
            raise TargetError(f"目标解析到内网地址，已拒绝：{hostname} -> {ip_text}")
