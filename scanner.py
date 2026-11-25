"""10 类 Web 安全检测模块的实现。

约定：每个 check_* 函数接收已归一化的目标 URL，返回 **list[dict]**（发现项）。
- 请求层面完全失败（连不上、域名解析失败、全部探测超时）时抛异常，
  由 server.py 统一转成 status="error" 的模块结果，避免"没检测"被当成"没问题"。
- 单个 payload 失败不影响其它 payload，属于正常的容错。

所有出站请求默认 `allow_redirects=False`：既避免跳转把扫描器带到内网地址
（SSRF 绕过路径），也避免把跳转后的第三方页面当成目标站分析。
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

USER_AGENT = "AISecurityAssistant/1.0 (+https://github.com/Seefanc/ai-security-assistant)"
REQUEST_TIMEOUT = 5
PROBE_TIMEOUT = 3
PORT_TIMEOUT = 1.5

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
SESSION.max_redirects = 3

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "medium",
        "desc": "未设置 HSTS，用户可能被降级到明文 HTTP",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "x-content-type-options": {
        "severity": "low",
        "desc": "缺少此头，浏览器可能错误猜测文件类型",
        "fix": "X-Content-Type-Options: nosniff",
    },
    "content-security-policy": {
        "severity": "medium",
        "desc": "缺少 CSP，对 XSS 缺少最后一道防线",
        "fix": "Content-Security-Policy: default-src 'self'",
    },
    "x-frame-options": {
        "severity": "low",
        "desc": "页面可能被嵌入第三方 iframe 做点击劫持",
        "fix": "X-Frame-Options: DENY",
    },
    "referrer-policy": {
        "severity": "low",
        "desc": "跳转时可能通过 Referer 泄漏敏感 URL",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "low",
        "desc": "未限制浏览器敏感 API（摄像头、麦克风、定位）",
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}

#: 只做提示、不计入风险统计的探测项
EXPOSED_PATHS = (
    ("/.git/HEAD", "high", "Git 仓库元数据可公开读取，可能被还原出源码"),
    ("/.env", "high", "环境变量文件可公开读取，可能泄漏密钥"),
    ("/admin/", "low", "管理后台入口可公开访问"),
)

SQLI_PAYLOADS = (
    "'",
    "' OR '1'='1",
    "' UNION SELECT 1--",
    '" OR "1"="1',
)

SQLI_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "uncaught mysqli_sql_exception",
    "warning: mysql_fetch",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    "sqlstate[",
    "pg_query(): query failed",
    "ora-01756",
    "quoted string not properly terminated",
)

XSS_PAYLOADS = (
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
)

TRAVERSAL_PAYLOADS = (
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2f..%2fwindows/win.ini",
    "..\\..\\..\\windows\\win.ini",
)

#: 用正则/组合特征降低误报：`localhost` 这种词几乎每个页面都有，不能作为特征
TRAVERSAL_MARKERS = {
    "root:": ("passwd",),          # 需要同时出现 root: 与 shell 字段特征
    "[extensions]": ("[fonts]",),  # win.ini 才同时有这两段
    "[fonts]": ("[extensions]",),
}

COMMON_PORTS = (80, 443, 22, 3306, 8080)
REDIRECT_PARAMS = ("redirect", "url", "next", "goto", "return")
EVIL_URL = "https://evil.example/"
MAX_WORKERS = 5


def _get(url: str, *, timeout: float = PROBE_TIMEOUT, **kwargs) -> requests.Response:
    kwargs.setdefault("allow_redirects", False)
    return SESSION.get(url, timeout=timeout, **kwargs)


def _with_query(url: str, key: str, value: str) -> str:
    """保留原有 query 再追加参数，避免 `?a=1?q=` 这种畸形 URL。"""
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _parallel(func, items, workers: int = MAX_WORKERS):
    """并发跑多个探测项；单项失败跳过，全部失败才抛异常。"""
    items = list(items)
    if not items:
        return []
    results: list[dict] = []
    errors: list[Exception] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        futures = [pool.submit(func, item) for item in items]
        for future in futures:
            try:
                results.extend(future.result())
            except Exception as exc:  # noqa: BLE001 - 探测项失败要逐个容忍
                errors.append(exc)
    if errors and not results:
        raise errors[0]
    return results


def check_headers(target_url: str) -> list[dict]:
    """检测缺失的安全响应头。"""
    resp = _get(target_url, timeout=REQUEST_TIMEOUT)
    present = {key.lower() for key in resp.headers}
    findings = []
    for header, info in SECURITY_HEADERS.items():
        if header in present:
            continue
        if header == "strict-transport-security" and urlsplit(target_url).scheme != "https":
            # HTTP 站点没有 HSTS 是必然的，降级为提示，避免噪声
            severity = "low"
        else:
            severity = info["severity"]
        findings.append(
            {
                "name": header,
                "severity": severity,
                "desc": info["desc"],
                "fix": info["fix"],
            }
        )
    return findings


def check_exposed_files(target_url: str) -> list[dict]:
    """探测 Git 元数据、.env、后台入口是否可未授权读取。"""
    base = target_url.rstrip("/")

    def probe(item):
        path, severity, desc = item
        resp = _get(base + path, timeout=PROBE_TIMEOUT)
        if resp.status_code != 200:
            return []
        body = resp.text[:4096]
        if path == "/.git/HEAD" and not body.lstrip().startswith("ref:"):
            return []  # 200 但不是 Git 内容，多半是 SPA 的兜底页
        if path == "/.env" and "=" not in body:
            return []
        return [
            {
                "path": path,
                "url": base + path,
                "severity": severity,
                "desc": desc,
            }
        ]

    return _parallel(probe, EXPOSED_PATHS)


def check_xss(target_url: str) -> list[dict]:
    """反射型 XSS：payload 在响应中原样出现即视为反射。"""

    def probe(payload):
        url = _with_query(target_url, "q", payload)
        resp = _get(url, timeout=PROBE_TIMEOUT)
        if "html" not in resp.headers.get("Content-Type", "").lower():
            return []
        if payload not in resp.text:
            return []
        return [
            {
                "type": "反射型 XSS",
                "severity": "high",
                "payload": payload,
                "url": url,
            }
        ]

    return _parallel(probe, XSS_PAYLOADS)


def check_sqli(target_url: str) -> list[dict]:
    """报错型 SQL 注入：用正常参数做基线，只有注入后才出现的报错才算命中。"""
    baseline_url = _with_query(target_url, "id", "1")
    try:
        baseline = _get(baseline_url, timeout=PROBE_TIMEOUT).text.lower()
    except requests.RequestException:
        baseline = ""

    def probe(payload):
        url = _with_query(target_url, "id", payload)
        resp = _get(url, timeout=PROBE_TIMEOUT)
        text = resp.text.lower()
        for signature in SQLI_ERROR_SIGNATURES:
            if signature in text and signature not in baseline:
                return [
                    {
                        "type": "报错型 SQL 注入",
                        "severity": "high",
                        "payload": payload,
                        "signature": signature,
                        "url": url,
                    }
                ]
        return []

    return _parallel(probe, SQLI_PAYLOADS)


def check_open_ports(target_url: str) -> list[dict]:
    """TCP 连通性探测常见端口（不是发 HTTP 请求）。"""
    parts = urlsplit(target_url)
    host = parts.hostname or ""
    skip_port = parts.port or (443 if parts.scheme == "https" else 80)

    def probe(port):
        if port == skip_port:
            return []
        try:
            with socket.create_connection((host, port), timeout=PORT_TIMEOUT):
                return [{"port": port, "status": "open"}]
        except OSError:
            return []

    return _parallel(probe, COMMON_PORTS)


def _set_cookie_values(resp: requests.Response) -> list[str]:
    headers = getattr(resp.raw, "headers", None)
    getlist = getattr(headers, "getlist", None)
    if getlist is not None:
        return list(getlist("Set-Cookie"))
    raw = resp.headers.get("Set-Cookie")
    return [raw] if raw else []


def check_cookie_flags(target_url: str) -> list[dict]:
    """Cookie 安全标记检测：没有下发 Cookie 时不应报缺失。"""
    resp = _get(target_url, timeout=REQUEST_TIMEOUT)
    cookies = _set_cookie_values(resp)
    if not cookies:
        return []
    findings = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip() or "cookie"
        lowered = cookie.lower()
        if "httponly" not in lowered:
            findings.append(
                {
                    "flag": "HttpOnly",
                    "cookie": name,
                    "severity": "medium",
                    "desc": "Cookie 可被 JS 读取，XSS 时会被直接窃取",
                }
            )
        if "secure" not in lowered:
            findings.append(
                {
                    "flag": "Secure",
                    "cookie": name,
                    "severity": "medium",
                    "desc": "Cookie 可能在明文 HTTP 下传输",
                }
            )
        if "samesite" not in lowered:
            findings.append(
                {
                    "flag": "SameSite",
                    "cookie": name,
                    "severity": "low",
                    "desc": "未声明 SameSite，跨站请求可能携带该 Cookie",
                }
            )
    return findings


def check_redirect_trap(target_url: str) -> list[dict]:
    """开放式重定向：参数被直接拼进 Location 即视为可被劫持。"""

    def probe(param):
        url = _with_query(target_url, param, EVIL_URL)
        resp = _get(url, timeout=PROBE_TIMEOUT)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return []
        location = resp.headers.get("Location", "")
        if "evil.example" not in location:
            return []
        return [
            {
                "param": param,
                "severity": "high",
                "location": location,
                "url": url,
            }
        ]

    return _parallel(probe, REDIRECT_PARAMS)


def _match_traversal(text: str) -> str | None:
    lowered = text.lower()
    for marker, companions in TRAVERSAL_MARKERS.items():
        if marker in lowered:
            if all(companion in lowered for companion in companions):
                return marker
    # passwd 文件更精确的特征：root 行带 shell/uid 结构
    if "root:" in lowered and (":/bin/" in lowered or ":/sbin/" in lowered):
        return "root:"
    return None


def check_path_traversal(target_url: str) -> list[dict]:
    """目录遍历：需要命中文件内容的组合特征，单靠 localhost 之类的词不算。"""

    def probe(payload):
        url = _with_query(target_url, "file", payload)
        resp = _get(url, timeout=PROBE_TIMEOUT)
        marker = _match_traversal(resp.text)
        if marker is None:
            return []
        return [
            {
                "type": "目录遍历",
                "severity": "high",
                "payload": payload,
                "signature": marker,
                "url": url,
            }
        ]

    return _parallel(probe, TRAVERSAL_PAYLOADS)


def check_cors_misconfig(target_url: str) -> list[dict]:
    """CORS 配置错误：通配符放行，或原样反射任意 Origin。"""
    origin = "https://evil.example"
    resp = _get(target_url, timeout=REQUEST_TIMEOUT, headers={"Origin": origin})
    allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        return [
            {
                "type": "CORS 配置错误",
                "severity": "high",
                "value": "Access-Control-Allow-Origin: * 且 Allow-Credentials: true",
            }
        ]
    if allow_origin == "*":
        return [
            {
                "type": "CORS 配置错误",
                "severity": "medium",
                "value": "Access-Control-Allow-Origin: *",
            }
        ]
    if allow_origin.strip() == origin:
        return [
            {
                "type": "CORS 反射任意 Origin",
                "severity": "high",
                "value": f"Access-Control-Allow-Origin 反射了 {origin}",
            }
        ]
    return []


def check_option(target_url: str) -> list[dict]:
    """危险 HTTP 方法：OPTIONS 的 Allow 里出现 PUT/DELETE/TRACE/PATCH。"""
    resp = SESSION.options(target_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    allow = resp.headers.get("Allow", "")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in allow.upper()]
    if not risky:
        return []
    return [
        {
            "type": "危险 HTTP 方法",
            "severity": "medium",
            "value": allow,
            "methods": risky,
        }
    ]


def summarize(findings) -> dict[str, int]:
    """按严重级别统计发现项数量（兼容异常/空结果）。"""
    counts: dict[str, int] = {}
    if not isinstance(findings, list):
        return counts
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = item.get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1
    return counts
