"""测试公共夹具：把项目根目录加入 sys.path，并提供伪造的 HTTP 响应对象。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class FakeResponse:
    """尽量模仿 requests.Response 的常用属性。"""

    def __init__(self, status_code=200, text="", headers=None, url="https://example.com/", raw_cookies=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.raw = type("Raw", (), {"headers": FakeCookieHeaders(raw_cookies or [])})()


class FakeCookieHeaders:
    def __init__(self, cookies):
        self._cookies = list(cookies)

    def getlist(self, name):
        return self._cookies if name.lower() == "set-cookie" else []


class FakeSession:
    """按 URL 前缀返回预设响应，并记录调用。"""

    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def _pick(self, url):
        for prefix, response in self.responses.items():
            if prefix in url:
                return response
        if self.default is not None:
            return self.default
        return FakeResponse(status_code=404, url=url)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._pick(url)

    def options(self, url, **kwargs):
        self.calls.append(("OPTIONS", url, kwargs))
        return self._pick(url)
