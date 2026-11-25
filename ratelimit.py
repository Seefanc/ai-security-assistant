"""极简内存滑动窗口限流。

公开部署的扫描服务如果没有限流，任何人（或脚本）都能把它当免费扫描器用，
还会顺带烧掉 DeepSeek 的 API 额度。这里用进程内字典做最小可用防护：
单实例足够，多实例部署应换成 Redis。
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float, clock=time.monotonic):
        if limit <= 0:
            raise ValueError("limit 必须为正整数")
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """返回 True 表示放行，同时记录一次命中。"""
        now = self._clock()
        deadline = now - self.window
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= deadline:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    def retry_after(self, key: str) -> float:
        """距离下一次可用大致的秒数，用于 Retry-After 头。"""
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return 0.0
            return max(0.0, self.window - (self._clock() - bucket[0]))

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
