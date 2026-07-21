## Small in-memory helpers for caching lookups and enforcing API quotas.

from __future__ import annotations

from collections import deque
from copy import deepcopy
from threading import Lock
from time import monotonic
from typing import Callable


class ReputationCache:
    """Thread-safe time-to-live cache for VirusTotal analysis statistics."""

    def __init__(self, ttl_seconds: float = 24 * 60 * 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[float, dict[str, int]]] = {}
        self._lock = Lock()

    def get(self, url: str) -> dict[str, int] | None:
        now = monotonic()
        with self._lock:
            item = self._items.get(url)
            if item is None:
                return None

            stored_at, value = item
            if now - stored_at >= self.ttl_seconds:
                del self._items[url]
                return None
            return deepcopy(value)

    def set(self, url: str, value: dict[str, int]) -> None:
        with self._lock:
            self._items[url] = (monotonic(), deepcopy(value))

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class CallRateLimiter:
    """Non-blocking sliding-window limiter shared by app reruns."""

    def __init__(
        self,
        max_calls: int = 4,
        period_seconds: float = 60,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._clock = clock
        self._calls: deque[float] = deque()
        self._lock = Lock()

    def try_acquire(self) -> bool:
        now = self._clock()
        with self._lock:
            cutoff = now - self.period_seconds
            while self._calls and self._calls[0] <= cutoff:
                self._calls.popleft()

            if len(self._calls) >= self.max_calls:
                return False

            self._calls.append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._calls.clear()


DEFAULT_REPUTATION_CACHE = ReputationCache()
VIRUSTOTAL_RATE_LIMITER = CallRateLimiter()
