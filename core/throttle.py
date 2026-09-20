"""Brute-force protection for sign-in: a failure counter per key over a sliding window.

In-process on purpose. Cerberus runs as one API process (see `fail_interrupted_scans`), and a
counter that lives in memory needs no extra infrastructure. If the API is ever scaled out, this is
the piece to move to a shared store; the interface would not change.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable

MAX_TRACKED_KEYS = 10_000


class Throttled(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"too many attempts; retry in {retry_after}s")
        self.retry_after = retry_after


class FailureLimiter:
    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 900,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.max_failures = max_failures
        self.window = window_seconds
        self._clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _recent(self, key: str) -> deque[float]:
        failures = self._failures[key]
        cutoff = self._clock() - self.window
        while failures and failures[0] <= cutoff:
            failures.popleft()
        return failures

    def check(self, key: str) -> None:
        """Raise `Throttled` if `key` has used up its failures for the window."""
        failures = self._recent(key)
        if len(failures) >= self.max_failures:
            raise Throttled(max(1, int(failures[0] + self.window - self._clock()) + 1))

    def record_failure(self, key: str) -> None:
        if len(self._failures) >= MAX_TRACKED_KEYS:
            self._prune()
        self._recent(key).append(self._clock())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)

    def _prune(self) -> None:
        for key in [k for k in self._failures if not self._recent(k)]:
            del self._failures[key]
