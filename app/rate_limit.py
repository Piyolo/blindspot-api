"""In-memory sliding-window failure rate limiting (per client IP).

State is process-local (one dict per limiter instance) — enough for the
single-worker deployment; no Redis, no new dependencies. Time comes from the
injectable ``now`` argument in tests, so nothing ever sleeps.
"""

import time
from collections import deque

from fastapi import Request


class FailureLimiter:
    """Allow at most ``limit`` recorded failures per key within ``window_seconds``.

    ``allowed()`` is a pure check: it prunes hits that have aged out of the
    window but never records anything. A hit exactly ``window_seconds`` old
    counts as expired.
    """

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = {}

    def allowed(self, key: str, *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        hits = self._hits.get(key)
        if not hits:
            return True
        self._prune(hits, current)
        return len(hits) < self.limit

    def record(self, key: str, *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        hits = self._hits.setdefault(key, deque())
        self._prune(hits, current)
        hits.append(current)

    def reset(self, key: str | None = None) -> None:
        """Forget one key's hits, or every key's hits when ``key`` is None."""
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)

    def _prune(self, hits: deque, now: float) -> None:
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()


login_limiter = FailureLimiter(limit=10, window_seconds=600)
signup_limiter = FailureLimiter(limit=5, window_seconds=3600)


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit keying.

    The LAST ``X-Forwarded-For`` entry wins: each trusted proxy appends the
    peer address it actually saw, so the rightmost entry is proxy-attested
    while anything to its left arrived from the client and is spoofable.
    Falls back to the socket peer, then to ``"unknown"`` — never raises,
    not even when ``request.client`` is ``None``.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"
