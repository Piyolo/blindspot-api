"""In-memory sliding-window failure rate limiting (per client IP).

State is process-local (one dict per limiter instance) — enough for the
single-worker deployment; no Redis, no new dependencies. Time comes from the
injectable ``now`` argument in tests, so nothing ever sleeps.
"""

import ipaddress
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


# Why no X-Forwarded-For position is ever used as a key: every Render service
# sits behind Cloudflare, which APPENDS to X-Forwarded-For — so the leftmost
# entry is caller-controlled and the remaining hops are rotating Cloudflare/
# Render edge addresses, which scattered consecutive requests across buckets
# and silently disabled the limiter in production. ``CF-Connecting-IP`` is the
# header Cloudflare *overwrites* (Render documents it as the trustworthy one),
# with ``True-Client-IP`` as a validated secondary. ``request.client.host`` is
# only reached in local/dev/test, and on Render it would be the internal load
# balancer's address anyway because uvicorn does not trust the proxy.


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit keying.

    Resolution order: ``CF-Connecting-IP``, then ``True-Client-IP`` (each only
    when the trimmed value parses as an IPv4/IPv6 address), then the socket
    peer, then ``"unknown"`` — never raises, not even when ``request.client``
    is ``None``. Never derived from ``X-Forwarded-For`` in any position.
    """
    for header in ("CF-Connecting-IP", "True-Client-IP"):
        raw = request.headers.get(header)
        if raw is None:
            continue
        candidate = raw.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue  # junk/unparseable: fall through, never key on it
        return candidate
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"
