"""
Rate limiting for PortWatch Pro.

A small, dependency-free fixed-window limiter keyed by client IP (or by user
when authenticated). It protects the brute-forceable and expensive endpoints:
login, register, password reset, and scan submission.

Scope: in-process memory. That is correct for the single-process deployment
this project ships (one gunicorn worker with threads, see docs/DEPLOYMENT.md).
If you scale to several worker processes, swap this for Flask-Limiter backed
by Redis; the decorator signature is compatible with that migration.

Limit strings: "<count>/<second|minute|hour|day>", e.g. "10/minute".
"""

import functools
import threading
import time

from flask import request, jsonify, current_app, g

_UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def parse_limit(spec):
    count, _, unit = spec.strip().partition("/")
    unit = unit.strip().rstrip("s") or "minute"
    if unit not in _UNITS:
        raise ValueError(f"Unknown rate-limit unit '{unit}' in '{spec}'")
    return int(count), _UNITS[unit]


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets = {}   # (name, key) -> [window_start, count]

    def reset(self):
        with self._lock:
            self._buckets.clear()

    def hit(self, name, key, limit, window):
        """Record one hit. Returns (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get((name, key))
            if bucket is None or now - bucket[0] >= window:
                bucket = [now, 0]
                self._buckets[(name, key)] = bucket
            bucket[1] += 1
            count = bucket[1]
            if len(self._buckets) > 10000:
                self._evict(now)
            if count > limit:
                retry = max(1, int(window - (now - bucket[0])) + 1)
                return False, 0, retry
            return True, limit - count, 0

    def _evict(self, now):
        stale = [k for k, (start, _) in self._buckets.items() if now - start > 86400]
        for k in stale:
            del self._buckets[k]


limiter = RateLimiter()


def _client_key():
    user = getattr(g, "user", None)
    if user is not None:
        return f"user:{user.id}"
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return "ip:" + fwd.split(",")[0].strip()
    return "ip:" + (request.remote_addr or "unknown")


def rate_limit(config_key, name=None):
    """Decorator. `config_key` names the app-config entry holding the limit
    string (e.g. RATELIMIT_LOGIN) so limits stay tunable by environment."""

    def deco(fn):
        bucket_name = name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            cfg = current_app.config
            if not cfg.get("RATELIMIT_ENABLED", True):
                return fn(*args, **kwargs)
            spec = cfg.get(config_key)
            if not spec:
                return fn(*args, **kwargs)
            limit, window = parse_limit(spec)
            allowed, remaining, retry = limiter.hit(bucket_name, _client_key(), limit, window)
            if not allowed:
                resp = jsonify({"error": "Too many requests, slow down and try again shortly",
                                "retry_after": retry})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                resp.headers["X-RateLimit-Limit"] = str(limit)
                resp.headers["X-RateLimit-Remaining"] = "0"
                return resp
            resp = current_app.make_response(fn(*args, **kwargs))
            resp.headers["X-RateLimit-Limit"] = str(limit)
            resp.headers["X-RateLimit-Remaining"] = str(remaining)
            return resp

        return wrapper

    return deco
