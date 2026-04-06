"""
Rate limiter for scan/exploit endpoints.
Uses Redis when available (REDIS_URL env var), falls back to in-memory.
Keyed by user email. Thread-safe.
"""
import os
import time
import threading
import logging
from fastapi import HTTPException

log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

SCAN_RATE_LIMIT = 5
SCAN_RATE_WINDOW = 60  # seconds

EXPLOIT_RATE_LIMIT = 10
EXPLOIT_RATE_WINDOW = 60

REDIS_URL = os.getenv("REDIS_URL", "")

# ── Backend selection ────────────────────────────────────────────────

_redis_client = None

if REDIS_URL:
    try:
        import redis
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
        log.info("Rate limiter: using Redis at %s", REDIS_URL)
    except Exception as e:
        log.warning("Rate limiter: Redis unavailable (%s), falling back to in-memory", e)
        _redis_client = None


# ── Redis backend ────────────────────────────────────────────────────

def _check_rate_redis(key: str, limit: int, window: int):
    """Sliding-window rate limit using a Redis sorted set."""
    now = time.time()
    pipe = _redis_client.pipeline()
    # Remove entries older than the window
    pipe.zremrangebyscore(key, 0, now - window)
    # Count remaining entries
    pipe.zcard(key)
    # Add current request
    pipe.zadd(key, {f"{now}": now})
    # Set expiry on the whole key so it auto-cleans
    pipe.expire(key, window + 1)
    results = pipe.execute()
    current_count = results[1]

    if current_count >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {limit} requests per {window}s."
        )


# ── In-memory backend ───────────────────────────────────────────────

_lock = threading.Lock()
_buckets: dict[str, list[float]] = {}


def _check_rate_memory(key: str, limit: int, window: int):
    now = time.time()
    with _lock:
        timestamps = _buckets.get(key, [])
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {limit} requests per {window}s."
            )
        timestamps.append(now)
        _buckets[key] = timestamps


# ── Public API ───────────────────────────────────────────────────────

def _check_rate(key: str, limit: int, window: int):
    if _redis_client is not None:
        try:
            _check_rate_redis(key, limit, window)
            return
        except HTTPException:
            raise
        except Exception as e:
            # Redis failed at runtime — fall through to in-memory
            log.warning("Redis rate-limit call failed (%s), using in-memory fallback", e)
    _check_rate_memory(key, limit, window)


def check_scan_rate(user_email: str):
    _check_rate(f"ashen:rate:scan:{user_email}", SCAN_RATE_LIMIT, SCAN_RATE_WINDOW)


def check_exploit_rate(user_email: str):
    _check_rate(f"ashen:rate:exploit:{user_email}", EXPLOIT_RATE_LIMIT, EXPLOIT_RATE_WINDOW)


def reset_rate_limits():
    """For testing only — clears both backends."""
    with _lock:
        _buckets.clear()
    if _redis_client is not None:
        try:
            for key in _redis_client.scan_iter("ashen:rate:*"):
                _redis_client.delete(key)
        except Exception:
            pass
