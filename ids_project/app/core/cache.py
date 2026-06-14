"""
Redis cache helper.

Thin wrapper around redis-py providing get/set/delete operations with
automatic JSON serialisation and configurable TTL.

If Redis is unavailable, operations degrade gracefully (log warning,
return None for gets).

Config keys:
  REDIS_URL  (str)  — Redis connection URL (default: redis://localhost:6379/0)
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_redis_client = None


def init_cache(app) -> None:
    """Initialise the Redis client from Flask app config."""
    global _redis_client
    redis_url = app.config.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        import redis
        _redis_client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=3)
        _redis_client.ping()
        app.logger.info("Redis cache connected: %s", redis_url)
    except Exception as exc:
        _redis_client = None
        app.logger.warning("Redis unavailable (%s) — caching disabled", exc)


def cache_get(key: str) -> Optional[Any]:
    """Retrieve a cached value by key.

    Returns:
        Deserialised Python object or None if key missing/error.
    """
    if _redis_client is None:
        return None
    try:
        raw = _redis_client.get(key)
        return json.loads(raw) if raw is not None else None
    except Exception as exc:
        logger.debug("Cache GET error for %s: %s", key, exc)
        return None


def cache_set(key: str, value: Any, ttl_seconds: int = 300) -> bool:
    """Store a value in cache with a TTL.

    Args:
        key:         Cache key.
        value:       Any JSON-serialisable object.
        ttl_seconds: Time-to-live in seconds (default 5 minutes).

    Returns:
        True if stored, False on error.
    """
    if _redis_client is None:
        return False
    try:
        _redis_client.setex(key, ttl_seconds, json.dumps(value, default=str))
        return True
    except Exception as exc:
        logger.debug("Cache SET error for %s: %s", key, exc)
        return False


def cache_delete(key: str) -> None:
    """Remove a key from cache."""
    if _redis_client is None:
        return
    try:
        _redis_client.delete(key)
    except Exception as exc:
        logger.debug("Cache DELETE error for %s: %s", key, exc)


def cache_delete_pattern(pattern: str) -> int:
    """Delete all keys matching a glob pattern.

    Returns:
        Count of deleted keys.
    """
    if _redis_client is None:
        return 0
    try:
        keys = _redis_client.keys(pattern)
        if keys:
            return _redis_client.delete(*keys)
        return 0
    except Exception as exc:
        logger.debug("Cache DELETE PATTERN error (%s): %s", pattern, exc)
        return 0
