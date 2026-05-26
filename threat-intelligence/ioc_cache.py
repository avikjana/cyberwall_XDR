"""
IOC Cache – Redis-backed TTL caching layer for Threat Intelligence lookups.
Prevents redundant external API calls and ensures sub-millisecond IOC enrichment.
"""
import json
import logging
import redis

logger = logging.getLogger("TI.Cache")


class IOCCache:
  def __init__(self, redis_url="redis://localhost:6379", default_ttl=3600):
    self.default_ttl = default_ttl
    try:
      self.client = redis.Redis.from_url(redis_url, decode_responses=True)
      self.client.ping()
      self.connected = True
      logger.info("IOC Cache connected to Redis.")
    except Exception as e:
      logger.warning(f"Redis not available for IOC caching. Falling back to in-memory. {e}")
      self.connected = False
      self._fallback = {}

  def _key(self, indicator_type, indicator):
    return f"ti:{indicator_type}:{indicator}"

  def get(self, indicator_type, indicator):
    key = self._key(indicator_type, indicator)
    try:
      if self.connected:
        raw = self.client.get(key)
        if raw:
          return json.loads(raw)
      else:
        entry = self._fallback.get(key)
        if entry:
          return entry
    except Exception as e:
      logger.error(f"Cache GET error: {e}")
    return None

  def set(self, indicator_type, indicator, data, ttl=None):
    key = self._key(indicator_type, indicator)
    ttl = ttl or self.default_ttl
    try:
      if self.connected:
        self.client.setex(key, ttl, json.dumps(data))
      else:
        self._fallback[key] = data
    except Exception as e:
      logger.error(f"Cache SET error: {e}")
