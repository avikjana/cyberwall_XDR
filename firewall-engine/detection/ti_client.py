"""
Threat Intelligence Client – Lightweight HTTP client used by the firewall-engine
to query the TI service for real-time IOC enrichment during packet processing.
Non-blocking with timeout guards to prevent packet pipeline stalls.
"""
import os
import logging
import threading
import requests

logger = logging.getLogger("FirewallEngine.TIClient")

TI_SERVICE_URL = os.getenv("TI_SERVICE_URL", "http://localhost:5004")


class ThreatIntelClient:
  """
  Async-safe client for enriching IPs/domains against the TI service.
  Uses a thread pool pattern to avoid blocking the packet capture loop.
  """

  def __init__(self):
    self.base_url = TI_SERVICE_URL
    self.session = requests.Session()
    self.session.headers.update({"Content-Type": "application/json"})
    adapter = requests.adapters.HTTPAdapter(pool_connections=3, pool_maxsize=5, max_retries=1)
    self.session.mount("http://", adapter)
    self._enrichment_cache = {}  # In-memory fast cache for current session
    self._lock = threading.Lock()
    logger.info(f"TI Client initialized → {self.base_url}")

  def enrich_ip_async(self, ip, callback=None):
    """
    Non-blocking IP enrichment — fires in a background thread.
    Calls callback(verdict_dict) when done.
    """
    # Quick session cache check
    with self._lock:
      if ip in self._enrichment_cache:
        if callback:
          callback(self._enrichment_cache[ip])
        return

    thread = threading.Thread(
      target=self._do_enrich_ip,
      args=(ip, callback),
      daemon=True
    )
    thread.start()

  def _do_enrich_ip(self, ip, callback):
    try:
      res = self.session.get(
        f"{self.base_url}/api/ti/enrich/ip",
        params={"ip": ip},
        timeout=3
      )
      if res.status_code == 200:
        verdict = res.json()
        with self._lock:
          self._enrichment_cache[ip] = verdict
        if callback:
          callback(verdict)
      else:
        logger.debug(f"TI enrichment returned {res.status_code} for {ip}")
    except requests.exceptions.RequestException:
      pass  # TI service unavailable — fail open
    except Exception as e:
      logger.error(f"TI enrichment error for {ip}: {e}")

  def enrich_ip_sync(self, ip, timeout=2):
    """
    Blocking IP enrichment with strict timeout.
    Returns verdict dict or None on failure.
    """
    with self._lock:
      if ip in self._enrichment_cache:
        return self._enrichment_cache[ip]

    try:
      res = self.session.get(
        f"{self.base_url}/api/ti/enrich/ip",
        params={"ip": ip},
        timeout=timeout
      )
      if res.status_code == 200:
        verdict = res.json()
        with self._lock:
          self._enrichment_cache[ip] = verdict
        return verdict
    except Exception:
      pass
    return None

  def is_known_malicious(self, ip):
    """
    Quick check: returns True if IP is in the cache with a malicious verdict.
    Does NOT make an external call — only checks session cache.
    """
    with self._lock:
      cached = self._enrichment_cache.get(ip)
    if cached and cached.get("verdict") == "malicious":
      return True
    return False
