"""
Feed Sync Worker – Async background scheduler that periodically pulls from external
threat intelligence feeds and pre-warms the IOC cache with known-bad indicators.
Runs as a daemon thread inside the TI service.
"""
import os
import time
import json
import logging
import threading
import requests

from ioc_cache import IOCCache

logger = logging.getLogger("TI.FeedSync")

# Default public blocklists (no API key required)
DEFAULT_IP_BLOCKLISTS = [
  "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
]

DEFAULT_DOMAIN_BLOCKLISTS = [
  "https://urlhaus.abuse.ch/downloads/text_recent/",
]


class FeedSyncWorker:
  """
  Background worker that syncs external IOC feeds on a configurable interval.
  Pre-populates the Redis IOC cache so that real-time lookups are instant.
  """

  def __init__(self, cache: IOCCache, interval_minutes=30):
    self.cache = cache
    self.interval = interval_minutes * 60
    self._stop_event = threading.Event()
    self._thread = None
    self._session = requests.Session()
    self._session.headers.update({"User-Agent": "CyberWall-XDR-TI/1.0"})

  def start(self):
    """Start the background sync daemon."""
    self._thread = threading.Thread(target=self._run_loop, daemon=True, name="FeedSyncWorker")
    self._thread.start()
    logger.info(f"Feed sync worker started (interval: {self.interval}s)")

  def stop(self):
    self._stop_event.set()
    if self._thread:
      self._thread.join(timeout=10)

  def _run_loop(self):
    # Run immediately on startup, then at intervals
    while not self._stop_event.is_set():
      try:
        self._sync_all()
      except Exception as e:
        logger.error(f"Feed sync error: {e}")
      self._stop_event.wait(self.interval)

  def _sync_all(self):
    logger.info("Starting feed synchronization...")
    total = 0

    # Sync IP blocklists
    for url in DEFAULT_IP_BLOCKLISTS:
      count = self._sync_ip_list(url)
      total += count

    # Sync domain blocklists
    for url in DEFAULT_DOMAIN_BLOCKLISTS:
      count = self._sync_domain_list(url)
      total += count

    # Sync custom IOC file if present
    custom_path = os.path.join(os.path.dirname(__file__), "custom_iocs.json")
    if os.path.exists(custom_path):
      count = self._sync_custom_iocs(custom_path)
      total += count

    logger.info(f"Feed sync complete. {total} IOCs cached.")

  def _sync_ip_list(self, url):
    """Download and cache a public IP blocklist."""
    count = 0
    try:
      res = self._session.get(url, timeout=30)
      if res.status_code != 200:
        logger.warning(f"Failed to fetch {url}: HTTP {res.status_code}")
        return 0
      for line in res.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
          continue
        # Some lists have format: "ip\ttabs" or "ip,score"
        ip = line.split("\t")[0].split(",")[0].split(" ")[0].strip()
        if self._is_valid_ip(ip):
          self.cache.set("ip", ip, {
            "indicator_type": "ip",
            "indicator": ip,
            "reputation_score": 85.0,
            "verdict": "malicious",
            "severity": "high",
            "source": "blocklist",
            "feed_url": url,
            "component_scores": {},
            "mitre_attack": [{"id": "TA0043", "name": "Reconnaissance"}],
            "tags": ["blocklist"],
            "metadata": {},
            "enrichments": []
          }, ttl=86400)  # 24h TTL for blocklist entries
          count += 1
    except Exception as e:
      logger.error(f"Error syncing IP list {url}: {e}")
    logger.info(f"Synced {count} IPs from {url}")
    return count

  def _sync_domain_list(self, url):
    """Download and cache a public domain blocklist."""
    count = 0
    try:
      res = self._session.get(url, timeout=30)
      if res.status_code != 200:
        return 0
      for line in res.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
          continue
        # URL lists often have full URLs — extract domain
        domain = line
        if "://" in domain:
          domain = domain.split("://")[1].split("/")[0]
        if domain and "." in domain:
          self.cache.set("domain", domain, {
            "indicator_type": "domain",
            "indicator": domain,
            "reputation_score": 80.0,
            "verdict": "malicious",
            "severity": "high",
            "source": "blocklist",
            "feed_url": url,
            "component_scores": {},
            "mitre_attack": [],
            "tags": ["blocklist"],
            "metadata": {},
            "enrichments": []
          }, ttl=86400)
          count += 1
    except Exception as e:
      logger.error(f"Error syncing domain list {url}: {e}")
    logger.info(f"Synced {count} domains from {url}")
    return count

  def _sync_custom_iocs(self, path):
    """Load custom IOCs from a local JSON file."""
    count = 0
    try:
      with open(path, "r") as f:
        iocs = json.load(f)
      for ioc in iocs:
        itype = ioc.get("type", "ip")
        indicator = ioc.get("indicator", "")
        if not indicator:
          continue
        self.cache.set(itype, indicator, {
          "indicator_type": itype,
          "indicator": indicator,
          "reputation_score": ioc.get("score", 90.0),
          "verdict": ioc.get("verdict", "malicious"),
          "severity": ioc.get("severity", "high"),
          "source": "custom",
          "component_scores": {},
          "mitre_attack": ioc.get("mitre", []),
          "tags": ioc.get("tags", ["custom-ioc"]),
          "metadata": ioc.get("metadata", {}),
          "enrichments": []
        }, ttl=ioc.get("ttl", 604800))  # Default 7 days
        count += 1
    except Exception as e:
      logger.error(f"Error loading custom IOCs: {e}")
    logger.info(f"Loaded {count} custom IOCs.")
    return count

  @staticmethod
  def _is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
      return False
    try:
      return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
      return False
