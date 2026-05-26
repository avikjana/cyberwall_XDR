"""
Enrichment Pipeline – Orchestrates multi-provider IOC lookups with caching and scoring.
This is the main interface the firewall-engine and backend services call.
"""
import os
import json
import logging
import threading

from ioc_cache import IOCCache
from feed_providers import VirusTotalProvider, AbuseIPDBProvider, AlienVaultOTXProvider
from reputation_engine import ReputationEngine

logger = logging.getLogger("TI.Pipeline")

# Load feed configuration
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "feeds_config.json")
with open(_CONFIG_PATH, "r") as f:
  _CONFIG = json.load(f)


class EnrichmentPipeline:
  """
  Main entry point for threat intelligence lookups.
  Caches results, fans out to all configured providers, and returns a scored verdict.
  Thread-safe for concurrent firewall-engine usage.
  """

  def __init__(self, redis_url=None):
    redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")

    self.cache = IOCCache(redis_url=redis_url, default_ttl=3600)
    self._lock = threading.Lock()

    # Initialize providers
    feeds = _CONFIG.get("feeds", {})
    self.providers = []
    if feeds.get("virustotal", {}).get("enabled"):
      self.providers.append(VirusTotalProvider(feeds["virustotal"]))
    if feeds.get("abuseipdb", {}).get("enabled"):
      self.providers.append(AbuseIPDBProvider(feeds["abuseipdb"]))
    if feeds.get("alienvault_otx", {}).get("enabled"):
      self.providers.append(AlienVaultOTXProvider(feeds["alienvault_otx"]))

    # Scoring engine
    self.scorer = ReputationEngine(
      scoring_config=_CONFIG.get("scoring", {}),
      mitre_config=_CONFIG.get("mitre_mapping", {})
    )

    logger.info(f"Enrichment Pipeline initialized with {len(self.providers)} provider(s).")

  def enrich_ip(self, ip, bypass_cache=False):
    """Enrich an IP address using all providers. Returns unified verdict."""
    if not bypass_cache:
      cached = self.cache.get("ip", ip)
      if cached:
        logger.debug(f"Cache HIT for IP {ip}")
        cached["_cached"] = True
        return cached

    enrichments = []
    for provider in self.providers:
      try:
        result = provider.lookup_ip(ip)
        if result:
          enrichments.append(result)
      except Exception as e:
        logger.error(f"Provider {provider.name} failed for IP {ip}: {e}")

    verdict = self.scorer.score_ip(enrichments)
    verdict["indicator"] = ip
    verdict["enrichments"] = enrichments
    verdict["_cached"] = False

    # Cache the result
    self.cache.set("ip", ip, verdict)
    return verdict

  def enrich_domain(self, domain, bypass_cache=False):
    """Enrich a domain using all providers. Returns unified verdict."""
    if not bypass_cache:
      cached = self.cache.get("domain", domain)
      if cached:
        cached["_cached"] = True
        return cached

    enrichments = []
    for provider in self.providers:
      try:
        result = provider.lookup_domain(domain)
        if result:
          enrichments.append(result)
      except Exception as e:
        logger.error(f"Provider {provider.name} failed for domain {domain}: {e}")

    verdict = self.scorer.score_domain(enrichments)
    verdict["indicator"] = domain
    verdict["enrichments"] = enrichments
    verdict["_cached"] = False

    self.cache.set("domain", domain, verdict)
    return verdict

  def enrich_hash(self, file_hash, bypass_cache=False):
    """Enrich a file hash using all providers. Returns unified verdict."""
    if not bypass_cache:
      cached = self.cache.get("hash", file_hash)
      if cached:
        cached["_cached"] = True
        return cached

    enrichments = []
    for provider in self.providers:
      try:
        result = provider.lookup_hash(file_hash)
        if result:
          enrichments.append(result)
      except Exception as e:
        logger.error(f"Provider {provider.name} failed for hash {file_hash}: {e}")

    verdict = self.scorer.score_hash(enrichments)
    verdict["indicator"] = file_hash
    verdict["enrichments"] = enrichments
    verdict["_cached"] = False

    self.cache.set("hash", file_hash, verdict)
    return verdict

  def bulk_enrich_ips(self, ips):
    """Batch enrich a list of IPs. Returns list of verdicts."""
    results = []
    for ip in ips:
      results.append(self.enrich_ip(ip))
    return results
